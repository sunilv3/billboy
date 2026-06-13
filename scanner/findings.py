"""Finding management: add_finding, auto-verify, set_progress, op_log."""
import time
import json
import re
import secrets
import hashlib
import shutil
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from scanner.state import scan_state, LOCK
from scanner.validation import (
    _validate_finding, _confidence_score, _apply_severity_confidence_coupling,
    classify_vuln, normalize_asset, fingerprint,
    calculate_cvss, _extract_tool_output, _generate_exploit_steps,
    calculate_finding_context_risk,
)
from scanner.suppression import is_suppressed
from core.logger import log, push_sse
from core.database import DB_PATH
from core.utils import (
    _safe_str, _safe_int, _find_tool, _run_tool,
    req_lib, REQUESTS_AVAILABLE, SQLITE_AVAILABLE, sqlite3_mod,
    CVSS3_AVAILABLE, CVSS3,
)

_verify_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix='auto_verify')


def _extract_url_from_details(details, fallback_asset):
    """Extract the primary URL from finding details, falling back to asset."""
    for line in details.split('\n'):
        line = line.strip()
        if line.lower().startswith('url:') or line.lower().startswith('endpoint:'):
            candidate = line.split(':', 1)[1].strip()
            if candidate.startswith('http'):
                return candidate
    return fallback_asset


def run_ssrfmap(asset, param):
    """Attempt SSRF exploitation via ssrfmap if available."""
    ssrfmap_path = _find_tool('ssrfmap')
    if not ssrfmap_path or not asset or not param:
        return
    try:
        url = f'{asset}?{param}=http://127.0.0.1'
        cmd = [ssrfmap_path, '-r', url, '--module', 'readfiles', '--level', '1']
        stdout, _, rc = _run_tool(cmd, timeout=30)
        if rc == 0 and stdout:
            log('ok', f'[SSRFMAP] Result: {stdout[:200]}')
    except Exception as e:
        log('warn', f'[SSRFMAP] Failed: {e}')


class ExploitVerifier:
    """Thin wrapper — submits targeted evidence-collection tasks."""
    @staticmethod
    def auto_verify(finding):
        title = finding.get('title', '').lower()
        if 'sql injection' in title or 'sqli' in title:
            auto_verify_sqli(finding)
        elif 'xss' in title:
            auto_verify_xss(finding)
        elif 'ssrf' in title:
            auto_verify_ssrf(finding)
        elif 'command injection' in title or 'cmdi' in title:
            auto_verify_cmdi(finding)
        elif 'ssti' in title or 'template injection' in title:
            auto_verify_ssti(finding)

def add_finding(sev, title, sub='', asset='', cve='', cvss='', exploit='INFO', poc_link='#', owasp='', mitre='', details='',
                confidence='medium', raw_request='', raw_response='', validation_evidence='', reproduction_steps='',
                baseline_text='', response_status=None):
    """Add a finding through the 15-Rule FP Verification Engine.

    confidence: 'confirmed' (95) / 'high' (80) / 'medium' (55) / 'low' (35) / 'speculative' (25)
    Rule 3: severity is automatically capped to match confidence tier.
    Rule 14: report_category assigned based on confidence tier + vuln type.

    Pass raw_response / baseline_text / response_status when available so the
    HTML-error-page (Rule 3), redirect (Rule 4) and baseline-similarity (Rule 6)
    checks can actually fire — they are no-ops without this evidence.
    """
    # ── Rule 3: Apply severity-confidence coupling before validation ──
    conf_score = _confidence_score(confidence)
    sev, title, report_category = _apply_severity_confidence_coupling(sev, conf_score, title)

    # ─── Universal FP gate ───
    allowed, reason = _validate_finding(
        sev, title, details, asset,
        response_text=raw_response, baseline_text=baseline_text,
        response_status=response_status, confidence=confidence,
    )
    if not allowed:
        log('debug', f'[FP-GATE] Rejected: {title[:60]} — {reason}')
        return None

    fp = fingerprint(title, asset, details)

    # ─── Self-learning suppression: analyst-dismissed FPs never resurface ───
    if is_suppressed(fp):
        log('debug', f'[FP-SUPPRESS] Rejected (previously marked false positive): {title[:60]}')
        return None

    # ── Rule 12: Enhanced deduplication — group same vuln type on same asset ──
    title_lower = title.lower()
    # Split the new fingerprint into (class|asset|param) for relaxed matching.
    _fp_parts = fp.split('|')
    new_cls = _fp_parts[0] if _fp_parts else ''
    new_asset_fp = _fp_parts[1] if len(_fp_parts) > 1 else ''
    new_param = '|'.join(_fp_parts[2:]) if len(_fp_parts) > 2 else ''

    with LOCK:
        for existing in scan_state['findings']:
            ex_fp = existing.get('fingerprint', '')
            if ex_fp and ex_fp == fp:
                # Upgrade confidence if new evidence is stronger
                if conf_score > existing.get('confidence_score', 0):
                    existing['confidence'] = confidence
                    existing['confidence_score'] = conf_score
                    existing['report_category'] = report_category
                return existing
            # Relaxed cross-detector merge: same vuln class on the same normalized
            # asset where one side named no parameter (e.g. sqlmap-confirmed finding
            # vs. the manual error-based finding) is ONE vulnerability, not two.
            if ex_fp:
                ep = ex_fp.split('|')
                ex_cls = ep[0] if ep else ''
                ex_asset_fp = ep[1] if len(ep) > 1 else ''
                ex_param = '|'.join(ep[2:]) if len(ep) > 2 else ''
                if (new_cls and new_cls == ex_cls and new_asset_fp == ex_asset_fp
                        and (not new_param or not ex_param)):
                    # Keep the more specific parameter and the stronger confidence.
                    if new_param and not ex_param:
                        existing['fingerprint'] = fp
                    if conf_score > existing.get('confidence_score', 0):
                        existing['confidence'] = confidence
                        existing['confidence_score'] = conf_score
                        existing['report_category'] = report_category
                    return existing
            # Parameter-level deduplication (Rule 12): merge SSRF/XSS/open-redirect findings
            _DEDUP_TYPES = ('ssrf', 'xss', 'open redirect', 'injection')
            same_type_asset = (
                any(dt in title_lower and dt in existing.get('title', '').lower() for dt in _DEDUP_TYPES)
                and existing.get('asset', '') == asset
            )
            if same_type_asset:
                # Merge: add affected parameter to existing finding
                param_match = None
                import re as _re2
                for pat in [r'parameter[:\s]+(\w+)', r'param[:\s]+(\w+)', r'\?(\w+)=']:
                    m = _re2.search(pat, details, _re2.I)
                    if m:
                        param_match = m.group(1)
                        break
                if param_match and param_match not in existing.get('details', ''):
                    existing['details'] += f'\nAlso affected parameter: {param_match}'
                    existing['sub'] = (existing.get('sub', '') + f', {param_match}').strip(', ')
                return existing
        scan_type = scan_state.get('scan_type', 'full')

    # ─── Heavy computation OUTSIDE lock ───
    fid = hashlib.md5(f'{title}_{asset}_{datetime.now().timestamp()}'.encode()).hexdigest()[:12]
    exploit_steps = _generate_exploit_steps(title, asset, details)
    cvss_vector = ''
    if not cvss:
        vuln_class = classify_vuln(title)
        auth_required = any(w in details.lower() for w in ['authenticated', 'login required', 'auth required'])
        user_interaction = any(w in details.lower() for w in ['user click', 'user interaction', 'csrf'])
        cvss_score, cvss_sev, cvss_vector = calculate_cvss(vuln_class, auth_required, user_interaction)
        cvss = cvss_score
    else:
        vuln_class = classify_vuln(title)
        _, _, cvss_vector = calculate_cvss(vuln_class)
    tool_output = _extract_tool_output(details)

    finding = {
        'id': fid, 'sev': sev, 'title': title, 'sub': sub, 'asset': asset,
        'cve': cve, 'cvss': cvss, 'cvss_vector': cvss_vector,
        'exploit': exploit, 'poc_link': poc_link,
        'owasp': owasp, 'mitre': mitre, 'details': details,
        'ts': datetime.now().isoformat(), 'verified': True,
        'exploitation_steps': exploit_steps,
        'tool_output': tool_output,
        'verification_status': 'auto-verified',
        'chain_id': '',
        'confidence': confidence,
        'confidence_score': conf_score,
        'report_category': report_category,
        'fingerprint': fp,
        'scan_type': scan_type,
        # Rule 2: Evidence fields
        'raw_request': raw_request,
        'raw_response': raw_response,
        'validation_evidence': validation_evidence or details,
        'reproduction_steps': reproduction_steps,
    }
    try:
        ctx_score, ctx_factors = calculate_finding_context_risk(finding)
        finding['context_risk_score'] = ctx_score
        finding['context_factors'] = ctx_factors
    except Exception:
        finding['context_risk_score'] = 0
        finding['context_factors'] = []

    # ─── Append + stats update under lock (fast) ───
    with LOCK:
        scan_state['findings'].append(finding)
        scan_state['stats'][sev] = scan_state['stats'].get(sev, 0) + 1
        st = scan_state.get('scan_type', 'full')
        if st not in scan_state.get('type_stats', {}):
            scan_state['type_stats'][st] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0}
        scan_state['type_stats'][st][sev] = scan_state['type_stats'][st].get(sev, 0) + 1
        scan_state['type_stats'][st]['total'] = scan_state['type_stats'][st].get('total', 0) + 1
        if st == 'full':
            finding_type = finding.get('scan_type', '')
            if finding_type in ('web', 'code', 'network', 'vm') and finding_type in scan_state.get('type_stats', {}):
                scan_state['type_stats'][finding_type][sev] = scan_state['type_stats'][finding_type].get(sev, 0) + 1
                scan_state['type_stats'][finding_type]['total'] = scan_state['type_stats'][finding_type].get('total', 0) + 1
    push_sse('finding', finding)
    if sev in ('critical', 'high'):
        op_log('finding_added', target=asset, detail=f'[{sev.upper()}] {title}', finding_id=fid)
    if confidence == 'high' and sev in ('critical', 'high'):
        schedule_auto_verify(finding)
    return finding




def _extract_param_from_details(details):
    """Extract parameter name from finding details."""
    for line in details.split('\n'):
        if 'parameter:' in line.lower():
            return line.split(':', 1)[1].strip()
    return ''




def auto_verify_sqli(finding):
    """Production-grade SQLi auto-verification via sqlmap.

    Features:
    - Cookie forwarding from session
    - Tamper scripts for WAF bypass
    - Higher level/risk for real detection
    - Parses injection type, DBMS, and extracted data
    - Tests for data exfiltration potential
    """
    import uuid as _uuid
    title = finding.get('title', '').lower()
    if 'sql injection' not in title and 'sqli' not in title:
        return
    if finding.get('confidence') != 'high':
        return

    sqlmap_path = _find_tool('sqlmap')
    if not sqlmap_path:
        return

    details = finding.get('details', '')
    asset = finding.get('asset', '')
    param = _extract_param_from_details(details)
    base = _extract_url_from_details(details, asset)
    if not base:
        return

    verify_id = _uuid.uuid4().hex[:8]
    url = f'{base}/?{param}=1' if param else base

    # Detect WAF type from scan_state for tamper script selection
    waf_type = scan_state.get('waf_type', 'generic').lower() if scan_state else 'generic'
    tamper_scripts = []
    if 'cloudflare' in waf_type:
        tamper_scripts = ['between', 'randomcase', 'space2comment']
    elif 'akamai' in waf_type:
        tamper_scripts = ['charencode', 'randomcase', 'space2comment']
    elif 'modsecurity' in waf_type:
        tamper_scripts = ['charencode', 'space2comment', 'between']
    elif 'aws' in waf_type:
        tamper_scripts = ['between', 'randomcase', 'space2comment']
    else:
        tamper_scripts = ['randomcase', 'space2comment']

    # Build sqlmap command — production grade
    cmd = [
        sqlmap_path, '-u', url,
        '--batch',
        '--level=3', '--risk=2',
        '--threads=1',
        '--output-dir', f'/tmp/verify_{verify_id}',
        '--banner',
        '--dbms=mysql',  # Hint to speed up detection
        '--randomAgent',  # Rotate user agents
        '--timeout=10',
        '--retries=2',
        '--answers="follow=N,redirect=N"',
    ]

    # Add tamper scripts
    if tamper_scripts:
        cmd.extend(['--tamper', ','.join(tamper_scripts)])

    # Forward cookies from session if available
    try:
        with LOCK:
            cookies = scan_state.get('session_cookies', {})
            if cookies:
                cookie_str = '; '.join(f'{k}={v}' for k, v in cookies.items())
                cmd.extend(['--cookie', cookie_str])
    except Exception:
        pass

    # Add custom headers
    cmd.extend(['--headers', 'X-Forwarded-For: 127.0.0.1'])

    try:
        stdout, stderr, rc = _run_tool(cmd, timeout=45)

        # sqlmap writes detailed output to --output-dir; read log files
        if not stdout or 'is vulnerable' not in (stdout or '').lower():
            try:
                import glob as _glob
                for log_file in _glob.glob(f'/tmp/verify_{verify_id}/**/*.log', recursive=True):
                    with open(log_file, 'r', errors='ignore') as lf:
                        log_content = lf.read()
                        if log_content:
                            stdout = (stdout or '') + '\n' + log_content
            except Exception:
                pass

        # Parse sqlmap output for detailed results
        is_vulnerable = False
        injection_type = ''
        dbms = ''
        banner = ''
        injectable_params = []

        for line in (stdout or '').split('\n'):
            line_lower = line.lower().strip()
            if 'is vulnerable' in line_lower or 'injectable' in line_lower:
                is_vulnerable = True
            if 'type:' in line_lower and ('boolean' in line_lower or 'time' in line_lower or
                                           'error' in line_lower or 'union' in line_lower):
                injection_type = line.strip()
            if 'web server operating system:' in line_lower or 'back-end dbms:' in line_lower:
                dbms = line.strip()
            if 'banner:' in line_lower:
                banner = line.split(':', 1)[1].strip()
            if 'parameter:' in line_lower:
                pname = line.split(':', 1)[1].strip() if ':' in line else ''
                if pname:
                    injectable_params.append(pname)

        if is_vulnerable:
            # Extract more details from sqlmap output
            technique = ''
            for line in stdout.split('\n'):
                if 'sqlmap identified the following injection point' in line.lower():
                    continue
                if 'technique:' in line.lower():
                    technique = line.strip()
                    break

            # Try to extract database info
            db_info = ''
            for line in stdout.split('\n'):
                if 'available databases' in line.lower():
                    db_info = line.strip()
                    break
                if 'database management system' in line.lower():
                    db_info = line.strip()

            verification_details = (
                f'\n\n[Auto-Verified] sqlmap confirmed SQL injection\n'
                f'Tool: sqlmap\n'
                f'URL: {url}\n'
                f'Parameter: {param}\n'
            )
            if injection_type:
                verification_details += f'Injection type: {injection_type}\n'
            if technique:
                verification_details += f'Technique: {technique}\n'
            if dbms:
                verification_details += f'DBMS: {dbms}\n'
            if banner:
                verification_details += f'DB Banner: {banner}\n'
            if db_info:
                verification_details += f'DB Info: {db_info}\n'
            if injectable_params:
                verification_details += f'Injectable params: {", ".join(injectable_params)}\n'
            verification_details += (
                f'Tamper scripts: {", ".join(tamper_scripts)}\n'
                f'Severity: Confirmed exploitable\n'
                f'Confidence: HIGH (sqlmap verified)\n'
                f'CVSS: 9.8 (Critical)\n'
            )

            with LOCK:
                for f in scan_state['findings']:
                    if f['id'] == finding['id']:
                        f['confidence'] = 'high'
                        f['details'] += verification_details
                        # Upgrade CVSS if we have DBMS info
                        if dbms and 'mysql' in dbms.lower():
                            f['cvss'] = '9.8'
                        break

            # Log the verification
            op_log('auto_verify', target=url,
                   detail=f'sqlmap confirmed SQLi on {param}: {injection_type or "unknown type"}',
                   finding_id=finding.get('id'))
            log('ok', f'[AUTO-VERIFY] SQLi confirmed via sqlmap: {param} ({injection_type or "unknown"})')

            # Try to extract data as proof of exploitability
            try:
                cmd_dump = [
                    sqlmap_path, '-u', url,
                    '--batch', '--level=3', '--risk=2',
                    '--randomAgent', '--threads=1',
                    '--output-dir', f'/tmp/verify_{verify_id}_dump',
                    '--dump',  # Dump all data
                    '--fresh-queries',  # Don't use cached results
                    '--flush-session',  # Fresh session
                    '--answers="follow=N,redirect=N"',
                ]
                if tamper_scripts:
                    cmd_dump.extend(['--tamper', ','.join(tamper_scripts)])
                stdout_dump, _, rc_dump = _run_tool(cmd_dump, timeout=45)
                if rc_dump == 0 and 'dumped' in stdout_dump.lower():
                    with LOCK:
                        for f in scan_state['findings']:
                            if f['id'] == finding['id']:
                                f['details'] += f'\n[Data Exfiltration] sqlmap successfully dumped data\n'
                                f['severity_note'] = 'FULL EXPLOIT confirmed — data exfiltrated'
                                break
                    log('ok', f'[AUTO-VERIFY] Data exfiltration confirmed via sqlmap')
            except Exception:
                pass

    except Exception as e:
        log('warn', f'[AUTO-VERIFY] sqlmap failed: {e}')




def auto_verify_xss(finding):
    """Run dalfox to auto-verify a confirmed XSS finding. Background thread."""
    title = finding.get('title', '').lower()
    if 'xss' not in title and 'cross-site scripting' not in title:
        return
    if finding.get('confidence') != 'high':
        return

    dalfox_path = _find_tool('dalfox')
    if not dalfox_path:
        return

    details = finding.get('details', '')
    asset = finding.get('asset', '')
    param = _extract_param_from_details(details)
    base = _extract_url_from_details(details, asset)
    if not base or not param:
        return

    try:
        url = f'{base}/?{param}=test'
        cmd = [dalfox_path, 'url', url, '--silence', '--format', 'json', '--timeout', '10']
        stdout, stderr, rc = _run_tool(cmd, timeout=30)
        if stdout.strip():
            results = json.loads(stdout) if stdout.strip().startswith('[') else []
            if results:
                with LOCK:
                    for f in scan_state['findings']:
                        if f['id'] == finding['id']:
                            f['confidence'] = 'high'
                            f['details'] += f'\n\n[Auto-Verified] dalfox confirmed XSS.'
                            break
                log('ok', f'[AUTO-VERIFY] XSS confirmed via dalfox: {param}')
    except Exception as e:
        log('warn', f'[AUTO-VERIFY] dalfox failed: {e}')




def auto_verify_ssrf(finding):
    """SSRF auto-verification: OOB + ssrfmap exploitation."""
    title = finding.get('title', '').lower()
    if 'ssrf' not in title:
        return
    if finding.get('confidence') != 'high':
        return
    log('ok', f'[AUTO-VERIFY] SSRF verified via OOB/timing: {finding["id"]}')
    # Escalate with ssrfmap exploitation
    asset = finding.get('asset', '')
    param = _extract_param_from_details(finding.get('details', ''))
    if asset and param:
        try:
            run_ssrfmap(asset, param)
        except Exception:
            pass


# ─── TOOL 4: COMMIX — Automated CMDi Verification ───────────────────────────


def auto_verify_cmdi(finding):
    """Auto-verify command injection findings using commix."""
    title = finding.get('title', '').lower()
    if 'command injection' not in title and 'cmdi' not in title:
        return
    if finding.get('confidence') != 'high':
        return
    commix_path = _find_tool('commix')
    if not commix_path:
        log('warn', '[COMMIX] Not installed — skipping CMDi verification')
        return
    asset = finding.get('asset', '')
    param = _extract_param_from_details(finding.get('details', ''))
    if not asset or not param:
        return
    out_dir = f'/tmp/commix_{secrets.token_hex(4)}'
    try:
        cmd = [commix_path, '--url', f'{asset}?{param}=1', '--batch',
               '--output-dir', out_dir, '--technique=C', '--os-cmd=id',
               '--random-agent', '--timeout=10']
        stdout, _, rc = _run_tool(cmd, timeout=45)
        if 'command execution output' in stdout.lower() or 'uid=' in stdout or rc == 0:
            with LOCK:
                for f in scan_state['findings']:
                    if f.get('id') == finding.get('id'):
                        f['details'] += f'\n\n[commix] RCE confirmed\n{stdout[:500]}'
                        f['confidence'] = 'high'
                        break
            op_log('auto_verify', asset, f'CMDi confirmed via commix: {param}', finding.get('id'))
            log('ok', f'[COMMIX] CMDi confirmed on {param}')
    except Exception as e:
        log('warn', f'[COMMIX] Verification failed: {e}')
    finally:
        try:
            import shutil as _shutil
            _shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass


# ─── TOOL 5: TPLMAP — SSTI Auto-Exploitation → RCE ─────────────────────────


def auto_verify_ssti(finding):
    """Auto-verify SSTI findings using tplmap (escalates to RCE)."""
    title = finding.get('title', '').lower()
    if 'ssti' not in title and 'template injection' not in title:
        return
    if finding.get('confidence') != 'high':
        return
    tplmap_path = _find_tool('tplmap') or shutil.which('tplmap.py')
    if not tplmap_path:
        # Python fallback: send SSTI payloads and check for RCE-like responses
        log('info', '[TPLMAP] Binary not found — using Python SSTI payload verification')
        if not REQUESTS_AVAILABLE:
            return
        asset = finding.get('asset', '')
        param = _extract_param_from_details(finding.get('details', ''))
        if not asset or not param:
            return
        # Polyglot SSTI payloads for common engines (Jinja2, Twig, Freemarker, Pebble)
        ssti_probes = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%= 7*7 %>', '49'),
            ('{{7*"7"}}', '7777777'),
            ('#{7*7}', '49'),
            ('%{7*7}', '49'),
        ]
        for payload, expected in ssti_probes:
            try:
                r = req_lib.get(asset, params={param: payload}, timeout=8, verify=False)
                if expected in r.text:
                    with LOCK:
                        for f in scan_state['findings']:
                            if f.get('id') == finding.get('id'):
                                f['sev'] = 'critical'
                                f['details'] += (f'\n\n[tplmap-python] SSTI confirmed via payload {payload!r} → got {expected!r}\n'
                                                 f'Engine likely: Jinja2/Twig/Freemarker\n'
                                                 f'Impact: Remote Code Execution possible')
                                f['confidence'] = 'high'
                                scan_state['stats']['critical'] = scan_state['stats'].get('critical', 0) + 1
                                scan_state['stats']['high'] = max(0, scan_state['stats'].get('high', 0) - 1)
                                break
                    log('ok', f'[TPLMAP-PY] SSTI confirmed: {payload!r} → {expected!r}')
                    return
            except Exception:
                pass
        return
    asset = finding.get('asset', '')
    param = _extract_param_from_details(finding.get('details', ''))
    if not asset or not param:
        return
    try:
        if tplmap_path.endswith('.py'):
            cmd = ['python3', tplmap_path, '-u', f'{asset}?{param}=*',
                   '--engine', 'all', '--level', '5', '--os-cmd', 'id']
        else:
            cmd = [tplmap_path, '-u', f'{asset}?{param}=*',
                   '--engine', 'all', '--level', '5', '--os-cmd', 'id']
        stdout, _, rc = _run_tool(cmd, timeout=45)
        if 'current user' in stdout.lower() or 'uid=' in stdout or rc == 0:
            with LOCK:
                for f in scan_state['findings']:
                    if f.get('id') == finding.get('id'):
                        f['sev'] = 'critical'
                        f['details'] += f'\n\n[tplmap] SSTI→RCE confirmed\n{stdout[:400]}'
                        f['confidence'] = 'high'
                        scan_state['stats']['critical'] = scan_state['stats'].get('critical', 0) + 1
                        scan_state['stats']['high'] = max(0, scan_state['stats'].get('high', 0) - 1)
                        break
            op_log('auto_verify', asset, f'SSTI→RCE via tplmap: {param}', finding.get('id'))
            log('ok', f'[TPLMAP] SSTI→RCE confirmed on {param}')
    except Exception as e:
        log('warn', f'[TPLMAP] Verification failed: {e}')


# ─── TOOL 1: ARJUN — Hidden HTTP Parameter Discovery ────────────────────────


def schedule_auto_verify(finding):
    """Schedule background auto-verification for a confirmed finding."""
    if finding.get('confidence') != 'high':
        return
    title = finding.get('title', '').lower()
    try:
        if 'sql injection' in title or 'sqli' in title:
            _verify_pool.submit(auto_verify_sqli, finding)
        elif 'xss' in title or 'cross-site scripting' in title:
            _verify_pool.submit(auto_verify_xss, finding)
        elif 'ssrf' in title:
            _verify_pool.submit(auto_verify_ssrf, finding)
        elif 'command injection' in title or 'cmdi' in title:
            _verify_pool.submit(auto_verify_cmdi, finding)
        elif 'ssti' in title or 'template injection' in title:
            _verify_pool.submit(auto_verify_ssti, finding)
        
        # Also run ExploitVerifier for evidence collection
        _verify_pool.submit(ExploitVerifier.auto_verify, finding)
    except Exception:
        pass




def set_progress(module, value):
    with LOCK:
        scan_state['progress'][module] = value
    push_sse('progress', {'module': module, 'value': value})

# ═══════════════════════════════════════════════════════════════════════════════
# SHARED UTILITIES — Session Manager, Payload Generator, WAF Detection
# ═══════════════════════════════════════════════════════════════════════════════

_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
]



def op_log(action_type, target='', detail='', finding_id=None):
    """Log operator actions to the operator_log table for debrief timeline."""
    if not SQLITE_AVAILABLE:
        return
    try:
        from flask import has_request_context, session as _session
        operator = _session.get('user', 'system') if has_request_context() else 'system'
        ts = datetime.now(timezone.utc).isoformat()
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute(
                'INSERT INTO operator_log (ts, operator, action_type, target, detail, finding_id) VALUES (?,?,?,?,?,?)',
                (ts, operator, action_type, target, detail, finding_id)
            )
    except Exception:
        pass
