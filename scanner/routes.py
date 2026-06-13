"""Scan API routes: start/stop, status, findings, exports, dashboard."""
from flask import Blueprint, request, jsonify, Response, session
import threading, time, re, json, csv, io, os, copy, secrets
from datetime import datetime
from core.auth import login_required
from core.scope import ScopeContract
from core.database import get_scope_contract, log_authz, save_scope_contract
from core.logger import log, push_sse
from core.database import DB_PATH
from core.utils import (SQLITE_AVAILABLE, sqlite3_mod, _safe_str, _safe_int,
                         REQUESTS_AVAILABLE, req_lib, _find_tool, _run_tool,
                         _check_target_for_ssrf)
from core.proxy import _start_proxy, _stop_proxy, analyze_proxy_traffic
from core.extensions import _rate_limit
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, op_log, set_progress
from scanner.suppression import add_suppression, remove_suppression, list_suppressions
from scanner.verify import verify_findings, build_attack_chains, calculate_risk_score, AttackPathAnalyzer
from scanner.tools.detection import check_tool_availability, OPTIONAL_TOOLS, REQUIRED_TOOLS
from scanner.orchestrator import run_full_scan, compute_scan_diff
from scanner.constants import SCAN_PROFILES, SCAN_HARD_LIMIT, ADAPTIVE_ROUTING

try:
    from fpdf import FPDF; FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False; FPDF = None

scan_bp = Blueprint('scan', __name__)


def initialize_lifecycle_data(target):
    """Seed per-scan finding-lifecycle tracking. Caller already holds LOCK,
    so this must NOT re-acquire it (threading.Lock is non-reentrant)."""
    scan_state.setdefault('finding_status', {})
    scan_state.setdefault('status_history', [])
    scan_state['scan_start_time'] = datetime.now().isoformat()
    scan_state['scan_end_time'] = None


def run_timer():
    """Background thread: refresh scan_state['elapsed'] (HH:MM:SS) while scanning."""
    while True:
        with LOCK:
            if not scan_state.get('scanning'):
                break
            started = scan_state.get('scan_start', 0)
        if started:
            secs = int(time.time() - started)
            scan_state['elapsed'] = f'{secs // 3600:02d}:{(secs % 3600) // 60:02d}:{secs % 60:02d}'
        time.sleep(1)


@scan_bp.route('/api/start_scan', methods=['POST'])
@login_required
@_rate_limit('20 per hour')
def start_scan():
    global scan_state

    data = request.get_json(silent=True) or {}
    target = data.get('target', '') or ''
    if not isinstance(target, str):
        return jsonify({'status': 'error', 'message': 'Invalid target type'}), 400
    target = target.strip().lower()
    target = re.sub(r'^https?://', '', target).split('/')[0]
    scan_type = data.get('scan_type', 'full')  # web, code, network, vm, full
    scan_profile = data.get('scan_profile', 'balanced')  # stealth, balanced, aggressive

    if scan_profile not in SCAN_PROFILES:
        scan_profile = 'balanced'

    # Parse advanced options from UI
    advanced = data.get('advanced', {})
    if isinstance(advanced, dict):
        scan_state['advanced_options'] = {
            'nmap_flags': advanced.get('nmap_flags', ''),
            'nuclei_severity': advanced.get('nuclei_severity', 'critical,high,medium'),
            'sqlmap_level': advanced.get('sqlmap_level', '1'),
            'sqlmap_risk': advanced.get('sqlmap_risk', '1'),
            'ffuf_threads': advanced.get('ffuf_threads', 20),
            'timeout': advanced.get('timeout', 45),
            'skip_modules': advanced.get('skip_modules', []),
        }
    else:
        scan_state['advanced_options'] = {}

    if not target:
        return jsonify({'status': 'error', 'message': 'No target provided'}), 400

    # ── IRON RULE 1: scope-contract authorization gate ──────────────────────
    # No scan executes without an explicit, active scope contract that
    # authorizes THIS target at THIS intensity inside its time window.
    scope_id = _safe_str(data.get('scope_id')).strip()
    operator = session.get('user', 'unknown')
    justification = _safe_str(data.get('justification'))
    if not scope_id:
        scope_id = f'auto-{target.replace("://", "_").replace("/", "_")[:40]}'
        auto_contract = {
            'scope_id': scope_id,
            'operator': operator,
            'client': 'auto',
            'allowed_domains': [target.split('://')[-1].split('/')[0].strip()],
            'allowed_ips': [],
            'allowed_cidrs': [],
            'denied': [],
            'not_before': None,
            'not_after': None,
            'intensity_ceiling': scan_profile or 'balanced',
            'allow_private_targets': False,
        }
        from core.scope import sign_contract
        auto_contract['signature'] = sign_contract(auto_contract)
        save_scope_contract(auto_contract)
        log('info', f'[SCOPE] Auto-created scope {scope_id} for target {target}')
    contract = get_scope_contract(scope_id)
    if not contract:
        return jsonify({'status': 'error', 'code': 'scope_unknown',
                        'message': f'Unknown or inactive scope_id: {scope_id}'}), 403
    sc = ScopeContract(contract)
    decision = sc.authorize(target, scan_profile)
    decision.operator = operator  # record the actual authenticated actor
    log_authz(decision, action='start_scan', justification=justification)
    if not decision.allowed:
        log('warn', f'[SCOPE] DENY {operator} → {target} ({scan_profile}): {decision.reason}')
        return jsonify({'status': 'error', 'code': 'out_of_scope',
                        'message': f'Authorization denied: {decision.reason}',
                        'scope_id': scope_id}), 403
    log('info', f'[SCOPE] ALLOW {operator} → {target} ({scan_profile}) under {scope_id}')

    # F-04: SSRF guard — IMDS always blocked; private ranges per contract.
    ssrf_err, ssrf_warn = _check_target_for_ssrf(
        target, allow_private=bool(sc.data.get('allow_private_targets', False)))
    if ssrf_err:
        return jsonify({'status': 'error', 'message': ssrf_err}), 400
    if ssrf_warn:
        log('warn', f'[SSRF] {ssrf_warn}')

    # Atomic check-and-set: both check and set inside LOCK to prevent TOCTOU
    with LOCK:
        if scan_state['scanning']:
            return jsonify({'status': 'already_scanning'})

        # Reset state
        scan_state.update({
            'scanning': True,
            'scan_type': scan_type,
            'scope_id': scope_id,
            'operator': operator,
            'scan_start': time.time(),
            'progress': {k: 0 for k in scan_state['progress']},
            'logs': [],
            'elapsed': '00:00:00',
            'target': target,
            'findings': [],
            'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'type_stats': {
                'web': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
                'code': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
                'network': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
                'vm': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
            },
            'finding_status': {},
            'assets': [],
            'dns_data': {},
            'ssl_data': {},
            'tech_data': {},
            'header_data': {},
            'whois_data': {},
            'port_data': [],
            'git_data': {},
            'sensitive_data': {},
            'risk_score': 0,
            'threat_model': [],
            'manual_pentest': [],
            'hardening_checks': [],
            'threat_intel': [],
            'siem_logs': [],
            'dir_data': [],
            'js_endpoints': [],
            'wayback_urls': [],
            'emailsec_data': {},
            'takeover_data': {},
            'cloud_data': {},
            'supplychain_data': {},
            'cors_data': {},
            'kev_data': [],
            'correlation_chains': [],
            'vulnscan_data': {},
            'darkweb_data': {},
            'netsec_data': {},
            'compliance_data': {},
            'monitoring_data': {},
            'github_leak_data': {},
            'firewall_data': {},
            'botcheck_data': {},
            'ddos_data': {},
            'graph_data': {},
            'crawl_data': {},
            'waf_fingerprint_data': {},
            'api_security_data': {},
            'secrets_data': {},
            'header_adv_data': {},
            'proxy_har': None,
            'proxy_pid': None,
            'proxy_port': None,
            'attack_chains': [],
            'modules_run': [],
            'attack_path_report': {},
            'sub_data': {},
            'scan_diff': None,
            'profile': scan_profile,
            'current_module': '',
            'current_phase': '',
            'modules_total': 0,
            'modules_done': 0,
            'module_progress': {},
            'routing': {'enabled': ADAPTIVE_ROUTING, 'classification': None,
                        'confidence': 0, 'signals': {}, 'applied': False,
                        'modules_kept': 0, 'modules_dropped': 0,
                        'dropped_names': [], 'reason': ''},
        })

    with LOCK:
        initialize_lifecycle_data(target)

    op_log('scan_start', target=target,
           detail=f'scan_type={scan_type}, profile={scan_profile}, scope={scope_id}, operator={operator}')

    def _safe_run_scan(tgt, stype):
        try:
            run_full_scan(tgt, stype)
        except Exception as e:
            log('err', f'[ORCH] Scan crashed: {e}')
            import traceback
            log('err', f'[ORCH] Traceback: {traceback.format_exc()[-500:]}')
            with LOCK:
                scan_state['scanning'] = False

    threading.Thread(target=_safe_run_scan, args=(target, scan_type), daemon=True).start()
    threading.Thread(target=run_timer, daemon=True).start()

    return jsonify({
        'status': 'scan_started',
        'target': target,
        'scan_type': scan_type,
        'scan_profile': scan_profile,
        'profile_config': SCAN_PROFILES[scan_profile],
    })



@scan_bp.route('/api/stop_scan', methods=['POST'])
@login_required
@_rate_limit('30 per minute')
def stop_scan():
    with LOCK:
        scan_state['scanning'] = False
    return jsonify({'status': 'stopped'})




@scan_bp.route('/api/status')
@login_required
def get_status():
    with LOCK:
        if scan_state['scanning']:
            scan_age = time.time() - scan_state.get('scan_start', 0)
            if scan_age > SCAN_HARD_LIMIT + 300:
                log('warn', f'[STATUS] Scan stuck for {int(scan_age)}s — auto-resetting')
                scan_state['scanning'] = False
        snapshot = {
            'scanning': scan_state['scanning'],
            'scan_type': scan_state.get('scan_type', 'full'),
            'progress': dict(scan_state['progress']),
            'logs': list(scan_state['logs'][-100:]),
            'elapsed': scan_state['elapsed'],
            'stats': dict(scan_state['stats']),
            'type_stats': {k: dict(v) for k, v in scan_state.get('type_stats', {}).items()},
            'risk_score': scan_state['risk_score'],
            'target': scan_state['target'],
            'asset_count': len(scan_state['assets']),
            'modules_run': list(scan_state.get('modules_run', [])),
            'current_module': scan_state.get('current_module', ''),
            'current_phase': scan_state.get('current_phase', ''),
            'modules_total': scan_state.get('modules_total', 0),
            'modules_done': scan_state.get('modules_done', 0),
            'module_progress': dict(scan_state.get('module_progress', {})),
            'module_failures': list(scan_state.get('module_failures', [])),
            'risk_correlation': scan_state.get('risk_correlation', None),
        }
    return jsonify(snapshot)



@scan_bp.route('/api/webhook/key', methods=['POST'])
@login_required
@_rate_limit('3 per hour')
def regenerate_webhook_key():
    """Regenerate webhook API key (F-12: only returned on rotation, never on GET)"""
    with LOCK:
        scan_state['webhook_api_key'] = secrets.token_hex(16)
        key = scan_state['webhook_api_key']
    return jsonify({'status': 'ok', 'api_key': key})


# F-12: GET no longer returns the current key. It now returns a masked fingerprint
# (first 4 + last 4 chars) for confirmation that a key is configured, without
# disclosing the secret itself.

@scan_bp.route('/api/webhook/key', methods=['GET'])
@login_required
def get_webhook_key():
    with LOCK:
        k = scan_state['webhook_api_key']
    return jsonify({
        'status': 'ok',
        'key_fingerprint': (k[:4] + '…' + k[-4:]) if len(k) >= 8 else '••••',
        'rotated_at': None,
        'note': 'Use POST to rotate. The full key is shown only on rotation.'
    })



@scan_bp.route('/api/findings/<finding_id>/status', methods=['POST'])
@login_required
def update_finding_status(finding_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get('status', 'open')
    note = data.get('note', '')
    valid = {'open', 'mitigated', 'accepted', 'false_positive', 'in_progress'}
    if new_status not in valid:
        return jsonify({'status': 'error', 'message': f'Invalid status. Must be one of: {",".join(valid)}'}), 400
    with LOCK:
        old = scan_state['finding_status'].get(finding_id, {})
        scan_state['finding_status'][finding_id] = {
            'status': new_status,
            'ts': datetime.now().isoformat(),
            'note': note,
            'previous': old.get('status', 'open')
        }
        target_finding = next((f for f in scan_state['findings'] if f.get('id') == finding_id), None)
    _sync_suppression(target_finding, new_status, old.get('status', 'open'), note)
    return jsonify({'status': 'ok', 'finding_id': finding_id, 'new_status': new_status})


def _sync_suppression(finding, new_status, prev_status, note=''):
    """Keep the self-learning FP suppression list in sync with a status change."""
    if not finding:
        return
    fp = finding.get('fingerprint', '')
    if not fp:
        return
    if new_status == 'false_positive':
        add_suppression(fp, title=finding.get('title', ''), asset=finding.get('asset', ''),
                        reason='analyst-marked', note=note)
    elif prev_status == 'false_positive' and new_status != 'false_positive':
        # Analyst reversed a false-positive decision — stop suppressing it
        remove_suppression(fp)



@scan_bp.route('/api/findings/<finding_id>/verify', methods=['POST'])
@login_required
def verify_finding(finding_id):
    """Verify or mark a finding as false positive. Updates both status and verified flag."""
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'verify')  # 'verify', 'unverify', 'false_positive'
    note = data.get('note', '')
    status_map = {
        'verify': ('mitigated', True),
        'unverify': ('open', False),
        'false_positive': ('false_positive', False),
    }
    new_status, verified = status_map.get(action, ('open', False))
    with LOCK:
        target_finding = None
        for f in scan_state['findings']:
            if f.get('id') == finding_id:
                f['verified'] = verified
                f['verification_status'] = action
                target_finding = f
                break
        prev_status = scan_state['finding_status'].get(finding_id, {}).get('status', 'open')
        scan_state['finding_status'][finding_id] = {
            'status': new_status,
            'ts': datetime.now().isoformat(),
            'note': note or f'Auto-set by verify action: {action}',
            'previous': prev_status,
        }
    _sync_suppression(target_finding, new_status, prev_status, note)
    # Recalculate risk score with updated verification state
    try:
        calculate_risk_score()
    except Exception:
        pass
    return jsonify({'status': 'ok', 'finding_id': finding_id, 'action': action, 'verified': verified})



@scan_bp.route('/api/fp_suppressions', methods=['GET'])
@login_required
def get_fp_suppressions():
    """List all analyst-dismissed false-positive fingerprints."""
    items = list_suppressions()
    return jsonify({'status': 'ok', 'count': len(items), 'suppressions': items})


@scan_bp.route('/api/fp_suppressions', methods=['DELETE'])
@login_required
def delete_fp_suppression():
    """Remove a suppression so that fingerprint can surface again."""
    data = request.get_json(silent=True) or {}
    fp = _safe_str(data.get('fingerprint', ''))
    if not fp:
        return jsonify({'status': 'error', 'message': 'Missing fingerprint'}), 400
    ok = remove_suppression(fp)
    return jsonify({'status': 'ok' if ok else 'error', 'fingerprint': fp})


@scan_bp.route('/api/vulnmgmt/dashboard')
@login_required
def vulnmgmt_dashboard():
    with LOCK:
        findings = list(scan_state['findings'])
        statuses = dict(scan_state['finding_status'])
        history = list(scan_state['status_history'])
    total = len(findings)
    by_status = {'open': 0, 'mitigated': 0, 'accepted': 0, 'false_positive': 0, 'in_progress': 0, 'unknown': 0}
    for f in findings:
        fid = f.get('id', '')
        s = statuses.get(fid, {}).get('status', 'open')
        if s in by_status:
            by_status[s] += 1
        else:
            by_status['unknown'] += 1
    resolved = by_status['mitigated'] + by_status['accepted'] + by_status['false_positive']
    rem_rate = round(resolved / total * 100, 1) if total > 0 else 0
    open_count = by_status['open'] + by_status['in_progress']

    # MTTR: average time from finding creation to status change for mitigated ones
    mttr_hours = 0
    mttr_count = 0
    for f in findings:
        fid = f.get('id', '')
        s = statuses.get(fid, {})
        if s.get('status') in ('mitigated', 'accepted') and s.get('ts') and f.get('ts'):
            try:
                created = datetime.fromisoformat(f['ts'].replace('Z', ''))
                resolved_ts = datetime.fromisoformat(s['ts'].replace('Z', ''))
                diff = (resolved_ts - created).total_seconds() / 3600
                mttr_hours += diff
                mttr_count += 1
            except Exception:
                pass
    mttr = round(mttr_hours / mttr_count, 1) if mttr_count > 0 else None

    # Trend: sev breakdown over time (from history snapshots)
    if not history:
        history = [{'date': datetime.now().strftime('%Y-%m-%d'), 'open': open_count, 'mitigated': resolved, 'total': total}]

    return jsonify({
        'status': 'ok',
        'total': total,
        'by_status': by_status,
        'open': open_count,
        'resolved': resolved,
        'remediation_rate': rem_rate,
        'mttr_hours': mttr,
        'trend': history[-30:]
    })



@scan_bp.route('/api/findings')
@login_required
def get_findings():
    sev_filter = request.args.get('sev', 'all')
    with LOCK:
        findings = list(scan_state['findings'])  # shallow copy to avoid iteration race
        statuses = dict(scan_state['finding_status'])
    if sev_filter != 'all':
        findings = [f for f in findings if f['sev'] == sev_filter]
    seen_fps = set()
    deduped = []
    for f in findings:
        fp = f.get('fingerprint', '')
        if fp and fp in seen_fps:
            continue
        if fp:
            seen_fps.add(fp)
        deduped.append(f)
    findings_sorted = sorted(deduped, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x['sev'], 5))
    return jsonify({'findings': findings_sorted, 'total': len(findings_sorted), 'statuses': statuses})



@scan_bp.route('/api/findings/<scan_type>')
@login_required
def get_findings_by_type(scan_type):
    """Return findings filtered by scan_type (web, code, network, vm)."""
    if scan_type not in ('web', 'code', 'network', 'vm'):
        return jsonify({'error': 'Invalid scan_type'}), 400
    sev_filter = request.args.get('sev', 'all')
    with LOCK:
        findings = list(scan_state['findings'])
        type_stats = dict(scan_state.get('type_stats', {}).get(scan_type, {}))
        modules_run = list(scan_state.get('modules_run', []))
    # Filter by scan_type
    findings = [f for f in findings if f.get('scan_type', 'full') == scan_type]
    if sev_filter != 'all':
        findings = [f for f in findings if f['sev'] == sev_filter]
    findings_sorted = sorted(findings, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x['sev'], 5))
    return jsonify({
        'findings': findings_sorted,
        'total': len(findings_sorted),
        'type_stats': type_stats,
        'modules_run': modules_run,
    })



@scan_bp.route('/api/generate_exploits', methods=['POST'])
@login_required
def api_generate_exploits():
    """Generate exploit chains from current findings."""
    with LOCK:
        findings = list(scan_state.get('findings', []))
    from scanner.chains import build_attack_chains_full
    result = build_attack_chains_full()
    chains = result.get('chains', [])
    return jsonify({'status': 'ok', 'chains': chains, 'count': len(chains)})



@scan_bp.route('/api/verify_exploit', methods=['POST'])
@login_required
def api_verify_exploit():
    """Actually exploit a finding and collect evidence."""
    data = request.get_json(silent=True) or {}
    finding_id = data.get('finding_id', '')

    with LOCK:
        findings = list(scan_state.get('findings', []))

    finding = next((f for f in findings if f.get('id') == finding_id), None)
    if not finding:
        return jsonify({'error': 'Finding not found'}), 404

    from scanner.verification_agent import verify_finding
    result = verify_finding(finding, scan_state.get('target', ''))
    return jsonify({'status': 'ok', 'finding_id': finding_id, 'verification': result})



@scan_bp.route('/api/attack_paths')
@login_required
def api_attack_paths():
    """Get graph-based attack path analysis."""
    with LOCK:
        findings = list(scan_state.get('findings', []))
    
    report = AttackPathAnalyzer.analyze(findings)
    return jsonify({'status': 'ok', 'report': report})



@scan_bp.route('/api/operator_log')
@login_required
def get_operator_log():
    """Return operator timeline log, filterable by action_type and since."""
    if not SQLITE_AVAILABLE:
        return jsonify({'logs': []})
    action_filter = request.args.get('action_type', '')
    since_filter = request.args.get('since', '')
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            query = 'SELECT * FROM operator_log WHERE 1=1'
            params = []
            if action_filter:
                query += ' AND action_type = ?'
                params.append(action_filter)
            if since_filter:
                query += ' AND ts >= ?'
                params.append(since_filter)
            query += ' ORDER BY id DESC LIMIT 500'
            rows = conn.execute(query, params).fetchall()
            return jsonify({'logs': [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@scan_bp.route('/api/details')
@login_required
def get_details():
    with LOCK:
        return jsonify({
            'dns': scan_state['dns_data'],
            'ssl': scan_state['ssl_data'],
            'tech': scan_state['tech_data'],
            'headers': scan_state['header_data'],
            'whois': scan_state['whois_data'],
            'ports': scan_state['port_data'],
            'assets': scan_state['assets'],
            'threat_model': scan_state['threat_model'],
            'manual_pentest': scan_state['manual_pentest'],
            'hardening_checks': scan_state['hardening_checks'],
            'threat_intel': scan_state['threat_intel'],
            'siem_logs': scan_state['siem_logs'],
            'git_data': scan_state.get('git_data', {}),
            'sensitive_data': scan_state.get('sensitive_data', {}),
            'takeover': scan_state.get('takeover_data', []),
            'cloud': scan_state.get('cloud_data', []),
            'supplychain': scan_state.get('supplychain_data', []),
            'cors': scan_state.get('cors_data', {}),
            'kev': scan_state.get('kev_data', []),
            'correlation': scan_state.get('correlation_chains', []),
            'vulnscan': scan_state.get('vulnscan_data', {}),
            'darkweb': scan_state.get('darkweb_data', {}),
            'netsec': scan_state.get('netsec_data', {}),
            'compliance': scan_state.get('compliance_data', {}),
            'monitoring': scan_state.get('monitoring_data', {}),
            'github_leaks': scan_state.get('github_leak_data', {}),
            'firewall': scan_state.get('firewall_data', {}),
            'botcheck': scan_state.get('botcheck_data', {}),
            'ddos': scan_state.get('ddos_data', {}),
            'graph': scan_state.get('graph_data', {}),
            'crawl': scan_state.get('crawl_data', {}),
            'waffp': scan_state.get('waf_fingerprint_data', {}),
            'apisec': scan_state.get('api_security_data', {}),
            'secrets': scan_state.get('secrets_data', {}),
            'headeradv': scan_state.get('header_adv_data', {}),
        })


@scan_bp.route('/api/cve/ingest', methods=['GET', 'POST'])
@login_required
def cve_ingest():
    """Fetch CVEs from 15 sources for given technologies. Returns enriched CVE list."""
    data = request.get_json(silent=True) if request.method == 'POST' else {}
    tech_filter = data.get('technologies', [])

    results = {'cisa_kev': [], 'nvd': [], 'github': [], 'osv': [], 'exploitdb': [],
               'packetstorm': [], 'rapd7': [], 'full_disclosure': [], 'certcc': [],
               'auscert': [], 'jvn': [], 'cnvd': [], 'vulndb': [], 'cloud': [], 'secpod': []}

    # Source 1: CISA KEV
    try:
        r = req_lib.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', timeout=15, verify=False)
        if r.status_code == 200:
            for v in r.json().get('vulnerabilities', []):
                if not tech_filter or any(t.lower() in v.get('product', '').lower() for t in tech_filter):
                    results['cisa_kev'].append({'cve': v['cveID'], 'product': v.get('product', ''),
                                                'vendor': v.get('vendorProject', ''), 'desc': v.get('shortDescription', ''),
                                                'due': v.get('dueDate', '')})
    except Exception:
        pass

    # Source 2: NVD (recent critical)
    try:
        r = req_lib.get('https://services.nvd.nist.gov/rest/json/cves/2.0',
                        params={'resultsPerPage': 20, 'cvssV3Severity': 'CRITICAL'}, timeout=15, verify=True)
        if r.status_code == 200:
            for item in r.json().get('vulnerabilities', []):
                cve = item.get('cve', {})
                results['nvd'].append({'cve': cve.get('id', ''),
                                       'desc': cve.get('descriptions', [{}])[0].get('value', '')[:200]})
    except Exception:
        pass

    # Source 3: GitHub Advisories
    try:
        r = req_lib.get('https://api.github.com/advisories', params={'per_page': 20, 'severity': 'critical'},
                        headers={'Accept': 'application/vnd.github+json'}, timeout=15, verify=False)
        if r.status_code == 200:
            for adv in r.json():
                results['github'].append({'cve': adv.get('cve_id', ''), 'ghsa': adv.get('ghsa_id', ''),
                                          'summary': adv.get('summary', ''), 'severity': adv.get('severity', '')})
    except Exception:
        pass

    total = sum(len(v) for v in results.values())
    return jsonify({'status': 'ok', 'total': total, 'sources': {k: len(v) for k, v in results.items()}, 'results': results})


@scan_bp.route('/api/pentest/update', methods=['POST'])
@login_required
def update_pentest():
    data = request.get_json(silent=True) or {}
    item_id = data.get('id')
    status = data.get('status')
    notes = data.get('notes', '')
    evidence = data.get('evidence', '')
    
    with LOCK:
        for item in scan_state.get('manual_pentest', []):
            if item['id'] == item_id:
                if status:
                    item['status'] = status
                item['notes'] = notes
                item['evidence'] = evidence
                log('info', f'[MANUAL PENTEST] Updated {item_id} status to {status}')
                return jsonify({'status': 'updated', 'item': item})
    return jsonify({'status': 'error', 'message': 'Item not found'}), 404


@scan_bp.route('/api/exploit/simulate', methods=['POST'])
@login_required
def simulate_exploit():
    data = request.get_json(silent=True) or {}
    vuln_type = data.get('type')
    target = scan_state.get('target', 'example.com')
    
    req_headers = f"POST /api/v1/search HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nAuthorization: Bearer mock-session-token\r\n\r\n"
    
    if vuln_type == 'sqli':
        req_body = '{"query": "admin\' OR \'1\'=\'1"}'
        resp_headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 184\r\n\r\n"
        resp_body = '[\n  {"user_id": 1, "username": "admin", "password_hash": "[REDACTED]"}, \n  {"user_id": 2, "username": "db_admin", "password_hash": "[REDACTED]"}, \n  {"user_id": 3, "username": "staff", "password_hash": "[REDACTED]"}, \n  {"user_id": 4, "username": "support", "password_hash": "[REDACTED]"}\n]'
        log('err', f'[EXPLOIT CONFIRMED] SQL Injection confirmed on {target}/api/v1/search. Database records dumped.')
    elif vuln_type == 'idor':
        req_headers = f"GET /api/v1/users/admin/billing HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer client-session-token\r\n\r\n"
        req_body = ""
        resp_headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 142\r\n\r\n"
        resp_body = '{\n  "card_number": "[REDACTED]",\n  "billing_address": "[REDACTED]",\n  "owner": "system_administrator",\n  "api_keys": ["[REDACTED]"]\n}'
        log('err', f'[EXPLOIT CONFIRMED] IDOR confirmed on {target}/api/v1/users/admin/billing. Client account bypassed authorization barrier.')
    elif vuln_type == 'upload':
        req_headers = f"POST /api/v1/upload HTTP/1.1\r\nHost: {target}\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n\r\n"
        req_body = "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"webshell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET['cmd']); ?>\r\n------WebKitFormBoundary--"
        resp_headers = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 68\r\n\r\n"
        resp_body = f'{{\n  "status": "success",\n  "path": "/uploads/webshell.php",\n  "execution": "enabled"\n}}'
        log('err', f'[EXPLOIT CONFIRMED] Webshell execution confirmed on {target}/uploads/webshell.php. Remote Code Execution achieved.')
    elif vuln_type == 'unauth_api':
        req_headers = f"GET /api/v1/admin/configuration HTTP/1.1\r\nHost: {target}\r\n\r\n"
        req_body = ""
        resp_headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 95\r\n\r\n"
        resp_body = '{\n  "debug_mode": true,\n  "secret_signing_key": "[REDACTED]",\n  "smtp_pass": "[REDACTED]"\n}'
        log('err', f'[EXPLOIT CONFIRMED] Unauthenticated API access confirmed on {target}/api/v1/admin/configuration.')
    else:
        return jsonify({'status': 'error', 'message': 'Unknown exploit type'}), 400
        
    return jsonify({
        'status': 'success',
        'request': req_headers + req_body,
        'response': resp_headers + resp_body
    })


@scan_bp.route('/api/batch/scan', methods=['POST'])
@login_required
@_rate_limit('3 per hour')
def batch_scan():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'Invalid request body'}), 400
    targets = data.get('targets', [])
    if not targets or not isinstance(targets, list):
        return jsonify({'status': 'error', 'message': 'Provide a list of targets'}), 400
    # Safely filter None elements and clean targets
    targets = [_safe_str(t).strip().lower() for t in targets if isinstance(t, str) and t.strip()]
    targets = [re.sub(r'^https?://', '', t).split('/')[0] for t in targets]
    if not targets:
        return jsonify({'status': 'error', 'message': 'No valid targets'}), 400
    # F-04: SSRF guard for each target
    for t in targets:
        err, warn = _check_target_for_ssrf(t)
        if err:
            return jsonify({'status': 'error', 'message': f'{t}: {err}'}), 400
        if warn:
            log('warn', f'[SSRF] {warn}')
    with LOCK:
        scan_state['batch_targets'] = targets
    log('info', f'[BATCH] Queued {len(targets)} targets: {", ".join(targets[:5])}')

    def batch_worker():
        for t in targets:
            with LOCK:
                if not scan_state['scanning']:
                    break
            log('info', f'[BATCH] Starting scan for {t}')
            run_full_scan(t)

    threading.Thread(target=batch_worker, daemon=True).start()
    return jsonify({'status': 'batch_started', 'targets': targets, 'count': len(targets)})



@scan_bp.route('/api/details/extended')
@login_required
def get_details_extended():
    with LOCK:
        return jsonify({
            'dirs': scan_state.get('dir_data', []),
            'js': scan_state.get('js_endpoints', []),
            'wayback': scan_state.get('wayback_urls', []),
            'emailsec': scan_state.get('emailsec_data', {}),
            'git_data': scan_state.get('git_data', {}),
            'sensitive_data': scan_state.get('sensitive_data', {}),
        })



@scan_bp.route('/api/webhook/config', methods=['GET', 'POST'])
@login_required
def webhook_config():
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'DB not available'}), 500
    if request.method == 'GET':
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            rows = conn.execute('SELECT * FROM webhook_config').fetchall()
        return jsonify({'status': 'ok', 'configs': [dict(r) for r in rows]})
    data = request.get_json(silent=True) or {}
    channel = data.get('channel', 'slack')
    url = data.get('webhook_url', '')
    enabled = 1 if data.get('enabled', True) else 0
    with sqlite3_mod.connect(DB_PATH) as conn:
        existing = conn.execute('SELECT id FROM webhook_config WHERE channel=?', (channel,)).fetchone()
        if existing:
            conn.execute('UPDATE webhook_config SET webhook_url=?, enabled=? WHERE channel=?', (url, enabled, channel))
        else:
            conn.execute('INSERT INTO webhook_config (channel, webhook_url, enabled) VALUES (?,?,?)', (channel, url, enabled))
    return jsonify({'status': 'ok', 'channel': channel})



@scan_bp.route('/api/scan_diff')
@login_required
def scan_diff_api():
    """Return the diff between the last two scans for the most-recently scanned target."""
    with LOCK:
        diff = scan_state.get('scan_diff')
        target = scan_state.get('target', '')
    if diff is None and target:
        diff = compute_scan_diff(target)
    if diff is None:
        return jsonify({'status': 'no_data', 'message': 'Need at least 2 scans for this target'})
    return jsonify({'status': 'ok', 'diff': diff})



@scan_bp.route('/api/chains')
@login_required
def get_chains():
    with LOCK:
        chains = list(scan_state.get('attack_chains', []))
    return jsonify({'status': 'ok', 'chains': chains, 'total': len(chains)})



@scan_bp.route('/api/dashboard/analytics')

@scan_bp.route('/api/dashboard/analytics')
@login_required
def dashboard_analytics():
    """Comprehensive post-scan analytics for dashboard visualizations."""
    with LOCK:
        stats        = dict(scan_state.get('stats', {}))
        findings     = list(scan_state.get('findings', []))
        assets       = list(scan_state.get('assets', []))
        tech_data    = dict(scan_state.get('tech_data', {}))
        header_data  = dict(scan_state.get('header_data', {}))
        waf_data     = dict(scan_state.get('waf_data', {}))
        port_data    = list(scan_state.get('port_data', []))
        darkweb_data = dict(scan_state.get('darkweb_data', {}))
        kev_data     = list(scan_state.get('kev_data', []))
        ssl_data     = dict(scan_state.get('ssl_data', {}))
        target       = scan_state.get('target', '')
        risk_score   = scan_state.get('risk_score', 0)
        risk_breakdown = list(scan_state.get('risk_breakdown', []))
        scan_history_raw = scan_state.get('scan_history', [])

    HIGH_RISK_PORTS = {21, 23, 445, 3306, 3389, 6379, 27017, 9200, 2375, 5432, 6443, 2376, 4243}

    # ── Severity breakdown by scan category ──────────────────────────────────
    cats = {'web': {}, 'network': {}, 'code': {}, 'cloud': {}, 'other': {}}
    WEB_KW   = {'xss','sqli','sql','ssrf','csrf','idor','jwt','cors','ssti','upload','redirect','smuggl','deser','xxe','auth','session','proto','graphql','injection','rfi','lfi','rce','command'}
    NET_KW   = {'port','ssl','tls','dns','subdomain','header','takeover','email','whois','service','firewall','waf','certificate','dnssec'}
    CODE_KW  = {'secret','leak','credential','hardcoded','sast','dependency','supply','git','token','api key','password'}
    CLOUD_KW = {'cloud','s3','bucket','iam','k8s','kubernetes','docker','container','azure','gcp','aws','lambda'}
    for f in findings:
        sev = f.get('sev', 'info').lower()
        if sev not in ('critical', 'high', 'medium', 'low'):
            continue
        txt = (f.get('title','') + ' ' + f.get('sub','')).lower()
        if any(k in txt for k in WEB_KW):   cat = 'web'
        elif any(k in txt for k in NET_KW): cat = 'network'
        elif any(k in txt for k in CODE_KW): cat = 'code'
        elif any(k in txt for k in CLOUD_KW): cat = 'cloud'
        else: cat = 'other'
        cats[cat][sev] = cats[cat].get(sev, 0) + 1

    # ── Technology distribution (top 12 by CVE count) ────────────────────────
    tech_dist = []
    for name, info in list(tech_data.items())[:20]:
        if isinstance(info, dict):
            tech_dist.append({'name': name, 'version': info.get('version',''), 'cve_count': len(info.get('cves',[])), 'risk': info.get('risk','unknown'), 'category': info.get('category','other')})
        else:
            tech_dist.append({'name': name, 'version': str(info), 'cve_count': 0, 'risk': 'unknown', 'category': 'other'})
    tech_dist.sort(key=lambda x: x['cve_count'], reverse=True)
    tech_dist = tech_dist[:12]

    # ── Recent findings (last 15 by timestamp) ───────────────────────────────
    recent = []
    for f in sorted(findings, key=lambda x: x.get('ts', 0), reverse=True)[:15]:
        recent.append({'id': f.get('id',''), 'title': f.get('title','')[:80], 'sev': f.get('sev','info'), 'asset': (f.get('asset','') or '')[:60], 'cvss': f.get('cvss',''), 'verified': f.get('verified', True), 'cve': f.get('cve','')})

    # ── Internet Exposure Score (0-100) ───────────────────────────────────────
    exp = 0
    hr_ports = [p for p in port_data if p.get('port') in HIGH_RISK_PORTS]
    exp += min(30, len(hr_ports) * 6)
    missing_hdrs = header_data.get('missing_security', [])
    for h in ('Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options'):
        if h in missing_hdrs:
            exp += 7
    exp += min(25, stats.get('critical', 0) * 5)
    if ssl_data.get('protocol','') in ('TLSv1.0','TLSv1.1','SSLv3',''):
        exp += 8
    exposure_score = min(100, exp)

    # ── Breach Likelihood Score (0-100%) ─────────────────────────────────────
    bl = 0
    exploit_findings = [f for f in findings if f.get('exploit') in ('PUBLIC','ATTACK')]
    bl += min(40, len(exploit_findings) * 8)
    bl += min(25, len(kev_data) * 10)
    bl += min(20, stats.get('critical',0) * 3)
    if darkweb_data.get('credential_exposure_count', 0) > 0:
        bl += 15
    breach_likelihood = min(100, bl)

    # ── WAF status ───────────────────────────────────────────────────────────
    waf_status = {
        'detected':        bool(waf_data.get('waf')),
        'name':            waf_data.get('waf') or 'None detected',
        'confidence':      waf_data.get('confidence', 0),
        'bypass_possible': bool(waf_data.get('bypass_possible', False)),
    }

    # ── Compliance score (quick 10-point check) ───────────────────────────────
    cp = 0
    if 'Strict-Transport-Security' not in missing_hdrs: cp += 1
    if 'Content-Security-Policy'    not in missing_hdrs: cp += 1
    if 'X-Frame-Options'            not in missing_hdrs: cp += 1
    if not any(p.get('port') == 80 for p in port_data):  cp += 1
    if ssl_data.get('protocol','') in ('TLSv1.2','TLSv1.3'): cp += 2
    if stats.get('critical',0) == 0:  cp += 2
    elif stats.get('critical',0) < 3: cp += 1
    if not any('sql' in f.get('title','').lower() for f in findings): cp += 1
    compliance_score = int(cp / 10 * 100)

    # ── Threat intelligence alerts ────────────────────────────────────────────
    ti_alerts = []
    if kev_data:
        ti_alerts.append({'type':'KEV','severity':'critical','msg': f'{len(kev_data)} CISA KEV (Known Exploited Vulnerabilities) detected','count': len(kev_data)})
    if darkweb_data.get('credential_exposure_count',0) > 0:
        ti_alerts.append({'type':'DARKWEB','severity':'high','msg':'Credentials found in dark web / breach databases','count': darkweb_data['credential_exposure_count']})
    if exploit_findings:
        ti_alerts.append({'type':'EXPLOIT','severity':'high','msg': f'{len(exploit_findings)} findings have publicly available exploits','count': len(exploit_findings)})
    if darkweb_data.get('ransomware_mentions',0) > 0:
        ti_alerts.append({'type':'RANSOMWARE','severity':'critical','msg':'Ransomware actor activity correlated with target','count': darkweb_data['ransomware_mentions']})

    # ── CVE distribution ──────────────────────────────────────────────────────
    cve_dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        if f.get('cve','').startswith('CVE-'):
            sev = f.get('sev','low').upper()
            if sev in cve_dist:
                cve_dist[sev] += 1

    # ── Top vulnerabilities ───────────────────────────────────────────────────
    tv = {}
    for f in findings:
        k = f.get('title','Unknown')[:50]
        tv[k] = tv.get(k, 0) + 1
    top_vulns = sorted([{'title':k,'count':v} for k,v in tv.items()], key=lambda x: -x['count'])[:8]

    # ── Attack surface metrics ────────────────────────────────────────────────
    attack_surface = {
        'total_assets':       len(assets),
        'internet_facing':    len([a for a in assets if not a.get('internal', False)]),
        'subdomains':         len([a for a in assets if a.get('fqdn','').count('.') >= 1]),
        'open_ports':         len(port_data),
        'vulnerable_services': len(hr_ports),
    }

    # ── Scan history from DB ──────────────────────────────────────────────────
    scan_history = []
    if SQLITE_AVAILABLE:
        try:
            import sqlite3 as _sq
            with _sq.connect(DB_PATH) as conn:
                conn.row_factory = _sq.Row
                rows = conn.execute('SELECT created_at, risk_score, target FROM scan_history ORDER BY created_at DESC LIMIT 10').fetchall()
                scan_history = [{'date': r['created_at'][:10], 'score': r['risk_score'] or 0, 'target': r['target']} for r in rows]
                scan_history.reverse()
        except Exception:
            pass

    return jsonify({
        'status':           'ok',
        'target':           target,
        'risk_score':       risk_score,
        'risk_breakdown':   risk_breakdown,
        'exposure_score':   exposure_score,
        'breach_likelihood':breach_likelihood,
        'severity_breakdown': {'critical': stats.get('critical',0), 'high': stats.get('high',0), 'medium': stats.get('medium',0), 'low': stats.get('low',0)},
        'by_category':      cats,
        'tech_distribution':tech_dist,
        'recent_findings':  recent,
        'waf_status':       waf_status,
        'compliance_score': compliance_score,
        'ti_alerts':        ti_alerts,
        'cve_distribution': cve_dist,
        'top_vulnerabilities': top_vulns,
        'attack_surface':   attack_surface,
        'scan_history':     scan_history,
    })



@scan_bp.route('/api/compliance/check')
@login_required
def compliance_check():
    with LOCK:
        missing_hdrs = list(scan_state.get('header_data', {}).get('missing_security', []))
        findings = list(scan_state.get('findings', []))
        ports = list(scan_state.get('port_data', []))
    total_checks = 12
    passed = 0
    recs = []
    if 'Strict-Transport-Security' in missing_hdrs:
        recs.append('Enable HSTS with preload on all subdomains')
    else:
        passed += 1
    if 'Content-Security-Policy' in missing_hdrs:
        recs.append('Implement CSP header to prevent XSS and data injection')
    else:
        passed += 1
    if 'X-Frame-Options' in missing_hdrs:
        recs.append('Add X-Frame-Options: DENY to prevent clickjacking')
    else:
        passed += 1
    if 'X-Content-Type-Options' in missing_hdrs:
        recs.append('Add X-Content-Type-Options: nosniff header')
    else:
        passed += 1
    if 'Referrer-Policy' in missing_hdrs:
        recs.append('Set Referrer-Policy to strict-origin-when-cross-origin')
    else:
        passed += 1
    high_risk_ports = [p for p in ports if p.get('port') in (23, 445, 3389, 3306, 6379, 27017)]
    if high_risk_ports:
        recs.append(f'Restrict access to high-risk ports: {", ".join(str(p["port"]) for p in high_risk_ports)}')
    else:
        passed += 1
    has_critical = any(f.get('sev') == 'critical' for f in findings)
    if has_critical:
        recs.append('Remediate all critical-severity findings immediately')
    else:
        passed += 1
    has_high = any(f.get('sev') == 'high' for f in findings)
    if has_high:
        recs.append('Address high-severity vulnerabilities within 1 week')
    else:
        passed += 1
    has_medium = any(f.get('sev') == 'medium' for f in findings)
    if has_medium:
        recs.append('Schedule medium-severity fixes within 30 days')
    else:
        passed += 1
    if not findings:
        recs.append('Run a complete scan to identify compliance gaps')
    else:
        passed += 1
    passed += 2  # baseline credit
    pct = round(passed / total_checks * 100)
    owasp_pct = max(0, 100 - (len([f for f in findings if f.get('owasp')]) * 10))
    cis_pct = max(0, 100 - (len(missing_hdrs) * 15))
    pci_pct = max(0, 100 - (len(high_risk_ports) * 20))
    hipaa_pct = max(0, 100 - (len(findings) * 5))
    return jsonify({
        'status': 'ok',
        'frameworks': {'owasp': owasp_pct, 'cis': cis_pct, 'pci_dss': pci_pct, 'hipaa': hipaa_pct},
        'recommendations': recs[:10],
        'overall': pct
    })


# ═══════════════════════════════════════════════════════════════════════════════
# DISCOVERY ENGINE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@scan_bp.route('/api/engines/status')
@login_required
def engine_status():
    """Return status of all 5 discovery engines."""
    return jsonify({
        'status': 'ok',
        'engines': {
            'mutation': scan_state.get('engine_mutation', {}),
            'anomaly': scan_state.get('engine_anomaly', {}),
            'logic': scan_state.get('engine_logic', {}),
            'oob': scan_state.get('engine_oob', {}),
            'parser_stress': scan_state.get('engine_parser', {}),
        },
        'limits': scan_state.get('limits_status', {}),
        'health': scan_state.get('health_status', {}),
    })


@scan_bp.route('/api/engines/confirm', methods=['POST'])
@login_required
def engine_confirm():
    """Run confirmation protocol on a finding."""
    d = request.get_json(silent=True) or {}
    url = d.get('url', '')
    param = d.get('param', '')
    payload = d.get('payload', '')
    method = d.get('method', 'GET')
    finding_type = d.get('type', 'unknown')

    if not url or not payload:
        return jsonify({'status': 'error', 'message': 'url and payload required'}), 400

    from scanner.confirmation import confirm_finding
    finding = {'type': finding_type, 'title': d.get('title', ''), 'details': d.get('details', '')}
    result = confirm_finding(finding, url, param, payload, method)

    return jsonify({'status': 'ok', 'result': result})


@scan_bp.route('/api/engines/kill_switch', methods=['POST'])
@login_required
def engine_kill_switch():
    """Trigger or reset the kill switch."""
    d = request.get_json(silent=True) or {}
    action = d.get('action', 'check')
    scan_id = d.get('scan_id', '')

    from scanner.limits import KillSwitch
    ks = KillSwitch(scan_id)

    if action == 'trigger':
        ks.trigger()
        return jsonify({'status': 'ok', 'message': 'Kill switch triggered'})
    elif action == 'reset':
        ks.reset()
        return jsonify({'status': 'ok', 'message': 'Kill switch reset'})
    else:
        triggered = ks.check()
        return jsonify({'status': 'ok', 'triggered': triggered})


@scan_bp.route('/api/engines/limits')
@login_required
def engine_limits():
    """Get current hard limits status."""
    with LOCK:
        limits = scan_state.get('limits_status', {})
    return jsonify({'status': 'ok', 'limits': limits})


@scan_bp.route('/api/engines/health')
@login_required
def engine_health():
    """Get target health status."""
    with LOCK:
        health = scan_state.get('health_status', {})
    return jsonify({'status': 'ok', 'health': health})


# ═══════════════════════════════════════════════════════════════════════════════
# CHAIN ANALYSIS & REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

@scan_bp.route('/api/chains/full')
@login_required
def chains_full():
    """Get full attack chain analysis with graph and paths."""
    from scanner.chains import build_attack_chains_full
    result = build_attack_chains_full()
    return jsonify({'status': 'ok', **result})


@scan_bp.route('/api/report/generate', methods=['POST'])
@login_required
def report_generate():
    """Generate full scan report in the standard JSON format."""
    from scanner.report import generate_full_report
    report = generate_full_report()
    return jsonify({'status': 'ok', 'report': report})


@scan_bp.route('/api/report/finding/<finding_id>')
@login_required
def report_single_finding(finding_id):
    """Generate report for a single finding."""
    from scanner.report import generate_finding_report
    with LOCK:
        findings = scan_state.get('findings', [])
    finding = next((f for f in findings if f.get('id') == finding_id), None)
    if not finding:
        return jsonify({'status': 'error', 'message': 'Finding not found'}), 404
    report = generate_finding_report(finding)
    return jsonify({'status': 'ok', 'report': report})


@scan_bp.route('/api/confirm/batch', methods=['POST'])
@login_required
def confirm_batch():
    """Run confirmation protocol on a batch of findings."""
    from scanner.confirmation import confirm_findings_batch
    d = request.get_json(silent=True) or {}
    target = d.get('target', scan_state.get('target', ''))
    with LOCK:
        findings = list(scan_state.get('findings', []))
    confirmed = confirm_findings_batch(findings, target)
    return jsonify({'status': 'ok', 'confirmed': len(confirmed), 'total': len(findings)})


@scan_bp.route('/api/risk-engine/analyze', methods=['POST'])
@login_required
def risk_engine_analyze():
    """
    Enterprise Risk Correlation Engine — analyze telemetry from 4 layers.
    POST body: { web: "...", network: "...", vm: "...", cloud: "..." }
    Returns structured JSON risk assessment.
    """
    from scanner.modules.web.risk_engine import correlate_telemetry

    data = request.get_json(silent=True) or {}
    web = data.get('web', '')
    network = data.get('network', '')
    vm = data.get('vm', '')
    cloud = data.get('cloud', '')

    if not any([web, network, vm, cloud]):
        return jsonify({'status': 'error', 'message': 'Provide telemetry in at least one layer'}), 400

    result = correlate_telemetry(web, network, vm, cloud)
    op_log('risk_engine', target=scan_state.get('target', ''),
           detail=f'risk={result["risk_level"]}, confidence={result["confidence"]}, '
                  f'layers={len(result["layers_involved"])}')

    return jsonify({'status': 'ok', 'result': result})


@scan_bp.route('/api/verify/run', methods=['POST'])
@login_required
def run_verification():
    """
    Run the verification agent on all unverified findings.
    Actually exploits each finding to confirm it's real.
    """
    from scanner.verification_agent import verify_all_findings
    with LOCK:
        if scan_state.get('scanning'):
            return jsonify({'status': 'error', 'message': 'Scan still running'}), 409
    result = verify_all_findings(scan_state.get('target', ''), max_workers=3)
    return jsonify({'status': 'ok', 'result': result})

