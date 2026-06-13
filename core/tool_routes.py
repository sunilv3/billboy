"""Utility routes: tools, schedule, notify, SIEM, proxy, page-type."""
import base64, json, os, time, threading, re
from datetime import datetime
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, Response
from core.auth import login_required
from core.logger import log, sse_stream
from core.utils import (_find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE,
                        SQLITE_AVAILABLE, sqlite3_mod, _safe_str,
                        _check_target_for_ssrf, validate_webhook_url,
                        run_nvd_lookup)
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, op_log
from scanner.routing import PageTypeDetector

tools_bp = Blueprint('tools', __name__)

@tools_bp.route('/api/tools')
@login_required
def api_tools():
    """Return tool availability status."""
    available = []
    missing_required = []
    missing_optional = []

    tool_defs = [
        ('nmap', 'nmap', 'Port scanning', True),
        ('sqlmap', 'sqlmap', 'SQL injection', True),
        ('nuclei', 'nuclei', 'Vulnerability scanning', True),
        ('ffuf', 'ffuf', 'Directory brute-force', True),
        ('httpx', 'httpx', 'HTTP probing', True),
        ('subfinder', 'subfinder', 'Subdomain enumeration', True),
        ('dalfox', 'dalfox', 'XSS scanning', True),
        ('gau', 'gau', 'URL collection (Wayback)', True),
        ('katana', 'katana', 'JS-aware crawling', True),
        ('osv-scanner', 'osv-scanner', 'Dependency scanning', True),
        ('gitleaks', 'gitleaks', 'Secret scanning', True),
        ('semgrep', 'semgrep', 'SAST analysis', True),
        ('trivy', 'trivy', 'Container CVE scanning', True),
        ('checkov', 'checkov', 'IaC scanning', True),
        ('wafw00f', 'wafw00f', 'WAF detection', True),
        ('arjun', 'arjun', 'Parameter discovery', False),
        ('naabu', 'naabu', 'Fast port scanning', False),
        ('dnsx', 'dnsx', 'DNS validation', False),
        ('assetfinder', 'assetfinder', 'Subdomain discovery', False),
        ('hakrawler', 'hakrawler', 'Deep URL crawling', False),
        ('crlfuzz', 'crlfuzz', 'CRLF injection scanning', False),
        ('gospider', 'gospider', 'Web crawling', False),
        ('puredns', 'puredns', 'DNS bruteforce', False),
        ('amass', 'amass', 'OSINT subdomain enum', False),
        ('mitmproxy', 'mitmproxy', 'Traffic capture proxy', False),
        ('sslyze', 'sslyze', 'SSL/TLS cipher analysis', False),
        ('nikto', 'nikto', 'Web server scanning', False),
        ('rustscan', 'rustscan', 'Fast port scanning', False),
        ('trufflehog', 'trufflehog', 'Deep secrets scanning', False),
        ('grype', 'grype', 'Container CVE scanning', False),
        ('bearer', 'bearer', 'SAST with data flow', False),
        ('testssl.sh', 'testssl.sh', 'SSL/TLS testing', False),
        ('commix', 'commix', 'Command injection', False),
        ('ssrfmap', 'ssrfmap', 'SSRF exploitation', False),
        ('wpscan', 'wpscan', 'WordPress scanning', False),
        ('feroxbuster', 'feroxbuster', 'Directory brute-force', False),
        ('jwt_tool', 'jwt_tool', 'JWT attacks', False),
        ('theharvester', 'theharvester', 'OSINT gathering', False),
        ('searchsploit', 'searchsploit', 'Exploit lookup', False),
        ('tplmap', 'tplmap', 'Template injection', False),
    ]

    # Check Scrapling (Python library, no binary)
    try:
        from scanner.engines.scrapling_fetcher import is_available as scrapling_ok
        if scrapling_ok():
            available.append({'name': 'scrapling', 'description': 'Stealth fetching, adaptive parsing, anti-bot bypass', 'path': 'python:scrapling'})
    except ImportError:
        pass

    for display_name, binary_name, desc, required in tool_defs:
        path = _find_tool(binary_name)
        if path:
            available.append({'name': display_name, 'description': desc, 'path': path})
        elif required:
            missing_required.append([display_name, desc])
        else:
            missing_optional.append([display_name, desc])

    total = len(available) + len(missing_required) + len(missing_optional)
    return jsonify({
        'available': available,
        'missing_required': missing_required,
        'missing_optional': missing_optional,
        'total': total,
    })



@tools_bp.route('/api/schedule', methods=['POST'])
@login_required
def set_schedule():
    global scan_state
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'Invalid request body'}), 400
    enabled = bool(data.get('enabled', False))
    interval = _safe_str(data.get('interval'), 'off').strip().lower()
    target = _safe_str(data.get('target')).strip().lower()
    target = re.sub(r'^https?://', '', target).split('/')[0]
    
    if enabled and not target:
        return jsonify({'status': 'error', 'message': 'No target domain provided for schedule'}), 400
        
    with LOCK:
        scan_state['schedule'].update({
            'enabled': enabled,
            'interval': interval if enabled else 'off',
            'target': target if enabled else '',
            'last_run': None,
            'next_run': time.time() if enabled else None
        })
        schedule_snapshot = dict(scan_state['schedule'])

    log('info', f'[SCHEDULER] Schedule updated: Enabled={enabled}, Interval={interval}, Target={target}')
    return jsonify({'status': 'schedule_updated', 'schedule': schedule_snapshot})


@tools_bp.route('/api/schedule/logs')
@login_required
def get_schedule_logs():
    with LOCK:
        return jsonify({
            'schedule': scan_state['schedule'],
            'logs': scan_state['schedule_logs']
        })


@tools_bp.route('/api/siem/test', methods=['POST'])
@login_required
def test_siem():
    data = request.get_json(silent=True) or {}
    attack_type = data.get('type')
    target = scan_state.get('target', 'example.com')
    
    with LOCK:
        if attack_type == 'bruteforce':
            scan_state['siem_logs'].append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'event': f'Brute force login flood against Auth Endpoint on {target}',
                'status': 'BLOCKED',
                'alert': 'HIGH'
            })
            log('warn', f'[WAF/SIEM] IP Rate limit triggered. Brute force traffic blocked by WAF.')
        elif attack_type == 'sqli_payload':
            scan_state['siem_logs'].append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'event': f'SQLi Union Select payload detected in query parameter from {target}',
                'status': 'BLOCKED',
                'alert': 'CRITICAL'
            })
            log('warn', f'[WAF/SIEM] WAF Alert: Signature rule #942100 triggered. SQLi pattern intercepted.')
        elif attack_type == 'xss_payload':
            scan_state['siem_logs'].append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'event': f'DOM XSS script inject load string matched on {target}/search',
                'status': 'DETECTED',
                'alert': 'MEDIUM'
            })
            log('warn', f'[WAF/SIEM] SIEM Event: Reflected XSS trace logged by application middleware.')
            
        logs = scan_state['siem_logs'][-20:]
        
    return jsonify({
        'status': 'success',
        'logs': logs
    })


@tools_bp.route('/api/tools/jwt-decode', methods=['POST'])
@login_required
def jwt_decode():
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    if not token or token.count('.') != 2:
        return jsonify({'status': 'error', 'message': 'Invalid JWT format'}), 400
    try:
        parts = token.split('.')
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        sig = parts[2][:20] + '...' if len(parts[2]) > 20 else parts[2]
        return jsonify({
            'status': 'ok',
            'header': header,
            'payload': payload,
            'algorithm': header.get('alg', 'unknown'),
            'signature': sig,
            'notes': 'Signature not verified — decoded client-side only'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Decode failed: {str(e)}'}), 400



@tools_bp.route('/api/tools/nvd-lookup', methods=['POST'])
@login_required
def nvd_lookup_api():
    data = request.get_json(silent=True) or {}
    tech = data.get('technology', '').strip()
    ver = data.get('version', '').strip()
    if not tech:
        return jsonify({'status': 'error', 'message': 'Technology name required'}), 400
    cves = run_nvd_lookup(tech, ver)
    return jsonify({'status': 'ok', 'cves': cves, 'count': len(cves)})


PRIVATE_IPS = re.compile(r'^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0|::1|fc00:|fe80:)')



@tools_bp.route('/api/notify/test', methods=['POST'])
@login_required
def notify_test():
    data = request.get_json(silent=True) or {}
    channel = data.get('channel', 'console')
    msg = data.get('message', 'Test notification from Security Scanner')
    try:
        if not REQUESTS_AVAILABLE or not req_lib:
            return jsonify({'status': 'error', 'message': 'HTTP client not available'}), 500
        if channel == 'slack':
            webhook = data.get('webhook_url', '')
            if webhook:
                if not validate_webhook_url(webhook):
                    return jsonify({'status': 'error', 'message': 'Invalid webhook URL'}), 400
                req_lib.post(webhook, json={'text': msg}, timeout=8)
        elif channel == 'discord':
            webhook = data.get('webhook_url', '')
            if webhook:
                if not validate_webhook_url(webhook):
                    return jsonify({'status': 'error', 'message': 'Invalid webhook URL'}), 400
                req_lib.post(webhook, json={'content': msg}, timeout=8)
        log('info', f'[NOTIFY] {channel} notification sent: {msg[:50]}')
        return jsonify({'status': 'ok', 'channel': channel})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@tools_bp.route('/api/proxy/traffic')
@login_required
def proxy_traffic():
    """Read HAR file and return simplified traffic entries."""
    har_path = scan_state.get('proxy_har', '')
    if not har_path or not os.path.exists(har_path):
        return jsonify({'entries': [], 'message': 'No HAR data available'})
    try:
        import json as _json
        with open(har_path, 'r') as f:
            har = _json.load(f)
        entries = []
        for e in har.get('log', {}).get('entries', [])[:500]:
            req = e.get('request', {})
            resp = e.get('response', {})
            entries.append({
                'method': req.get('method', '?'),
                'url': req.get('url', ''),
                'status': resp.get('status', 0),
                'size': resp.get('content', {}).get('size', 0),
                'time_ms': int(e.get('time', 0) * 1000),
                'resp_body': (resp.get('content', {}).get('text', '') or '')[:2000],
            })
        return jsonify({'entries': entries, 'total': len(entries)})
    except Exception as ex:
        return jsonify({'entries': [], 'error': str(ex)})


@tools_bp.route('/api/replay', methods=['POST'])
@login_required
def request_replay():
    """Replay an HTTP request with optional modifications."""
    data = request.get_json(silent=True) or {}
    method = data.get('method', 'GET').upper()
    url = data.get('url', '')
    headers = data.get('headers', {})
    body = data.get('body', '')
    modifications = data.get('modifications', {})
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    # SECURITY: SSRF guard — extract hostname and validate before making outbound request
    try:
        _parsed_replay = urlparse(url)
        _replay_host = _parsed_replay.hostname or ''
    except Exception:
        return jsonify({'error': 'Invalid URL'}), 400
    if not _replay_host:
        return jsonify({'error': 'Invalid URL'}), 400
    _ssrf_err, _ssrf_warn = _check_target_for_ssrf(_replay_host)
    if _ssrf_err:
        return jsonify({'error': f'SSRF guard: {_ssrf_err}'}), 400
    # SECURITY: restrict to safe HTTP methods only
    if method not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'):
        return jsonify({'error': 'Invalid HTTP method'}), 400
    # SECURITY: strip sensitive internal headers that could be used to impersonate
    _blocked_headers = {'host', 'x-forwarded-for', 'x-real-ip', 'authorization'}
    headers = {k: v for k, v in (headers or {}).items() if k.lower() not in _blocked_headers}
    try:
        import time as _t
        t0 = _t.time()
        r = req_lib.request(
            method, url, headers=headers, data=body,
            timeout=15,
            verify=True,
            allow_redirects=False,
        )
        elapsed = round((_t.time() - t0) * 1000)
        return jsonify({
            'status': r.status_code,
            'headers': dict(r.headers),
            'body': r.text[:50000],
            'elapsed': elapsed,
            'final_url': r.url,
        })
    except Exception as ex:
        return jsonify({'error': 'Replay request failed'}), 500


@tools_bp.route('/api/page_type')
@login_required
def get_page_type():
    """Return the page type detection result for the current/last scan."""
    with LOCK:
        result = scan_state.get('page_type_result', {})
        page_type = scan_state.get('page_type', 'unknown')
        target = scan_state.get('target', '')
    return jsonify({
        'status': 'ok',
        'target': target,
        'page_type': page_type,
        'result': result,
    })



@tools_bp.route('/api/page_type/detect', methods=['POST'])
@login_required
def detect_page_type_api():
    """
    On-demand page type detection for any target.
    Does NOT require an active scan. Can be called before starting a scan
    to preview which modules will run.

    POST body: {"target": "example.com"}
    Returns:   {page_type, confidence, scan_strategy, signals, recommended_modules, skip_modules}
    """
    data = request.get_json(silent=True) or {}
    target = _safe_str(data.get('target', '')).strip().lower()
    target = re.sub(r'^https?://', '', target).split('/')[0]
    if not target:
        return jsonify({'status': 'error', 'message': 'No target provided'}), 400
    ssrf_err, _ = _check_target_for_ssrf(target)
    if ssrf_err:
        return jsonify({'status': 'error', 'message': ssrf_err}), 400
    try:
        result = PageTypeDetector.detect(target)
        return jsonify({'status': 'ok', 'target': target, **result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': 'Detection failed'}), 500


