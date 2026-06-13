"""Mitmproxy traffic capture layer for scan evidence collection."""
import os
import json
import time
import secrets
import subprocess
import threading
import socket
import signal
from urllib.parse import urlparse
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK

# ─── MITMPROXY PROXY LAYER ───────────────────────────────────────────────────
_PROXY_PORT = 8082

def _start_proxy(scan_id):
    """Start mitmdump as background subprocess for traffic capture."""
    mitmdump_path = _find_tool('mitmdump')
    if not mitmdump_path:
        log('warn', '[PROXY] mitmdump not found — traffic capture disabled')
        return None
    # Kill any stale mitmdump on the port first
    try:
        import subprocess as _sp
        _sp.run(['pkill', '-f', f'mitmdump.*-p.*{_PROXY_PORT}'], timeout=3, capture_output=True)
        time.sleep(0.5)
    except Exception:
        pass
    import tempfile as _tempfile
    har_fd, har_path = _tempfile.mkstemp(suffix='.har', prefix='scan_', dir='/tmp')
    os.close(har_fd)
    try:
        proc = subprocess.Popen(
            [mitmdump_path, '-p', str(_PROXY_PORT), '--save-stream-file', har_path,
             '--quiet'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Wait up to 5s for the port to become available
        bound = False
        for _ in range(10):
            time.sleep(0.5)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', _PROXY_PORT))
                sock.close()
                if result == 0:
                    bound = True
                    break
            except Exception:
                pass
        with LOCK:
            scan_state['proxy_pid'] = proc.pid if bound else None
            scan_state['proxy_har'] = har_path if bound else None
            scan_state['proxy_port'] = _PROXY_PORT if bound else None
        if bound:
            log('ok', f'[PROXY] mitmdump started on port {_PROXY_PORT}, HAR={har_path}')
            return har_path
        else:
            log('warn', f'[PROXY] mitmdump failed to bind port {_PROXY_PORT} — proxy disabled')
            try:
                proc.kill()
            except Exception:
                pass
            return None
    except Exception as e:
        log('warn', f'[PROXY] Failed to start mitmdump: {e}')
        return None

def _stop_proxy():
    """Stop mitmdump and flush HAR file."""
    with LOCK:
        pid = scan_state.get('proxy_pid')
        if not pid:
            return
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        log('ok', f'[PROXY] mitmdump stopped (pid={pid})')
        with LOCK:
            scan_state['proxy_pid'] = None
    except ProcessLookupError:
        with LOCK:
            scan_state['proxy_pid'] = None
    except Exception as e:
        log('warn', f'[PROXY] Error stopping mitmdump: {e}')

def attach_har_evidence(finding, har_path):
    """Match finding asset URL against HAR entries, return formatted HTTP block."""
    if not har_path or not os.path.exists(har_path):
        return ''
    try:
        import json as _json
        with open(har_path, 'r') as f:
            har = _json.load(f)
        entries = har.get('log', {}).get('entries', [])
        asset = finding.get('asset', '')
        for entry in entries:
            req = entry.get('request', {})
            resp = entry.get('response', {})
            url = req.get('url', '')
            if asset and asset in url:
                method = req.get('method', '?')
                status = resp.get('status', '?')
                req_headers = '\n'.join(f'{h["name"]}: {h["value"]}' for h in req.get('headers', [])[:10])
                resp_headers = '\n'.join(f'{h["name"]}: {h["value"]}' for h in resp.get('headers', [])[:10])
                resp_body = resp.get('content', {}).get('text', '')[:600]
                return (
                    f'── REQUEST ──\n{method} {url}\n{req_headers}\n\n'
                    f'── RESPONSE ──\nHTTP {status}\n{resp_headers}\n\n{resp_body}'
                )
    except Exception:
        pass
    return ''

def analyze_proxy_traffic(har_path, scan_id):
    """
    Analyze captured HAR traffic for security issues — this is the REAL value
    of the proxy layer, not just recording traffic.

    Detects:
    1. Auth tokens/session IDs in URL query strings (logged in browser history, logs, referrers)
    2. Sensitive data in POST bodies (passwords, credit cards, SSNs in plaintext)
    3. Missing Secure/HttpOnly/SameSite flags on auth cookies
    4. Mixed content (HTTPS page loading HTTP resources)
    5. CORS misconfiguration (permissive Origin reflection)
    6. Cache-Control missing on sensitive responses
    7. Server-sent credentials (Set-Cookie without Secure on HTTPS)
    8. Content-Security-Policy absence
    9. HSTS missing on HTTPS responses
    10. Verbose error messages leaking stack traces/DB info
    """
    if not har_path or not os.path.exists(har_path):
        return []

    findings = []
    try:
        import json as _json
        with open(har_path, 'r') as f:
            har = _json.load(f)
        entries = har.get('log', {}).get('entries', [])
    except Exception:
        return []

    # Compile patterns for sensitive data detection
    import re as _re
    secret_patterns = [
        (_re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+', _re.I), 'Plaintext password in request'),
        (_re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*[A-Za-z0-9+/=_-]{16,}', _re.I), 'API key in request'),
        (_re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'), 'Credit card number in request'),
        (_re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'SSN in request'),
        (_re.compile(r'(?i)(bearer|token)\s+[A-Za-z0-9+/=._-]{20,}', _re.I), 'Bearer token in request'),
        (_re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*\S+'), 'AWS credentials in request'),
    ]

    # Track per-request analysis
    seen_tokens_in_urls = []
    missing_cookie_flags = []
    mixed_content = []
    cors_issues = []
    cache_issues = []
    csp_missing = []
    hsts_missing = []
    verbose_errors = []

    for entry in entries:
        req = entry.get('request', {})
        resp = entry.get('response', {})
        url = req.get('url', '')
        method = req.get('method', '?')
        status = resp.get('status', 0)
        parsed_url = urlparse(url)

        # ── 1. Auth tokens in URL query strings ──
        if parsed_url.query:
            query_lower = parsed_url.query.lower()
            token_params = ['token', 'access_token', 'session', 'sessionid', 'sid',
                           'auth', 'jwt', 'bearer', 'api_key', 'apikey', 'key',
                           'state', 'code', 'redirect_uri']
            for param in token_params:
                if f'{param}=' in query_lower:
                    seen_tokens_in_urls.append({
                        'url': url, 'param': param,
                        'method': method, 'status': status,
                    })

        # ── 2. Sensitive data in POST body ──
        if method in ('POST', 'PUT', 'PATCH'):
            req_body = ''
            for postData in [req.get('postData', {})]:
                if isinstance(postData, dict):
                    req_body = postData.get('text', '')
                    # Check MIME params too
                    for p in postData.get('params', []):
                        req_body += f' {p.get("name", "")}={p.get("value", "")}'
            for pattern, desc in secret_patterns:
                if pattern.search(req_body):
                    findings.append({
                        'type': 'sensitive_data_in_request',
                        'severity': 'critical',
                        'url': url,
                        'method': method,
                        'detail': f'{desc} sent in {method} body',
                        'evidence': req_body[:300],
                    })

        # ── 3. Cookie security analysis ──
        resp_headers = {h['name'].lower(): h['value'] for h in resp.get('headers', [])}
        set_cookies_raw = []
        for h in resp.get('headers', []):
            if h['name'].lower() == 'set-cookie':
                set_cookies_raw.append(h['value'])

        for cookie_str in set_cookies_raw:
            cookie_name = cookie_str.split('=')[0].strip() if '=' in cookie_str else ''
            cookie_lower = cookie_str.lower()
            is_auth_cookie = any(x in cookie_lower for x in [
                'session', 'sid', 'token', 'auth', 'jwt', 'csrf',
                'login', 'user', 'account', 'access'
            ])
            if is_auth_cookie:
                missing_flags_list = []
                if 'secure' not in cookie_lower:
                    missing_flags_list.append('Secure')
                if 'httponly' not in cookie_lower:
                    missing_flags_list.append('HttpOnly')
                if 'samesite' not in cookie_lower:
                    missing_flags_list.append('SameSite')
                if missing_flags_list:
                    missing_cookie_flags.append({
                        'cookie': cookie_name, 'url': url,
                        'missing': missing_flags_list,
                        'raw': cookie_str[:200],
                    })

        # ── 4. Mixed content (HTTPS page loading HTTP resources) ──
        if parsed_url.scheme == 'https':
            for h in req.get('headers', []):
                if h['name'].lower() == 'referer' and h['value'].startswith('http://'):
                    mixed_content.append({'page': url, 'resource': h['value']})

        # ── 5. CORS misconfiguration ──
        origin = ''
        for h in req.get('headers', []):
            if h['name'].lower() == 'origin':
                origin = h['value']
                break
        if origin:
            acao = resp_headers.get('access-control-allow-origin', '')
            acac = resp_headers.get('access-control-allow-credentials', '')
            if acao == '*' and acac.lower() == 'true':
                cors_issues.append({'url': url, 'origin': origin,
                    'detail': 'ACA-Origin=* with ACAC=true — allows credential theft from any origin'})
            elif acao == origin and acac.lower() == 'true':
                # Check if origin is reflected without validation
                parsed_origin = urlparse(origin)
                if parsed_origin.netloc and parsed_origin.netloc not in url:
                    cors_issues.append({'url': url, 'origin': origin,
                        'detail': f'Origin {origin} reflected with credentials — check if validation is domain-based'})

        # ── 6. Cache-Control missing on sensitive responses ──
        cache_control = resp_headers.get('cache-control', '')
        pragma = resp_headers.get('pragma', '')
        if not cache_control or 'no-store' not in cache_control.lower():
            is_sensitive = any(x in url.lower() for x in [
                '/api/', '/auth/', '/login', '/token', '/session',
                '/admin/', '/dashboard', '/profile', '/settings'
            ])
            if is_sensitive:
                cache_issues.append({'url': url, 'status': status,
                    'detail': 'No Cache-Control: no-store on sensitive endpoint — response may be cached'})

        # ── 7. CSP missing ──
        csp = resp_headers.get('content-security-policy', '')
        content_type = resp_headers.get('content-type', '')
        if 'text/html' in content_type and not csp:
            csp_missing.append({'url': url, 'status': status})

        # ── 8. HSTS missing ──
        if parsed_url.scheme == 'https':
            hsts = resp_headers.get('strict-transport-security', '')
            if not hsts:
                # Only flag on main document responses, not assets
                if method == 'GET' and status in (200, 301, 302):
                    hsts_missing.append({'url': url})

        # ── 9. Verbose error messages ──
        if status >= 500:
            resp_body = resp.get('content', {}).get('text', '')
            error_indicators = [
                'stack trace', 'traceback', 'exception',
                'syntax error', 'mysql_', 'postgresql', 'ORA-',
                'at line', 'in file', 'database', 'query failed',
                'internal server error', '/var/www', '/home/',
            ]
            if any(ind in resp_body.lower() for ind in error_indicators):
                verbose_errors.append({'url': url, 'status': status,
                    'body_preview': resp_body[:200]})

    # ── Generate findings from analysis ──
    if seen_tokens_in_urls:
        add_finding(
            'high',
            f'Auth tokens exposed in {len(seen_tokens_in_urls)} URL query strings',
            sub='Tokens in URLs are logged in browser history, server logs, referrer headers, and proxy logs',
            asset=seen_tokens_in_urls[0]['url'],
            cvss='6.5', owasp='A04', mitre='T1552',
            details='\n'.join(f'  {e["method"]} {e["url"][:100]} (param: {e["param"]})' for e in seen_tokens_in_urls[:10])
                    + '\n\nImpact: Tokens leaked via Referer header, browser history, proxy logs, SIEM\n'
                    f'Remediation: Move tokens to Authorization header or HttpOnly cookie')
        findings.append({'type': 'tokens_in_urls', 'count': len(seen_tokens_in_urls)})

    if missing_cookie_flags:
        add_finding(
            'high',
            f'{len(missing_cookie_flags)} auth cookies missing security flags',
            sub='Missing Secure/HttpOnly/SameSite flags on session cookies',
            asset=missing_cookie_flags[0]['url'],
            cvss='7.0', owasp='A05', mitre='T1539',
            details='\n'.join(f'  {e["cookie"]}: missing {", ".join(e["missing"])} (from {e["url"][:80]})' for e in missing_cookie_flags[:10])
                    + '\n\nImpact: Session hijacking via XSS (no HttpOnly), MITM (no Secure), CSRF (no SameSite)\n'
                    f'Remediation: Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict')
        findings.append({'type': 'cookie_flags_missing', 'count': len(missing_cookie_flags)})

    if cors_issues:
        add_finding(
            'high',
            f'{len(cors_issues)} CORS misconfigurations with credential reflection',
            sub='Origin reflected in ACA-Origin with ACAC=true allows cross-origin credential theft',
            asset=cors_issues[0]['url'],
            cvss='7.5', owasp='A05', mitre='T1189',
            details='\n'.join(f'  Origin: {e["origin"]} → {e["url"][:80]}\n    {e["detail"]}' for e in cors_issues[:5])
                    + '\n\nImpact: Attacker-controlled page can read authenticated API responses\n'
                    f'Remediation: Validate Origin against allowlist, never reflect arbitrary origins with credentials')
        findings.append({'type': 'cors_misconfig', 'count': len(cors_issues)})

    if cache_issues:
        add_finding(
            'medium',
            f'{len(cache_issues)} sensitive responses missing Cache-Control',
            sub='Sensitive API/auth responses may be cached by browser or intermediate proxies',
            asset=cache_issues[0]['url'],
            cvss='4.0', owasp='A04', mitre='T1552',
            details='\n'.join(f'  {e["url"][:80]} (HTTP {e["status"]})' for e in cache_issues[:10])
                    + '\n\nImpact: Sensitive data persisted in browser cache, proxy cache, CDN cache\n'
                    f'Remediation: Add Cache-Control: no-store, no-cache, must-revalidate')
        findings.append({'type': 'cache_missing', 'count': len(cache_issues)})

    if csp_missing:
        add_finding(
            'medium',
            f'{len(csp_missing)} HTML pages missing Content-Security-Policy',
            sub='No CSP header — XSS attacks not mitigated by browser policy',
            asset=csp_missing[0]['url'],
            cvss='5.0', owasp='A03', mitre='T1189',
            details='\n'.join(f'  {e["url"][:80]}' for e in csp_missing[:10])
                    + '\n\nImpact: XSS payloads execute without CSP restrictions\n'
                    f'Remediation: Add Content-Security-Policy header with appropriate directives')
        findings.append({'type': 'csp_missing', 'count': len(csp_missing)})

    if hsts_missing:
        add_finding(
            'low',
            f'{len(hsts_missing)} HTTPS endpoints missing HSTS',
            sub='Strict-Transport-Security header not set — first request may be over HTTP',
            asset=hsts_missing[0]['url'],
            cvss='3.0', owasp='A02', mitre='T1557',
            details='\n'.join(f'  {e["url"][:80]}' for e in hsts_missing[:5])
                    + '\n\nImpact: Downgrade attack on first visit\n'
                    f'Remediation: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload')
        findings.append({'type': 'hsts_missing', 'count': len(hsts_missing)})

    if verbose_errors:
        add_finding(
            'medium',
            f'{len(verbose_errors)} verbose error messages in HTTP 5xx responses',
            sub='Server errors leak stack traces, file paths, database info',
            asset=verbose_errors[0]['url'],
            cvss='5.3', owasp='A05', mitre='T1592',
            details='\n'.join(f'  {e["url"][:80]} (HTTP {e["status"]})\n    Preview: {e["body_preview"][:100]}' for e in verbose_errors[:5])
                    + '\n\nImpact: Information disclosure aids further attacks (path traversal, SQL injection)\n'
                    f'Remediation: Return generic error pages, log detailed errors server-side only')
        findings.append({'type': 'verbose_errors', 'count': len(verbose_errors)})

    if mixed_content:
        add_finding(
            'medium',
            f'{len(mixed_content)} mixed content references detected',
            sub='HTTPS pages loading HTTP resources — downgrade attack vector',
            asset=mixed_content[0]['page'],
            cvss='4.0', owasp='A02', mitre='T1557',
            details='\n'.join(f'  Page: {e["page"][:60]} → HTTP ref: {e["resource"][:60]}' for e in mixed_content[:5])
                    + '\n\nImpact: Man-in-the-middle can inject content into HTTP resources\n'
                    f'Remediation: Use protocol-relative URLs or upgrade all resources to HTTPS')
        findings.append({'type': 'mixed_content', 'count': len(mixed_content)})

    total = sum(f.get('count', 1) for f in findings)
    log('ok', f'[PROXY-ANALYSIS] {len(findings)} issue classes, {total} total instances across {len(entries)} requests')
    return findings
