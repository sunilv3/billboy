"""
Application Security Modules: JS secrets, API surface, auth, data exposure,
cloud configs, payment keys, sensitive files, business logic.
"""
import re
import json
import time
import os
import secrets
from urllib.parse import urlparse, parse_qs, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: JS SECRET SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

SECRET_PATTERNS = [
    # API Keys
    (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key', 'high'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'critical'),
    (r'SK[0-9a-fA-F]{32,}', 'Stripe Secret Key', 'critical'),
    (r'rk_(?:test|live)_[0-9a-zA-Z]{24,}', 'Razorpay Key', 'high'),
    (r'pk_(?:test|live)_[0-9a-zA-Z]{24,}', 'Razorpay Public Key', 'medium'),
    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token', 'critical'),
    (r'glpat-[0-9a-zA-Z_-]{20,}', 'GitLab PAT', 'critical'),
    (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Key', 'critical'),
    (r'sk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Key', 'medium'),
    (r'xox[bpsa]-[0-9a-zA-Z-]+', 'Slack Token', 'critical'),
    (r'AAAA[a-zA-Z0-9+/=]{100,}', 'Facebook Access Token', 'high'),
    (r'EAAG[0-9a-zA-Z]+', 'Facebook App Token', 'high'),
    (r'AC[a-z0-9]{32}', 'Twilio Account SID', 'high'),
    (r'SK[0-9a-fA-F]{32}', 'Twilio API Key', 'high'),
    # Webhooks
    (r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', 'Discord Webhook URL', 'critical'),
    (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+', 'Slack Webhook URL', 'high'),
    (r'https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+', 'Telegram Bot Token', 'critical'),
    # JWT / Tokens
    (r'eyJhbGciOi[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', 'JWT Token', 'high'),
    # Firebase
    (r'firebaseConfig\s*[:=]\s*\{[^}]+\}', 'Firebase Config', 'high'),
    (r'(?:authDomain|storageBucket|messagingSenderId|appId)["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Firebase Config Field', 'medium'),
    # Private URLs
    (r'https?://localhost:\d+', 'Localhost URL', 'high'),
    (r'https?://127\.0\.0\.1:\d+', 'Loopback URL', 'high'),
    (r'https?://192\.168\.\d+\.\d+:\d+', 'Private LAN URL', 'critical'),
    (r'https?://10\.\d+\.\d+\.\d+:\d+', 'Private LAN URL', 'critical'),
    (r'https?://172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+:\d+', 'Private LAN URL', 'critical'),
    (r'https?://[a-z0-9-]+\.dev\.tunnels\.ms[^\s"\']*', 'Dev Tunnel URL', 'high'),
    # Database URLs
    (r'mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+', 'MySQL Connection String', 'critical'),
    (r'postgres(?:ql)?://[^\s"\']+:[^\s"\']+@[^\s"\']+', 'PostgreSQL Connection String', 'critical'),
    (r'mongodb(\+srv)?://[^\s"\']+:[^\s"\']+@[^\s"\']+', 'MongoDB Connection String', 'critical'),
    (r'redis://[^\s"\']+:[^\s"\']+@[^\s"\']+', 'Redis Connection String', 'critical'),
    # AWS
    (r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"\']+', 'AWS ARN', 'high'),
    (r'["\']?aws_bucket_name["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'AWS Bucket Name', 'medium'),
    # Generic secrets
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']', 'Hardcoded Password', 'critical'),
    (r'(?:secret|api_?secret|app_?secret)\s*[:=]\s*["\']([^\s"\']{16,})["\']', 'Hardcoded Secret', 'critical'),
    (r'(?:client_?secret)\s*[:=]\s*["\']([^\s"\']{16,})["\']', 'Client Secret', 'critical'),
    # SSH Keys
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', 'Private Key', 'critical'),
    # Sentry
    (r'sentry[_-]?public[_-]?key["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'Sentry Public Key', 'info'),
    (r'sentry[_-]?dsn["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Sentry DSN', 'medium'),
    (r'o\d+\.ingest\.sentry\.io', 'Sentry Ingest URL', 'info'),
    # Pusher
    (r'pusher[_-]?key["\']?\s*[:=]\s*["\']([a-f0-9]{20})["\']', 'Pusher Key', 'medium'),
    (r'wss?://[a-z0-9.-]*pusher[a-z0-9.-]*[/\s"\']', 'Pusher WebSocket Endpoint', 'info'),
    # Internal backend URLs (company-specific patterns)
    (r'wss?://[a-z0-9.-]*backend-[a-z]+\.com[^\s"\']*', 'Internal Backend WebSocket', 'high'),
    (r'https?://api-[a-z0-9.-]+\.backend-[a-z]+\.com[^\s"\']*', 'Internal Backend API URL', 'high'),
    # Version/build strings in JS
    (r'(?:version|release|build)["\']?\s*[:=]\s*["\']([^"\']{5,50})["\']', 'Version String in JS', 'info'),
    # Next.js build data
    (r'__NEXT_DATA__[^<]*', 'Next.js Build Data', 'info'),
    # Sentry release
    (r'sentry[_-]?release["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Sentry Release Version', 'info'),
]


def run_js_secret_module(target):
    """Scan JavaScript bundles for hardcoded secrets, API keys, and private URLs."""
    log('info', f'[JS-SECRETS] Scanning JS bundles on {target}')
    base_url = f'https://{target}'
    found_secrets = []

    # Step 1: Find all JS file URLs from the page
    js_urls = []
    try:
        r = req_lib.get(base_url, timeout=10, verify=False)
        if r:
            # Find script src tags
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I)
            for s in scripts:
                url = s if s.startswith('http') else f'{base_url}{s}'
                if url.endswith('.js') or '.js?' in url:
                    js_urls.append(url)

            # Also check for inline scripts
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.S | re.I)
            for idx, block in enumerate(inline_scripts):
                if len(block.strip()) > 50:
                    js_urls.append(f'inline:{idx}')
    except Exception as e:
        log('warn', f'[JS-SECRETS] Error fetching page: {e}')

    # Check manifest.json for additional JS files
    try:
        r_manifest = req_lib.get(f'{base_url}/assets/favicon/manifest.json', timeout=5, verify=False)
        if r_manifest and r_manifest.status_code == 200:
            manifest = r_manifest.json()
            # Not directly useful for JS but confirms app structure
    except Exception:
        pass

    log('info', f'[JS-SECRETS] Found {len(js_urls)} JS sources to scan')

    # Step 2: Scan each JS file for secrets
    for js_url in js_urls:
        if not scan_state.get('scanning'):
            break
        try:
            if js_url.startswith('inline:'):
                # Already have inline content
                idx = int(js_url.split(':')[1])
                content = inline_scripts[idx] if idx < len(inline_scripts) else ''
            else:
                r = req_lib.get(js_url, timeout=10, verify=False)
                content = r.text if r else ''

            if not content:
                continue

            # Skip minified/CDN bundles — they contain variable names matching secret patterns
            # (password=null, token=undefined, etc.) that are all false positives
            content_lower = content.lower()
            _is_minified = (
                len(content) > 50000 and  # Large file
                content.count(';') > 100 and  # Many statements
                content.count('\n') < 50 and  # Very few newlines
                ('function(' in content_lower or 'var ' in content_lower or 'const ' in content_lower)
            )
            _is_cdn = any(cdn in js_url.lower() for cdn in [
                'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
                'ajax.googleapis.com', 'cdn.bootcdn.net', 'code.jquery.com',
                'stackpath.bootstrapcdn.com', 'fonts.googleapis.com',
            ])
            if _is_cdn:
                log('info', f'[JS-SECRETS] Skipping CDN bundle: {js_url}')
                continue

            # Scan for each secret pattern
            for pattern, name, severity in SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    # Filter common false positives in minified JS
                    match_lower = match.lower().strip()
                    _FP_VALUES = [
                        'null', 'undefined', 'false', 'true', 'void 0',
                        'process.env', 'window.', 'document.', 'console.',
                        'module.exports', 'exports.', 'require(',
                        'WEBPACK_CHUNK', 'chunk', 'asset',
                    ]
                    if any(fp in match_lower for fp in _FP_VALUES):
                        continue
                    # Skip matches that are just variable assignments (not actual secrets)
                    if _is_minified and severity in ('medium', 'info'):
                        # In minified code, medium/info severity matches are almost always FPs
                        continue
                    # Deduplicate
                    secret_key = f'{name}:{match[:50]}'
                    if not any(s.get('key') == secret_key for s in found_secrets):
                        # Redact the actual value
                        redacted = match[:8] + '...' + match[-4:] if len(match) > 20 else '***'
                        found_secrets.append({
                            'key': secret_key,
                            'type': name,
                            'severity': severity,
                            'redacted': redacted,
                            'source': js_url,
                        })
                        log('ok', f'[JS-SECRETS] Found {name} in {js_url}')
        except Exception:
            pass

    # Step 3: Report findings
    for secret in found_secrets:
        sev = secret['severity']
        add_finding(sev, f'{secret["type"]} exposed in JavaScript',
            sub=f'{secret["type"]} found in client-side code',
            asset=secret['source'], cvss='9.1' if sev == 'critical' else '7.5',
            exploit='PUBLIC', owasp='A02', mitre='T1592',
            details=f'Type: {secret["type"]}\n'
                    f'Severity: {sev}\n'
                    f'Value (redacted): {secret["redacted"]}\n'
                    f'Source: {secret["source"]}\n'
                    f'Impact: Attacker can use exposed credentials to access services, '
                    f'impersonate users, or access internal infrastructure')

    log('ok', f'[JS-SECRETS] Found {len(found_secrets)} secrets')
    set_progress('js_secrets', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: API SURFACE MAPPER
# ═══════════════════════════════════════════════════════════════════════════════

def run_api_surface_module(target):
    """Discover and map API endpoints, including Swagger/OpenAPI docs."""
    log('info', f'[API-SURFACE] Mapping API surface for {target}')
    base_url = f'https://{target}'
    api_endpoints = []

    # Common API base paths
    api_bases = [
        f'https://api.{target}',
        f'https://{target}/api',
        f'https://{target}',
    ]

    # Swagger/OpenAPI discovery
    swagger_paths = ['/docs', '/docs/', '/swagger', '/swagger/',
                     '/swagger.json', '/swagger-ui', '/swagger-ui/',
                     '/api-docs', '/api-docs/', '/openapi.json',
                     '/openapi.yaml', '/api/swagger.json',
                     '/redoc', '/redoc/',
                     '/.well-known/openapi.json']

    for api_base in api_bases:
        if not scan_state.get('scanning'):
            break
        for path in swagger_paths:
            try:
                url = f'{api_base}{path}'
                r = req_lib.get(url, timeout=8, verify=False, allow_redirects=True)
                if r and r.status_code == 200:
                    content_type = r.headers.get('content-type', '')
                    body = r.text[:5000]

                    # Check if it's a Swagger/OpenAPI spec
                    is_swagger = False
                    if 'swagger' in body.lower() or 'openapi' in body.lower():
                        is_swagger = True
                    if 'swagger-ui' in body.lower():
                        is_swagger = True
                    if '"openapi"' in body or '"swagger"' in body:
                        is_swagger = True

                    if is_swagger:
                        # Try to extract the full spec
                        spec_url = url
                        if path.endswith('.json') or path.endswith('.yaml'):
                            spec_url = url
                        elif 'swagger-ui-init.js' in body:
                            # Extract spec URL from swagger-ui-init.js
                            spec_match = re.search(r'"url"\s*:\s*"([^"]+)"', body)
                            if spec_match:
                                spec_url = spec_match.group(1)

                        # Parse spec
                        try:
                            if 'json' in content_type or path.endswith('.json'):
                                spec = r.json()
                            elif 'swagger-ui-init.js' in body:
                                # Extract JSON from JS
                                json_match = re.search(r'"swaggerDoc"\s*:\s*(\{.+?\})\s*,\s*"onComplete"', body, re.S)
                                if json_match:
                                    spec = json.loads(json_match.group(1))
                                else:
                                    spec = {'raw': body[:2000]}
                            else:
                                spec = {'raw': body[:2000]}

                            # Extract endpoints from spec
                            if isinstance(spec, dict):
                                paths = spec.get('paths', {})
                                for path_key, methods in paths.items():
                                    for method in methods:
                                        if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                                            api_endpoints.append({
                                                'method': method.upper(),
                                                'path': path_key,
                                                'source': 'swagger',
                                                'api_base': api_base,
                                            })

                                # Extract servers
                                servers = spec.get('servers', [])
                                for server in servers:
                                    url_val = server.get('url', '')
                                    desc = server.get('description', '')
                                    add_finding('info', f'API Server discovered: {url_val}',
                                        sub=f'Swagger spec reveals server: {desc}',
                                        asset=url_val, cvss='0.0',
                                        details=f'Server URL: {url_val}\nDescription: {desc}\n'
                                                f'Source: {url}')

                                # Check for exposed schemas
                                schemas = spec.get('components', {}).get('schemas', {})
                                if schemas:
                                    schema_names = list(schemas.keys())
                                    add_finding('medium', f'API schemas exposed ({len(schema_names)} schemas)',
                                        sub=f'Swagger exposes data models: {", ".join(schema_names[:10])}',
                                        asset=url, cvss='5.3',
                                        details=f'Schemas: {json.dumps(schema_names, indent=2)}')

                                # Check for security schemes
                                security = spec.get('components', {}).get('securitySchemes', {})
                                if security:
                                    add_finding('high', 'API authentication scheme exposed',
                                        sub=f'Swagger reveals auth mechanism: {list(security.keys())}',
                                        asset=url, cvss='7.5',
                                        details=f'Security schemes: {json.dumps(security, indent=2)}')

                        except Exception:
                            pass

                        add_finding('high', f'API documentation publicly accessible',
                            sub=f'Swagger/OpenAPI docs exposed at {path}',
                            asset=url, cvss='7.5', exploit='PUBLIC',
                            owasp='A01', mitre='T1592',
                            details=f'URL: {url}\nAPI Base: {api_base}\n'
                                    f'Endpoints found: {len(api_endpoints)}')
                        log('ok', f'[API-SURFACE] Swagger found at {url}')
                        break  # Found swagger for this base, no need to check more paths

            except Exception:
                pass

    # Check for ReDoc documentation
    redoc_paths = ['/redoc', '/redoc/', '/docs', '/docs/', '/api-docs', '/api-docs/']
    for api_base in api_bases:
        for path in redoc_paths:
            if not scan_state.get('scanning'):
                break
            try:
                url = f'{api_base}{path}'
                r = req_lib.get(url, timeout=8, verify=False, allow_redirects=True)
                if r and r.status_code == 200:
                    body = r.text.lower()
                    if 'redoc' in body or 'swagger' in body or 'openapi' in body:
                        add_finding('high', f'API documentation publicly accessible at {path}',
                            sub=f'ReDoc/Swagger documentation exposed',
                            asset=url, cvss='7.5', exploit='PUBLIC',
                            owasp='A01', mitre='T1592',
                            details=f'URL: {url}\nDocumentation type: {"ReDoc" if "redoc" in body else "Swagger/OpenAPI"}')
                        log('ok', f'[API-SURFACE] ReDoc/Swagger found at {url}')
                        break
            except Exception:
                pass

    # Parse CSP headers for internal API endpoints
    try:
        r_home = req_lib.get(base_url, timeout=10, verify=False)
        if r_home:
            csp = r_home.headers.get('content-security-policy', '')
            if csp:
                # Extract domains from CSP that look like API endpoints
                api_domains = re.findall(r'https://([a-z0-9.-]+\.(?:com|io|net|dev))', csp)
                internal_apis = [d for d in api_domains if any(x in d for x in ['api', 'backend', 'ws', 'stream', 'proxy'])]
                if internal_apis:
                    add_finding('medium', f'Internal API endpoints leaked in CSP header',
                        sub=f'CSP reveals {len(internal_apis)} internal endpoints: {", ".join(internal_apis[:5])}',
                        asset=target, cvss='5.3',
                        details=f'Internal endpoints from CSP:\n' + '\n'.join(internal_apis))
                    for domain in internal_apis:
                        api_endpoints.append({'method': 'CSP', 'path': f'https://{domain}', 'source': 'csp-header'})
    except Exception:
        pass

    # Test common API endpoints
    common_endpoints = [
        '/api', '/api/v1', '/api/v2', '/graphql', '/graphiql',
        '/health', '/status', '/info', '/version', '/config',
        '/users', '/user', '/admin', '/profile',
        '/products', '/product', '/orders', '/order',
        '/cart', '/wishlist', '/coupon',
        '/auth', '/login', '/register', '/signup',
        '/upload', '/files', '/assets',
        '/webhook', '/webhooks', '/callback',
    ]

    for api_base in api_bases[:1]:
        for ep in common_endpoints:
            if not scan_state.get('scanning'):
                break
            try:
                r = req_lib.get(f'{api_base}{ep}', timeout=5, verify=False)
                if r and r.status_code not in [404, 0]:
                    api_endpoints.append({
                        'method': 'GET',
                        'path': ep,
                        'status': r.status_code,
                        'source': 'discovery',
                        'api_base': api_base,
                    })
            except Exception:
                pass

    # Report findings
    if api_endpoints:
        add_finding('info', f'API surface mapped: {len(api_endpoints)} endpoints discovered',
            sub=f'Found {len(api_endpoints)} API endpoints across {len(api_bases)} base URLs',
            asset=target, cvss='0.0',
            details='\n'.join([f'{e.get("method", "?")} {e.get("path", "?")} ({e.get("status", "?")}) [{e.get("source", "?")}]'
                               for e in api_endpoints[:50]]))

    log('ok', f'[API-SURFACE] Mapped {len(api_endpoints)} endpoints')
    set_progress('api_surface', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: AUTH FLOW ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

def run_auth_flow_module(target):
    """Analyze authentication flow for security issues."""
    log('info', f'[AUTH-FLOW] Analyzing authentication on {target}')
    base_url = f'https://{target}'
    api_base = f'https://api.{target}'

    # Step 1: Check if JWT is stored in localStorage
    try:
        r = req_lib.get(base_url, timeout=10, verify=False)
        if r:
            js_content = r.text
            # Check localStorage usage
            if 'localStorage' in js_content and ('token' in js_content.lower() or 'jwt' in js_content.lower()):
                add_finding('high', 'JWT stored in localStorage',
                    sub='Authentication tokens stored in localStorage are accessible to XSS attacks',
                    asset=base_url, cvss='7.5', owasp='A07', mitre='T1539',
                    details='Authentication tokens are stored in localStorage instead of HttpOnly cookies.\n'
                            'Any XSS vulnerability can steal the token.\n'
                            'Recommendation: Use HttpOnly, Secure, SameSite cookies.')

            # Check for Firebase Auth
            if 'firebase' in js_content.lower() and 'auth' in js_content.lower():
                add_finding('info', 'Firebase Authentication detected',
                    sub='App uses Firebase Auth for authentication',
                    asset=base_url, cvss='0.0',
                    details='Firebase Authentication is used.\n'
                            'Check: Email enumeration, weak password policy, MFA enabled.')

            # Check for OAuth providers
            oauth_providers = ['google.com', 'facebook.com', 'github.com', 'twitter.com']
            found_providers = [p for p in oauth_providers if p in js_content]
            if found_providers:
                add_finding('info', f'OAuth providers configured: {", ".join(found_providers)}',
                    sub=f'App supports OAuth login via: {", ".join(found_providers)}',
                    asset=base_url, cvss='0.0')
    except Exception:
        pass

    # Step 2: Test auth bypass on protected endpoints
    protected_endpoints = ['/cart', '/wishlist', '/orders', '/profile', '/my-account']
    # Get SPA baseline for comparison
    _auth_baseline_hash = None
    try:
        _r_base = req_lib.get(f'{api_base}/__nonexistent_auth_check_{secrets.token_hex(4)}__.txt', timeout=3, verify=False)
        if _r_base and _r_base.status_code == 200:
            _auth_baseline_hash = hash(_r_base.text)
    except Exception:
        pass
    for ep in protected_endpoints:
        try:
            r = req_lib.get(f'{api_base}{ep}', timeout=5, verify=False)
            if r and r.status_code == 200:
                # Filter SPA catch-all: if response is SPA shell, skip
                _body = r.text
                if _auth_baseline_hash and hash(_body) == _auth_baseline_hash:
                    continue
                # Also check if response matches homepage
                try:
                    _r_home = req_lib.get(api_base, timeout=3, verify=False)
                    if _r_home and hash(_body) == hash(_r_home.text):
                        continue
                except Exception:
                    pass
                # Check for SPA shell markers
                _body_lower = _body.lower()
                _is_spa = sum(1 for m in [
                    '<div id="root">', '<div id="app">', 'noscript',
                    'bundle.js', 'main.js', 'static/js/',
                ] if m in _body_lower) >= 2
                if _is_spa:
                    continue
                add_finding('critical', f'Authentication bypass: {ep}',
                    sub=f'Protected endpoint {ep} accessible without authentication',
                    asset=f'{api_base}{ep}', cvss='9.1', owasp='A07', mitre='T1130',
                    details=f'Endpoint: {ep}\nStatus: {r.status_code}\n'
                            f'Response length: {len(r.text)} bytes\n'
                            f'Response preview: {r.text[:200]}')
                log('ok', f'[AUTH-FLOW] Auth bypass: {ep}')
        except Exception:
            pass

    # Step 3: Test for user enumeration via verbose error messages
    # Capital.com shows different errors for non-existent vs wrong password
    login_endpoints = ['/auth/login', '/session', '/api/auth/login', '/login']
    for ep in login_endpoints:
        try:
            # Test with non-existent user
            r1 = req_lib.post(f'{api_base}{ep}', json={'email': 'nonexistent_test_999@fake.com', 'password': 'wrongpassword'}, timeout=5, verify=False)
            # Test with invalid password
            r2 = req_lib.post(f'{api_base}{ep}', json={'email': 'test@test.com', 'password': 'wrongpassword'}, timeout=5, verify=False)
            if r1 and r2:
                # Check if error messages differ (user enumeration)
                if r1.status_code != r2.status_code or (r1.text.lower() != r2.text.lower() and len(r1.text) > 10):
                    add_finding('medium', f'User enumeration via {ep}',
                        sub='Different error responses for existing vs non-existing users',
                        asset=f'{api_base}{ep}', cvss='5.3', owasp='A07',
                        details=f'Non-existent user response ({r1.status_code}): {r1.text[:300]}\n'
                                f'Wrong password response ({r2.status_code}): {r2.text[:300]}')
                    log('ok', f'[AUTH-FLOW] User enumeration via {ep}')
        except Exception:
            pass

    # Step 4: Check for verbose error messages (info disclosure)
    verbose_errors = [
        '/auth/login', '/session', '/api/auth/login',
        '/api/v1/session', '/api/v2/session',
    ]
    for ep in verbose_errors:
        try:
            r = req_lib.post(f'{api_base}{ep}', json={'email': 'test@test.com', 'password': 'wrong'}, timeout=5, verify=False)
            if r:
                body = r.text.lower()
                # Capital.com reveals specific error codes and field names
                verbose_patterns = [
                    'error.null', 'error.invalid', 'error.missing',
                    'password', 'email', 'account', 'token',
                    'error.too-many', 'error.locked', 'error.disabled',
                ]
                found_verbose = [p for p in verbose_patterns if p in body]
                if len(found_verbose) >= 2:
                    add_finding('medium', f'Verbose error messages at {ep}',
                        sub=f'Login errors reveal field names and validation logic',
                        asset=f'{api_base}{ep}', cvss='5.3',
                        details=f'Verbose patterns found: {found_verbose}\nResponse: {r.text[:500]}')
                    log('ok', f'[AUTH-FLOW] Verbose errors at {ep}')
        except Exception:
            pass

    # Step 5: Check for rate limiting inconsistency (mix of 400/429)
    try:
        rate_codes = []
        import time as _rate_time
        for i in range(4):
            r = req_lib.post(f'{api_base}/auth/login',
                           json={'email': f'test{i}@ratelimit-check.com', 'password': 'wrongpassword123'},
                           timeout=5, verify=False)
            if r:
                rate_codes.append(r.status_code)
            _rate_time.sleep(0.5)  # Brief delay to avoid triggering legitimate rate limiting
        # Only flag if we see BOTH 400 (bad request) AND 429 (rate limited) — means rate limiting is inconsistent
        # Also require at least 2 of each to be confident
        count_400 = rate_codes.count(400)
        count_429 = rate_codes.count(429)
        if count_400 >= 2 and count_429 >= 2:
            add_finding('medium', 'Inconsistent rate limiting',
                sub=f'Login endpoint returns mix of 400 and 429 responses — rate limiting not consistently enforced',
                asset=f'{api_base}/auth/login', cvss='5.3',
                details=f'Response codes: {rate_codes}\n'
                        f'400 count: {count_400}, 429 count: {count_429}\n'
                        f'Mixed 400/429 indicates rate limiting is enabled but inconsistently applied\n'
                        f'Recommendation: Ensure rate limiting triggers BEFORE the 400 threshold')
            log('ok', f'[AUTH-FLOW] Inconsistent rate limiting detected')
    except Exception:
        pass

    log('ok', f'[AUTH-FLOW] Auth analysis complete')
    set_progress('auth_flow', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: DATA EXPOSURE CHECKER
# ═══════════════════════════════════════════════════════════════════════════════

def run_data_exposure_module(target):
    """Check if APIs leak sensitive data (PII, internal IDs, business data)."""
    log('info', f'[DATA-EXPOSURE] Checking data exposure on {target}')
    api_base = f'https://api.{target}'
    base_url = f'https://{target}'

    # Step 0: Parse CSP header for internal domains and endpoints
    try:
        r_home = req_lib.get(base_url, timeout=10, verify=False)
        if r_home:
            csp = r_home.headers.get('content-security-policy', '')
            if csp:
                # Extract all domains from CSP
                all_domains = re.findall(r'https://([a-z0-9.-]+\.[a-z]{2,})', csp)
                # Filter for internal-looking domains
                internal = [d for d in all_domains if any(x in d for x in ['backend', 'internal', 'api', 'ws', 'stream', 'proxy', 'itcapital', 'backend-capital'])]
                if internal:
                    add_finding('medium', f'Internal domains leaked in CSP',
                        sub=f'Content-Security-Policy reveals {len(internal)} internal domains',
                        asset=target, cvss='5.3',
                        details=f'Internal domains from CSP:\n' + '\n'.join(internal))
                    log('ok', f'[DATA-EXPOSURE] CSP leaks internal domains: {internal}')

            # Parse Server header for version info
            server = r_home.headers.get('server', '')
            if server and any(x in server.lower() for x in ['apache', 'nginx', 'iis', 'express']):
                add_finding('info', f'Server version disclosed',
                    sub=f'Server header reveals technology: {server}',
                    asset=target, cvss='0.0',
                    details=f'Server header: {server}')

            # Parse X-Powered-By header
            xpb = r_home.headers.get('x-powered-by', '')
            if xpb:
                add_finding('info', f'X-Powered-By header disclosed',
                    sub=f'X-Powered-By reveals: {xpb}',
                    asset=target, cvss='0.0',
                    details=f'X-Powered-By: {xpb}')

            # Extract version strings from HTML
            body = r_home.text
            version_patterns = [
                r'["\']?version["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']',
                r'["\']?release["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']',
                r'["\']?build["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']',
                r'v(\d+\.\d+\.\d+)',
                r'(\d+\.\d+\.\d+\.\d+)',
            ]
            for pat in version_patterns:
                ver_match = re.search(pat, body)
                if ver_match:
                    ver = ver_match.group(1) if ver_match.lastindex else ver_match.group(0)
                    if len(ver) > 3 and not ver.startswith('0.'):
                        add_finding('info', f'Version string found in HTML',
                            sub=f'Version: {ver}',
                            asset=target, cvss='0.0',
                            details=f'Version string: {ver}\nSource: HTML response')
                        break

    except Exception:
        pass

    # Step 1: Check product listing for over-exposure
    try:
        r = req_lib.get(f'{api_base}/product', timeout=8, verify=False)
        if r and r.status_code == 200:
            data = r.json()
            products = data.get('data', [])
            if products:
                first = products[0] if isinstance(products, list) else {}
                exposed_fields = []
                sensitive_fields = ['sku', 'hsn', 'inventory', 'cost', 'margin',
                                   'internal_id', 'user_id', 'email', 'phone',
                                   'address', 'password', 'token', 'secret']
                for field in sensitive_fields:
                    if field in json.dumps(first).lower():
                        exposed_fields.append(field)

                if exposed_fields:
                    add_finding('medium', f'Product API over-exposes data',
                        sub=f'Sensitive fields in API response: {", ".join(exposed_fields)}',
                        asset=f'{api_base}/product', cvss='5.3',
                        details=f'Exposed fields: {json.dumps(exposed_fields)}\n'
                                f'Consider removing internal business data from public API')

                # Check for internal IDs
                if 'id' in first:
                    add_finding('info', 'Sequential IDs in API response',
                        sub='Products use sequential integer IDs (enumerable)',
                        asset=f'{api_base}/product', cvss='0.0',
                        details=f'Product IDs are sequential integers, enabling enumeration')
    except Exception:
        pass

    # Step 2: Check user review data for PII
    try:
        r = req_lib.get(f'{api_base}/product/1', timeout=8, verify=False)
        if r and r.status_code == 200:
            data = r.json()
            reviews = data.get('data', {}).get('review_details', [])
            if reviews:
                pii_found = []
                for review in reviews[:3]:
                    user = review.get('user_details', {})
                    if user.get('name'):
                        pii_found.append(f'User name: {user["name"]}')
                    if review.get('user_id'):
                        pii_found.append(f'Firebase UID: {review["user_id"]}')

                if pii_found:
                    add_finding('high', 'User PII exposed via product reviews',
                        sub=f'Review API leaks user names and Firebase UIDs',
                        asset=f'{api_base}/product/1', cvss='7.5',
                        details=f'Exposed PII:\n' + '\n'.join(pii_found[:10]))
    except Exception:
        pass

    # Step 3: Check for error message information disclosure
    error_triggers = [
        ('/product/999999', 'GET'),
        ('/product/abc', 'GET'),
        ('/product/-1', 'GET'),
        ("/product/1' OR '1'='1", 'GET'),
        ("/product/1; DROP TABLE products--", 'GET'),
    ]
    for path, method in error_triggers:
        try:
            r = req_lib.get(f'{api_base}{path}', timeout=5, verify=False)
            if r:
                body = r.text.lower()
                # Check for stack traces, DB errors, internal paths
                if any(x in body for x in ['stack trace', 'at line', 'syntax error',
                                            'mysql', 'postgresql', 'sqlite', 'ORA-',
                                            '/home/', '/var/', '/usr/', 'internal server error']):
                    add_finding('medium', 'Information disclosure in error messages',
                        sub=f'Error response reveals internal details',
                        asset=f'{api_base}{path}', cvss='5.3',
                        details=f'URL: {path}\nResponse: {r.text[:500]}')
        except Exception:
            pass

    log('ok', f'[DATA-EXPOSURE] Data exposure check complete')
    set_progress('data_exposure', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5: CLOUD CONFIG CHECKER
# ═══════════════════════════════════════════════════════════════════════════════

def run_cloud_config_module(target):
    """Check for exposed cloud configurations (Firebase, AWS, Azure, GCP)."""
    log('info', f'[CLOUD-CONFIG] Checking cloud configurations on {target}')
    base_url = f'https://{target}'

    # Step 1: Fetch main page and JS for cloud configs
    try:
        r = req_lib.get(base_url, timeout=10, verify=False)
        if not r:
            set_progress('cloud_config', 100)
            return

        content = r.text

        # Find JS files
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.I)
        js_urls = [s if s.startswith('http') else f'{base_url}{s}' for s in scripts if '.js' in s]

        for js_url in js_urls[:5]:
            try:
                r_js = req_lib.get(js_url, timeout=10, verify=False)
                if r_js:
                    content += r_js.text
            except Exception:
                pass

        # Firebase configurations
        firebase_patterns = [
            (r'firebaseConfig\s*[:=]\s*\{([^}]+)\}', 'Firebase Config'),
            (r'apiKey\s*:\s*["\']([^"\']+)["\']', 'Firebase API Key'),
            (r'authDomain\s*:\s*["\']([^"\']+)["\']', 'Firebase Auth Domain'),
            (r'projectId\s*:\s*["\']([^"\']+)["\']', 'Firebase Project ID'),
            (r'storageBucket\s*:\s*["\']([^"\']+)["\']', 'Firebase Storage Bucket'),
            (r'messagingSenderId\s*:\s*["\']([^"\']+)["\']', 'Firebase Messaging Sender ID'),
            (r'appId\s*:\s*["\']([^"\']+)["\']', 'Firebase App ID'),
        ]

        firebase_found = []
        for pattern, name in firebase_patterns:
            matches = re.findall(pattern, content)
            if matches:
                firebase_found.append((name, matches[0] if len(matches) == 1 else matches[:3]))

        if firebase_found:
            details = '\n'.join([f'{k}: {v}' for k, v in firebase_found])
            add_finding('medium', 'Firebase configuration exposed',
                sub=f'Firebase config found in client-side code ({len(firebase_found)} fields)',
                asset=base_url, cvss='5.3', owasp='A05',
                details=f'Firebase Configuration:\n{details}\n\n'
                        f'Risk: Enables Firebase resource enumeration and potential abuse')

        # AWS configs
        aws_patterns = [
            (r'["\']?AWS_ACCESS_KEY_ID["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'AWS Access Key ID'),
            (r'["\']?AWS_SECRET_ACCESS_KEY["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'AWS Secret Key'),
            (r'["\']?AWS_REGION["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'AWS Region'),
            (r'["\']?S3_BUCKET["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'S3 Bucket'),
        ]

        for pattern, name in aws_patterns:
            matches = re.findall(pattern, content, re.I)
            if matches:
                add_finding('high', f'{name} exposed',
                    sub=f'{name} found in client-side code',
                    asset=base_url, cvss='7.5',
                    details=f'Value: {matches[0][:8]}...{matches[0][-4:] if len(matches[0]) > 12 else ""}')

        # Azure configs
        azure_patterns = [
            (r'["\']?AZURE_STORAGE_ACCOUNT["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Azure Storage Account'),
            (r'["\']?AZURE_STORAGE_KEY["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Azure Storage Key'),
        ]

        for pattern, name in azure_patterns:
            matches = re.findall(pattern, content, re.I)
            if matches:
                add_finding('high', f'{name} exposed',
                    sub=f'{name} found in client-side code',
                    asset=base_url, cvss='7.5')

        # GCP configs
        gcp_patterns = [
            (r'["\']?GOOGLE_CLOUD_PROJECT["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'GCP Project'),
            (r'["\']?GCS_BUCKET["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'GCS Bucket'),
        ]

        for pattern, name in gcp_patterns:
            matches = re.findall(pattern, content, re.I)
            if matches:
                add_finding('medium', f'{name} exposed',
                    sub=f'{name} found in client-side code',
                    asset=base_url, cvss='5.3')

        # Pusher configuration
        pusher_patterns = [
            (r'pusher\.key\s*[:=]\s*["\']([a-f0-9]{20})["\']', 'Pusher App Key'),
            (r'pusher\.cluster\s*[:=]\s*["\']([^"\']+)["\']', 'Pusher Cluster'),
            (r'PUSHER_KEY\s*[:=]\s*["\']([a-f0-9]{20})["\']', 'Pusher Key (env)'),
            (r'wss?://[a-z0-9.-]*pusher[a-z0-9.-]*[/\s"\']', 'Pusher WebSocket'),
        ]
        pusher_found = []
        for pattern, name in pusher_patterns:
            matches = re.findall(pattern, content)
            if matches:
                pusher_found.append((name, matches[0] if isinstance(matches[0], str) else matches[0]))

        if pusher_found:
            add_finding('medium', f'Pusher configuration exposed',
                sub=f'Pusher realtime config found in client code',
                asset=base_url, cvss='5.3',
                details=f'Pusher config:\n' + '\n'.join([f'{k}: {v}' for k, v in pusher_found]))

        # Sentry configuration
        sentry_patterns = [
            (r'sentry[_-]?dsn\s*[:=]\s*["\']([^"\']+)["\']', 'Sentry DSN'),
            (r'sentry[_-]?release\s*[:=]\s*["\']([^"\']+)["\']', 'Sentry Release'),
            (r'sentry[_-]?environment\s*[:=]\s*["\']([^"\']+)["\']', 'Sentry Environment'),
            (r'o\d+\.ingest\.sentry\.io', 'Sentry Ingest Endpoint'),
        ]
        sentry_found = []
        for pattern, name in sentry_patterns:
            matches = re.findall(pattern, content)
            if matches:
                sentry_found.append((name, matches[0] if isinstance(matches[0], str) else str(matches[0])))

        if sentry_found:
            add_finding('info', f'Sentry configuration exposed',
                sub=f'Sentry error tracking config found ({len(sentry_found)} fields)',
                asset=base_url, cvss='0.0',
                details=f'Sentry config:\n' + '\n'.join([f'{k}: {v}' for k, v in sentry_found]))

        # CSP header analysis for internal domains
        try:
            r_check = req_lib.get(base_url, timeout=8, verify=False)
            if r_check:
                csp = r_check.headers.get('content-security-policy', '')
                if csp:
                    # Extract all domains from CSP
                    all_domains = re.findall(r'https?://([a-z0-9.-]+\.[a-z]{2,})', csp)
                    internal = [d for d in all_domains if any(x in d for x in ['backend', 'internal', 'ws', 'stream', 'proxy', 'itcapital', 'backend-capital'])]
                    if internal:
                        add_finding('medium', f'Internal domains leaked in CSP header',
                            sub=f'Content-Security-Policy reveals {len(internal)} internal endpoints',
                            asset=target, cvss='5.3',
                            details=f'Internal domains from CSP:\n' + '\n'.join(internal))
        except Exception:
            pass

    except Exception as e:
        log('warn', f'[CLOUD-CONFIG] Error: {e}')

    log('ok', f'[CLOUD-CONFIG] Cloud config check complete')
    set_progress('cloud_config', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 6: PAYMENT KEY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_payment_key_module(target):
    """Detect exposed payment API keys (Stripe, Razorpay, PayPal, etc.)."""
    log('info', f'[PAYMENT-KEY] Scanning for payment keys on {target}')
    base_url = f'https://{target}'

    PAYMENT_PATTERNS = [
        (r'rk_live_[0-9a-zA-Z]{24,}', 'Razorpay Live Key', 'critical'),
        (r'rk_test_[0-9a-zA-Z]{24,}', 'Razorpay Test Key', 'medium'),
        (r'rzp_live_[0-9a-zA-Z]+', 'Razorpay Live Key (rzp_)', 'critical'),
        (r'rzp_test_[0-9a-zA-Z]+', 'Razorpay Test Key (rzp_)', 'medium'),
        (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Secret Key', 'critical'),
        (r'sk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Secret Key', 'medium'),
        (r'pk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Publishable Key', 'low'),
        (r'pk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Publishable Key', 'low'),
        (r'AXr2[Kk]Lh[A-Za-z0-9]{30,}', 'PayPal Live Client ID', 'critical'),
        (r'AXrq[A-Za-z0-9]{30,}', 'PayPal Sandbox Client ID', 'medium'),
        (r' SQUARE_ACCESS_TOKEN[:=]["\']([^"\']+)["\']', 'Square Access Token', 'critical'),
        (r'SQ0[a-z]{30,}', 'Square Application ID', 'medium'),
        (r'client_token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', 'Braintree Client Token', 'medium'),
    ]

    try:
        r = req_lib.get(base_url, timeout=10, verify=False)
        if not r:
            set_progress('payment_key', 100)
            return

        content = r.text

        # Find and scan JS files
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.I)
        js_urls = [s if s.startswith('http') else f'{base_url}{s}' for s in scripts if '.js' in s]

        for js_url in js_urls[:10]:
            if not scan_state.get('scanning'):
                break
            try:
                r_js = req_lib.get(js_url, timeout=10, verify=False)
                if r_js:
                    for pattern, name, severity in PAYMENT_PATTERNS:
                        matches = re.findall(pattern, r_js.text)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            redacted = match[:8] + '...' + match[-4:] if len(match) > 15 else '***'
                            add_finding(severity, f'{name} exposed in client code',
                                sub=f'{name} found in JavaScript bundle',
                                asset=js_url, cvss='9.1' if severity == 'critical' else '5.3',
                                exploit='PUBLIC', owasp='A02', mitre='T1592',
                                details=f'Key type: {name}\nValue (redacted): {redacted}\n'
                                        f'Source: {js_url}\n'
                                        f'Impact: Attacker can make unauthorized payment API calls')
                            log('ok', f'[PAYMENT-KEY] Found {name}')
            except Exception:
                pass

        # Check for Razorpay script specifically
        if 'razorpay' in content.lower() or 'checkout.razorpay.com' in content:
            add_finding('info', 'Razorpay payment integration detected',
                sub='App uses Razorpay for payment processing',
                asset=base_url, cvss='0.0',
                details='Razorpay checkout.js loaded. Verify server-side order verification.')

        # Check for Stripe
        if 'stripe.com' in content.lower():
            add_finding('info', 'Stripe payment integration detected',
                sub='App uses Stripe for payment processing',
                asset=base_url, cvss='0.0',
                details='Stripe.js loaded. Verify server-side payment intent verification.')

    except Exception as e:
        log('warn', f'[PAYMENT-KEY] Error: {e}')

    log('ok', f'[PAYMENT-KEY] Payment key scan complete')
    set_progress('payment_key', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 7: SENSITIVE FILE SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

SENSITIVE_FILES = [
    # Config files
    ('/.env', 200, 'critical', 'Environment file with secrets'),
    ('/.env.local', 200, 'critical', 'Local environment file'),
    ('/.env.production', 200, 'critical', 'Production environment file'),
    ('/.env.development', 200, 'high', 'Development environment file'),
    ('/.env.example', 200, 'medium', 'Environment template file'),
    ('/.env.bak', 200, 'critical', 'Backup environment file'),
    ('/.git/config', 200, 'critical', 'Git configuration'),
    ('/.git/HEAD', 200, 'high', 'Git HEAD reference'),
    ('/.gitignore', 200, 'low', 'Git ignore rules'),
    ('/.svn/entries', 200, 'high', 'SVN entries'),
    ('/.svn/wc.db', 200, 'critical', 'SVN working copy database'),
    ('/.hg/dirstate', 200, 'high', 'Mercurial repository'),
    # Server configs
    ('/.htaccess', 200, 'high', 'Apache configuration'),
    ('/.htpasswd', 200, 'critical', 'Apache password file'),
    ('/web.config', 200, 'high', 'IIS configuration'),
    ('/server-status', 200, 'high', 'Apache server status'),
    ('/server-info', 200, 'high', 'Apache server info'),
    ('/nginx_status', 200, 'medium', 'Nginx status'),
    # Backup files
    ('/backup', 200, 'high', 'Backup directory'),
    ('/backup.sql', 200, 'critical', 'SQL backup file'),
    ('/backup.zip', 200, 'critical', 'ZIP backup file'),
    ('/backup.tar.gz', 200, 'critical', 'TAR backup file'),
    ('/db.sql', 200, 'critical', 'Database dump'),
    ('/database.sql', 200, 'critical', 'Database dump'),
    ('/dump.sql', 200, 'critical', 'Database dump'),
    ('/site.tar.gz', 200, 'critical', 'Site backup'),
    ('/www.zip', 200, 'critical', 'Website backup'),
    ('/website.zip', 200, 'critical', 'Website backup'),
    # Debug/Info
    ('/phpinfo.php', 200, 'high', 'PHP info page'),
    ('/info.php', 200, 'high', 'PHP info page'),
    ('/test.php', 200, 'medium', 'Test page'),
    ('/debug', 200, 'high', 'Debug endpoint'),
    ('/debug/vars', 200, 'critical', 'Debug variables'),
    ('/trace.axd', 200, 'high', 'ASP.NET trace'),
    ('/elmah.axd', 200, 'critical', 'ASP.NET error log'),
    # Admin panels
    ('/admin', 200, 'medium', 'Admin panel'),
    ('/admin/', 200, 'medium', 'Admin panel'),
    ('/administrator', 200, 'medium', 'Admin panel'),
    ('/wp-admin', 200, 'medium', 'WordPress admin'),
    ('/wp-login.php', 200, 'medium', 'WordPress login'),
    ('/phpmyadmin', 200, 'high', 'phpMyAdmin'),
    ('/pma', 200, 'high', 'phpMyAdmin'),
    ('/adminer', 200, 'high', 'Adminer DB tool'),
    # API docs
    ('/docs', 200, 'high', 'API documentation'),
    ('/docs/', 200, 'high', 'API documentation'),
    ('/swagger', 200, 'high', 'Swagger docs'),
    ('/swagger.json', 200, 'critical', 'Swagger specification'),
    ('/api-docs', 200, 'high', 'API documentation'),
    ('/openapi.json', 200, 'critical', 'OpenAPI specification'),
    ('/graphql', 200, 'high', 'GraphQL endpoint'),
    ('/redoc', 200, 'high', 'ReDoc documentation'),
    # Sensitive paths
    ('/.well-known/security.txt', 200, 'info', 'Security contact'),
    ('/security.txt', 200, 'info', 'Security contact'),
    ('/crossdomain.xml', 200, 'medium', 'Cross-domain policy'),
    ('/clientaccesspolicy.xml', 200, 'medium', 'Client access policy'),
    ('/robots.txt', 200, 'info', 'Robots configuration'),
    ('/sitemap.xml', 200, 'info', 'Sitemap'),
    # PGP / Security keys
    ('/pgp-key.txt', 200, 'medium', 'PGP public key'),
    ('/.well-known/pgp-key.txt', 200, 'medium', 'PGP public key'),
    # Common secrets
    ('/config.json', 200, 'critical', 'Configuration file'),
    ('/config.js', 200, 'critical', 'Configuration file'),
    ('/config.php', 200, 'critical', 'Configuration file'),
    ('/settings.json', 200, 'critical', 'Settings file'),
    ('/credentials.json', 200, 'critical', 'Credentials file'),
    ('/service-account.json', 200, 'critical', 'Service account key'),
    ('/firebase-config.json', 200, 'high', 'Firebase config'),
    # Version control
    ('/package.json', 200, 'medium', 'Node.js package manifest'),
    ('/package-lock.json', 200, 'low', 'Node.js lock file'),
    ('/yarn.lock', 200, 'low', 'Yarn lock file'),
    ('/composer.json', 200, 'medium', 'PHP package manifest'),
    ('/Gemfile', 200, 'medium', 'Ruby package manifest'),
]


def run_sensitive_file_module(target):
    """Scan for sensitive files and directories exposed on the server.
    
    Confirmation strategy:
    1. Get baseline response (random non-existent URL) to detect SPA catch-all
    2. Compare each response against baseline (size, hash, content-type)
    3. Verify content matches expected file type
    4. For JSON/XML files, verify valid structure
    5. Only report files that differ from baseline AND match expected content
    """
    log('info', f'[SENSITIVE-FILES] Scanning {target} for exposed files')
    base_url = f'https://{target}'
    found_files = []

    with LOCK:
        scan_state.setdefault('sensitive_files', [])

    # Step 1: Get SPA baseline — request MULTIPLE random non-existent URLs
    # A true SPA catch-all returns the same HTML for ANY route
    baseline_hash = None
    baseline_size = None
    baseline_content_type = None
    baseline_hashes = set()
    try:
        fake_urls = [
            f'{base_url}/__nonexistent_file_12345__.txt',
            f'{base_url}/__random_probe_xyz_999__.html',
            f'{base_url}/__fake_test_abc_777__.json',
        ]
        for fake_url in fake_urls:
            try:
                r_fake = req_lib.get(fake_url, timeout=5, verify=False)
                if r_fake and r_fake.status_code == 200:
                    baseline_hashes.add(hash(r_fake.text))
                    if baseline_hash is None:
                        baseline_hash = hash(r_fake.text)
                        baseline_size = len(r_fake.content)
                        baseline_content_type = r_fake.headers.get('content-type', '')
            except Exception:
                pass
        if baseline_hash:
            log('info', f'[SENSITIVE-FILES] SPA baseline: size={baseline_size}, type={baseline_content_type}, unique_hashes={len(baseline_hashes)}')
    except Exception:
        pass

    # Step 2: Also get homepage for SPA fingerprint
    homepage_hash = None
    try:
        r_home = req_lib.get(base_url, timeout=5, verify=False)
        if r_home:
            homepage_hash = hash(r_home.text)
    except Exception:
        pass

    # Step 3: Test each sensitive file
    for filepath, expected_status, severity, description in SENSITIVE_FILES:
        if not scan_state.get('scanning'):
            break
        try:
            url = f'{base_url}{filepath}'
            r = req_lib.get(url, timeout=5, verify=False, allow_redirects=False)
            if not r or r.status_code != expected_status:
                continue

            content_type = r.headers.get('content-type', '')
            body = r.text
            resp_size = len(r.content)
            resp_hash = hash(body)

            # === CONFIRMATION CHECK 1: Is it SPA catch-all? ===
            # If response matches ANY baseline (random non-existent URL), it's SPA catch-all
            if baseline_hashes and resp_hash in baseline_hashes:
                continue
            # If response matches the baseline hash, it's SPA catch-all
            if baseline_hash and resp_hash == baseline_hash:
                continue
            # If response matches homepage, it's SPA catch-all
            if homepage_hash and resp_hash == homepage_hash:
                continue

            # === CONFIRMATION CHECK 1b: SPA catch-all via content similarity ===
            # SPA returns same HTML structure with minor differences (title, meta)
            # Check if response body stripped of <title> and <meta> matches baseline
            if baseline_hash and baseline_size:
                import re as _re_sp
                # Strip title and meta tags for comparison
                stripped_body = _re_sp.sub(r'<title>.*?</title>', '', body, flags=_re_sp.I | _re_sp.S)
                stripped_body = _re_sp.sub(r'<meta[^>]*>', '', stripped_body, flags=_re_sp.I)
                stripped_baseline = _re_sp.sub(r'<title>.*?</title>', '', body, flags=_re_sp.I | _re_sp.S)
                # Also try fetching baseline content for comparison
                try:
                    r_baseline2 = req_lib.get(f'{base_url}/__spa_check_{secrets.token_hex(4)}__.html', timeout=3, verify=False)
                    if r_baseline2 and r_baseline2.status_code == 200:
                        stripped_baseline2 = _re_sp.sub(r'<title>.*?</title>', '', r_baseline2.text, flags=_re_sp.I | _re_sp.S)
                        stripped_baseline2 = _re_sp.sub(r'<meta[^>]*>', '', stripped_baseline2, flags=_re_sp.I)
                        if stripped_body.strip() == stripped_baseline2.strip() and len(stripped_body.strip()) > 100:
                            continue
                except Exception:
                    pass

            # === CONFIRMATION CHECK 2: Size-based detection ===
            # SPA typically returns same size for all routes
            if baseline_size and resp_size == baseline_size and resp_size < 5000:
                # Same size as baseline — likely SPA shell, skip unless content is different
                if body.strip() == '' or body.strip() == '<!DOCTYPE html>':
                    continue

            # === CONFIRMATION CHECK 3: Content-type validation ===
            # File extension should match content-type
            EXT_CONTENT_MAP = {
                '.json': 'application/json',
                '.js': 'javascript',
                '.xml': 'xml',
                '.sql': 'sql',
                '.txt': 'text/plain',
                '.php': 'text/html',
                '.env': 'text/plain',
            }
            for ext, expected_ct in EXT_CONTENT_MAP.items():
                if filepath.endswith(ext) and expected_ct not in content_type:
                    # Content-type doesn't match expected — likely SPA catch-all returning HTML
                    if 'text/html' in content_type and ext != '.php':
                        log('info', f'[SENSITIVE-FILES] Skipping {filepath} — content-type mismatch ({content_type} for {ext})')
                        continue

            # === CONFIRMATION CHECK 4: Known SPA markers ===
            SPA_MARKERS = [
                '<div id="root">',
                '<div id="app">',
                '<div id="app-root">',
                'You need to enable JavaScript',
                'noscript',
                'bundle.js',
                'main.js',
                'static/js/',
            ]
            is_spa_shell = sum(1 for marker in SPA_MARKERS if marker in body) >= 2

            # For HTML responses, verify it's NOT just the SPA shell
            if 'text/html' in content_type and is_spa_shell:
                # Check if it's a REAL page with unique content
                UNIQUE_CONTENT = [
                    'phpinfo', 'swagger', 'phpmyadmin', 'adminer',
                    '<title>error', '<title>403', '<title>404',
                    'forbidden', 'not found', 'directory listing',
                    'index of', 'parent directory', '<form',
                    'login', 'password', 'database', 'mysql',
                ]
                has_unique = any(x in body.lower() for x in UNIQUE_CONTENT)
                if not has_unique:
                    continue

            # === CONFIRMATION CHECK 5: For JSON files, verify valid JSON ===
            if filepath.endswith('.json'):
                try:
                    json.loads(body)
                except json.JSONDecodeError:
                    # Not valid JSON — likely SPA HTML
                    if 'text/html' in content_type or '<!doctype' in body.lower():
                        continue

            # === CONFIRMATION CHECK 6: For .env files, verify key=value format ===
            if filepath.endswith('.env') or filepath.endswith('.env.local'):
                env_lines = [l.strip() for l in body.splitlines() if l.strip() and not l.startswith('#')]
                has_env_format = any('=' in l and not l.startswith('<') for l in env_lines[:10])
                if not has_env_format:
                    continue

            # === CONFIRMATION CHECK 7: For .git files, verify git format ===
            if '/.git/' in filepath:
                if filepath.endswith('/HEAD') and not body.strip().startswith('ref:'):
                    continue
                if filepath.endswith('/config') and '[core]' not in body:
                    continue

            # === CONFIRMATION CHECK 8: For XML files, verify XML structure ===
            if filepath.endswith('.xml') or filepath.endswith('.xml.gz'):
                if not body.strip().startswith('<?xml') and not body.strip().startswith('<'):
                    continue

            # === CONFIRMATION CHECK 9: Response must be different from other confirmed files ===
            # (prevent duplicate reports for SPA catching multiple routes)
            file_content_hash = hash(body[:500])  # Hash first 500 chars
            if any(f.get('content_hash') == file_content_hash for f in found_files):
                continue

            # === ALL CHECKS PASSED — File is genuinely exposed ===
            found_files.append({
                'path': filepath,
                'status': r.status_code,
                'severity': severity,
                'description': description,
                'size': resp_size,
                'content_type': content_type,
                'content_hash': file_content_hash,
            })

            add_finding(severity, f'Sensitive file exposed: {filepath}',
                sub=f'{description} accessible at {filepath}',
                asset=url, cvss='9.1' if severity == 'critical' else '7.5',
                exploit='PUBLIC', owasp='A01', mitre='T1592',
                details=f'URL: {url}\nHTTP Status: {r.status_code}\n'
                        f'Content-Type: {content_type}\nSize: {resp_size} bytes\n'
                        f'Description: {description}\n'
                        f'Confirmation: Response differs from SPA baseline, '
                        f'content-type matches expected type, content structure verified')
            log('ok', f'[SENSITIVE-FILES] CONFIRMED: {filepath} ({r.status_code}, {resp_size}b, {content_type})')
        except Exception:
            pass

    log('ok', f'[SENSITIVE-FILES] Confirmed {len(found_files)} sensitive files (from {len(SENSITIVE_FILES)} tested)')
    set_progress('sensitive_files', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 8: BUSINESS LOGIC TESTER
# ═══════════════════════════════════════════════════════════════════════════════

def run_bizlogic_audit_module(target):
    """Test for business logic vulnerabilities (IDOR, price manipulation, coupon abuse)."""
    log('info', f'[BIZLOGIC] Testing business logic on {target}')
    api_base = f'https://api.{target}'

    # Step 1: Test IDOR on product endpoints
    try:
        # Test sequential product IDs
        product_ids = list(range(1, 15))
        accessible = []
        for pid in product_ids:
            if not scan_state.get('scanning'):
                break
            try:
                r = req_lib.get(f'{api_base}/product/{pid}', timeout=5, verify=False)
                if r and r.status_code == 200:
                    data = r.json()
                    if data.get('data'):
                        accessible.append(pid)
            except Exception:
                pass

        if len(accessible) > 5:
            add_finding('medium', 'Product IDOR - Sequential IDs enumerable',
                sub=f'{len(accessible)} products accessible via sequential IDs',
                asset=f'{api_base}/product/*', cvss='5.3',
                details=f'Accessible IDs: {accessible}\n'
                        f'Attack: Attacker can enumerate all products by iterating IDs')
    except Exception:
        pass

    # Step 2: Test price manipulation in cart
    try:
        # Try to add product with manipulated price
        cart_payloads = [
            {'productId': 1, 'quantity': 1, 'price': 1},
            {'productId': 1, 'quantity': 1, 'salePrice': 0},
            {'productId': 1, 'quantity': -1},
            {'productId': 1, 'quantity': 999999},
            {'productId': 1, 'quantity': 0},
            {'productId': 1, 'quantity': 1, 'discount': 100},
        ]
        for payload in cart_payloads:
            try:
                r = req_lib.post(f'{api_base}/cart', json=payload, timeout=5, verify=False)
                if r and r.status_code in [200, 201]:
                    body = r.text.lower()
                    if 'price' in body or 'total' in body:
                        add_finding('high', 'Price manipulation possible',
                            sub=f'Cart accepts manipulated price data',
                            asset=f'{api_base}/cart', cvss='8.1',
                            details=f'Payload: {json.dumps(payload)}\n'
                                    f'Response: {r.text[:500]}')
                        log('ok', f'[BIZLOGIC] Price manipulation: {payload}')
                        break
            except Exception:
                pass
    except Exception:
        pass

    # Step 3: Test coupon abuse
    try:
        coupon_payloads = [
            {'couponCode': 'ADMIN', 'cartTotal': 599},
            {'couponCode': 'TEST', 'cartTotal': 599},
            {'couponCode': 'FREE', 'cartTotal': 599},
            {'couponCode': 'DISCOUNT100', 'cartTotal': 599},
            {'couponCode': 'WELCOME', 'cartTotal': 599},
            {'couponCode': 'SAVE100', 'cartTotal': 599},
            {'couponCode': '../../etc/passwd', 'cartTotal': 599},
            {"couponCode": "' OR '1'='1", 'cartTotal': 599},
        ]
        for payload in coupon_payloads:
            try:
                r = req_lib.post(f'{api_base}/coupon/apply', json=payload, timeout=5, verify=False)
                if r and r.status_code == 200:
                    body = r.text.lower()
                    if 'discount' in body or 'applied' in body or 'success' in body:
                        add_finding('high', 'Coupon code brute-force possible',
                            sub=f'Coupon "{payload["couponCode"]}" accepted',
                            asset=f'{api_base}/coupon/apply', cvss='7.5',
                            details=f'Accepted coupon: {payload["couponCode"]}\n'
                                    f'Response: {r.text[:500]}')
                        log('ok', f'[BIZLOGIC] Coupon accepted: {payload["couponCode"]}')
            except Exception:
                pass
    except Exception:
        pass

    # Step 4: Test for mass assignment
    try:
        mass_payload = {
            'productId': 1,
            'quantity': 1,
            'isAdmin': True,
            'role': 'admin',
            'discount': 100,
            'price': 0,
            'userId': 'admin',
        }
        r = req_lib.post(f'{api_base}/cart', json=mass_payload, timeout=5, verify=False)
        if r and r.status_code in [200, 201]:
            body = r.text.lower()
            if any(x in body for x in ['admin', 'role', 'discount', 'price']):
                add_finding('high', 'Mass assignment vulnerability',
                    sub='API accepts unexpected fields (isAdmin, role, price)',
                    asset=f'{api_base}/cart', cvss='8.1',
                    details=f'Payload: {json.dumps(mass_payload)}\n'
                            f'Response: {r.text[:500]}')
    except Exception:
        pass

    # Step 5: Test for integer overflow/underflow on quantity
    try:
        overflow_payloads = [
            {'productId': 1, 'quantity': 2147483647},  # Max 32-bit int
            {'productId': 1, 'quantity': -1},
            {'productId': 1, 'quantity': 0},
        ]
        for payload in overflow_payloads:
            try:
                r = req_lib.post(f'{api_base}/cart', json=payload, timeout=5, verify=False)
                if r and r.status_code in [200, 201]:
                    add_finding('medium', 'Quantity validation missing',
                        sub=f'API accepts quantity: {payload["quantity"]}',
                        asset=f'{api_base}/cart', cvss='5.3',
                        details=f'Payload: {json.dumps(payload)}\n'
                                f'Response: {r.text[:300]}')
                    break
            except Exception:
                pass
    except Exception:
        pass

    log('ok', f'[BIZLOGIC] Business logic test complete')
    set_progress('bizlogic', 100)
