"""API security, GraphQL, and WebSocket vulnerability modules."""
import re
import json
import os
import time
import socket
import secrets
import struct
import base64
import hashlib
import hmac
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE, BS4_AVAILABLE, BeautifulSoup
from core.logger import log

def run_api_security_module(target):
    log('info', f'[APISEC] Testing API security on {target}')
    api_data = {
        'endpoints_found': [], 'graphql': {}, 'swagger': {},
        'auth_bypass': [], 'rate_limiting': {}, 'cors_misconfig': [],
        'method_override': [], 'content_type': [], 'summary': {},
    }
    if not REQUESTS_AVAILABLE:
        with LOCK:
            scan_state['api_security_data'] = api_data
        set_progress('apisec', 100)
        return

    base_url = f'https://{target}'
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    # ── Discover API endpoints ──
    api_paths = [
        '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2',
        '/rest', '/graphql', '/graphiql', '/api/graphql',
        '/swagger', '/swagger.json', '/swagger/v1/swagger.json',
        '/api-docs', '/api/docs', '/openapi.json', '/openapi.yaml',
        '/api/swagger.json', '/api/openapi.json',
        '/.well-known/openapi.json', '/.well-known/openid-configuration',
        '/wp-json', '/wp-json/wp/v2', '/api/wordpress',
        '/api/users', '/api/user', '/api/me', '/api/profile',
        '/api/admin', '/api/config', '/api/settings', '/api/health',
        '/api/status', '/api/version', '/api/info', '/api/metrics',
        '/api/auth', '/api/login', '/api/token', '/api/oauth',
        '/api/register', '/api/signup', '/api/forgot-password',
    ]
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ENHANCE: Add discovered API endpoints from Phase 1 crawl
    # ═══════════════════════════════════════════════════════════════════════════
    with LOCK:
        discovery = dict(scan_state.get('discovery_data', {}))
    discovered_api = discovery.get('api_endpoints', [])
    if discovered_api:
        # Add discovered API paths to test list
        for ep in discovered_api:
            if isinstance(ep, str):
                path = urlparse(ep).path if ep.startswith('http') else ep
                if path and path not in api_paths:
                    api_paths.append(path)
            elif isinstance(ep, dict):
                path = ep.get('path', ep.get('url', ''))
                if path:
                    path = urlparse(path).path if path.startswith('http') else path
                    if path and path not in api_paths:
                        api_paths.append(path)
        log('info', f'[APISEC] Added {len(discovered_api)} discovered API endpoints from Phase 1')

    # Fetch homepage once for redirect-destination comparison in this module
    _apisec_homepage_body = ''
    _apisec_homepage_size = 0
    try:
        _hp2 = req_lib.get(base_url, timeout=6, verify=False, allow_redirects=True,
                           headers={'User-Agent': ua})
        _apisec_homepage_body = _hp2.text.lower()
        _apisec_homepage_size = len(_hp2.text)
    except Exception:
        pass

    def _apisec_is_redirect_fp(resp):
        """Return True if the response is just the homepage served after a redirect."""
        from urllib.parse import urlparse as _up3
        # Final URL landed on root/home path
        final_path = _up3(resp.url).path if hasattr(resp, 'url') else ''
        if final_path in ('/', '', '/index', '/index.html', '/index.php', '/home'):
            return True
        # Body nearly identical to homepage
        if _apisec_homepage_body and resp.text:
            t1 = set(_apisec_homepage_body[:4000].split())
            t2 = set(resp.text.lower()[:4000].split())
            sim = len(t1 & t2) / max(len(t1 | t2), 1)
            if sim > 0.80:
                return True
        # Size ratio ±5% of homepage
        if _apisec_homepage_size > 0 and abs(len(resp.text) - _apisec_homepage_size) / _apisec_homepage_size < 0.05:
            return True
        return False

    for path in api_paths:
        if not scan_state.get('scanning'):
            break
        try:
            # Check raw redirect first (allow_redirects=False)
            r_raw = req_lib.get(f'{base_url}{path}', timeout=5, verify=False, allow_redirects=False,
                                headers={'User-Agent': ua, 'Accept': 'application/json'})
            # If it redirects anywhere → not a real API endpoint, skip
            if r_raw.status_code in (301, 302, 303, 307, 308):
                log('debug', f'[APISEC] {path} redirects ({r_raw.status_code}) — skipping as FP')
                continue

            r = req_lib.get(f'{base_url}{path}', timeout=5, verify=False, allow_redirects=True,
                            headers={'User-Agent': ua, 'Accept': 'application/json'})

            if r.status_code not in (404, 405, 500, 502, 503):
                # Redirect FP check: if the followed response is just the homepage, skip
                if _apisec_is_redirect_fp(r):
                    log('debug', f'[APISEC] {path} resolved to homepage — skipping FP')
                    continue

                endpoint_info = {
                    'path': path, 'status': r.status_code,
                    'content_type': r.headers.get('content-type', ''),
                    'size': len(r.content),
                }
                try:
                    r.json()
                    endpoint_info['is_json'] = True
                except Exception:
                    endpoint_info['is_json'] = False

                api_data['endpoints_found'].append(endpoint_info)

                # Check for Swagger/OpenAPI — must return actual spec JSON, not HTML
                if any(k in path.lower() for k in ['swagger', 'openapi', 'api-docs', 'api/docs']):
                    try:
                        spec = r.json()
                        # Must have real spec structure — not just any JSON
                        has_spec = ('paths' in spec and len(spec.get('paths', {})) > 0) or \
                                   ('swagger' in spec and spec.get('swagger')) or \
                                   ('openapi' in spec and spec.get('openapi'))
                        if has_spec:
                            api_data['swagger'] = {
                                'path': path, 'version': spec.get('swagger', spec.get('openapi', 'unknown')),
                                'title': spec.get('info', {}).get('title', 'Unknown'),
                                'paths_count': len(spec.get('paths', {})),
                            }
                            paths_list = list(spec.get('paths', {}).keys())[:20]
                            for p in paths_list:
                                api_data['endpoints_found'].append({'path': p, 'source': 'swagger', 'status': 'discovered'})
                            add_finding('medium', f'API Specification Exposed: {path}',
                                sub='Swagger/OpenAPI spec publicly accessible', asset=f'{base_url}{path}',
                                cvss='5.3', owasp='A01', mitre='T1592', confidence='high',
                                details=f'Confirmed: API specification returned real spec data\nPath: {path}\nVersion: {spec.get("swagger", spec.get("openapi", "?"))}\nTitle: {spec.get("info", {}).get("title", "?")}\nEndpoints: {len(spec.get("paths", {}))}\nStatus: {r.status_code}\n\nRemediation: Restrict access to API documentation in production.')
                            log('warn', f'[APISEC] Swagger/OpenAPI exposed at {path}')
                    except Exception:
                        pass

                log('ok', f'[APISEC] Endpoint: {path} ({r.status_code})')
        except Exception:
            pass

    # ── GraphQL deep testing ──
    graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/query', '/gql']
    for gql_path in graphql_paths:
        if not scan_state.get('scanning'):
            break
        try:
            # Introspection
            introspection_q = '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind fields{name type{name kind}}}}}}"}'
            r = req_lib.post(f'{base_url}{gql_path}', timeout=8, verify=False,
                             headers={'User-Agent': ua, 'Content-Type': 'application/json'},
                             data=introspection_q)
            if r.status_code == 200:
                try:
                    schema = r.json()
                    # FP guard: servers that DISABLE introspection still return a 200 with
                    # an error body containing "__schema". We require ACTUAL introspection
                    # data (types with kind fields) — not just the word "__schema" in an error.
                    gql_data = schema.get('data', {})
                    gql_schema = gql_data.get('__schema', {}) if isinstance(gql_data, dict) else {}
                    types = gql_schema.get('types', []) if isinstance(gql_schema, dict) else []
                    custom_types = [t for t in types
                                    if isinstance(t, dict) and not t.get('name', '').startswith('__')]
                    has_real_introspection = len(custom_types) > 0
                    if has_real_introspection and not api_data['graphql']:
                        api_data['graphql'] = {
                            'endpoint': gql_path,
                            'introspection': True,
                            'types_count': len(custom_types),
                            'type_names': [t['name'] for t in custom_types[:20]],
                        }
                        add_finding('medium', f'GraphQL Introspection Enabled: {gql_path}',
                            sub='Full schema introspection accessible', asset=f'{base_url}{gql_path}',
                            cvss='5.3', owasp='A01', mitre='T1592',
                            details=f'GraphQL introspection enabled at {gql_path}\n'
                                    f'Types found: {len(custom_types)}\n'
                                    f'Type names: {", ".join(t["name"] for t in custom_types[:15])}\n\n'
                                    f'Confirmed: introspection — {len(custom_types)} custom types returned\n\n'
                                    f'Remediation: Disable introspection in production. Use persisted queries.')
                        log('warn', f'[APISEC] GraphQL introspection at {gql_path}')
                        break  # Only report once — first endpoint that has real introspection

                        # Test for batch query abuse
                        batch_q = '{"query":"{__typename}"}' * 10
                        r_batch = req_lib.post(f'{base_url}{gql_path}', timeout=8, verify=False,
                                               headers={'User-Agent': ua, 'Content-Type': 'application/json'},
                                               data=batch_q)
                        if r_batch.status_code == 200:
                            api_data['graphql']['batch_allowed'] = True
                            log('warn', '[APISEC] GraphQL batch queries allowed')

                except Exception:
                    pass
        except Exception:
            pass

    # ── Authentication bypass testing ──
    auth_endpoints = ['/api/users', '/api/admin', '/api/me', '/api/profile', '/api/config']
    for ep in auth_endpoints:
        if not scan_state.get('scanning'):
            break
        try:
            # No auth
            r_none = req_lib.get(f'{base_url}{ep}', timeout=5, verify=False,
                                 headers={'User-Agent': ua, 'Accept': 'application/json'})

            if r_none.status_code == 200:
                body = r_none.text.lower()
                # FP guard: require HIGH-SIGNAL indicators only. Generic key names like
                # "id", "user", "config", "email" appear in almost every JSON response
                # (even error bodies). Require at least one of:
                #   a) An actual email address pattern (@)
                #   b) A password/secret/token/key VALUE (not just the key name in a schema)
                #   c) A cloud credential pattern
                #   d) A database connection string
                _high_signal = [
                    '@',                          # actual email address
                    '"password":', '"passwd":',   # password value exposed
                    '"secret":', '"api_key":',
                    '"access_token":', '"auth_token":',
                    '"private_key":', '"aws_access',
                    'akia[',                       # AWS key prefix
                    'database_url', 'mongodb://', 'postgresql://', 'mysql://',
                ]
                # Also require actual JSON data (not empty, not an error stub)
                is_meaningful = (len(r_none.text) > 200
                                 and r_none.text.strip() not in ['[]', '{}', 'null', '""']
                                 and not any(err in body for err in ['unauthorized', 'forbidden', 'not found', 'error']))
                has_high_signal = any(sig in body for sig in _high_signal)
                if has_high_signal and is_meaningful:
                    found_signals = [s for s in _high_signal if s in body]
                    api_data['auth_bypass'].append({'endpoint': ep, 'method': 'no-auth', 'status': r_none.status_code})
                    add_finding('high', f'API Auth Bypass: {ep}',
                        sub='Endpoint returns sensitive data without authentication',
                        asset=f'{base_url}{ep}', cvss='7.5', owasp='A01', mitre='T1190',
                        details=f'API endpoint returns sensitive data without authentication.\n'
                                f'Endpoint: {ep}\nStatus: {r_none.status_code}\n'
                                f'Response size: {len(r_none.text)} bytes\n'
                                f'High-signal indicators: {found_signals}\n\n'
                                f'Confirmed: Sensitive data exposed without auth\n\n'
                                f'Remediation: Implement authentication on all API endpoints.')
                    log('err', f'[APISEC] Auth bypass: {ep} returns high-signal sensitive data without auth')
                else:
                    log('info', f'[APISEC] {ep} accessible (status {r_none.status_code}) but no high-signal sensitive data — FP suppressed')

        except Exception:
            pass

    # ── HTTP method testing ──
    test_methods_ep = '/api/users'
    for method in ['OPTIONS', 'TRACE', 'PATCH', 'DELETE', 'PUT']:
        try:
            r = req_lib.request(method, f'{base_url}{test_methods_ep}', timeout=5, verify=False,
                                headers={'User-Agent': ua})
            if r.status_code not in (404, 405, 501):
                # For DELETE, verify it actually modifies data (not just returns 200 with error)
                if method == 'DELETE':
                    body = r.text.lower()
                    # Check if response indicates actual deletion or just method acceptance
                    deletion_indicators = ['deleted', 'removed', 'destroyed', 'purged']
                    error_indicators = ['error', 'not allowed', 'forbidden', 'unauthorized', 'method not']
                    has_deletion = any(ind in body for ind in deletion_indicators)
                    has_error = any(ind in body for ind in error_indicators)
                    if has_deletion and not has_error:
                        api_data['method_override'].append({'method': method, 'status': r.status_code})
                        add_finding('medium', f'HTTP {method} Allowed: {test_methods_ep}',
                            sub=f'{method} method actually deletes data',
                            asset=f'{base_url}{test_methods_ep}', cvss='5.0', owasp='A05',
                            details=f'HTTP {method} method is allowed and appears to delete data.\nStatus: {r.status_code}\nResponse: {r.text[:200]}\n\nRemediation: Disable unnecessary HTTP methods.')
                        log('warn', f'[APISEC] {method} actually deletes data at {test_methods_ep}')
                    else:
                        log('info', f'[APISEC] {method} accepted but no actual deletion (status {r.status_code})')
                else:
                    api_data['method_override'].append({'method': method, 'status': r.status_code})
                    if method == 'TRACE':
                        add_finding('medium', f'HTTP {method} Allowed: {test_methods_ep}',
                            sub=f'{method} method accepted', asset=f'{base_url}{test_methods_ep}',
                            cvss='5.0', owasp='A05',
                            details=f'HTTP {method} method is allowed.\nStatus: {r.status_code}\n\nRemediation: Disable unnecessary HTTP methods.')
                        log('warn', f'[APISEC] {method} allowed at {test_methods_ep}')
        except Exception:
            pass

    # ── Content-Type confusion ──
    try:
        r_xml = req_lib.post(f'{base_url}/api', timeout=5, verify=False,
                             headers={'User-Agent': ua, 'Content-Type': 'application/xml'},
                             data='<?xml version="1.0"?><root><test>1</test></root>')
        if r_xml.status_code not in (404, 405, 415):
            api_data['content_type'].append({'type': 'xml', 'status': r_xml.status_code})
            log('warn', f'[APISEC] XML content type accepted (status {r_xml.status_code})')
    except Exception:
        pass

    # ── Rate limiting test ──
    rate_results = {'total': 0, 'blocked': 0}
    try:
        for _ in range(20):
            r = req_lib.get(f'{base_url}/api', timeout=3, verify=False, headers={'User-Agent': ua})
            rate_results['total'] += 1
            if r.status_code in (429, 503):
                rate_results['blocked'] += 1
        rate_results['block_rate'] = round((rate_results['blocked'] / max(rate_results['total'], 1)) * 100, 1)
        api_data['rate_limiting'] = rate_results
        if rate_results['block_rate'] == 0:
            log('info', '[APISEC] No rate limiting headers on API endpoints (informational)')
    except Exception:
        pass

    api_data['summary'] = {
        'endpoints_count': len(api_data['endpoints_found']),
        'has_swagger': bool(api_data['swagger']),
        'has_graphql': bool(api_data['graphql']),
        'auth_bypasses': len(api_data['auth_bypass']),
        'methods_allowed': len(api_data['method_override']),
    }
    log('ok', f'[APISEC] Found {len(api_data["endpoints_found"])} endpoints, {len(api_data["auth_bypass"])} auth bypasses')
    with LOCK:
        scan_state['api_security_data'] = api_data
    set_progress('apisec', 100)


# ─── ENHANCED SECRETS SCANNING MODULE ─────────────────────────────────────────


def run_api_abuse_module(target):
    """Test for API abuse: BOLA, mass assignment, excessive data exposure."""
    log('info', '[API-ABUSE] Testing API abuse patterns')
    base_url = f'https://{target}'
    api_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        api_endpoints = disc.get('api_endpoints', [])
        urls = disc.get('urls', [])

    # Common API endpoints
    api_paths = ['/api/v1/users', '/api/v1/user', '/api/users', '/api/user',
                 '/api/v1/admin', '/api/admin', '/api/v1/settings',
                 '/api/v1/profile', '/api/profile', '/api/v1/orders',
                 '/api/orders', '/api/v1/products', '/api/products',
                 '/api/v1/accounts', '/api/v1/customers']

    # Test BOLA (Broken Object Level Authorization)
    # FP guard: first establish that the base collection endpoint requires authentication
    # (returns 401/403). Only then test object-level access with different IDs.
    # Without a baseline auth requirement, any public API returning user data would fire.
    for path in api_paths:
        if not scan_state.get('scanning'):
            break
        try:
            # Step 1: Establish baseline — does the collection endpoint require auth?
            r_base = req_lib.get(f'{base_url}{path}', timeout=5, verify=False)
            if r_base.status_code not in (401, 403):
                # Endpoint is publicly accessible — BOLA requires an auth-protected endpoint
                log('info', f'[API-ABUSE] {path} baseline={r_base.status_code} — not auth-protected, skipping BOLA')
                continue
            # Step 2: Test object-level access — can we access a specific ID that should be blocked?
            for test_id in ['1', '2', '100', 'admin']:
                r = req_lib.get(f'{base_url}{path}/{test_id}', timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 50:
                    try:
                        data = r.json()
                        data_str = str(data).lower()
                        # Require actual sensitive personal data, not just common key names
                        sensitive_fields = ['email', 'phone', 'address', 'ssn', 'credit', 'password', 'secret']
                        has_pii = any(k in data_str for k in sensitive_fields)
                        # Also require the response contains '@' (email) or actual data values
                        has_real_values = '@' in data_str or (isinstance(data, dict) and len(data) > 2)
                        if isinstance(data, dict) and has_pii and has_real_values:
                            add_finding(
                                'high',
                                f'BOLA via {path}/{test_id}',
                                sub=f'Auth-protected collection allows unauthenticated object access',
                                asset=f'{base_url}{path}/{test_id}', cvss='8.0', owasp='A01', mitre='T1213',
                                details=f'Endpoint: {path}/{test_id}\n'
                                        f'Baseline {path}: {r_base.status_code} (auth required)\n'
                                        f'Object access: {r.status_code} (data returned)\n'
                                        f'Sensitive fields: {[k for k in sensitive_fields if k in data_str]}\n'
                                        f'Response: {data_str[:300]}\n'
                                        f'Confirmed: Bypassed — user data returned without auth')
                            api_findings.append({'endpoint': f'{path}/{test_id}', 'type': 'BOLA'})
                            log('ok', f'[API-ABUSE] BOLA confirmed at {path}/{test_id}')
                            break
                    except Exception:
                        pass
        except Exception:
            pass

    # Test excessive data exposure
    # FP guard: only flag if the field name appears with a likely non-null value.
    # Field names like "token" or "key" commonly appear in JSON as empty/null (e.g. {"token": null}).
    # Also require the response to be meaningful (not a schema/error stub).
    _exposure_patterns = [
        (r'"password"\s*:\s*"[^"]{4,}"', 'password'),
        (r'"passwd"\s*:\s*"[^"]{4,}"', 'password'),
        (r'"secret"\s*:\s*"[^"]{8,}"', 'secret'),
        (r'"api_key"\s*:\s*"[^"]{8,}"', 'api_key'),
        (r'"private_key"\s*:\s*"[^"]{8,}"', 'private_key'),
        (r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}"', 'ssn'),
        (r'"credit_card"\s*:\s*"\d{13,19}"', 'credit_card'),
        (r'AKIA[0-9A-Z]{16}', 'aws_key'),
        (r'"access_token"\s*:\s*"[^"]{10,}"', 'access_token'),
    ]
    for path in api_paths[:5]:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(f'{base_url}{path}', timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 100:
                try:
                    r.json()  # must be valid JSON
                    found_fields = []
                    for pattern, label in _exposure_patterns:
                        if re.search(pattern, r.text):
                            found_fields.append(label)
                    if found_fields:
                        add_finding(
                            'high',
                            f'Excessive data exposure at {path}',
                            sub=f'API returns sensitive field values: {", ".join(found_fields)}',
                            asset=f'{base_url}{path}', cvss='7.5', owasp='A01', mitre='T1213',
                            details=f'Sensitive field values detected: {", ".join(found_fields)}\n'
                                    f'Endpoint: {path}\n'
                                    f'Confirmed: Actual sensitive data values in API response')
                        api_findings.append({'endpoint': path, 'type': 'excessive_data'})
                        log('ok', f'[API-ABUSE] Excessive data confirmed at {path}: {found_fields}')
                except Exception:
                    pass
        except Exception:
            pass

    log('ok', f'[API-ABUSE] Scan complete - {len(api_findings)} findings')
    set_progress('api_abuse', 100)


# ─── SUBDOMAIN TAKEOVER VERIFY ────────────────────────────────────────────────


def run_graphql_test_module(target):
    """Test for GraphQL security vulnerabilities."""
    log('info', f'[GRAPHQL] Testing GraphQL security on {target}')
    base_url = f'https://{target}'
    graphql_findings = []

    # Check if GraphQL endpoint exists
    graphql_endpoints = ['/graphql', '/graphiql', '/v1/graphql', '/v2/graphql',
                         '/api/graphql', '/query', '/gql']

    introspection_query = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

    for endpoint in graphql_endpoints:
        if not scan_state.get('scanning'):
            break
        try:
            # Test GET with introspection
            r = req_lib.get(f'{base_url}{endpoint}',
                          params={'query': '{ __schema { types { name } } }'},
                          timeout=8, verify=False)

            if r.status_code == 200 and ('schema' in r.text.lower() or 'types' in r.text.lower()):
                add_finding(
                    'medium',
                    f'GraphQL introspection enabled at {endpoint}',
                    sub='Full schema disclosure via introspection query',
                    asset=f'{base_url}{endpoint}', cvss='5.3', owasp='A03', mitre='T1592',
                    details=f'Endpoint: {endpoint}\n'
                            f'Introspection query returned schema\n'
                            f'Response length: {len(r.text)} chars\n'
                            f'Confirmed: Schema fully accessible')
                graphql_findings.append({'endpoint': endpoint, 'type': 'introspection'})
                log('ok', f'[GRAPHQL] Introspection enabled at {endpoint}')

            # Test POST with introspection
            r2 = req_lib.post(f'{base_url}{endpoint}',
                            json={'query': '{ __schema { types { name fields { name } } } }'},
                            timeout=8, verify=False)
            if r2.status_code == 200 and ('schema' in r2.text.lower() or 'types' in r2.text.lower()):
                if not any(f.get('endpoint') == endpoint for f in graphql_findings):
                    add_finding(
                        'medium',
                        f'GraphQL introspection enabled at {endpoint} (POST)',
                        sub='Full schema disclosure via POST introspection query',
                        asset=f'{base_url}{endpoint}', cvss='5.3', owasp='A03', mitre='T1592',
                        details=f'Endpoint: {endpoint}\nMethod: POST\n'
                                f'Introspection query returned schema\n'
                                f'Confirmed: Schema fully accessible')
                    graphql_findings.append({'endpoint': endpoint, 'type': 'introspection_post'})
                    log('ok', f'[GRAPHQL] Introspection enabled at {endpoint} (POST)')

            # Test for batch query abuse
            batch_payload = [
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
            ]
            r3 = req_lib.post(f'{base_url}{endpoint}',
                            json=batch_payload,
                            timeout=8, verify=False)
            if r3.status_code == 200:
                try:
                    batch_resp = r3.json()
                    if isinstance(batch_resp, list) and len(batch_resp) == 3:
                        add_finding(
                            'medium',
                            f'GraphQL batch query enabled at {endpoint}',
                            sub='Server accepts batched queries — potential for abuse',
                            asset=f'{base_url}{endpoint}', cvss='5.3', owasp='A04', mitre='T1499',
                            details=f'Endpoint: {endpoint}\n'
                                    f'Batch queries accepted: 3 queries in single request\n'
                                    f'Confirmed: Batch queries processed')
                        graphql_findings.append({'endpoint': endpoint, 'type': 'batch'})
                        log('ok', f'[GRAPHQL] Batch queries enabled at {endpoint}')
                except Exception:
                    pass

        except Exception:
            pass

    log('ok', f'[GRAPHQL] Scan complete — {len(graphql_findings)} GraphQL findings')
    set_progress('graphql', 100)




def run_graphql_module(target):
    """Production-grade GraphQL attack surface analysis with full schema parsing.

    Phases:
    1. Endpoint discovery + liveness check
    2. Full schema introspection → parse types, fields, args, return types
    3. Schema-aware mutation testing (correct args, no guesswork)
    4. Authorization bypass testing (query sensitive fields without auth)
    5. Information disclosure via error messages
    6. Rate-limit bypass (alias batching, batch queries)
    7. Resource exhaustion (deep nesting, circular fragments)
    """
    log('info', f'[GRAPHQL-ADV] Starting production GraphQL analysis on {target}')
    base_url = f'https://{target}'
    findings_count = 0

    graphql_endpoints = ['/graphql', '/api/graphql', '/gql', '/query',
                         '/v1/graphql', '/v2/graphql', '/graphiql',
                         '/graphql/console', '/altair', '/playground']

    # ─── Phase 1: Endpoint discovery ───────────────────────────────────────
    live_endpoints = []
    for endpoint in graphql_endpoints:
        if not scan_state.get('scanning'):
            break
        url = f'{base_url}{endpoint}'
        alive = False
        try:
            r = req_lib.post(url, json={'query': '{__typename}'}, timeout=5, verify=False)
            if r.status_code == 200:
                alive = True
        except Exception:
            try:
                r = req_lib.get(url, params={'query': '{__typename}'}, timeout=5, verify=False)
                alive = r.status_code == 200
            except Exception:
                pass
        if alive:
            live_endpoints.append(endpoint)
            log('ok', f'[GRAPHQL-ADV] Live endpoint: {endpoint}')

    if not live_endpoints:
        log('info', '[GRAPHQL-ADV] No live GraphQL endpoints found')
        set_progress('graphql', 100)
        return

    for endpoint in live_endpoints:
        if not scan_state.get('scanning'):
            break
        url = f'{base_url}{endpoint}'

        # ─── Phase 2: Full schema introspection ────────────────────────────
        schema = {}
        query_type_name = 'Query'
        mutation_type_name = 'Mutation'
        all_types = {}
        query_fields = []
        mutation_fields = []

        introspection_full = '''
        {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name
              kind
              fields {
                name
                args {
                  name
                  type { name kind ofType { name kind } }
                  defaultValue
                }
                type { name kind ofType { name kind ofType { name kind } } }
                isDeprecated
                deprecationReason
              }
              inputFields {
                name
                type { name kind ofType { name kind } }
              }
            }
          }
        }
        '''

        try:
            r = req_lib.post(url, json={'query': introspection_full}, timeout=15, verify=False)
            if r.status_code == 200 and '__schema' in r.text:
                schema = r.json().get('data', {}).get('__schema', {})

                # Report introspection finding
                add_finding(
                    'medium',
                    f'GraphQL introspection enabled at {endpoint}',
                    sub='Full schema disclosure — all types, fields, and arguments exposed',
                    asset=url, cvss='5.3', owasp='A05', mitre='T1190',
                    details=f'Endpoint: {endpoint}\n'
                            f'Full introspection query returned complete schema\n'
                            f'Impact: Attacker can enumerate entire API surface, '
                            f'find hidden fields, mutations, and argument structures',
                    confidence='high')
                findings_count += 1
                log('ok', f'[GRAPHQL-ADV] Full introspection at {endpoint}')

                # Parse schema
                query_type_name = (schema.get('queryType') or {}).get('name', 'Query')
                mutation_type_name = (schema.get('mutationType') or {}).get('name', 'Mutation')

                for t in schema.get('types', []):
                    tname = t.get('name', '')
                    if tname.startswith('__'):
                        continue
                    all_types[tname] = t
                    if tname == query_type_name:
                        query_fields = t.get('fields', [])
                    if tname == mutation_type_name:
                        mutation_fields = t.get('fields', [])

                log('ok', f'[GRAPHQL-ADV] Parsed schema: {len(all_types)} types, '
                          f'{len(query_fields)} query fields, {len(mutation_fields)} mutations')
        except Exception:
            pass

        # ─── Phase 3: Schema-aware mutation testing ────────────────────────
        if mutation_fields:
            for mf in mutation_fields[:10]:
                if not scan_state.get('scanning'):
                    break
                mut_name = mf.get('name', '')
                if not mut_name:
                    continue

                # Build proper argument list from schema
                args = mf.get('args', [])
                input_type = mf.get('type', {})

                # Build mutation with dummy values matching arg types
                arg_parts = []
                for arg in args:
                    aname = arg.get('name', '')
                    atype = arg.get('type', {})
                    # Resolve non-null wrapper
                    inner = atype.get('ofType') or atype
                    type_name = inner.get('name', 'String')
                    kind = inner.get('kind', 'SCALAR')

                    if kind == 'NON_NULL':
                        inner2 = inner.get('ofType') or inner
                        type_name = inner2.get('name', 'String')
                        kind = inner2.get('kind', 'SCALAR')

                    if kind == 'ENUM':
                        arg_parts.append(f'{aname}: "test"')
                    elif type_name in ('Int', 'Float'):
                        arg_parts.append(f'{aname}: 1')
                    elif type_name == 'Boolean':
                        arg_parts.append(f'{aname}: true')
                    elif kind == 'INPUT_OBJECT':
                        # Build input object with dummy fields
                        input_t = all_types.get(type_name, {})
                        input_fields = input_t.get('inputFields', [])
                        if input_fields:
                            inner_parts = []
                            for inf in input_fields:
                                iname = inf.get('name', '')
                                itype = inf.get('type', {})
                                inner2 = itype.get('ofType') or itype
                                iname_type = inner2.get('name', 'String')
                                if iname_type in ('Int', 'Float'):
                                    inner_parts.append(f'{iname}: 1')
                                elif iname_type == 'Boolean':
                                    inner_parts.append(f'{iname}: true')
                                else:
                                    inner_parts.append(f'{iname}: "test"')
                            arg_parts.append(f'{aname}: {{' + ', '.join(inner_parts) + '}')
                        else:
                            arg_parts.append(f'{aname}: {{}}')
                    elif kind == 'LIST':
                        arg_parts.append(f'{aname}: ["test"]')
                    else:
                        arg_parts.append(f'{aname}: "test"')

                args_str = ', '.join(arg_parts)
                # Build field selection from return type
                return_fields = 'id'
                ret_of = input_type.get('ofType') or input_type
                ret_kind = ret_of.get('kind', '')
                if ret_kind == 'OBJECT':
                    ret_name = ret_of.get('name', '')
                    ret_type = all_types.get(ret_name, {})
                    ret_fields_list = ret_type.get('fields', [])
                    if ret_fields_list:
                        return_fields = ' '.join(f2.get('name', '') for f2 in ret_fields_list[:5])
                    else:
                        return_fields = 'id name'
                elif ret_kind == 'LIST':
                    ret_of2 = ret_of.get('ofType') or ret_of
                    ret_name2 = ret_of2.get('name', '')
                    ret_type2 = all_types.get(ret_name2, {})
                    ret_fields_list2 = ret_type2.get('fields', [])
                    if ret_fields_list2:
                        return_fields = ' '.join(f2.get('name', '') for f2 in ret_fields_list2[:5])

                mutation_query = f'mutation {{ {mut_name}({args_str}) {{ {return_fields} }} }}'

                try:
                    r = req_lib.post(url, json={'query': mutation_query}, timeout=8, verify=False)
                    resp_text = r.text.lower()
                    # If no auth error and no missing-argument error → mutation accessible
                    is_auth_error = any(e in resp_text for e in ['unauthorized', 'forbidden', 'authentication', 'not authenticated', 'permission denied'])
                    is_arg_error = 'required' in resp_text and 'not provided' in resp_text
                    has_data = '"data"' in resp_text and 'null' not in resp_text.split('"data"')[1][:20]

                    if r.status_code == 200 and not is_auth_error and not is_arg_error:
                        severity = 'critical' if any(w in mut_name.lower() for w in ['delete', 'remove', 'update', 'create', 'modify', 'change', 'reset', 'transfer']) else 'high'
                        add_finding(
                            severity,
                            f'GraphQL mutation {mut_name}() accessible without auth at {endpoint}',
                            sub=f'Schema-disclosed mutation with correct arguments accepted without authentication',
                            asset=url, cvss='8.1' if severity == 'critical' else '7.5', owasp='A01', mitre='T1190',
                            details=f'Endpoint: {endpoint}\n'
                                    f'Mutation: {mut_name}\n'
                                    f'Arguments: {args_str}\n'
                                    f'Response: {r.status_code}\n'
                                    f'Full query: {mutation_query}\n'
                                    f'Impact: Unauthorized data modification/deletion',
                            confidence='high')
                        findings_count += 1
                        log('ok', f'[GRAPHQL-ADV] Unauth mutation {mut_name}() at {endpoint}')
                except Exception:
                    pass

        # ─── Phase 3b: Common mutation names fallback ──
        if not mutation_fields:
            common_mutations = [
                ('createUser', '{input: {name: "test", email: "test@test.com"}}', 'id name'),
                ('register', '{input: {email: "test@test.com", password: "test123"}}', 'id email'),
                ('login', '{input: {email: "test@test.com", password: "test123"}}', 'token'),
                ('deleteUser', '{id: 1}', 'id'),
                ('updateUser', '{id: 1, input: {name: "test"}}', 'id name'),
                ('createPost', '{input: {title: "test", body: "test"}}', 'id title'),
                ('postComment', '{input: {postId: 1, body: "test"}}', 'id body'),
                ('sendMessage', '{input: {to: "test@test.com", body: "test"}}', 'id'),
                ('resetPassword', '{email: "test@test.com"}', 'success'),
                ('transferMoney', '{from: "acc1", to: "acc2", amount: 1}', 'id'),
            ]
            for mut_name, mut_args, ret_fields in common_mutations:
                if not scan_state.get('scanning'):
                    break
                try:
                    q = f'mutation {{ {mut_name}({mut_args}) {{ {ret_fields} }} }}'
                    r = req_lib.post(url, json={'query': q}, timeout=6, verify=False)
                    resp_text = r.text.lower()
                    is_auth_err = any(e in resp_text for e in ['unauthorized', 'forbidden', 'not authenticated'])
                    if r.status_code == 200 and not is_auth_err and '"data"' in r.text:
                        add_finding(
                            'high',
                            f'GraphQL mutation {mut_name}() accessible at {endpoint}',
                            sub=f'Common mutation name accepted without authentication',
                            asset=url, cvss='7.5', owasp='A01', mitre='T1190',
                            details=f'Endpoint: {endpoint}\nMutation: {mut_name}\n'
                                    f'Query: {q}\nResponse: {r.status_code}',
                            confidence='medium')
                        findings_count += 1
                        log('ok', f'[GRAPHQL-ADV] Mutation {mut_name}() at {endpoint}')
                except Exception:
                    pass

        # ─── Phase 4: Authorization bypass — query sensitive fields ─────────
        if query_fields:
            SENSITIVE_KEYWORDS = ['user', 'admin', 'account', 'profile', 'member', 'staff',
                                  'employee', 'customer', 'patient', 'student']
            SENSITIVE_FIELD_PATTERNS = ['email', 'phone', 'password', 'token', 'secret',
                                        'ssn', 'credit', 'address', 'salary', 'balance',
                                        'apikey', 'api_key', 'access_token', 'refresh_token',
                                        'private', 'internal', 'admin', 'role', 'permission']

            for qf in query_fields:
                qfname = (qf.get('name') or '').lower()
                if not any(sk in qfname for sk in SENSITIVE_KEYWORDS):
                    continue

                # This field looks like it accesses user/admin data
                # Build query with common argument patterns
                qf_args = qf.get('args', [])
                ret_type = qf.get('type', {})
                ret_of = ret_type.get('ofType') or ret_type
                ret_kind = ret_of.get('kind', '')
                ret_name = ret_of.get('name', '')

                # Get fields of return type
                ret_fields_list = []
                if ret_kind == 'OBJECT':
                    ret_t = all_types.get(ret_name, {})
                    ret_fields_list = ret_t.get('fields', [])
                elif ret_kind == 'LIST':
                    ret_of2 = ret_of.get('ofType') or ret_of
                    ret_name2 = ret_of2.get('name', '')
                    ret_t2 = all_types.get(ret_name2, {})
                    ret_fields_list = ret_t2.get('fields', [])

                # Select sensitive fields from return type
                sensitive_return_fields = []
                for rf in ret_fields_list:
                    rfname = (rf.get('name') or '').lower()
                    if any(p in rfname for p in SENSITIVE_FIELD_PATTERNS):
                        sensitive_return_fields.append(rf.get('name', ''))

                if not sensitive_return_fields:
                    # Just query id and first few fields
                    sensitive_return_fields = [rf.get('name', '') for rf in ret_fields_list[:3]]

                if not sensitive_return_fields:
                    continue

                fields_str = ' '.join(sensitive_return_fields)

                # Build query with common arg patterns (no auth)
                arg_parts = []
                for qa in qf_args:
                    qaname = qa.get('name', '')
                    qatype = qa.get('type', {})
                    qainner = qatype.get('ofType') or qatype
                    qatypename = qainner.get('name', 'String')
                    qakind = qainner.get('kind', 'SCALAR')
                    if qakind == 'NON_NULL':
                        qainner2 = qainner.get('ofType') or qainner
                        qatypename = qainner2.get('name', 'String')
                    if qatypename in ('Int', 'Float'):
                        arg_parts.append(f'{qaname}: 1')
                    elif qatypename == 'ID':
                        arg_parts.append(f'{qaname}: "1"')
                    else:
                        arg_parts.append(f'{qaname}: "1"')

                args_str = ', '.join(arg_parts)
                query_str = f'{{ {qf.get("name", "")}({args_str}) {{ {fields_str} }} }}'

                try:
                    r = req_lib.post(url, json={'query': query_str}, timeout=8, verify=False)
                    resp_text = r.text.lower()
                    is_auth_err = any(e in resp_text for e in ['unauthorized', 'forbidden', 'not authenticated', 'permission denied'])
                    has_data = '"data"' in r.text

                    if r.status_code == 200 and has_data and not is_auth_err:
                        # Check if we got actual data (not null)
                        resp_json = r.json() if r.text.strip().startswith('{') else {}
                        data = resp_json.get('data', {})
                        field_data = data.get(qf.get('name', ''), None)
                        if field_data is not None:
                            add_finding(
                                'critical',
                                f'GraphQL authorization bypass: {qf.get("name", "")}() exposes sensitive data at {endpoint}',
                                sub=f'Query returns {", ".join(sensitive_return_fields)} without authentication',
                                asset=url, cvss='9.1', owasp='A01', mitre='T1190',
                                details=f'Endpoint: {endpoint}\n'
                                        f'Query: {qf.get("name", "")}\n'
                                        f'Fields accessed: {fields_str}\n'
                                        f'Response: {r.status_code}\n'
                                        f'Impact: Unauthorized access to PII/credentials',
                                confidence='high')
                            findings_count += 1
                            log('ok', f'[GRAPHQL-ADV] Auth bypass: {qf.get("name", "")}() at {endpoint}')
                except Exception:
                    pass

        # ─── Phase 5: Error-based information disclosure ───────────────────
        error_disclosure_tests = [
            ('{ users { id nonExistentField } }', 'Field suggestion in error'),
            ('{ __type(name: "User") { name fields { name } } }', '__type introspection'),
            ('{ __type(name: "Query") { name fields { name args { name } } } }', 'Query field args disclosure'),
        ]
        for test_query, test_name in error_disclosure_tests:
            try:
                r = req_lib.post(url, json={'query': test_query}, timeout=6, verify=False)
                resp_text = r.text.lower()
                if 'did you mean' in resp_text or 'suggest' in resp_text:
                    add_finding(
                        'medium',
                        f'GraphQL error disclosure: {test_name} at {endpoint}',
                        sub='Error message reveals schema information',
                        asset=url, cvss='5.3', owasp='A05', mitre='T1190',
                        details=f'Endpoint: {endpoint}\nTest: {test_name}\n'
                                f'Error reveals field/type names',
                        confidence='high')
                    findings_count += 1
            except Exception:
                pass

        # ─── Phase 6: Rate-limit bypass via alias batching ─────────────────
        try:
            alias_parts = ','.join([f'a{i}:__typename' for i in range(100)])
            batch_query = f'{{{alias_parts}}}'
            r = req_lib.post(url, json={'query': batch_query}, timeout=10, verify=False)
            if r.status_code == 200:
                try:
                    resp = r.json()
                    data = resp.get('data', {})
                    if len(data) >= 90:
                        add_finding(
                            'medium',
                            f'GraphQL alias batching enabled at {endpoint}',
                            sub='100 aliased queries processed — rate-limit bypass possible',
                            asset=url, cvss='5.3', owasp='A04', mitre='T1499',
                            details=f'Endpoint: {endpoint}\nTest: 100 aliased __typename queries\n'
                                    f'All aliases processed in single request\n'
                                    f'Impact: Bypass rate limiting, brute-force, DoS',
                            confidence='high')
                        findings_count += 1
                        log('ok', f'[GRAPHQL-ADV] Alias batching at {endpoint}')
                except Exception:
                    pass
        except Exception:
            pass

        # ─── Phase 6b: Batch query abuse ──────────────────────────────────
        try:
            batch = [
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
            ]
            r = req_lib.post(url, json=batch, timeout=8, verify=False)
            if r.status_code == 200:
                try:
                    batch_resp = r.json()
                    if isinstance(batch_resp, list) and len(batch_resp) == 3:
                        add_finding(
                            'medium',
                            f'GraphQL batch queries enabled at {endpoint}',
                            sub='Server accepts array of queries — potential for abuse',
                            asset=url, cvss='5.3', owasp='A04', mitre='T1499',
                            details=f'Endpoint: {endpoint}\n'
                                    f'3 queries in array accepted\n'
                                    f'Impact: Amplification attacks, rate-limit bypass',
                            confidence='high')
                        findings_count += 1
                except Exception:
                    pass
        except Exception:
            pass

        # ─── Phase 7: Deep nesting DoS ────────────────────────────────────
        try:
            nested = '{' + 'a{' * 20 + '__typename' + '}' * 20 + '}'
            import time as _time
            t0 = _time.time()
            r = req_lib.post(url, json={'query': nested}, timeout=20, verify=False)
            elapsed = _time.time() - t0
            if elapsed > 3.0 and r.status_code == 200:
                add_finding(
                    'medium' if elapsed < 10 else 'high',
                    f'GraphQL deep nesting DoS at {endpoint}',
                    sub=f'20-level nested query took {elapsed:.1f}s — {"resource exhaustion" if elapsed < 10 else "confirmed DoS"}',
                    asset=url, cvss='5.3' if elapsed < 10 else '7.5', owasp='A04', mitre='T1499',
                    details=f'Endpoint: {endpoint}\nTest: 20-level nested query\n'
                            f'Response time: {elapsed:.1f}s\n'
                            f'Impact: CPU exhaustion, denial of service',
                    confidence='high')
                findings_count += 1
                log('ok', f'[GRAPHQL-ADV] Deep nesting DoS at {endpoint} ({elapsed:.1f}s)')
        except Exception:
            pass

        # ─── Phase 8: Circular fragment DoS ────────────────────────────────
        try:
            # Attempt to create infinite fragment spread
            circular_q = 'query A { ...A } fragment A on Query { __typename }'
            t0 = _time.time()
            r = req_lib.post(url, json={'query': circular_q}, timeout=10, verify=False)
            elapsed = _time.time() - t0
            if elapsed > 2.0:
                add_finding(
                    'medium',
                    f'GraphQL circular fragment DoS at {endpoint}',
                    sub=f'Circular fragment caused {elapsed:.1f}s delay',
                    asset=url, cvss='5.3', owasp='A04', mitre='T1499',
                    details=f'Endpoint: {endpoint}\n'
                            f'Test: Circular fragment spread\n'
                            f'Response time: {elapsed:.1f}s',
                    confidence='medium')
                findings_count += 1
        except Exception:
            pass

    log('ok', f'[GRAPHQL-ADV] Scan complete — {findings_count} findings')
    set_progress('graphql', 100)


# ─── XXE INJECTION MODULE ──────────────────────────────────────────────────────


def run_graphql_deep_module(target):
    """Pure-Python GraphQL security testing with introspection, batch, IDOR, injection."""
    log('info', f'[GRAPHQL-DEEP] GraphQL security testing on {target}')
    base_url = f'https://{target}'
    results = {'endpoints': [], 'issues': []}

    if not REQUESTS_AVAILABLE:
        with LOCK:
            scan_state['graphql_data'] = results
        set_progress('graphql_deep', 100)
        return

    gql_paths = ['/graphql', '/api/graphql', '/graphql/v1', '/graphiql',
                 '/playground', '/api', '/gql', '/query', '/v1/graphql']

    # ── Phase 1: Endpoint discovery ──
    live_endpoints = []
    for path in gql_paths:
        if not scan_state.get('scanning'):
            break
        url = f'{base_url}{path}'
        try:
            r = req_lib.post(url, json={'query': '{__typename}'}, timeout=10, verify=False,
                             headers={'Content-Type': 'application/json',
                                      'User-Agent': 'Mozilla/5.0'})
            body = r.text
            if r.status_code == 200 and ('data' in body or 'errors' in body):
                live_endpoints.append(url)
                results['endpoints'].append(url)
                log('ok', f'[GRAPHQL-DEEP] Live endpoint: {path}')
        except Exception:
            pass

    if not live_endpoints:
        log('info', '[GRAPHQL-DEEP] No live GraphQL endpoints found')
        with LOCK:
            scan_state['graphql_data'] = results
        set_progress('graphql_deep', 100)
        return

    for ep_url in live_endpoints[:3]:
        if not scan_state.get('scanning'):
            break

        # ── Phase 2: Introspection ──
        try:
            intro_q = {'query': '{ __schema { types { name fields { name } } } }'}
            r_intro = req_lib.post(ep_url, json=intro_q, timeout=10, verify=False,
                                   headers={'Content-Type': 'application/json',
                                            'User-Agent': 'Mozilla/5.0'})
            if r_intro.status_code == 200 and '__schema' in r_intro.text:
                results['issues'].append({'type': 'introspection', 'url': ep_url})
                add_finding('medium', 'GraphQL Introspection Enabled',
                            sub='Full schema exposed via introspection query',
                            asset=ep_url, cvss='5.3', owasp='A05', mitre='T1190',
                            details=f'Endpoint: {ep_url}\nQuery: {intro_q["query"]}\n'
                                    f'Schema exposed: Yes\nRemediation: Disable introspection in production',
                            confidence='high')
                log('ok', f'[GRAPHQL-DEEP] Introspection enabled at {ep_url}')
        except Exception as e:
            log('warn', f'[GRAPHQL-DEEP] Introspection test failed: {e}')

        # ── Phase 3: Batch query DoS ──
        try:
            batch_q = [{'query': '{__typename}'}] * 50
            r_batch = req_lib.post(ep_url, json=batch_q, timeout=10, verify=False,
                                   headers={'Content-Type': 'application/json',
                                            'User-Agent': 'Mozilla/5.0'})
            if r_batch.status_code == 200 and '__typename' in r_batch.text:
                results['issues'].append({'type': 'batch_dos', 'url': ep_url})
                add_finding('high', 'GraphQL Batching Attack (DoS Vector)',
                            sub='Server processes large batched query arrays without rate limiting',
                            asset=ep_url, cvss='7.5', owasp='A04', mitre='T1499',
                            details=f'Endpoint: {ep_url}\nBatch size: 50\nAll queries processed\n'
                                    f'Remediation: Limit batch query size or disable batching',
                            confidence='high')
                log('ok', f'[GRAPHQL-DEEP] Batch DoS confirmed at {ep_url}')
        except Exception as e:
            log('warn', f'[GRAPHQL-DEEP] Batch test failed: {e}')

        # ── Phase 4: Field suggestion info disclosure ──
        try:
            r_typo = req_lib.post(ep_url, json={'query': '{ usr { id } }'}, timeout=10,
                                  verify=False,
                                  headers={'Content-Type': 'application/json',
                                           'User-Agent': 'Mozilla/5.0'})
            if 'Did you mean' in r_typo.text or 'did_you_mean' in r_typo.text.lower():
                results['issues'].append({'type': 'field_suggestion', 'url': ep_url})
                add_finding('low', 'GraphQL Field Suggestion Info Disclosure',
                            sub='Server reveals field names via error suggestions',
                            asset=ep_url, cvss='3.5', owasp='A05', mitre='T1190',
                            details=f'Endpoint: {ep_url}\nServer suggests correct field names\n'
                                    f'Remediation: Disable field suggestions in production',
                            confidence='high')
        except Exception:
            pass

        # ── Phase 5: IDOR via ID enumeration ──
        try:
            r_id1 = req_lib.post(ep_url,
                                  json={'query': '{ user(id: "1") { id email } }'},
                                  timeout=10, verify=False,
                                  headers={'Content-Type': 'application/json',
                                           'User-Agent': 'Mozilla/5.0'})
            r_id2 = req_lib.post(ep_url,
                                  json={'query': '{ user(id: "2") { id email } }'},
                                  timeout=10, verify=False,
                                  headers={'Content-Type': 'application/json',
                                           'User-Agent': 'Mozilla/5.0'})
            if (r_id1.status_code == 200 and r_id2.status_code == 200 and
                    r_id1.text != r_id2.text and 'email' in r_id1.text):
                results['issues'].append({'type': 'idor', 'url': ep_url})
                add_finding('medium', 'GraphQL IDOR — User Data Accessible by ID',
                            sub='Different user objects returned for different IDs without auth check',
                            asset=ep_url, cvss='6.5', owasp='A01', mitre='T1190',
                            details=f'Endpoint: {ep_url}\nID 1 and ID 2 return different user data\n'
                                    f'Remediation: Enforce authorization on all object queries',
                            confidence='medium')
                log('ok', f'[GRAPHQL-DEEP] IDOR confirmed at {ep_url}')
        except Exception:
            pass

        # ── Phase 6: Alias overload ──
        try:
            aliases = ' '.join([f'a{i}: __typename' for i in range(50)])
            r_alias = req_lib.post(ep_url, json={'query': '{ ' + aliases + ' }'},
                                   timeout=10, verify=False,
                                   headers={'Content-Type': 'application/json',
                                            'User-Agent': 'Mozilla/5.0'})
            if r_alias.status_code == 200 and 'a0' in r_alias.text:
                results['issues'].append({'type': 'alias_overload', 'url': ep_url})
                add_finding('medium', 'GraphQL Alias Overload (DoS Vector)',
                            sub='Server processes 50-alias query, enabling resource exhaustion',
                            asset=ep_url, cvss='5.8', owasp='A04', mitre='T1499',
                            details=f'Endpoint: {ep_url}\n50 aliases processed in single query\n'
                                    f'Remediation: Implement query depth/alias limits',
                            confidence='high')
        except Exception:
            pass

        # ── Phase 7: NoSQL/injection in args ──
        try:
            r_inj = req_lib.post(ep_url,
                                  json={'query': '{ user(id: "1 OR 1=1") { email } }'},
                                  timeout=10, verify=False,
                                  headers={'Content-Type': 'application/json',
                                           'User-Agent': 'Mozilla/5.0'})
            if r_inj.status_code == 200 and 'email' in r_inj.text:
                emails = r_inj.text.count('@')
                if emails > 1:
                    results['issues'].append({'type': 'injection', 'url': ep_url})
                    add_finding('high', 'GraphQL Injection — Multiple Records Returned',
                                sub='SQL/NoSQL injection in GraphQL argument returns multiple records',
                                asset=ep_url, cvss='8.1', owasp='A03', mitre='T1190',
                                details=f'Endpoint: {ep_url}\nPayload: id: "1 OR 1=1"\n'
                                        f'Multiple email addresses in response',
                                confidence='high')
                    log('ok', f'[GRAPHQL-DEEP] Injection confirmed at {ep_url}')
        except Exception:
            pass

    with LOCK:
        scan_state['graphql_data'] = results
    set_progress('graphql_deep', 100)
    log('ok', f'[GRAPHQL-DEEP] Done. {len(results["endpoints"])} endpoints, '
              f'{len(results["issues"])} issues found.')


# ─── MODULE 5: JWT Deep Testing ───────────────────────────────────────────────


def run_websocket_test_module(target):
    """Test WebSocket security."""
    log('info', '[WS] Testing WebSocket security')
    base_url = f'https://{target}'
    ws_findings = []

    import hashlib as _hashlib

    # Find WebSocket endpoints
    ws_paths = ['/ws', '/socket', '/websocket', '/ws/chat', '/ws/notifications',
                '/api/ws', '/socket.io', '/signalr', '/hub']

    for path in ws_paths:
        if not scan_state.get('scanning'):
            break
        try:
            # Test WebSocket upgrade
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': _hashlib.sha1(b'key').hexdigest(),
                'Sec-WebSocket-Version': '13',
                'Origin': 'https://evil.com',
            }
            r = req_lib.get(f'{base_url}{path}', headers=headers,
                          timeout=5, verify=False)
            if r.status_code == 101 or 'websocket' in r.headers.get('Upgrade', '').lower():
                # Check for CORS bypass
                if 'evil.com' in str(r.headers):
                    add_finding(
                        'high',
                        f'WebSocket CORS bypass at {path}',
                        sub='WebSocket accepts connections from evil.com origin',
                        asset=f'{base_url}{path}', cvss='7.5', owasp='A01', mitre='T1189',
                        details=f'Path: {path}\nOrigin: evil.com\n'
                                f'Confirmed: WebSocket upgraded with evil origin')
                    ws_findings.append({'path': path})
                    log('ok', f'[WS] CORS bypass at {path}')

                # Check for missing authentication
                if 'Sec-WebSocket-Protocol' not in r.headers:
                    add_finding(
                        'medium',
                        f'WebSocket without authentication at {path}',
                        sub='WebSocket endpoint accepts connections without auth',
                        asset=f'{base_url}{path}', cvss='5.3', owasp='A07', mitre='T1190',
                        details=f'Path: {path}\nConfirmed: WebSocket upgraded without auth protocol')
                    ws_findings.append({'path': path})
                    log('ok', f'[WS] No auth at {path}')
        except Exception:
            pass

    log('ok', f'[WS] Scan complete - {len(ws_findings)} findings')
    set_progress('ws', 100)


# ─── CREDENTIAL STUFFING SIMULATION ───────────────────────────────────────────
