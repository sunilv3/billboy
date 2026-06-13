"""Intelligent reconnaissance agent with adaptive scanning."""
import re
import json
import time
import socket
import secrets
import threading
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE, DNS_AVAILABLE, _safe_str
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding

# Import helpers that live in app.py — resolved at runtime via the app context.
# When running under app.py these names are injected into the module namespace
# by the caller; when running standalone, import them from their split modules.
try:
    from core.utils import _check_target_for_ssrf
except ImportError:
    _check_target_for_ssrf = None  # resolved at runtime from app.py caller

try:
    from scanner.routing import PageTypeDetector
except ImportError:
    PageTypeDetector = None

RECON_STATE = {
    'running': False,
    'target': '',
    'phase': '',
    'phase_num': 0,
    'started_at': None,
    'completed_at': None,
    'logs': [],
    'report': {},
}
RECON_LOCK = threading.Lock()


def _recon_log(msg, level='info'):
    ts = datetime.now().strftime('%H:%M:%S')
    with RECON_LOCK:
        RECON_STATE['logs'].append({'ts': ts, 'level': level, 'msg': msg})
        if len(RECON_STATE['logs']) > 500:
            RECON_STATE['logs'] = RECON_STATE['logs'][-500:]
    print(f'[RECON][{ts}] {msg}')


# ─── TOOL SELECTOR ───────────────────────────────────────────────────────────

_TOOL_MATRIX = {
    'static': {
        'tools': [
            ('Katana',       'passive web crawl — enumerate links, JS files, external refs',
             _find_tool('katana')),
            ('Gau',          'pull historical URLs from Wayback Machine + Common Crawl',
             _find_tool('gau') or _find_tool('gau-linux-amd64')),
            ('Waybackurls',  'enumerate archived URLs from the Wayback Machine',
             _find_tool('waybackurls')),
            ('Httpx',        'probe URLs for live status, headers, tech fingerprint',
             _find_tool('httpx')),
            ('LinkFinder',   'extract URLs/endpoints from static JS files',
             _find_tool('linkfinder') or shutil.which('linkfinder.py')),
        ],
        'rationale': (
            'Static sites have no server-side attack surface (no forms, no DB queries). '
            'Active attack tools (SQLMap, Dalfox) would produce only false positives. '
            'Focus: enumerate the full URL corpus, check header hardening, CDN config, '
            'and historical exposure via Wayback Machine.'
        ),
    },
    'dynamic': {
        'tools': [
            ('Katana',      'deep crawl — follows forms, SPA routes, AJAX calls',
             _find_tool('katana')),
            ('Nuclei',      'template-based CVE / misconfiguration detection',
             _find_tool('nuclei')),
            ('Dalfox',      'parameter-aware XSS scanning with PoC generation',
             _find_tool('dalfox')),
            ('ParamSpider', 'extract parameters from Wayback Machine corpus',
             _find_tool('paramspider') or shutil.which('paramspider.py')),
            ('SQLMap',      'automated SQL injection on discovered parameters',
             _find_tool('sqlmap') or shutil.which('sqlmap')),
            ('Feroxbuster', 'recursive directory and endpoint bruteforce',
             _find_tool('feroxbuster')),
            ('FFUF',        'fast fuzzer — directories, parameters, virtual hosts',
             _find_tool('ffuf')),
        ],
        'rationale': (
            'Dynamic sites process user input server-side and use databases — full active '
            'attack surface available. Prioritise injection vectors (SQLi, XSS, SSRF), '
            'authentication tests, and directory bruteforce to map hidden endpoints.'
        ),
    },
    'spa': {
        'tools': [
            ('Katana',      'headless-mode JS crawl — renders React/Vue/Angular routes',
             _find_tool('katana')),
            ('JSFinder',    'extract API endpoints and secrets from bundled JS files',
             _find_tool('jsfinder') or shutil.which('jsfinder.py')),
            ('SecretFinder', 'regex-based secret/API-key hunting in JS bundles',
             _find_tool('secretfinder') or shutil.which('secretfinder.py')),
            ('LinkFinder',  'extract URLs and paths from minified JS',
             _find_tool('linkfinder') or shutil.which('linkfinder.py')),
            ('Nuclei',      'template checks for SPA-specific misconfigs (CORS, JWT, OIDC)',
             _find_tool('nuclei')),
        ],
        'rationale': (
            'SPA frameworks (React/Vue/Angular/Next.js) embed API endpoints and route maps '
            'inside bundled JS files — traditional crawlers miss them. JS analysis tools '
            'recover those endpoints for downstream testing. Headless Katana renders '
            'client-side routes that server-side scanners cannot reach.'
        ),
    },
    'api': {
        'tools': [
            ('Kiterunner',   'API endpoint bruteforce with OpenAPI-aware wordlists',
             _find_tool('kr') or _find_tool('kiterunner')),
            ('Nuclei',       'API-focused templates: auth bypass, BOLA, rate limit',
             _find_tool('nuclei')),
            ('FFUF',         'fuzz API parameters, headers, and versioned endpoints',
             _find_tool('ffuf')),
        ],
        'rationale': (
            'Pure REST/GraphQL APIs have no HTML surface — web crawlers add no value. '
            'API-specific tools map versioned routes (/v1/, /v2/), test authentication '
            'controls, and probe for BOLA/BFLA patterns.'
        ),
    },
}

# ─── TECH FINGERPRINTER (standalone, no side-effects on scan_state) ──────────

def _recon_fingerprint_tech(target, response):
    """Return a structured tech-stack dict from HTTP response."""
    headers = response.headers
    body = response.text[:200_000]
    body_lower = body.lower()
    server = headers.get('Server', '')
    powered = headers.get('X-Powered-By', '')
    ct = headers.get('Content-Type', '')
    via = headers.get('Via', '')
    cf_ray = headers.get('CF-Ray', '')
    x_cache = headers.get('X-Cache', '')
    fastly = headers.get('X-Served-By', '')

    detected = {
        'web_server': '',
        'framework': [],
        'cms': '',
        'language': '',
        'cdn_waf': [],
        'analytics': [],
        'third_party': [],
        'js_frameworks': [],
        'databases': [],
    }

    # Web server
    for srv in ('nginx', 'apache', 'iis', 'litespeed', 'caddy', 'lighttpd', 'openresty', 'gunicorn', 'uvicorn'):
        if srv in server.lower():
            detected['web_server'] = server.strip()
            break

    # Language / runtime
    lang_map = {
        'php': 'PHP', 'python': 'Python', 'ruby': 'Ruby',
        'java': 'Java', 'node': 'Node.js', 'asp.net': 'ASP.NET',
        'perl': 'Perl', 'coldfusion': 'ColdFusion', 'go': 'Go',
    }
    for key, lang in lang_map.items():
        if key in powered.lower() or key in server.lower():
            detected['language'] = lang
            break

    # Frameworks
    fw_patterns = [
        (r'wp-content|wp-includes|wordpress', 'WordPress'),
        (r'drupal\.js|drupal/modules', 'Drupal'),
        (r'joomla|\/components\/com_', 'Joomla'),
        (r'laravel|csrf-token.*laravel', 'Laravel'),
        (r'django|csrfmiddlewaretoken', 'Django'),
        (r'rails|csrf-param|action_dispatch', 'Ruby on Rails'),
        (r'magento|mage\.', 'Magento'),
        (r'shopify\.com/assets|cdn\.shopify', 'Shopify'),
        (r'prestashop', 'PrestaShop'),
        (r'x-powered-by.*express', 'Express.js'),
        (r'strapi', 'Strapi'),
        (r'next\.js|__next_data__', 'Next.js'),
        (r'nuxt\.js|__nuxt', 'Nuxt.js'),
        (r'gatsby', 'Gatsby'),
    ]
    for pat, name in fw_patterns:
        if re.search(pat, body_lower + powered.lower(), re.I):
            if name not in detected['framework']:
                detected['framework'].append(name)
            if any(c in name for c in ('WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'PrestaShop')):
                detected['cms'] = name

    # JS frameworks
    js_map = [
        (r'react(?:\.min)?\.js|data-reactroot|__react', 'React'),
        (r'vue(?:\.min)?\.js|data-v-[0-9a-f]+', 'Vue.js'),
        (r'angular(?:\.min)?\.js|ng-version', 'Angular'),
        (r'ember(?:\.min)?\.js', 'Ember.js'),
        (r'backbone(?:\.min)?\.js', 'Backbone.js'),
        (r'svelte', 'Svelte'),
        (r'alpinejs|x-data=', 'Alpine.js'),
    ]
    for pat, name in js_map:
        if re.search(pat, body_lower, re.I):
            if name not in detected['js_frameworks']:
                detected['js_frameworks'].append(name)

    # CDN / WAF
    cdn_map = [
        ('cf-ray', 'Cloudflare'),
        ('x-amz-cf-id', 'AWS CloudFront'),
        ('x-azure-ref', 'Azure CDN'),
        ('x-fastly-request-id', 'Fastly'),
        ('x-akamai-transformed', 'Akamai'),
        ('x-cache: hit from cloudfront', 'AWS CloudFront'),
        ('via: 1.1 varnish', 'Varnish'),
        ('server: sucuri', 'Sucuri WAF'),
        ('x-sucuri-id', 'Sucuri WAF'),
        ('x-waf-event', 'WAF'),
        ('server: barracuda', 'Barracuda WAF'),
        ('x-powered-by: mod_security', 'ModSecurity'),
    ]
    headers_str = '\n'.join(f'{k.lower()}: {v.lower()}' for k, v in headers.items())
    for indicator, cdn_name in cdn_map:
        if indicator.lower() in headers_str:
            if cdn_name not in detected['cdn_waf']:
                detected['cdn_waf'].append(cdn_name)

    # Analytics
    analytics_map = [
        (r'google-analytics|googletagmanager|gtag\(', 'Google Analytics / GTM'),
        (r'hotjar\.com', 'Hotjar'),
        (r'mixpanel\.com', 'Mixpanel'),
        (r'segment\.com', 'Segment'),
        (r'amplitude\.com', 'Amplitude'),
        (r'mouseflow\.com', 'Mouseflow'),
        (r'clarity\.ms', 'Microsoft Clarity'),
    ]
    for pat, name in analytics_map:
        if re.search(pat, body_lower, re.I):
            if name not in detected['analytics']:
                detected['analytics'].append(name)

    # Third-party services
    tp_map = [
        (r'stripe\.com/v3|stripe\.js', 'Stripe Payments'),
        (r'paypal\.com/sdk', 'PayPal'),
        (r'intercom\.io', 'Intercom'),
        (r'zendesk\.com', 'Zendesk'),
        (r'hubspot\.com', 'HubSpot'),
        (r'salesforce\.com', 'Salesforce'),
        (r'recaptcha|hcaptcha', 'CAPTCHA Service'),
        (r'sentry\.io', 'Sentry Error Tracking'),
        (r'auth0\.com', 'Auth0'),
        (r'okta\.com', 'Okta'),
        (r'firebase\.googleapis', 'Firebase'),
        (r'amazonaws\.com', 'AWS'),
        (r'twilio\.com', 'Twilio'),
    ]
    for pat, name in tp_map:
        if re.search(pat, body_lower, re.I):
            if name not in detected['third_party']:
                detected['third_party'].append(name)

    return detected


# ─── SURFACE MAPPER ───────────────────────────────────────────────────────────

def _recon_surface_map(target, base_url, session):
    """Enumerate attack surface. Returns a structured dict."""
    surface = {
        'subdomains': [],
        'directories': [],
        'parameters': [],
        'api_endpoints': [],
        'js_files': [],
        'forms': [],
        'auth_pages': [],
        'upload_pages': [],
        'search_pages': [],
        'external_links': [],
        'robots_disallowed': [],
        'sitemap_urls': [],
    }

    # ── Subdomains via crt.sh ──
    try:
        r = session.get(f'https://crt.sh/?q=%.{target}&output=json', timeout=12, verify=False)
        if r.status_code == 200:
            seen = set()
            for entry in r.json():
                for name in entry.get('name_value', '').split('\n'):
                    name = name.strip().lower().lstrip('*.')
                    if name.endswith(f'.{target}') and name not in seen:
                        seen.add(name)
                        surface['subdomains'].append(name)
            surface['subdomains'] = sorted(surface['subdomains'])[:50]
            _recon_log(f'[SURFACE] crt.sh → {len(surface["subdomains"])} subdomains')
    except Exception as e:
        _recon_log(f'[SURFACE] crt.sh failed: {e}', 'warn')

    # ── robots.txt ──
    try:
        r = session.get(f'{base_url}/robots.txt', timeout=8, verify=False)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        surface['robots_disallowed'].append(path)
            _recon_log(f'[SURFACE] robots.txt → {len(surface["robots_disallowed"])} disallowed paths')
    except Exception:
        pass

    # ── sitemap.xml ──
    for sitemap_url in [f'{base_url}/sitemap.xml', f'{base_url}/sitemap_index.xml']:
        try:
            r = session.get(sitemap_url, timeout=8, verify=False)
            if r.status_code == 200 and '<url' in r.text.lower():
                urls = re.findall(r'<loc>\s*(https?://[^<]+)\s*</loc>', r.text, re.I)
                surface['sitemap_urls'] = [u for u in urls[:100] if target in u]
                _recon_log(f'[SURFACE] sitemap → {len(surface["sitemap_urls"])} URLs')
                break
        except Exception:
            pass

    # ── Active directory probe ──
    probe_paths = [
        '/admin', '/administrator', '/wp-admin', '/wp-login.php',
        '/login', '/signin', '/auth', '/api', '/api/v1', '/api/v2',
        '/graphql', '/graphiql', '/swagger', '/swagger.json', '/api-docs',
        '/openapi.json', '/upload', '/uploads', '/files', '/search',
        '/register', '/signup', '/.env', '/.git/HEAD',
        '/config.json', '/debug', '/health', '/status', '/metrics',
        '/actuator', '/actuator/health', '/actuator/env', '/console',
        '/phpinfo.php', '/info.php', '/server-status', '/server-info',
    ]
    for path in probe_paths:
        try:
            r = session.get(f'{base_url}{path}', timeout=5, verify=False,
                            allow_redirects=False)
            if r.status_code not in (404, 410):
                surface['directories'].append({
                    'path': path,
                    'status': r.status_code,
                    'size': len(r.content),
                    'content_type': r.headers.get('Content-Type', ''),
                })
        except Exception:
            pass

    # ── Crawl root page for forms, inputs, links, JS files ──
    try:
        r = session.get(base_url, timeout=10, verify=False)
        body = r.text
        body_lower = body.lower()

        # JS files
        js_urls = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.I)
        for js in js_urls[:30]:
            if js.startswith('//'):
                js = 'https:' + js
            elif js.startswith('/'):
                js = base_url + js
            if target in js or js.startswith(base_url):
                surface['js_files'].append(js)

        # Forms and their actions
        form_actions = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', body, re.I)
        form_methods = re.findall(r'<form[^>]+method=["\']([^"\']*)["\']', body, re.I)
        for i, action in enumerate(form_actions[:20]):
            method = form_methods[i] if i < len(form_methods) else 'GET'
            surface['forms'].append({'action': action, 'method': method.upper()})

        # Input names (parameters)
        input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I)
        surface['parameters'] = list(dict.fromkeys(input_names[:50]))

        # Auth pages
        for pat, label in [
            (r'/login|/signin|/sign-in|/auth/login', 'Login'),
            (r'/register|/signup|/sign-up|/create-account', 'Registration'),
            (r'/forgot-password|/reset-password|/password/reset', 'Password Reset'),
            (r'/logout|/signout|/sign-out', 'Logout'),
        ]:
            if re.search(pat, body_lower, re.I) or re.search(pat, str(form_actions), re.I):
                surface['auth_pages'].append(label)

        # Upload functionality
        if re.search(r'type=["\']file["\']|enctype=["\']multipart', body, re.I):
            surface['upload_pages'].append(base_url)

        # Search functionality
        search_inputs = re.findall(r'<input[^>]+(?:type=["\'](?:search|text)["\'])[^>]*name=["\']([^"\']+)["\']', body, re.I)
        if search_inputs or 'search' in body_lower:
            surface['search_pages'].append(base_url)

        # External links
        ext_links = re.findall(r'href=["\']https?://([^/"\']+)["\']', body, re.I)
        surface['external_links'] = list(dict.fromkeys(
            d for d in ext_links if d and target not in d
        ))[:20]

    except Exception as e:
        _recon_log(f'[SURFACE] Root page crawl failed: {e}', 'warn')

    # ── API endpoint probing from JS files ──
    api_patterns = [
        r'(?:fetch|axios|http\.get|http\.post|http\.put|http\.delete|ajax)\s*\(\s*["\']([/][^"\']+)["\']',
        r'url:\s*["\']([/][^"\']+)["\']',
        r'endpoint:\s*["\']([/][^"\']+)["\']',
        r'"(/api/[^"\'<>\s]+)"',
        r"'(/api/[^\"'<>\s]+)'",
    ]
    for js_url in surface['js_files'][:10]:
        try:
            r_js = session.get(js_url, timeout=8, verify=False)
            if r_js.status_code == 200:
                for pat in api_patterns:
                    endpoints = re.findall(pat, r_js.text)
                    for ep in endpoints:
                        if ep not in surface['api_endpoints'] and len(ep) > 3:
                            surface['api_endpoints'].append(ep)
            surface['api_endpoints'] = surface['api_endpoints'][:50]
        except Exception:
            pass

    _recon_log(f'[SURFACE] Map complete — dirs:{len(surface["directories"])} '
               f'params:{len(surface["parameters"])} api:{len(surface["api_endpoints"])} '
               f'js:{len(surface["js_files"])} forms:{len(surface["forms"])}')
    return surface


# ─── ADAPTIVE RECON RUNNER ────────────────────────────────────────────────────

def _recon_adaptive_scan(target, base_url, site_type, surface, session):
    """
    Run vulnerability checks adapted to the detected site type.
    Returns list of finding dicts.
    """
    findings = []

    def _finding(sev, title, url, evidence, reproduction, remediation, confidence='medium'):
        findings.append({
            'severity': sev,
            'confidence': confidence,
            'title': title,
            'affected_url': url,
            'evidence': evidence,
            'reproduction_steps': reproduction,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat(),
        })
        _recon_log(f'[FINDING][{sev.upper()}] {title}', 'ok')

    # ── 1. Security headers check (all site types) ──
    try:
        r = session.get(base_url, timeout=8, verify=False)
        h = r.headers
        missing_headers = []
        header_checks = [
            ('Content-Security-Policy', 'CSP missing — XSS and data injection not mitigated'),
            ('Strict-Transport-Security', 'HSTS missing — MITM downgrade attacks possible'),
            ('X-Frame-Options', 'Clickjacking protection absent'),
            ('X-Content-Type-Options', 'MIME-type sniffing not blocked'),
            ('Referrer-Policy', 'Referrer-Policy absent — URL leakage risk'),
            ('Permissions-Policy', 'Permissions-Policy absent — camera/mic/geo unrestricted'),
        ]
        for header, desc in header_checks:
            if not h.get(header):
                missing_headers.append(f'{header}: {desc}')
        if missing_headers:
            _finding(
                'medium', 'Missing Security Headers',
                base_url,
                'HTTP response headers:\n' + '\n'.join(f'  ✗ {h}' for h in missing_headers),
                ['1. Open DevTools → Network tab', '2. Reload page and select the root request',
                 '3. Inspect Response Headers — listed headers are absent'],
                'Add the missing headers to the web server / CDN configuration. '
                'Use https://securityheaders.com to validate.',
                confidence='high',
            )
        # Check HTTPS
        if r.url.startswith('http://'):
            _finding(
                'high', 'Site served over HTTP (no TLS)',
                base_url,
                f'Root URL responded over HTTP: {r.url}',
                ['1. Access the site at http:// and confirm no redirect to https://'],
                'Redirect all HTTP traffic to HTTPS. Obtain a TLS certificate (Let\'s Encrypt is free).',
                confidence='high',
            )
    except Exception as e:
        _recon_log(f'[ADAPTIVE] Header check failed: {e}', 'warn')

    # ── 2. Sensitive file exposure ──
    sensitive_probes = [
        ('/.env',              'Environment file',    ['DB_PASSWORD', 'APP_KEY', 'AWS_SECRET']),
        ('/.git/HEAD',         'Git repository',      ['ref: refs/heads']),
        ('/config.json',       'Config file',         ['password', 'secret', 'key']),
        ('/wp-config.php',     'WordPress config',    ['DB_PASSWORD', 'DB_USER']),
        ('/.htpasswd',         'htpasswd file',       [':']),
        ('/package.json',      'Node package info',   ['"name"', '"version"']),
        ('/composer.json',     'PHP composer file',   ['"require"']),
        ('/server-status',     'Apache server-status', ['Total Accesses']),
        ('/phpinfo.php',       'PHP info page',       ['PHP Version']),
        ('/actuator/env',      'Spring Boot env',     ['spring.datasource']),
        ('/api-docs',          'API docs exposed',    ['swagger', 'openapi', 'paths']),
        ('/swagger.json',      'Swagger spec',        ['"paths"', '"swagger"']),
        ('/graphql',           'GraphQL endpoint',    []),
    ]
    for path, name, indicators in sensitive_probes:
        try:
            r = session.get(f'{base_url}{path}', timeout=6, verify=False,
                            allow_redirects=False)
            if r.status_code == 200:
                body_sample = r.text[:1000].lower()
                confirmed = not indicators or any(ind.lower() in body_sample for ind in indicators)
                if confirmed:
                    _finding(
                        'high', f'Sensitive File Exposed: {name}',
                        f'{base_url}{path}',
                        f'GET {path} → HTTP 200\nContent preview: {r.text[:300]}',
                        [f'1. curl -sk {base_url}{path}',
                         '2. Confirm the response contains sensitive content'],
                        f'Block direct access to {path} via web server configuration. '
                        f'Move sensitive files outside the web root.',
                        confidence='high',
                    )
        except Exception:
            pass

    # ── 3. CORS misconfiguration ──
    try:
        evil_origins = [
            'https://evil.com',
            f'https://{target}.evil.com',
            'null',
        ]
        for origin in evil_origins:
            r = session.get(base_url, timeout=8, verify=False,
                            headers={'Origin': origin})
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
            if acao == origin:
                sev = 'critical' if acac == 'true' else 'high'
                _finding(
                    sev,
                    f'CORS Misconfiguration — Reflected Origin{"+ Credentials" if acac == "true" else ""}',
                    base_url,
                    f'Request: Origin: {origin}\n'
                    f'Response: Access-Control-Allow-Origin: {acao}\n'
                    f'         Access-Control-Allow-Credentials: {acac}',
                    [f'curl -sk -H "Origin: {origin}" -I {base_url}',
                     'Observe that ACAO reflects the attacker origin'],
                    'Restrict ACAO to a specific trusted origin list. '
                    'Never reflect arbitrary origins when credentials are allowed.',
                    confidence='high',
                )
                break
    except Exception as e:
        _recon_log(f'[ADAPTIVE] CORS check failed: {e}', 'warn')

    # ── 4. Information disclosure in error pages ──
    try:
        for path in ['/DOESNOTEXIST_recon', '/../../../../etc/passwd']:
            r = session.get(f'{base_url}{path}', timeout=6, verify=False)
            body = r.text[:2000]
            # Stack trace / framework disclosure
            for indicator, desc in [
                ('Traceback (most recent call last)', 'Python stack trace'),
                ('at org.springframework', 'Java/Spring stack trace'),
                ('System.Web.HttpException', 'ASP.NET exception'),
                ('Fatal error:', 'PHP fatal error'),
                ('Warning: ', 'PHP warning'),
                ('debug=True', 'Django debug mode'),
                ('ActiveRecord::', 'Ruby on Rails exception'),
            ]:
                if indicator in body:
                    _finding(
                        'medium',
                        f'Information Disclosure — {desc}',
                        f'{base_url}{path}',
                        f'GET {path} → HTTP {r.status_code}\nBody excerpt: {body[:500]}',
                        ['1. Send a request to a non-existent path',
                         '2. Observe framework internals in the error response'],
                        'Disable debug mode in production. Configure a custom error page '
                        'that returns only the status code without stack traces.',
                        confidence='high',
                    )
                    break
    except Exception:
        pass

    # ── 5. Dynamic-only tests ──
    if site_type in ('dynamic', 'spa', 'hybrid'):
        # Authentication page checks
        for auth_path in ['/login', '/signin', '/auth/login', '/user/login']:
            try:
                r = session.get(f'{base_url}{auth_path}', timeout=6, verify=False)
                if r.status_code == 200:
                    body = r.text
                    # No CSRF token
                    if '<form' in body.lower() and not re.search(r'csrf|_token|xsrf', body, re.I):
                        _finding(
                            'medium', 'Login Form Lacks CSRF Protection',
                            f'{base_url}{auth_path}',
                            f'Login form at {auth_path} has no CSRF token in the HTML',
                            [f'1. View source of {base_url}{auth_path}',
                             '2. Find the login <form> — no hidden csrf/xsrf token field'],
                            'Add a synchronizer token (CSRF token) to all state-changing forms.',
                        )
                    # Password field without autocomplete=off
                    if 'type="password"' in body.lower() and 'autocomplete="off"' not in body.lower():
                        _finding(
                            'low', 'Password Autocomplete Not Disabled',
                            f'{base_url}{auth_path}',
                            'Password input does not set autocomplete="off"',
                            ['1. Inspect the password field HTML',
                             '2. Confirm autocomplete attribute is absent or "on"'],
                            'Set autocomplete="off" on password fields in sensitive forms.',
                        )
                    break
            except Exception:
                pass

        # Rate limiting check on login
        for auth_path in ['/login', '/api/login', '/api/auth', '/api/auth/login']:
            try:
                blocked = 0
                for _ in range(10):
                    r = session.post(
                        f'{base_url}{auth_path}',
                        json={'username': 'test@test.com', 'password': 'WrongPass123!'},
                        timeout=5, verify=False,
                    )
                    if r.status_code in (429, 423, 503):
                        blocked += 1
                if blocked == 0:
                    _finding(
                        'medium', 'No Rate Limiting on Login Endpoint',
                        f'{base_url}{auth_path}',
                        '10 consecutive failed login attempts returned no HTTP 429/423/503',
                        [f'for i in $(seq 10); do curl -sk -X POST {base_url}{auth_path} '
                         '-d \'{"username":"test","password":"wrong"}\'; done',
                         'Observe no 429 Too Many Requests responses'],
                        'Implement rate limiting (e.g., max 5 attempts per IP per minute) '
                        'and account lockout after repeated failures.',
                    )
                break
            except Exception:
                continue

    # ── 6. Open redirect detection ──
    try:
        redirect_params = ['redirect', 'next', 'url', 'return', 'returnUrl', 'callback', 'goto', 'dest']
        for param in redirect_params:
            r = session.get(f'{base_url}/?{param}=https://evil.com',
                            timeout=6, verify=False, allow_redirects=False)
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get('Location', '')
                if 'evil.com' in location:
                    _finding(
                        'medium', f'Open Redirect via ?{param}=',
                        f'{base_url}/?{param}=https://evil.com',
                        f'GET /?{param}=https://evil.com → HTTP {r.status_code} Location: {location}',
                        [f'1. curl -sk -I "{base_url}/?{param}=https://evil.com"',
                         f'2. Observe Location header redirects to evil.com'],
                        f'Validate redirect targets against an allowlist of permitted domains. '
                        f'Reject or encode external URLs in the {param} parameter.',
                        confidence='high',
                    )
    except Exception:
        pass

    # ── 7. API-specific checks ──
    for api_ep in surface.get('api_endpoints', [])[:10]:
        ep_url = f'{base_url}{api_ep}' if api_ep.startswith('/') else api_ep
        try:
            r = session.get(ep_url, timeout=5, verify=False)
            if r.status_code == 200:
                try:
                    data = r.json()
                    # Look for high-signal sensitive fields
                    data_str = str(data).lower()
                    sensitive = [f for f in ('"password"', '"secret"', '"api_key"', '"token"', '@')
                                 if f in data_str]
                    if sensitive:
                        _finding(
                            'high', f'API Endpoint Returns Sensitive Data Without Auth',
                            ep_url,
                            f'GET {api_ep} → 200 OK\nSensitive fields: {sensitive}\n'
                            f'Response sample: {data_str[:300]}',
                            [f'1. curl -sk {ep_url}',
                             '2. Observe sensitive data in JSON response without auth header'],
                            'Require authentication on all API endpoints. '
                            'Implement proper authorization checks before returning sensitive data.',
                            confidence='high',
                        )
                except Exception:
                    pass
        except Exception:
            pass

    # ── 8. Upload functionality checks ──
    if surface.get('upload_pages'):
        for upload_url in surface['upload_pages'][:3]:
            try:
                # Check if server accepts PHP/dangerous file extensions
                r = session.post(
                    upload_url,
                    files={'file': ('test.php', b'<?php echo "TEST"; ?>', 'application/x-php')},
                    timeout=6, verify=False,
                )
                if r.status_code in (200, 201) and ('success' in r.text.lower() or 'uploaded' in r.text.lower()):
                    _finding(
                        'critical', 'Unrestricted File Upload — PHP Accepted',
                        upload_url,
                        f'POST with test.php → HTTP {r.status_code}\nResponse: {r.text[:300]}',
                        ['1. Create a PHP file: echo \'<?php echo "pwned"; ?>\' > test.php',
                         f'2. curl -F "file=@test.php" {upload_url}',
                         '3. Browse to the uploaded file location'],
                        'Validate file extensions server-side. '
                        'Store uploads outside the web root. '
                        'Use a content-type allowlist (image/jpeg, image/png, application/pdf only). '
                        'Rename files on upload to prevent directory traversal.',
                        confidence='medium',
                    )
            except Exception:
                pass

    # ── 9. Search/XSS reflection check ──
    if surface.get('search_pages') and site_type in ('dynamic', 'hybrid'):
        xss_probe = '<script>alert(1)</script>'
        for search_url in surface['search_pages'][:3]:
            for param in ['q', 's', 'search', 'query', 'keyword']:
                try:
                    r = session.get(
                        f'{search_url}?{param}={xss_probe}',
                        timeout=6, verify=False,
                    )
                    if xss_probe in r.text:
                        _finding(
                            'high', f'Reflected XSS via ?{param}= (Unencoded)',
                            f'{search_url}?{param}={xss_probe}',
                            f'Payload {xss_probe} reflected unencoded in HTTP {r.status_code} response',
                            [f'1. Open browser to: {search_url}?{param}=<script>alert(1)</script>',
                             '2. Observe alert dialog — XSS confirmed'],
                            'HTML-encode all user-supplied values before rendering them in page output. '
                            'Implement a strict Content-Security-Policy.',
                            confidence='high',
                        )
                        break
                except Exception:
                    pass

    # ── 10. SSL/TLS check ──
    try:
        import ssl as _ssl
        import socket as _sock
        ctx = _ssl.create_default_context()
        with _sock.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                # Check expiry
                import email.utils as _eu
                not_after = cert.get('notAfter', '')
                if not_after:
                    import time as _time
                    exp_ts = _eu.parsedate_to_datetime(not_after).timestamp()
                    days_left = int((exp_ts - _time.time()) / 86400)
                    if days_left < 30:
                        _finding(
                            'high', f'TLS Certificate Expires in {days_left} Days',
                            base_url,
                            f'Certificate notAfter: {not_after} ({days_left} days remaining)',
                            ['1. openssl s_client -connect ' + target + ':443 -brief 2>/dev/null | grep notAfter'],
                            'Renew the TLS certificate before expiry. '
                            'Configure auto-renewal (certbot renew --cron, or ACM auto-renewal).',
                            confidence='high',
                        )
                    elif days_left < 60:
                        _finding(
                            'medium', f'TLS Certificate Expires Soon ({days_left} Days)',
                            base_url,
                            f'Certificate notAfter: {not_after}',
                            ['openssl s_client -connect ' + target + ':443 -brief 2>/dev/null | grep notAfter'],
                            'Plan certificate renewal. Automate with certbot or ACM.',
                        )
    except Exception:
        pass

    _recon_log(f'[ADAPTIVE] Adaptive scan complete — {len(findings)} findings', 'ok')
    return findings


# ─── MASTER ORCHESTRATOR ─────────────────────────────────────────────────────

def run_intelligent_recon_agent(target):
    """
    Full intelligent recon workflow:
      Phase 0 → Initial analysis (site type + tech fingerprint)
      Phase 1 → Surface mapping
      Phase 2 → Strategy selection
      Phase 3 → Adaptive recon
      Phase 4 → Report compilation
    """
    with RECON_LOCK:
        RECON_STATE.update({
            'running': True, 'target': target,
            'phase': 'Starting', 'phase_num': 0,
            'started_at': datetime.now().isoformat(),
            'completed_at': None, 'logs': [], 'report': {},
        })

    try:
        base_url = f'https://{target}'
        session = req_lib.Session() if REQUESTS_AVAILABLE else None
        if not session:
            _recon_log('requests library not available — aborting', 'error')
            with RECON_LOCK:
                RECON_STATE['running'] = False
                RECON_STATE['completed_at'] = datetime.now().isoformat()
                RECON_STATE['report'] = {'error': 'requests library not available'}
            return

        session.verify = False
        session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; InfoSecRecon/2.0)'})

        # ══════════════════════════════════════════════════════════
        # PHASE 0: INITIAL ANALYSIS
        # ══════════════════════════════════════════════════════════
        with RECON_LOCK:
            RECON_STATE['phase'] = 'Phase 0: Initial Analysis'
            RECON_STATE['phase_num'] = 0
        _recon_log('[PHASE 0] Initial analysis — fetching root page')

        try:
            r0 = session.get(base_url, timeout=12, verify=False)
            http_status = r0.status_code
            _recon_log(f'[PHASE 0] Root page: HTTP {http_status} '
                       f'({len(r0.content)} bytes, {r0.elapsed.total_seconds():.2f}s)')
        except Exception as e:
            _recon_log(f'[PHASE 0] Root page fetch failed: {e} — trying http://', 'warn')
            try:
                r0 = session.get(f'http://{target}', timeout=12, verify=False)
                base_url = f'http://{target}'
                http_status = r0.status_code
            except Exception as e2:
                _recon_log(f'[PHASE 0] Target unreachable: {e2}', 'error')
                with RECON_LOCK:
                    RECON_STATE['running'] = False
                    RECON_STATE['report'] = {'error': f'Target unreachable: {e2}'}
                return

        # Site classification
        _recon_log('[PHASE 0] Running multi-signal site type detection')
        if PageTypeDetector is not None:
            page_type_result = PageTypeDetector.detect(target)
        else:
            page_type_result = {'page_type': 'dynamic', 'confidence': 0.5, 'scan_strategy': 'dynamic_full'}
        site_type = page_type_result.get('page_type', 'dynamic')
        pt_confidence = page_type_result.get('confidence', 0.5)
        scan_strategy = page_type_result.get('scan_strategy', 'dynamic_full')

        # Is it an API?
        is_api_only = ('application/json' in r0.headers.get('Content-Type', '') and
                       '<html' not in r0.text.lower())
        if is_api_only:
            site_type = 'api'
            scan_strategy = 'api_focused'

        _recon_log(f'[PHASE 0] Classification: {site_type.upper()} '
                   f'(confidence={pt_confidence:.0%}, strategy={scan_strategy})')

        # Tech fingerprinting
        _recon_log('[PHASE 0] Fingerprinting technology stack')
        tech_stack = _recon_fingerprint_tech(target, r0)
        tech_summary_parts = []
        if tech_stack['web_server']:
            tech_summary_parts.append(f"Server: {tech_stack['web_server']}")
        if tech_stack['language']:
            tech_summary_parts.append(f"Lang: {tech_stack['language']}")
        if tech_stack['cms']:
            tech_summary_parts.append(f"CMS: {tech_stack['cms']}")
        if tech_stack['cdn_waf']:
            tech_summary_parts.append(f"CDN/WAF: {', '.join(tech_stack['cdn_waf'])}")
        if tech_stack['js_frameworks']:
            tech_summary_parts.append(f"JS: {', '.join(tech_stack['js_frameworks'])}")
        _recon_log(f'[PHASE 0] Tech stack: {" | ".join(tech_summary_parts) or "No tech detected"}')

        # ══════════════════════════════════════════════════════════
        # PHASE 1: SURFACE MAPPING
        # ══════════════════════════════════════════════════════════
        with RECON_LOCK:
            RECON_STATE['phase'] = 'Phase 1: Surface Mapping'
            RECON_STATE['phase_num'] = 1
        _recon_log('[PHASE 1] Mapping attack surface')
        surface = _recon_surface_map(target, base_url, session)

        # Determine if there's a GraphQL endpoint
        has_graphql = any('/graphql' in d.get('path', '') for d in surface['directories'])
        has_login = bool(surface['auth_pages'])
        has_upload = bool(surface['upload_pages'])
        has_search = bool(surface['search_pages'])
        has_api = bool(surface['api_endpoints']) or any(
            '/api' in d.get('path', '') for d in surface['directories']
        )

        _recon_log(f'[PHASE 1] Surface: login={has_login} upload={has_upload} '
                   f'search={has_search} api={has_api} graphql={has_graphql}')

        # ══════════════════════════════════════════════════════════
        # PHASE 2: SCAN STRATEGY SELECTION
        # ══════════════════════════════════════════════════════════
        with RECON_LOCK:
            RECON_STATE['phase'] = 'Phase 2: Strategy Selection'
            RECON_STATE['phase_num'] = 2
        _recon_log(f'[PHASE 2] Selecting scan strategy for {site_type} site')

        # Choose tool matrix based on site type; fall back to 'dynamic'
        matrix_key = site_type if site_type in _TOOL_MATRIX else 'dynamic'

        # If GraphQL or API features detected on a dynamic site, supplement with API tools
        if has_graphql or has_api:
            api_tools = _TOOL_MATRIX['api']['tools']
        else:
            api_tools = []

        selected_tools = _TOOL_MATRIX[matrix_key]['tools']
        tool_rationale = _TOOL_MATRIX[matrix_key]['rationale']

        # Evaluate tool availability
        tool_status = []
        for name, desc, path in selected_tools + api_tools:
            tool_status.append({
                'name': name, 'description': desc,
                'available': bool(path), 'path': path or 'Not installed',
            })
            status = 'AVAILABLE' if path else 'NOT FOUND'
            _recon_log(f'[PHASE 2] Tool {name}: {status}')

        # Adaptive recommendations based on discovered features
        adaptive_notes = []
        if has_login:
            adaptive_notes.append(
                'Login page detected — test pre-auth (rate limiting, brute-force) '
                'and post-auth (IDOR, privilege escalation) surfaces.'
            )
        if has_api or has_graphql:
            adaptive_notes.append(
                'API/GraphQL endpoints found — enumerate versioned routes, test '
                'auth bypass (BOLA/BFLA), check for introspection disclosure.'
            )
        if has_upload:
            adaptive_notes.append(
                'File upload functionality detected — test extension bypass, '
                'MIME-type spoofing, directory traversal, web shell upload.'
            )
        if has_search:
            adaptive_notes.append(
                'Search functionality detected — test XSS (reflected/stored), '
                'SQL injection, NoSQL injection, and SSTI via search parameters.'
            )
        if tech_stack['cms'] == 'WordPress':
            adaptive_notes.append(
                'WordPress detected — run WPScan for plugin/theme CVE enumeration, '
                'check /xmlrpc.php, test /wp-json/wp/v2/users for user enumeration.'
            )
        if is_api_only:
            adaptive_notes.append(
                'Pure API target — enumerate all routes, test auth, '
                'check OpenAPI/Swagger spec for exposure, test BOLA at /v1/users/{id}.'
            )

        _recon_log(f'[PHASE 2] Strategy: {scan_strategy} — '
                   f'{len(selected_tools)} primary tools, {len(adaptive_notes)} adaptive notes')

        # ══════════════════════════════════════════════════════════
        # PHASE 3: ADAPTIVE RECON
        # ══════════════════════════════════════════════════════════
        with RECON_LOCK:
            RECON_STATE['phase'] = 'Phase 3: Adaptive Recon'
            RECON_STATE['phase_num'] = 3
        _recon_log('[PHASE 3] Running adaptive security checks')
        findings = _recon_adaptive_scan(target, base_url, site_type, surface, session)

        # ══════════════════════════════════════════════════════════
        # PHASE 3.5: AI-POWERED ANALYSIS (Optional — requires Ollama)
        # ══════════════════════════════════════════════════════════
        ai_analysis = None
        try:
            from ai.ollama import _ollama_generate, _ollama_available, OLLAMA_MODEL
            if _ollama_available() and findings:
                with RECON_LOCK:
                    RECON_STATE['phase'] = 'Phase 3.5: AI Analysis'
                    RECON_STATE['phase_num'] = 3
                _recon_log('[PHASE 3.5] AI analysis — Ollama available, triaging findings')

                # Build compact finding summaries for the LLM
                finding_summaries = []
                for f in findings[:60]:
                    finding_summaries.append({
                        'id': f.get('id', f.get('title', '')[:40]),
                        'severity': f.get('severity', 'info'),
                        'title': f.get('title', ''),
                        'affected_url': f.get('affected_url', ''),
                        'evidence': (f.get('evidence', '') or '')[:200],
                        'confidence': f.get('confidence', 'medium'),
                    })

                tech_summary = ', '.join(sorted(tech_stack.keys())[:15]) if tech_stack else 'unknown'

                # ── AI Triage: classify findings ──
                triage_prompt = f"""Analyze these security findings for target: {target}
Site type: {site_type}
Technologies: {tech_summary}

For EACH finding, classify as:
- TRUE: confirmed vulnerability with real evidence
- FALSE_POSITIVE: likely false alarm
- UNCERTAIN: needs manual verification

Findings:
{json.dumps(finding_summaries, indent=1)}

Respond in EXACTLY this JSON format (no markdown fences):
{{
  "triage": [
    {{"id": "finding-id", "verdict": "TRUE|FALSE_POSITIVE|UNCERTAIN", "confidence": 0.0-1.0, "reason": "brief reason"}},
    ...
  ],
  "false_positive_count": N,
  "true_positive_count": N,
  "executive_summary": "2-3 sentence risk assessment"
}}"""

                triage_raw = _ollama_generate(
                    triage_prompt,
                    system='You are an expert penetration tester. Respond ONLY in valid JSON. Be precise.'
                )
                triage_result = None
                if triage_raw:
                    try:
                        json_match = re.search(r'\{[\s\S]*"triage"[\s\S]*\}', triage_raw)
                        if json_match:
                            triage_result = json.loads(json_match.group())
                            _recon_log(f'[PHASE 3.5] AI triage complete — '
                                       f'{triage_result.get("true_positive_count", 0)} true, '
                                       f'{triage_result.get("false_positive_count", 0)} false positives')
                    except Exception as e:
                        _recon_log(f'[PHASE 3.5] AI triage JSON parse failed: {e}', 'warn')

                # ── AI Attack Paths: chain findings ──
                attack_prompt = f"""Target: {target}
Site type: {site_type}
Technologies: {tech_summary}
Findings: {json.dumps([{'sev': f['severity'], 'title': f['title'], 'url': f['affected_url']} for f in finding_summaries[:25]], indent=1)}

Identify attack chains — sequences of findings an attacker could combine to escalate access.
Respond in EXACTLY this JSON format (no markdown fences):
{{
  "attack_paths": [
    {{
      "name": "path name",
      "description": "step by step explanation",
      "findings": ["finding-id-1", "finding-id-2"],
      "impact": "critical|high|medium",
      "likelihood": "high|medium|low"
    }}
  ],
  "prioritized_remediation": [
    {{"priority": 1, "action": "what to fix", "effort": "low|medium|high", "prevents": "what this prevents"}}
  ]
}}"""

                attack_raw = _ollama_generate(
                    attack_prompt,
                    system='You are a red team operator. Think like an attacker. Respond ONLY in valid JSON.'
                )
                attack_result = None
                if attack_raw:
                    try:
                        json_match = re.search(r'\{[\s\S]*"attack_paths"[\s\S]*\}', attack_raw)
                        if json_match:
                            attack_result = json.loads(json_match.group())
                            _recon_log(f'[PHASE 3.5] AI attack paths — '
                                       f'{len(attack_result.get("attack_paths", []))} paths identified')
                    except Exception as e:
                        _recon_log(f'[PHASE 3.5] AI attack path JSON parse failed: {e}', 'warn')

                ai_analysis = {
                    'model': OLLAMA_MODEL,
                    'triage': triage_result,
                    'attack_paths': attack_result,
                    'raw_triage': triage_raw[:1500] if triage_raw else None,
                    'raw_attack': attack_raw[:1500] if attack_raw else None,
                }

                # Apply triage verdicts to findings
                if triage_result and triage_result.get('triage'):
                    for verdict in triage_result['triage']:
                        if verdict.get('verdict') == 'FALSE_POSITIVE':
                            for f in findings:
                                if f.get('title', '')[:40] == verdict.get('id', ''):
                                    f['ai_triaged'] = True
                                    f['verified'] = False
                                    _recon_log(f'[PHASE 3.5] Marked FP: {f["title"]}', 'warn')
                                    break
            else:
                if not _ollama_available():
                    _recon_log('[PHASE 3.5] Ollama not available — skipping AI analysis', 'warn')
                else:
                    _recon_log('[PHASE 3.5] No findings to analyze — skipping AI', 'info')
        except ImportError:
            _recon_log('[PHASE 3.5] AI module not available — skipping', 'warn')
        except Exception as e:
            _recon_log(f'[PHASE 3.5] AI analysis failed: {e}', 'warn')

        # ══════════════════════════════════════════════════════════
        # PHASE 4: REPORT COMPILATION
        # ══════════════════════════════════════════════════════════
        with RECON_LOCK:
            RECON_STATE['phase'] = 'Phase 4: Report Compilation'
            RECON_STATE['phase_num'] = 4
        _recon_log('[PHASE 4] Compiling structured report')

        # Severity counts
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Overall risk level
        if sev_counts['critical'] >= 1:
            risk_level = 'CRITICAL'
        elif sev_counts['high'] >= 3:
            risk_level = 'HIGH'
        elif sev_counts['high'] >= 1 or sev_counts['medium'] >= 5:
            risk_level = 'MEDIUM'
        elif sev_counts['medium'] >= 1:
            risk_level = 'LOW'
        else:
            risk_level = 'INFORMATIONAL'

        # Recommended next actions
        next_actions = []
        if sev_counts['critical']:
            next_actions.append('URGENT: Address all critical findings within 24 hours')
        if any(f['title'] == 'Missing Security Headers' for f in findings):
            next_actions.append('Harden HTTP response headers immediately (CSP, HSTS, X-Frame-Options)')
        if any('Sensitive File' in f['title'] for f in findings):
            next_actions.append('Block access to exposed sensitive files via server config')
        if any('CORS' in f['title'] for f in findings):
            next_actions.append('Fix CORS policy — restrict Access-Control-Allow-Origin to known domains')
        if has_login:
            next_actions.append('Perform authenticated testing: IDOR, horizontal privilege escalation, session management')
        if has_api:
            next_actions.append('Run Kiterunner or FFUF to enumerate hidden API routes')
        if has_upload:
            next_actions.append('Test file upload with security-specific bypass payloads (null byte, double extension)')
        if site_type in ('dynamic', 'hybrid'):
            next_actions.append('Run SQLMap against all discovered parameters')
            next_actions.append('Run Dalfox for XSS scanning on input parameters')
        if site_type == 'spa':
            next_actions.append('Use Katana in headless mode to map client-side routes')
            next_actions.append('Analyse JS bundles with SecretFinder for hardcoded credentials')

        report = {
            'target': target,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration_s': round(time.time() - (
                datetime.fromisoformat(RECON_STATE['started_at']).timestamp()), 1),
            # ── Section 1: Technology Stack ──
            'technology_stack': {
                'web_server': tech_stack['web_server'] or 'Unknown',
                'language': tech_stack['language'] or 'Unknown',
                'frameworks': tech_stack['framework'],
                'cms': tech_stack['cms'] or None,
                'js_frameworks': tech_stack['js_frameworks'],
                'cdn_waf': tech_stack['cdn_waf'],
                'analytics': tech_stack['analytics'],
                'third_party_services': tech_stack['third_party'],
            },
            # ── Section 2: Classification ──
            'website_classification': {
                'type': site_type,
                'confidence': f'{pt_confidence:.0%}',
                'scan_strategy': scan_strategy,
                'is_spa': site_type == 'spa',
                'is_api_only': is_api_only,
                'classification_signals': {
                    'dynamic_signals': page_type_result.get('signals', {}).get('dynamic', []),
                    'static_signals': page_type_result.get('signals', {}).get('static', []),
                },
            },
            # ── Section 3: Attack Surface ──
            'attack_surface': {
                'subdomains': surface['subdomains'],
                'subdomains_count': len(surface['subdomains']),
                'directories_found': surface['directories'],
                'directories_count': len(surface['directories']),
                'parameters': surface['parameters'],
                'parameters_count': len(surface['parameters']),
                'api_endpoints': surface['api_endpoints'],
                'api_endpoints_count': len(surface['api_endpoints']),
                'js_files': surface['js_files'],
                'js_files_count': len(surface['js_files']),
                'forms': surface['forms'],
                'forms_count': len(surface['forms']),
                'auth_pages': surface['auth_pages'],
                'has_login': has_login,
                'has_upload': has_upload,
                'has_search': has_search,
                'has_graphql': has_graphql,
                'has_api': has_api,
                'robots_disallowed': surface['robots_disallowed'],
                'sitemap_url_count': len(surface['sitemap_urls']),
                'external_services': surface['external_links'],
            },
            # ── Section 4: Tools ──
            'selected_tools': {
                'site_type': site_type,
                'rationale': tool_rationale,
                'tools': tool_status,
                'adaptive_notes': adaptive_notes,
            },
            # ── Section 5: Findings ──
            'scan_results': {
                'total_findings': len(findings),
                'severity_breakdown': sev_counts,
                'risk_level': risk_level,
                'findings': sorted(findings, key=lambda f: {
                    'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
                }.get(f.get('severity', 'info'), 5)),
            },
            # ── Section 6: AI Analysis ──
            'ai_analysis': ai_analysis,
            # ── Section 7: Next Actions ──
            'recommended_next_actions': next_actions,
        }

        with RECON_LOCK:
            RECON_STATE['report'] = report
            RECON_STATE['phase'] = 'Complete'
            RECON_STATE['phase_num'] = 5
            RECON_STATE['completed_at'] = datetime.now().isoformat()
            RECON_STATE['running'] = False

        _recon_log(
            f'[PHASE 4] Report complete — site_type={site_type} '
            f'findings={len(findings)} risk={risk_level}', 'ok'
        )

    except Exception as e:
        _recon_log(f'[RECON] Unhandled error: {e}', 'error')
        with RECON_LOCK:
            RECON_STATE['running'] = False
            RECON_STATE['phase'] = 'Error'
            RECON_STATE['report'] = {'error': str(e)}
