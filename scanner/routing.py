"""Adaptive routing: classify targets and prune scan modules accordingly."""
import re
from core.utils import req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.constants import ADAPTIVE_ROUTING, DYNAMIC_ONLY_MODULES


class PageTypeDetector:
    """
    Classifies a web target as STATIC or DYNAMIC using multi-signal analysis.

    STATIC signals:
      - No forms, no login, no POST endpoints found
      - Content-Type: text/html with no JS framework fingerprint
      - ETag and Last-Modified present, Cache-Control: max-age set
      - No session cookies, no authentication challenge
      - Server: nginx/apache serving flat files (no app server header)
      - All discovered URLs have file extensions (.html, .css, .jpg, .pdf, .png)
      - No JSON API responses
      - Identical response for requests with different Accept headers

    DYNAMIC signals:
      - Login form, registration, search input, or any POST form detected
      - Session cookie (PHPSESSID, JSESSIONID, session, connect.sid, etc.)
      - JS framework detected (React, Vue, Angular, Next.js, Nuxt, Svelte)
      - API endpoints returning JSON (Content-Type: application/json)
      - CMS detected (WordPress, Drupal, Joomla, Django, Rails)
      - CSRF token in form (strong indicator of server-side session)
      - Server header contains: php, python, ruby, java, express, gunicorn, uvicorn
      - URL patterns with dynamic segments (/user/123, /post?id=, /api/v1/)
      - GraphQL endpoint found
      - WebSocket upgrade attempted by client
    """

    STATIC_EXTENSIONS = {'.html', '.htm', '.css', '.js', '.jpg', '.jpeg',
                         '.png', '.gif', '.svg', '.ico', '.pdf', '.woff',
                         '.woff2', '.ttf', '.eot', '.mp4', '.webp', '.xml',
                         '.txt', '.json', '.rss', '.atom'}

    DYNAMIC_SERVER_KEYWORDS = [
        'php', 'python', 'ruby', 'java', 'express', 'gunicorn', 'uvicorn',
        'unicorn', 'puma', 'tornado', 'django', 'rails', 'flask', 'fastapi',
        'node', 'asp.net', 'iis', 'jetty', 'tomcat', 'jboss', 'wildfly',
        'coldfusion', 'spring', 'struts',
    ]

    SESSION_COOKIE_NAMES = [
        'phpsessid', 'jsessionid', 'session', 'connect.sid', 'asp.net_sessionid',
        '_session', 'sessionid', 'sid', 'csrf', 'xsrf', 'token', 'auth',
        '__stripe_mid', 'cf_clearance',
    ]

    JS_FRAMEWORK_PATTERNS = [
        r'react(?:\.min)?\.js', r'vue(?:\.min)?\.js', r'angular(?:\.min)?\.js',
        r'next(?:\.min)?\.js', r'nuxt(?:\.min)?\.js', r'svelte', r'ember',
        r'backbone(?:\.min)?\.js', r'jquery(?:\.min)?\.js',
        r'__NEXT_DATA__', r'__nuxt', r'ng-version', r'data-reactroot',
        r'data-v-[0-9a-f]+', r'_N_E', r'window\.__svelte',
    ]

    CMS_PATTERNS = [
        r'wp-content', r'wp-includes', r'wordpress',
        r'drupal', r'joomla', r'sites/default/files',
        r'magento', r'shopify', r'prestashop',
        r'django', r'rails', r'laravel', r'symfony',
    ]

    DYNAMIC_URL_PATTERNS = [
        r'/api/', r'/graphql', r'/v\d+/', r'\?[a-z_]+=\d+',
        r'/user/\d+', r'/post/\d+', r'/product/\d+', r'/search\?',
        r'/login', r'/register', r'/signup', r'/signin', r'/auth/',
        r'/dashboard', r'/admin', r'/profile', r'/account',
    ]

    @classmethod
    def detect(cls, target):
        """Run multi-signal detection. Returns page_type, confidence, scan_strategy, module lists."""
        if not REQUESTS_AVAILABLE:
            return cls._default_dynamic()

        base_url = f'https://{target}'
        signals = {'static': [], 'dynamic': []}
        static_score = 0
        dynamic_score = 0

        log('info', f'[PAGE-TYPE] Detecting page type for {target}')

        try:
            r = req_lib.get(base_url, timeout=10, verify=False,
                            headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'})
            content_type = r.headers.get('Content-Type', '')
            server_header = r.headers.get('Server', '').lower()
            x_powered_by = r.headers.get('X-Powered-By', '').lower()
            body = r.text
            cookies = r.cookies

            for kw in cls.DYNAMIC_SERVER_KEYWORDS:
                if kw in server_header or kw in x_powered_by:
                    dynamic_score += 2
                    signals['dynamic'].append(f'Server header indicates app server: {kw}')
                    break
            else:
                if server_header in ('nginx', 'apache', 'lighttpd', 'caddy'):
                    static_score += 1
                    signals['static'].append(f'Static file server: {server_header}')

            if 'application/json' in content_type:
                dynamic_score += 3
                signals['dynamic'].append('Root returns JSON (API endpoint)')
            elif 'text/html' in content_type:
                static_score += 0.5
                signals['static'].append('Root returns HTML')

            cache_control = r.headers.get('Cache-Control', '')
            etag = r.headers.get('ETag', '')
            last_modified = r.headers.get('Last-Modified', '')
            if ('max-age' in cache_control or 'public' in cache_control) and (etag or last_modified):
                static_score += 2
                signals['static'].append('Cache-Control+ETag/Last-Modified (typical of static CDN)')
            if 'no-store' in cache_control or 'no-cache' in cache_control:
                dynamic_score += 1.5
                signals['dynamic'].append('Cache-Control: no-store/no-cache (typical of dynamic auth pages)')

            for cookie in cookies:
                if cookie.name.lower() in cls.SESSION_COOKIE_NAMES:
                    dynamic_score += 3
                    signals['dynamic'].append(f'Session cookie set: {cookie.name}')
                    break

            body_lower = body.lower()
            form_count = body_lower.count('<form')
            if form_count > 0:
                dynamic_score += 3 * form_count
                signals['dynamic'].append(f'{form_count} HTML form(s) detected (login/search/input)')

            input_count = body_lower.count('<input')
            if input_count > 2:
                dynamic_score += 1.5
                signals['dynamic'].append(f'{input_count} <input> elements (interactive page)')

            if 'csrf' in body_lower or 'xsrf' in body_lower or '_token' in body_lower:
                dynamic_score += 2
                signals['dynamic'].append('CSRF token found in page (server-side session)')

            for pat in cls.JS_FRAMEWORK_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    dynamic_score += 2
                    signals['dynamic'].append(f'JS framework detected: {pat[:30]}')
                    break

            for pat in cls.CMS_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    dynamic_score += 2.5
                    signals['dynamic'].append(f'CMS/framework detected: {pat}')
                    break

            for pat in cls.DYNAMIC_URL_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    dynamic_score += 1
                    signals['dynamic'].append(f'Dynamic URL pattern in page: {pat}')

            if 'websocket' in body_lower or 'ws://' in body_lower or 'wss://' in body_lower:
                dynamic_score += 1.5
                signals['dynamic'].append('WebSocket references found (real-time dynamic app)')

            if 'graphql' in body_lower or '__typename' in body_lower:
                dynamic_score += 2
                signals['dynamic'].append('GraphQL references detected')

            if 'id="root"' in body_lower or 'id="app"' in body_lower or 'id="__next"' in body_lower:
                dynamic_score += 2.5
                signals['dynamic'].append('SPA mount point detected (#root/#app/#__next)')

            if len(body) < 2000 and form_count == 0 and 'script' not in body_lower:
                static_score += 2
                signals['static'].append('Very small page, no scripts, no forms (likely static)')

        except Exception as e:
            log('warn', f'[PAGE-TYPE] Root fetch failed: {e}')
            return cls._default_dynamic()

        try:
            r_api = req_lib.get(f'{base_url}/api', timeout=5, verify=False)
            if 'application/json' in r_api.headers.get('Content-Type', ''):
                dynamic_score += 3
                signals['dynamic'].append('JSON API endpoint at /api responds')
        except Exception:
            pass

        for login_path in ['/login', '/signin', '/auth/login', '/user/login']:
            try:
                r_login = req_lib.get(f'{base_url}{login_path}', timeout=5, verify=False, allow_redirects=True)
                if r_login.status_code in (200, 302):
                    login_body = r_login.text.lower()
                    if 'password' in login_body or 'username' in login_body or 'email' in login_body:
                        dynamic_score += 4
                        signals['dynamic'].append(f'Login page found at {login_path}')
                        break
            except Exception:
                pass

        try:
            r_robots = req_lib.get(f'{base_url}/robots.txt', timeout=5, verify=False)
            if r_robots.status_code == 200 and r_robots.text:
                disallowed = [line.split(': ', 1)[1].strip()
                              for line in r_robots.text.splitlines()
                              if line.lower().startswith('disallow:')]
                dynamic_paths = [p for p in disallowed
                                 if not any(p.endswith(ext) for ext in cls.STATIC_EXTENSIONS)]
                if dynamic_paths:
                    dynamic_score += 1.5
                    signals['dynamic'].append(f'Robots.txt disallows {len(dynamic_paths)} dynamic paths')
                else:
                    static_score += 1
                    signals['static'].append('Robots.txt contains only static file paths')
        except Exception:
            pass

        try:
            r_json_req = req_lib.get(base_url, timeout=5, verify=False,
                                     headers={'Accept': 'application/json'})
            r_html_req = req_lib.get(base_url, timeout=5, verify=False,
                                     headers={'Accept': 'text/html'})
            if (r_json_req.status_code == r_html_req.status_code and
                    abs(len(r_json_req.text) - len(r_html_req.text)) < 50):
                static_score += 2
                signals['static'].append('Same response regardless of Accept header (no content negotiation)')
            elif 'application/json' in r_json_req.headers.get('Content-Type', ''):
                dynamic_score += 2
                signals['dynamic'].append('Content negotiation: server returns JSON on Accept: application/json')
        except Exception:
            pass

        total = static_score + dynamic_score
        if total == 0:
            return cls._default_dynamic()

        dynamic_ratio = dynamic_score / total
        static_ratio  = static_score  / total
        confidence     = max(dynamic_ratio, static_ratio)

        is_spa = (dynamic_score > 5 and
                  any('SPA mount point' in s or 'JS framework' in s for s in signals['dynamic']) and
                  not any('Session cookie' in s or 'CSRF token' in s for s in signals['dynamic']))

        if is_spa:
            page_type = 'spa'
            scan_strategy = 'spa_full'
        elif dynamic_ratio >= 0.60:
            page_type = 'dynamic'
            scan_strategy = 'dynamic_full'
        elif static_ratio >= 0.75:
            page_type = 'static'
            scan_strategy = 'static_hardening'
        else:
            page_type = 'hybrid'
            scan_strategy = 'hybrid'

        recommended, skip = cls._get_module_strategy(page_type, signals)

        result = {
            'page_type': page_type,
            'confidence': round(confidence, 2),
            'static_score': round(static_score, 1),
            'dynamic_score': round(dynamic_score, 1),
            'signals': signals,
            'scan_strategy': scan_strategy,
            'recommended_modules': recommended,
            'skip_modules': skip,
        }

        log('ok', f'[PAGE-TYPE] Result: {page_type.upper()} (confidence={confidence:.0%}, '
                  f'static={static_score:.1f}, dynamic={dynamic_score:.1f}) → strategy={scan_strategy}')
        log('info', f'[PAGE-TYPE] Dynamic signals: {"; ".join(signals["dynamic"][:5])}')
        log('info', f'[PAGE-TYPE] Static signals:  {"; ".join(signals["static"][:5])}')

        return result

    @classmethod
    def _get_module_strategy(cls, page_type, signals):
        """Return (recommended_modules, skip_modules) for the detected page type."""
        if page_type == 'static':
            recommended = [
                'SSL/TLS', 'Security Headers', 'DNS', 'WHOIS', 'Port Scan',
                'Tech Detection', 'Subdomains', 'Subdomain Enum', 'Wayback',
                'Email Security', 'Takeover', 'Subdomain Takeover Verify',
                'Cloud Storage', 'Secrets Scan', 'JS Analysis', 'Supply Chain',
                'KEV', 'Git Leaks', 'Correlation', 'Attack Graph',
            ]
            skip = [
                'SQLi Manual', 'XSS Manual', 'SSRF Manual', 'Command Injection',
                'SSTI', 'File Inclusion LFI/RFI', 'SQLMap', 'Dalfox XSS',
                'Open Redirect Manual', 'XXE Injection', 'Advanced XXE',
                'Cache Poisoning', 'Insecure Deserialization', 'NoSQL Injection',
                'LDAP Injection', 'File Upload', 'Header Injection', 'Prototype Pollution',
                'Session Fixation', 'JWT Advanced', 'API Abuse', 'OAuth Testing',
                'OAuth Attack', 'Auth Testing', 'Web Crawler', 'Web Scanner',
                'Credential Stuffing', '2FA Bypass', 'IDOR Deep Test', 'SQLi Deep Test',
                'Business Logic', 'Race Condition', 'Request Smuggling',
                'WebSocket Testing', 'Mass Assignment', 'Clickjacking Deep',
                'DNS Rebinding', 'Bot Detection', 'DDoS Readiness',
                'Firewall Bypass', 'WAF Bypass', 'Host Header Injection',
                'Deep Endpoint Crawl', 'Unauth Endpoint Analysis',
                'Enhanced Subdomain Enum',
            ]
            return recommended, skip

        elif page_type in ('dynamic', 'hybrid'):
            recommended = [
                'SSL/TLS', 'Security Headers', 'DNS', 'Web Crawler',
                'SQLi Manual', 'XSS Manual', 'SSRF Manual', 'Command Injection',
                'SSTI', 'File Inclusion LFI/RFI', 'SQLMap', 'Dalfox XSS',
                'Open Redirect Manual', 'XXE Injection', 'Advanced XXE',
                'Cache Poisoning', 'Insecure Deserialization', 'NoSQL Injection',
                'LDAP Injection', 'File Upload', 'Header Injection', 'Prototype Pollution',
                'Session Fixation', 'JWT Advanced', 'API Abuse', 'OAuth Testing',
                'OAuth Attack', 'Auth Testing', 'Credential Stuffing', '2FA Bypass',
                'IDOR Deep Test', 'SQLi Deep Test', 'Business Logic', 'Race Condition',
                'Request Smuggling', 'WebSocket Testing', 'Mass Assignment',
                'Clickjacking Deep', 'Host Header Injection', 'Deep Endpoint Crawl',
                'Unauth Endpoint Analysis', 'Token & Secret Hunt',
                'CORS', 'WAF Fingerprint', 'Port Scan', 'Tech Detection',
                'Subdomains', 'Subdomain Enum', 'Enhanced Subdomain Enum',
                'Wayback', 'Email Security', 'Supply Chain', 'KEV', 'Git Leaks',
                'Secrets Scan', 'JS Analysis', 'Gitleaks Secrets', 'TruffleHog Deep',
                'Semgrep SAST', 'WHOIS', 'Net Sec', 'Dark Web', 'OOB Detection',
                'Cloud Storage', 'Container Security', 'Kubernetes Security',
                'Correlation', 'Attack Graph',
            ]
            return recommended, []

        elif page_type == 'spa':
            recommended = [
                'SSL/TLS', 'Security Headers', 'DNS', 'Web Crawler',
                'JS Analysis', 'API Abuse', 'JWT Advanced', 'OAuth Testing', 'OAuth Attack',
                'CORS', 'SSRF Manual', 'SQLi Manual', 'XSS Manual', 'Dalfox XSS',
                'Open Redirect Manual', 'IDOR Deep Test', 'Business Logic',
                'Race Condition', 'WebSocket Testing', 'Prototype Pollution',
                'WAF Fingerprint', 'Port Scan', 'Tech Detection',
                'Subdomains', 'Subdomain Enum', 'Wayback', 'Secrets Scan',
                'Gitleaks Secrets', 'TruffleHog Deep', 'Supply Chain', 'KEV', 'WHOIS',
                'Token & Secret Hunt', 'Correlation', 'Attack Graph',
            ]
            skip = [
                'SQLMap', 'SSTI', 'File Upload', 'LDAP Injection',
                'XXE Injection', 'Advanced XXE', 'Command Injection',
                'File Inclusion LFI/RFI', 'Insecure Deserialization',
                'Cache Poisoning', 'Session Fixation', 'Header Injection',
                'Credential Stuffing', 'Bot Detection', 'DDoS Readiness',
                'Net Sec', 'Dark Web',
            ]
            return recommended, skip

        return [], []

    @classmethod
    def _default_dynamic(cls):
        """Fallback: treat as dynamic when detection is inconclusive."""
        return {
            'page_type': 'dynamic',
            'confidence': 0.5,
            'static_score': 0,
            'dynamic_score': 0,
            'signals': {'static': [], 'dynamic': ['Detection inconclusive — defaulting to dynamic (safe)']},
            'scan_strategy': 'dynamic_full',
            'recommended_modules': [],
            'skip_modules': [],
        }


def classify_target(target, tech_data, crawl_data, waf_data, discovery_data):
    """Classify a target as static/dynamic/mixed from Phase 1+2A signals.

    Returns (classification, confidence, signals).
    """
    signals = {
        'forms': 0, 'inputs': 0, 'api_endpoints': 0,
        'js_files': 0, 'parameters': 0,
        'websocket_endpoints': 0, 'graphql_endpoints': 0,
        'tech_categories': set(),
    }
    if isinstance(crawl_data, dict):
        signals['forms'] = len(crawl_data.get('forms') or [])
        signals['inputs'] = len(crawl_data.get('inputs') or [])
        signals['api_endpoints'] = len(crawl_data.get('api_endpoints') or [])
        signals['js_files'] = len(crawl_data.get('js_files') or [])
        signals['parameters'] = len(crawl_data.get('parameters') or [])
        signals['websocket_endpoints'] = len(crawl_data.get('websocket_endpoints') or [])
        signals['graphql_endpoints'] = len(crawl_data.get('graphql_endpoints') or [])

    SERVER_TECH_KEYWORDS = {
        'php', 'asp.net', 'jsp', 'servlet', 'node.js', 'django',
        'flask', 'rails', 'spring', 'tomcat', 'iis', 'wordpress',
        'laravel', 'drupal', 'joomla', 'magento', 'fastapi',
    }
    DYNAMIC_TECH_KEYWORDS = {
        'react', 'angular', 'vue.js', 'next.js', 'nuxt.js',
        'graphql', 'strapi', 'ghost', 'express',
    }
    if isinstance(tech_data, dict):
        for tech in tech_data.get('technologies', []):
            if isinstance(tech, dict):
                name = (tech.get('name') or '').lower()
                if name:
                    signals['tech_categories'].add(name)

    tech_str = ' '.join(signals['tech_categories'])
    has_server_side = any(k in tech_str for k in SERVER_TECH_KEYWORDS)
    has_dynamic_framework = any(k in tech_str for k in DYNAMIC_TECH_KEYWORDS)

    dynamic_score = 0
    if signals['forms'] > 0:            dynamic_score += 3
    if signals['inputs'] > 0:           dynamic_score += 2
    if signals['api_endpoints'] > 0:    dynamic_score += 3
    if signals['websocket_endpoints']:  dynamic_score += 2
    if signals['graphql_endpoints']:    dynamic_score += 3
    if signals['parameters'] > 0:       dynamic_score += 2
    if has_server_side:                 dynamic_score += 4
    if has_dynamic_framework:           dynamic_score += 2
    if signals['js_files'] > 0:         dynamic_score += 1
    if waf_data and waf_data.get('wafs_detected'):
        dynamic_score += 1

    if dynamic_score >= 5:
        classification = 'dynamic'
        confidence = min(0.6 + dynamic_score * 0.05, 0.95)
    elif dynamic_score >= 2:
        classification = 'mixed'
        confidence = 0.5 + dynamic_score * 0.04
    else:
        classification = 'static'
        confidence = max(0.95 - dynamic_score * 0.1, 0.5)

    return classification, round(confidence, 2), signals


def recommend_modules(classification, scanning_modules, signals):
    """Filter candidate modules based on target classification."""
    if not ADAPTIVE_ROUTING or classification == 'dynamic':
        return scanning_modules, {'kept': len(scanning_modules), 'dropped': 0,
                                  'reason': 'dynamic-or-flag-off'}

    if classification == 'static':
        kept, dropped = [], []
        for name, func in scanning_modules:
            if name in DYNAMIC_ONLY_MODULES:
                dropped.append(name)
            else:
                kept.append((name, func))
        tech_list = sorted(t for t in signals.get('tech_categories', set()) if t)
        return kept, {
            'kept': len(kept),
            'dropped': len(dropped),
            'reason': (f'static-site (forms={signals["forms"]}, '
                       f'api={signals["api_endpoints"]}, '
                       f'server_tech={tech_list})'),
        }

    return scanning_modules, {'kept': len(scanning_modules), 'dropped': 0,
                              'reason': 'mixed-classification'}


def apply_adaptive_routing(scanning_modules, phase1_data):
    """Top-level entry point. Returns (filtered_modules, routing_meta)."""
    classification, confidence, signals = classify_target(
        target=phase1_data.get('target', ''),
        tech_data=phase1_data.get('tech_data', {}),
        crawl_data=phase1_data.get('crawl_data', {}),
        waf_data=phase1_data.get('waf_data', {}),
        discovery_data=phase1_data.get('discovery_data', {}),
    )
    filtered, meta = recommend_modules(classification, scanning_modules, signals)
    kept_names = {m for m, _ in filtered}
    routing = {
        'enabled': ADAPTIVE_ROUTING,
        'classification': classification,
        'confidence': confidence,
        'signals': {k: (sorted(v) if isinstance(v, set) else v)
                    for k, v in signals.items()},
        'modules_kept': meta['kept'],
        'modules_dropped': meta['dropped'],
        'dropped_names': [n for n, _ in scanning_modules if n not in kept_names],
        'reason': meta['reason'],
    }
    return filtered, routing
