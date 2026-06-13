"""Web security modules — HTTP headers, CORS, WAF, firewall, bot detection."""
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
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE, BS4_AVAILABLE, BeautifulSoup, DNS_AVAILABLE
from core.logger import log

try:
    import dns.resolver
except ImportError:
    dns = None

def run_header_module(target):
    log('info', f'[HEADERS] Fetching HTTP headers from {target}')
    header_data = {}
    try:
        if REQUESTS_AVAILABLE:
            for proto in ('https', 'http'):
                url = f'{proto}://{target}'
                try:
                    r = req_lib.get(url, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0 INFOSEC Recon'}, allow_redirects=True)
                    header_data['url'] = url
                    header_data['status'] = r.status_code
                    header_data['server'] = r.headers.get('Server', '')
                    header_data['powered_by'] = r.headers.get('X-Powered-By', '')
                    header_data['waf'] = ''
                    cookies_data = []
                    for c in r.cookies:
                        cookies_data.append({'name': c.name, 'secure': c.secure, 'httponly': c.has_nonstandard_attr('httponly') or 'rest' in dir(c)})
                    header_data['cookies'] = cookies_data
                    security_headers = ['Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','Referrer-Policy','Permissions-Policy']
                    if proto == 'https':
                        security_headers.append('Strict-Transport-Security')
                    missing = [h for h in security_headers if h not in r.headers]
                    header_data['missing_security'] = missing
                    if missing:
                        log('warn', f'[HEADERS] Missing security headers: {", ".join(missing)}')
                        for hdr in missing:
                            add_finding('medium', f'Missing security header: {hdr}',
                                sub=f'The {hdr} header is not present in HTTP response',
                                asset=url, cve='', cvss='5.0', owasp='A05', mitre='T1595')
                    log('ok', f'[HEADERS] {url} — {r.status_code} — Server: {r.headers.get("Server","N/A")}')
                    break
                except Exception as e:
                    log('dim', f'[HEADERS] {proto}://{target}: {e}')
        else:
            log('warn', '[HEADERS] requests library not available')
    except Exception as e:
        log('err', f'[HEADERS] Error: {e}')
    with LOCK:
        scan_state['header_data'] = header_data
    set_progress('headers', 100)

# ─── TECH DETECTION MODULE ────────────────────────────────────────────────────
TECH_PATTERNS = [
    # Web Servers
    ('nginx', 'Nginx', 'Web Server', [r'nginx/([\d.]+)', r'nginx']),
    ('apache', 'Apache HTTP Server', 'Web Server', [r'Apache(?:/([\d.]+))?', r'Apache-HttpClient']),
    ('iis', 'Microsoft IIS', 'Web Server', [r'IIS/([\d.]+)', r'Microsoft-IIS']),
    ('openresty', 'OpenResty', 'Web Server', [r'openresty/([\d.]+)']),
    ('caddy', 'Caddy', 'Web Server', [r'Caddy(?:/([\d.]+))?']),
    ('lighttpd', 'Lighttpd', 'Web Server', [r'lighttpd(?:/([\d.]+))?']),
    ('litespeed', 'LiteSpeed', 'Web Server', [r'LiteSpeed(?:/([\d.]+))?']),
    ('h2o', 'H2O', 'Web Server', [r'h2o/([\d.]+)']),
    ('ats', 'Apache Traffic Server', 'Web Server', [r'ATS/([\d.]+)']),
    ('envoy', 'Envoy Proxy', 'Proxy', [r'envoy(?:/([\d.]+))?']),
    ('traefik', 'Traefik', 'Proxy', [r'Traefik(?:/([\d.]+))?']),

    # Application Servers
    ('tomcat', 'Apache Tomcat', 'Application Server', [r'Apache Tomcat/([\d.]+)']),
    ('jetty', 'Jetty', 'Application Server', [r'Jetty\(([\d.]+)?\)']),
    ('jboss', 'JBoss/WildFly', 'Application Server', [r'JBoss', r'WildFly']),
    ('weblogic', 'Oracle WebLogic', 'Application Server', [r'WebLogic(?:/([\d.]+))?']),
    ('gunicorn', 'Gunicorn', 'Application Server', [r'gunicorn/([\d.]+)']),
    ('uwsgi', 'uWSGI', 'Application Server', [r'uWSGI']),
    ('puma', 'Puma', 'Application Server', [r'Puma(?:/([\d.]+))?']),
    ('passenger', 'Phusion Passenger', 'Application Server', [r'Passenger(?:/([\d.]+))?']),
    ('undertow', 'Undertow', 'Application Server', [r'Undertow(?:/([\d.]+))?']),

    # CDN & WAF
    ('cloudflare', 'Cloudflare', 'CDN/WAF', [r'cloudflare', r'__cfduid', r'cf-ray']),
    ('akamai', 'Akamai', 'CDN', [r'akamai', r'AkamaiGHost']),
    ('fastly', 'Fastly', 'CDN', [r'fastly', r'Fastly-SSL']),
    ('cloudfront', 'AWS CloudFront', 'CDN', [r'cloudfront', r'X-Amz-Cf-Id']),
    ('incapsula', 'Imperva/Incapsula', 'WAF', [r'incapsula', r'incap_ses']),
    ('sucuri', 'Sucuri', 'WAF', [r'sucuri', r'cloudproxy']),
    ('wordfence', 'Wordfence', 'WAF', [r'wordfence', r'wfvt_']),
    ('barracuda', 'Barracuda WAF', 'WAF', [r'barracuda']),
    ('f5', 'F5 BIG-IP', 'Load Balancer', [r'F5', r'BIG-IP', r'BigIP']),
    ('citrix', 'Citrix NetScaler', 'Load Balancer', [r'NetScaler', r'Citrix']),
    ('azure-frontdoor', 'Azure Front Door', 'CDN', [r'x-azure-ref', r'azurefd']),
    ('stackpath', 'StackPath', 'CDN', [r'stackpath']),

    # Languages & Runtimes
    ('php', 'PHP', 'Language', [r'PHP/([\d.]+)', r'X-Powered-By: PHP', r'\.php']),
    ('python', 'Python', 'Language', [r'Python/([\d.]+)', r'X-Powered-By: Python']),
    ('ruby', 'Ruby', 'Language', [r'Ruby/([\d.]+)', r'X-Powered-By: Phusion Passenger']),
    ('java', 'Java', 'Language', [r'Java/([\d.]+)', r'X-Powered-By: Servlet']),
    ('asp.net', 'ASP.NET', 'Framework', [r'ASP\.NET(?:/([\d.]+))?', r'X-AspNet-Version', r'X-Powered-By: ASP\.NET']),
    ('nodejs', 'Node.js', 'Runtime', [r'Node\.?(?:js)?/([\d.]+)', r'X-Powered-By: Express']),
    ('perl', 'Perl', 'Language', [r'Perl/([\d.]+)']),
    ('go', 'Go', 'Language', [r'Go/([\d.]+)']),
    ('rust', 'Rust', 'Language', [r'actix', r'rocket', r'warp']),
    ('dotnet', '.NET', 'Framework', [r'\.NET(?: Framework)?(?:/([\d.]+))?']),

    # Web Frameworks
    ('express', 'Express.js', 'Web Framework', [r'Express(?:/([\d.]+))?']),
    ('django', 'Django', 'Web Framework', [r'Django/([\d.]+)', r'csrftoken', r'django']),
    ('flask', 'Flask', 'Web Framework', [r'Flask(?:/([\d.]+))?', r'werkzeug']),
    ('rails', 'Ruby on Rails', 'Web Framework', [r'Rails/([\d.]+)', r'_rails_session']),
    ('laravel', 'Laravel', 'Web Framework', [r'laravel', r'XSRF-TOKEN']),
    ('spring', 'Spring Framework', 'Web Framework', [r'Spring(?:/([\d.]+))?', r'X-Application-Context']),
    ('symfony', 'Symfony', 'Web Framework', [r'Symfony(?:/([\d.]+))?']),
    ('fastapi', 'FastAPI', 'Web Framework', [r'fastapi', r'uvicorn']),
    ('nextjs', 'Next.js', 'Web Framework', [r'next(?:\.js)?(?:/([\d.]+))?', r'_next/', r'__next']),
    ('nuxtjs', 'Nuxt.js', 'Web Framework', [r'nuxt(?:\.js)?(?:/([\d.]+))?', r'_nuxt/']),
    ('gatsby', 'Gatsby', 'Web Framework', [r'gatsby(?:/([\d.]+))?']),
    ('django-rest', 'Django REST Framework', 'API Framework', [r'djangorestframework', r'DRF']),
    ('graphql', 'GraphQL', 'API', [r'graphql', r'__schema', r'query\s*\{']),

    # CMS
    ('wordpress', 'WordPress', 'CMS', [r'wp-content', r'wp-admin', r'WordPress(?:/([\d.]+))?', r'wp-json']),
    ('drupal', 'Drupal', 'CMS', [r'Drupal(?:/([\d.]+))?', r'X-Generator: Drupal']),
    ('joomla', 'Joomla', 'CMS', [r'Joomla(?:/([\d.]+))?', r'/administrator/']),
    ('magento', 'Magento', 'E-commerce', [r'Magento(?:/([\d.]+))?', r'mage/', r'mage-cache-storage']),
    ('shopify', 'Shopify', 'E-commerce', [r'Shopify', r'cdn\.shopify\.com']),
    ('woocommerce', 'WooCommerce', 'E-commerce', [r'woocommerce', r'wc-']),
    ('prestashop', 'PrestaShop', 'E-commerce', [r'PrestaShop(?:/([\d.]+))?']),
    ('ghost', 'Ghost CMS', 'CMS', [r'ghost(?:/([\d.]+))?', r'ghost-']),
    ('contentful', 'Contentful', 'CMS', [r'contentful', r'ctfl']),
    ('strapi', 'Strapi', 'CMS', [r'strapi(?:/([\d.]+))?', r'admin/strapi']),
    ('typo3', 'TYPO3', 'CMS', [r'TYPO3(?:/([\d.]+))?']),

    # JavaScript Frameworks
    ('react', 'React', 'JavaScript Framework', [r'react(?:\.production\.min\.js|/([\d.]+))', r'_reactRoot', r'data-reactroot']),
    ('angular', 'Angular', 'JavaScript Framework', [r'angular(?:\.min\.js)?(?:/([\d.]+))?', r'ng-version', r'ng-app']),
    ('vue', 'Vue.js', 'JavaScript Framework', [r'vue(?:\.min\.js)?(?:/([\d.]+))?', r'Vue(?:/([\d.]+))?', r'data-v-']),
    ('svelte', 'Svelte', 'JavaScript Framework', [r'svelte(?:/([\d.]+))?', r'__svelte']),
    ('backbone', 'Backbone.js', 'JavaScript Framework', [r'backbone(?:\.min\.js)?(?:/([\d.]+))?']),
    ('ember', 'Ember.js', 'JavaScript Framework', [r'ember(?:\.min\.js)?(?:/([\d.]+))?']),
    ('preact', 'Preact', 'JavaScript Framework', [r'preact(?:/([\d.]+))?']),
    ('jquery', 'jQuery', 'JavaScript Library', [r'jquery[.-]?([\d.]+)?\.min\.js', r'jQuery v([\d.]+)', r'jquery']),
    ('lodash', 'Lodash', 'JavaScript Library', [r'lodash(?:\.min\.js)?(?:/([\d.]+))?']),
    ('moment', 'Moment.js', 'JavaScript Library', [r'moment(?:\.min\.js)?(?:/([\d.]+))?']),
    ('axios', 'Axios', 'JavaScript Library', [r'axios(?:\.min\.js)?(?:/([\d.]+))?']),

    # CSS Frameworks
    ('bootstrap', 'Bootstrap', 'CSS Framework', [r'bootstrap(?:\.min\.css)?(?:/([\d.]+))?', r'bootstrap/([\d.]+)']),
    ('tailwind', 'Tailwind CSS', 'CSS Framework', [r'tailwind(?:css)?(?:/([\d.]+))?']),
    ('fontawesome', 'Font Awesome', 'Icon Library', [r'font-?awesome(?:/([\d.]+))?']),
    ('material', 'Material Design', 'CSS Framework', [r'material(?:-design)?(?:/([\d.]+))?']),
    ('bulma', 'Bulma', 'CSS Framework', [r'bulma(?:/([\d.]+))?']),

    # Databases & Cache
    ('mysql', 'MySQL', 'Database', [r'MySQL', r'mysql', r'mysqlnd']),
    ('postgresql', 'PostgreSQL', 'Database', [r'PostgreSQL', r'postgres']),
    ('mongodb', 'MongoDB', 'Database', [r'MongoDB', r'mongo']),
    ('redis', 'Redis', 'Cache/Database', [r'redis(?:/([\d.]+))?']),
    ('memcached', 'Memcached', 'Cache', [r'memcached(?:/([\d.]+))?']),
    ('elasticsearch', 'Elasticsearch', 'Search Engine', [r'elasticsearch', r'elastic']),
    ('cassandra', 'Apache Cassandra', 'Database', [r'Cassandra(?:/([\d.]+))?']),
    ('couchdb', 'CouchDB', 'Database', [r'CouchDB(?:/([\d.]+))?']),

    # Message Queues
    ('rabbitmq', 'RabbitMQ', 'Message Queue', [r'RabbitMQ(?:/([\d.]+))?']),
    ('kafka', 'Apache Kafka', 'Message Queue', [r'Kafka(?:/([\d.]+))?']),
    ('activemq', 'Apache ActiveMQ', 'Message Queue', [r'ActiveMQ(?:/([\d.]+))?']),

    # Analytics & Tracking
    ('google-analytics', 'Google Analytics', 'Analytics', [r'google-analytics\.com', r'ga\.js', r'analytics\.js', r'gtag']),
    ('google-tagmanager', 'Google Tag Manager', 'Analytics', [r'googletagmanager\.com', r'gtm\.js']),
    ('hotjar', 'Hotjar', 'Analytics', [r'hotjar\.com', r'hj\(']),
    ('segment', 'Segment', 'Analytics', [r'segment\.com', r'analytics\.load']),
    ('mixpanel', 'Mixpanel', 'Analytics', [r'mixpanel\.com', r'mixpanel\.init']),
    ('newrelic', 'New Relic', 'Monitoring', [r'newrelic\.com', r'nr-']),
    ('sentry', 'Sentry', 'Error Tracking', [r'sentry\.io', r'Raven\.config']),
    ('datadog', 'Datadog', 'Monitoring', [r'datadoghq\.com', r'DD_RUM']),
    ('rollbar', 'Rollbar', 'Error Tracking', [r'rollbar\.com', r'Rollbar\.init']),

    # Security
    ('recaptcha', 'Google reCAPTCHA', 'Security', [r'recaptcha', r'g-recaptcha']),
    ('hcaptcha', 'hCaptcha', 'Security', [r'hcaptcha', r'h-captcha']),
    ('turnstile', 'Cloudflare Turnstile', 'Security', [r'turnstile', r'cf-turnstile']),

    # Miscellaneous
    ('varnish', 'Varnish Cache', 'Cache', [r'Varnish(?:/([\d.]+))?']),
    ('haproxy', 'HAProxy', 'Load Balancer', [r'HAProxy(?:/([\d.]+))?']),
    ('elb', 'AWS ELB', 'Load Balancer', [r'AWSELB', r'awselb']),
    ('consul', 'HashiCorp Consul', 'Service Mesh', [r'consul(?:/([\d.]+))?']),
    ('kubernetes', 'Kubernetes', 'Container Orchestration', [r'kubernetes', r'kubectl']),
    ('docker', 'Docker', 'Containerization', [r'docker', r'Docker']),
    ('terraform', 'Terraform', 'IaC', [r'terraform']),
    ('ansible', 'Ansible', 'Configuration Management', [r'ansible']),
    ('grafana', 'Grafana', 'Monitoring', [r'grafana(?:/([\d.]+))?']),
    ('prometheus', 'Prometheus', 'Monitoring', [r'prometheus(?:/([\d.]+))?']),
    ('kibana', 'Kibana', 'Visualization', [r'kibana(?:/([\d.]+))?']),
    ('jenkins', 'Jenkins', 'CI/CD', [r'jenkins(?:/([\d.]+))?']),
    ('gitlab', 'GitLab', 'DevOps', [r'gitlab(?:/([\d.]+))?']),
    ('github', 'GitHub', 'DevOps', [r'github\.com']),
    ('bitbucket', 'Bitbucket', 'DevOps', [r'bitbucket']),
]

# Known vulnerable versions (CVE mappings)
VULNERABLE_VERSIONS = {
    'nginx': {
        '1.21.0': ['CVE-2021-23017', 'DNS resolver off-by-one'],
        '1.20.0': ['CVE-2021-23017', 'DNS resolver vulnerability'],
        '1.19.0': ['CVE-2020-36391', 'HTTP/2 vulnerability'],
    },
    'apache': {
        '2.4.49': ['CVE-2021-41773', 'Path traversal'],
        '2.4.50': ['CVE-2021-42013', 'Path traversal bypass'],
        '2.4.46': ['CVE-2021-40438', 'SSRF via mod_proxy'],
    },
    'php': {
        '7.4.0': ['CVE-2021-21702', 'SSRF in SOAP'],
        '7.3.0': ['CVE-2020-7068', 'Null pointer dereference'],
        '8.0.0': ['CVE-2021-21705', 'SSRF in FILTER_VALIDATE_URL'],
    },
    'wordpress': {
        '5.7.0': ['CVE-2021-29447', 'XXE in Media Library'],
        '5.6.0': ['CVE-2021-29450', 'SQL Injection in WP_Query'],
        '5.5.0': ['CVE-2020-28035', 'Prototype pollution in lodash'],
    },
    'jquery': {
        '1.9.0': ['CVE-2020-11022', 'XSS in htmlPrefilter'],
        '1.8.0': ['CVE-2019-11358', 'Prototype pollution'],
        '2.0.0': ['CVE-2020-11023', 'XSS in jQuery.html()'],
    },
    'tomcat': {
        '9.0.0': ['CVE-2021-25329', 'Incomplete fix for CVE-2020-1938'],
        '8.5.0': ['CVE-2021-25122', 'Response mix-up with h2c'],
        '7.0.0': ['CVE-2021-24122', 'Information disclosure'],
    },
    'spring': {
        '5.3.0': ['CVE-2022-22965', 'Spring4Shell RCE'],
        '5.2.0': ['CVE-2021-22118', 'Local privilege escalation'],
    },
    'django': {
        '3.2.0': ['CVE-2021-35042', 'SQL Injection'],
        '3.1.0': ['CVE-2021-33203', 'Directory traversal'],
        '2.2.0': ['CVE-2021-33571', 'URL validation bypass'],
    },
    'laravel': {
        '8.0.0': ['CVE-2021-3129', 'RCE via Ignition'],
        '7.0.0': ['CVE-2021-21263', 'Mass assignment bypass'],
    },
    'log4j': {
        '2.14.0': ['CVE-2021-44228', 'Log4Shell RCE - CRITICAL'],
        '2.15.0': ['CVE-2021-45046', 'Log4Shell bypass'],
    },
    'openssl': {
        '1.1.1': ['CVE-2022-0778', 'Infinite loop in BN_mod_sqrt'],
        '1.0.2': ['CVE-2021-3449', 'NULL pointer dereference'],
    },
}



def run_advanced_header_module(target):
    log('info', f'[HEADERADV] Deep header and cookie analysis on {target}')
    header_adv = {
        'csp_analysis': {}, 'cookie_audit': [], 'cors_deep': {},
        'hsts_analysis': {}, 'feature_policy': {}, 'referrer_policy': {},
        'permissions_policy': {}, 'coop_coep': {}, 'summary': {},
    }
    if not REQUESTS_AVAILABLE:
        with LOCK:
            scan_state['header_adv_data'] = header_adv
        set_progress('headeradv', 100)
        return

    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    url = f'https://{target}'

    try:
        r = req_lib.get(url, timeout=10, verify=False, headers={'User-Agent': ua})
        headers = r.headers

        # ── CSP Deep Analysis ──
        csp = headers.get('Content-Security-Policy', '')
        if csp:
            csp_issues = []
            directives = {}
            for part in csp.split(';'):
                part = part.strip()
                if part:
                    tokens = part.split()
                    if tokens:
                        directives[tokens[0]] = tokens[1:]

            # Check for unsafe directives
            if "'unsafe-inline'" in csp:
                csp_issues.append({'severity': 'high', 'issue': "unsafe-inline in CSP", 'detail': 'Allows inline scripts/styles, weakening XSS protection'})
            if "'unsafe-eval'" in csp:
                csp_issues.append({'severity': 'high', 'issue': "unsafe-eval in CSP", 'detail': 'Allows eval(), weakening XSS protection'})
            if 'data:' in csp:
                csp_issues.append({'severity': 'medium', 'issue': 'data: URI allowed in CSP', 'detail': 'Data URIs can be used to bypass CSP'})
            if '*' in csp and 'default-src' in csp:
                csp_issues.append({'severity': 'high', 'issue': 'Wildcard default-src', 'detail': 'default-src * allows loading resources from anywhere'})
            if not any(d in csp for d in ['script-src', 'default-src']):
                csp_issues.append({'severity': 'medium', 'issue': 'No script-src directive', 'detail': 'No restriction on script sources'})
            if 'http:' in csp:
                csp_issues.append({'severity': 'medium', 'issue': 'HTTP sources in CSP', 'detail': 'Loading resources over HTTP allows MitM attacks'})

            header_adv['csp_analysis'] = {
                'raw': csp[:500],
                'directives': directives,
                'issues': csp_issues,
                'has_nonce': 'nonce-' in csp,
                'has_hash': 'sha256-' in csp or 'sha384-' in csp or 'sha512-' in csp,
            }
            for issue in csp_issues:
                if issue['severity'] in ('high', 'critical'):
                    add_finding(issue['severity'], f'CSP Issue: {issue["issue"]}',
                        sub=issue['detail'], asset=url,
                        cvss='6.0' if issue['severity'] == 'high' else '8.0',
                        owasp='A05', mitre='T1189',
                        details=f'Content-Security-Policy issue\n{issue["detail"]}\nCSP: {csp[:300]}\n\nRemediation: Remove unsafe-inline and unsafe-eval. Use nonces or hashes for inline scripts.')
                    log('warn', f'[HEADERADV] CSP: {issue["issue"]}')
        else:
            header_adv['csp_analysis'] = {'present': False}
            add_finding('medium', 'No Content-Security-Policy Header',
                sub='CSP header not found', asset=url,
                cvss='5.0', owasp='A05', mitre='T1189',
                details='Content-Security-Policy header is missing.\n\nRemediation: Implement a strict CSP to prevent XSS and data injection attacks.')

        # ── Cookie Security Audit ──
        for cookie in r.cookies:
            cookie_audit = {
                'name': cookie.name,
                'secure': cookie.secure,
                'httponly': 'httponly' in str(cookie).lower() or cookie.has_nonstandard_attr('httponly'),
                'samesite': None,
                'domain': cookie.domain,
                'path': cookie.path,
                'issues': [],
            }
            # Check SameSite
            for attr in str(cookie).split(';'):
                attr = attr.strip().lower()
                if attr.startswith('samesite'):
                    cookie_audit['samesite'] = attr.split('=')[-1].strip() if '=' in attr else 'None'

            # Skip known non-sensitive cookies (language, analytics, preference)
            non_sensitive_cookies = [
                'pll_language', 'wp-wpml_', '_ga', '_gid', '_fbp', '_gcl',
                'language', 'lang', 'locale', 'theme', 'consent', 'cookie',
                '__utm', '_gat', 'NID', 'SID', 'HSID', 'SSID', 'APISID',
                'SAPISID', '1P_JAR', 'ANID', 'IDE', 'DSID', 'FLC', 'AID',
                'TAID', 'exchange_uid', 'ab_test_group', 'optimizely',
            ]
            if cookie.name.lower() in [c.lower() for c in non_sensitive_cookies]:
                log('info', f'[HEADERADV] Cookie {cookie.name}: known non-sensitive cookie, skipping audit')
                continue

            if not cookie_audit['secure']:
                cookie_audit['issues'].append('Missing Secure flag')
            if not cookie_audit['httponly']:
                cookie_audit['issues'].append('Missing HttpOnly flag')
            if not cookie_audit['samesite'] or cookie_audit['samesite'] == 'None':
                cookie_audit['issues'].append('Missing or None SameSite')

            if cookie_audit['issues']:
                add_finding('medium', f'Insecure Cookie: {cookie.name}',
                    sub=f'Cookie missing: {", ".join(cookie_audit["issues"])}', asset=url,
                    cvss='5.0', owasp='A05',
                    details=f'Cookie: {cookie.name}\nIssues: {", ".join(cookie_audit["issues"])}\nSecure: {cookie_audit["secure"]}\nHttpOnly: {cookie_audit["httponly"]}\nSameSite: {cookie_audit["samesite"]}\n\nRemediation: Set Secure, HttpOnly, and SameSite=Lax/Strict on all cookies.')
                log('warn', f'[HEADERADV] Cookie {cookie.name}: {", ".join(cookie_audit["issues"])}')

            header_adv['cookie_audit'].append(cookie_audit)

        # ── HSTS Analysis ──
        hsts = headers.get('Strict-Transport-Security', '')
        if hsts:
            hsts_analysis = {'raw': hsts, 'present': True}
            max_age = re.search(r'max-age=(\d+)', hsts)
            if max_age:
                hsts_analysis['max_age'] = int(max_age.group(1))
                if hsts_analysis['max_age'] < 31536000:
                    add_finding('low', 'HSTS Max-Age Too Short',
                        sub=f'max-age is {hsts_analysis["max_age"]}s (recommended: 31536000s)', asset=url,
                        cvss='3.0', owasp='A05',
                        details=f'HSTS max-age: {hsts_analysis["max_age"]}s\nRecommended: 31536000s (1 year)\n\nRemediation: Increase max-age to at least 31536000 seconds.')
            hsts_analysis['include_subdomains'] = 'includesubdomains' in hsts.lower()
            hsts_analysis['preload'] = 'preload' in hsts.lower()
            if not hsts_analysis['include_subdomains']:
                add_finding('info', 'HSTS Missing includeSubDomains',
                    sub='HSTS does not cover subdomains', asset=url, owasp='A05')
            if not hsts_analysis['preload']:
                add_finding('info', 'HSTS Missing preload',
                    sub='HSTS not eligible for preload list', asset=url, owasp='A05')
        else:
            hsts_analysis = {'present': False}
            add_finding('medium', 'No HSTS Header',
                sub='HTTP Strict-Transport-Security not set', asset=url,
                cvss='4.0', owasp='A05',
                details='HSTS header is missing.\n\nRemediation: Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload')
        header_adv['hsts_analysis'] = hsts_analysis

        # ── CORS Deep Analysis ──
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '')
        cors_issues = []
        if acao == '*':
            cors_issues.append({'severity': 'high', 'issue': 'Wildcard ACAO', 'detail': 'Access-Control-Allow-Origin: * allows any origin to read responses'})
        # NOTE: browsers reject ACAO:* + ACAC:true combinations, but it is still a misconfiguration.
        if acao == '*' and acac.lower() == 'true':
            cors_issues.append({'severity': 'high', 'issue': 'Wildcard ACAO with credentials flag',
                                 'detail': 'Both wildcard origin and credentials flag set — browsers will reject this but it indicates a configuration error'})
        # FP guard: "reflected origin with credentials" requires testing with an attacker-controlled
        # Origin header — checking the homepage response without sending an Origin is NOT sufficient
        # evidence. A fixed ACAO + ACAC:true for the server's own domain is legitimate. Removed.

        header_adv['cors_deep'] = {
            'acao': acao, 'acac': acac,
            'acah': headers.get('Access-Control-Allow-Headers', ''),
            'acam': headers.get('Access-Control-Allow-Methods', ''),
            'issues': cors_issues,
        }
        for issue in cors_issues:
            if issue['severity'] in ('high', 'critical'):
                add_finding(issue['severity'], f'CORS: {issue["issue"]}',
                    sub=issue['detail'], asset=url,
                    cvss='7.0' if issue['severity'] == 'critical' else '5.0',
                    owasp='A05', mitre='T1189',
                    details=f'CORS misconfiguration\n{issue["detail"]}\n\nRemediation: Restrict ACAO to specific trusted origins. Never use wildcard with credentials.')

        # ── COOP / COEP / CORP ──
        coop = headers.get('Cross-Origin-Opener-Policy', '')
        coep = headers.get('Cross-Origin-Embedder-Policy', '')
        corp = headers.get('Cross-Origin-Resource-Policy', '')
        header_adv['coop_coep'] = {
            'coop': coop or 'Not set',
            'coep': coep or 'Not set',
            'corp': corp or 'Not set',
        }
        if not coop:
            add_finding('info', 'Missing Cross-Origin-Opener-Policy',
                sub='COOP header not set - recommended: same-origin', asset=url, owasp='A05')

        # ── Referrer Policy ──
        referrer = headers.get('Referrer-Policy', '')
        if referrer:
            header_adv['referrer_policy'] = {'value': referrer}
            if referrer.lower() in ('unsafe-url', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin'):
                add_finding('low', f'Weak Referrer-Policy: {referrer}',
                    sub='Referrer policy may leak sensitive URLs', asset=url, owasp='A05',
                    details=f'Referrer-Policy: {referrer}\n\nRemediation: Use strict-origin-when-cross-origin or no-referrer.')
        else:
            header_adv['referrer_policy'] = {'present': False}

        # ── Permissions Policy ──
        pp = headers.get('Permissions-Policy', '') or headers.get('Feature-Policy', '')
        if pp:
            header_adv['permissions_policy'] = {'raw': pp[:500], 'present': True}
        else:
            header_adv['permissions_policy'] = {'present': False}
            add_finding('info', 'No Permissions-Policy Header',
                sub='Permissions-Policy not set', asset=url, owasp='A05',
                details='Permissions-Policy header is missing.\n\nRemediation: Restrict browser features (camera, microphone, geolocation) with Permissions-Policy.')

        # ── X-Frame-Options ──
        xfo = headers.get('X-Frame-Options', '')
        if not xfo and 'frame-ancestors' not in csp.lower():
            add_finding('medium', 'Missing Clickjacking Protection',
                sub='Neither X-Frame-Options nor CSP frame-ancestors set', asset=url,
                cvss='5.0', owasp='A05',
                details='No clickjacking protection found.\n\nRemediation: Set X-Frame-Options: DENY or CSP frame-ancestors directive.')

    except Exception as e:
        log('warn', f'[HEADERADV] Error: {e}')

    issues_count = sum(len(v.get('issues', [])) for v in [header_adv.get('csp_analysis', {}), header_adv.get('cors_deep', {})] if isinstance(v, dict))
    issues_count += len(header_adv.get('cookie_audit', []))
    log('ok', f'[HEADERADV] Analysis complete: {issues_count} issues found')
    with LOCK:
        scan_state['header_adv_data'] = header_adv
    set_progress('headeradv', 100)


# ─── NUCLEI VULNERABILITY SCANNER ──────────────────────────────────────────────


def run_cors_module(target):
    log('info', f'[CORS] Testing CORS misconfigurations on {target}')
    cors_data = {'cors': [], 'redirects': []}
    test_origins = ['https://evil.com', 'null', 'https://evil.' + target, f'https://{target}.evil.com']
    if REQUESTS_AVAILABLE:
        url = f'https://{target}'
        for origin in test_origins:
            try:
                r = req_lib.get(url, timeout=5, verify=False, headers={'Origin': origin, 'User-Agent': 'Mozilla/5.0'})
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                acc = r.headers.get('Access-Control-Allow-Credentials', '')
                if acao == origin or acao == '*':
                    cors_data['cors'].append({'url': url, 'origin': origin, 'credentials': acc or 'false'})
                    add_finding('high', f'CORS misconfiguration: reflects {origin}',
                        sub=f'Server reflects arbitrary origin {origin} in ACAO header',
                        asset=url, cvss='6.5', owasp='A01', mitre='T1559')
                    log('err', f'[CORS] VULNERABLE: {url} reflects {origin}')
            except Exception:
                pass
        # Open redirect detection moved to vulnscan module to avoid false positives
        # CORS module only tests CORS misconfigurations
    log('ok', f'[CORS] Found {len(cors_data["cors"])} misconfigurations, {len(cors_data["redirects"])} open redirects')
    with LOCK:
        scan_state['cors_data'] = cors_data
    set_progress('cors', 100)

# ─── KEV MODULE ────────────────────────────────────────────────────────────────


def run_cors_creds_module(target):
    """Test for CORS with credentials and reflected origin."""
    log('info', '[CORS-CREDS] Testing CORS with credentials')
    base_url = f'https://{target}'
    cors_findings = []

    evil_origins = [
        'https://evil.com',
        'https://attacker.com',
        f'https://{target}.evil.com',
        'null',
        f'https://{target.replace(".", "")}.com',
    ]

    for origin in evil_origins:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(base_url,
                          headers={'Origin': origin},
                          timeout=8, verify=False)

            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')

            if acao == origin and acac.lower() == 'true':
                add_finding(
                    'critical',
                    f'CORS with credentials: {origin}',
                    sub=f'Server reflects attacker origin with credentials',
                    asset=base_url, cvss='9.1', owasp='A01', mitre='T1189',
                    details=f'Origin: {origin}\nACAO: {acao}\nACAC: {acac}\n'
                            f'Confirmed: Reflected origin with credentials=true')
                cors_findings.append({'origin': origin})
                log('ok', f'[CORS-CREDS] Confirmed: {origin}')

            elif acao == '*' and acac.lower() == 'true':
                add_finding(
                    'high',
                    'CORS: Wildcard with credentials',
                    sub='Access-Control-Allow-Origin: * with credentials',
                    asset=base_url, cvss='7.5', owasp='A01', mitre='T1189',
                    details='ACAO: *\nACAC: true\nConfirmed: Wildcard with credentials')
                cors_findings.append({'origin': '*'})
                log('ok', '[CORS-CREDS] Wildcard with credentials')
        except Exception:
            pass

    log('ok', f'[CORS-CREDS] Scan complete - {len(cors_findings)} findings')
    set_progress('cors_creds', 100)


# ─── CRYPTO MINING DETECTION ──────────────────────────────────────────────────


def run_firewall_bypass_module(target):
    log('info', f'[FW] Testing firewall/WAF bypass techniques on {target}')
    firewall_data = {'waf_detected': [], 'bypass_techniques': [], 'evasion_testing': {}, 'waf_confidence': {}, 'summary': {}}
    if REQUESTS_AVAILABLE:
        url = f'https://{target}'
        try:
            r = req_lib.get(url, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            headers = r.headers
            body = r.text[:5000].lower()
            headers_str = str(headers).lower()
            cookies = r.cookies

            waf_signatures = {
                'Cloudflare': {'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-apo-via'], 'cookies': ['__cfduid', '__cflb'], 'body': ['cloudflare', 'ray id:'], 'codes': [403, 503, 429]},
                'AWS WAF': {'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amzn-errortype'], 'cookies': ['aws-waf-token'], 'body': ['request blocked', 'aws waf'], 'codes': [403, 400]},
                'Imperva/Incapsula': {'headers': ['x-iinfo', 'x-cdn', 'incap-ses', 'visid_incap'], 'cookies': ['incap_ses_', 'visid_incap_'], 'body': ['incapsula', 'imperva'], 'codes': [403, 412]},
                'Akamai': {'headers': ['x-akamai', 'akamai-grn', 'x-akamaitech', 'x-akamai-transformed'], 'cookies': ['ak_bmsc', 'bm_sz', 'akavpau_'], 'body': ['akamai', 'reference error'], 'codes': [403, 400]},
                'Sucuri': {'headers': ['x-sucuri-id', 'x-sucuri-cache'], 'cookies': ['sucuri-'], 'body': ['sucuri', 'cloudproxy'], 'codes': [403]},
                'Fortinet/FortiWeb': {'headers': ['x-fortigate', 'x-fortiadc'], 'cookies': ['FORTIWAFSID'], 'body': ['fortiweb'], 'codes': [403, 406]},
                'F5 BIG-IP ASM': {'headers': ['x-wa-info', 'x-asm-version', 'f5-asm'], 'cookies': ['TSxxxxxx', 'ASM'], 'body': ['f5', 'the requested url was rejected'], 'codes': [403, 404]},
                'ModSecurity': {'headers': [], 'cookies': [], 'body': ['modsecurity', 'this error was generated by mod_security'], 'codes': [403, 406]},
                'Azure Front Door': {'headers': ['x-azure-ref', 'x-fd-healthproberesponse'], 'cookies': [], 'body': ['azure front door', 'afd'], 'codes': [403, 429]},
                'Fastly': {'headers': ['x-fastly', 'fastly-io', 'x-served-by', 'x-cache-hits'], 'cookies': ['fastly'], 'body': ['fastly'], 'codes': [403, 429]},
                'Wordfence': {'headers': [], 'cookies': ['wfvt_', 'wordfence_verifiedHuman'], 'body': ['wordfence', 'blocked by wordfence'], 'codes': [503]},
                'Barracuda': {'headers': ['barracuda'], 'cookies': [], 'body': ['barracuda'], 'codes': [403]},
            }
            detected = []
            waf_confidence = {}
            for name, sigs in waf_signatures.items():
                score = 0
                matches = []
                for s in sigs['headers']:
                    if s in headers_str:
                        score += 25; matches.append(f'header:{s}')
                for s in sigs['cookies']:
                    if any(s.lower() in k.lower() for k in cookies):
                        score += 20; matches.append(f'cookie:{s}')
                for s in sigs['body']:
                    if s in body:
                        score += 15; matches.append(f'body:{s}')
                if r.status_code in sigs['codes']:
                    score += 10; matches.append(f'status:{r.status_code}')
                if score >= 25:
                    detected.append(name)
                    waf_confidence[name] = {'score': min(score, 100), 'evidence': matches[:5]}
                    log('ok', f'[FW] WAF detected: {name} ({score}% confidence)')
            firewall_data['waf_detected'] = detected
            firewall_data['waf_confidence'] = waf_confidence
            # Only log WAF detection, don't add as finding (not a vulnerability)
            if detected:
                log('ok', f'[FW] WAF protection detected: {", ".join(detected)}')

            bypass_headers = [
                ('X-Forwarded-For', '127.0.0.1'), ('X-Real-IP', '127.0.0.1'),
                ('X-Originating-IP', '127.0.0.1'), ('X-Remote-IP', '127.0.0.1'),
                ('X-Client-IP', '127.0.0.1'), ('X-Host', 'localhost'),
                ('X-Forwarded-Host', 'localhost'),
            ]
            bypass_results = []
            block_status = r.status_code
            for hdr, val in bypass_headers:
                try:
                    br = req_lib.get(url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0', hdr: val})
                    if br.status_code != block_status and br.status_code not in (403, 429, 503):
                        bypass_results.append({'header': hdr, 'value': val, 'status': br.status_code, 'note': 'Potential bypass'})
                        add_finding('medium', f'Firewall bypass via {hdr}: {val}',
                            sub=f'WAF bypass using {hdr}: {val} returned status {br.status_code}',
                            asset=target, cvss='5.0', owasp='A01', mitre='T1595')
                        log('warn', f'[FW] Bypass: {hdr}: {val} -> {br.status_code}')
                except Exception:
                    pass
            firewall_data['bypass_techniques'] = bypass_results

            evasion_payloads = {
                'SQLi Evasion': {'endpoint': '/?id=1', 'payloads': [
                    ('sElEcT 1 FrOm dual', 'SELECT 1 FROM dual'),
                    ('%55%4e%49%4f%4e%20%53%45%4c%45%43%54', 'UNION SELECT'),
                    ('1/**/UNION/**/SELECT/**/', '1 UNION SELECT'),
                    ('%2527%20OR%201%3D1', "' OR 1=1"),
                    ('/*!50000UNION*//*!50000SELECT*/', 'UNION SELECT'),
                    ('1%0aUNION%0aSELECT', 'UNION SELECT (newline)'),
                    ("1' || '1'='1", "' OR '1'='1"),
                    ('1%27%20OR%201%3D1%20--%20', "' OR 1=1 --"),
                    ('0x31303030303030', 'hex encoded'),
                    ('CHAR(49,48,48,48,48,48,48)', 'CHAR() bypass'),
                ]},
                'XSS Evasion': {'endpoint': '/?q=test', 'payloads': [
                    ('<ScRiPt>alert(1)</ScRiPt>', '<script>alert(1)</script>'),
                    ('%3Cscript%3Ealert(1)%3C/script%3E', '<script>alert(1)</script>'),
                    ('<img src=x onerror=alert(1)>', '<img onerror>'),
                    ('<svg/onload=alert(1)>', '<svg onload>'),
                    ('<details open ontoggle=alert(1)>', '<details ontoggle>'),
                    ('javascript:alert(1)', 'javascript: URI'),
                    ('<iframe src="javascript:alert(1)">', '<iframe javascript>'),
                    ('"><img src=x onerror=alert(1)//', 'attribute breakout'),
                    ('<math><mtext></mtext><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">', 'math/svg mXSS'),
                    ('<![CDATA[<script>alert(1)</script>]]>', 'CDATA bypass'),
                ]},
                'Path Traversal Evasion': {'endpoint': '/?file=test', 'payloads': [
                    ('....//....//....//etc/passwd', '../../../etc/passwd'),
                    ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', '../../../etc/passwd'),
                    ('..;/..;/..;/etc/passwd', '../../../etc/passwd'),
                    ('..%252f..%252f..%252fetc/passwd', 'double encoded'),
                    ('..%c0%af..%c0%af..%c0%afetc/passwd', 'UTF-8 bypass'),
                    ('/etc/passwd%00.png', 'null byte injection'),
                    ('....\\....\\....\\etc\\passwd', 'backslash variant'),
                ]},
                'CMDi Evasion': {'endpoint': '/?ping=127.0.0.1', 'payloads': [
                    ('; ls', '; ls'), ('| ls', '| ls'),
                    ('%3B%20whoami', '; whoami'), ('$(whoami)', '$(whoami)'),
                    ('`whoami`', 'backtick execution'),
                    ('%0als', 'newline injection'),
                    ('||ls', 'OR operator'),
                    ('&&ls', 'AND operator'),
                    (';{cat,/etc/passwd}', 'brace expansion'),
                    ('%0a%0dwhoami', 'CRLF injection'),
                ]},
                'SSRF Evasion': {'endpoint': '/?url=test', 'payloads': [
                    ('http://127.0.0.1', 'localhost'),
                    ('http://0x7f000001', 'hex IP'),
                    ('http://2130706433', 'decimal IP'),
                    ('http://0177.0.0.1', 'octal IP'),
                    ('http://localhost%00@evil.com', 'null byte'),
                    ('http://169.254.169.254/latest/meta-data/', 'AWS metadata'),
                    ('http://[::1]', 'IPv6 localhost'),
                    ('http://0.0.0.0', 'all interfaces'),
                    ('gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a', 'gopher Redis'),
                    ('http://127.0.0.1:80@evil.com', 'URL confusion'),
                ]},
                'HTTP Parameter Pollution': {'endpoint': '/', 'payloads': [
                    ('id=1&id=2', 'HPP duplicate'),
                    ('id=1&id=UNION SELECT', 'HPP injection'),
                    ('id=1%26id=2', 'encoded ampersand'),
                    ('id=1;id=2', 'semicolon separator'),
                ]},
                'JSON Injection': {'endpoint': '/?data=test', 'payloads': [
                    ('{"admin":true}', 'JSON injection'),
                    ('{"$gt":""}', 'MongoDB injection'),
                    ('{"$ne":null}', 'MongoDB not equal'),
                    ('true', 'boolean injection'),
                ]},
                'LDAP Injection': {'endpoint': '/?user=test', 'payloads': [
                    ('*)(&', 'LDAP wildcard'),
                    ('*)(uid=*))(|(uid=*', 'LDAP bypass'),
                    ('admin)(&)', 'LDAP admin'),
                    ('*()|&', 'LDAP special chars'),
                ]},
                'XML/XXE Evasion': {'endpoint': '/?xml=test', 'payloads': [
                    ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', 'XXE file read'),
                    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>', 'XXE SSRF'),
                ]},
            }
            evasion_results = {}
            for tech_name, tech_data in evasion_payloads.items():
                baseline_url = url + tech_data['endpoint']
                try:
                    bl = req_lib.get(baseline_url, timeout=5, verify=False)
                    baseline_len = len(bl.text)
                except:
                    baseline_len = 0
                tech_payloads = []
                success_count = 0
                for payload, _ in tech_data['payloads']:
                    try:
                        test_url = baseline_url.replace('test', urllib.parse.quote(payload)) if 'test' in baseline_url else f"{baseline_url}&p={urllib.parse.quote(payload)}"
                        pr = req_lib.get(test_url, timeout=5, verify=False)
                        diff = abs(len(pr.text) - baseline_len)
                        success = diff > 100
                        if success:
                            success_count += 1
                        tech_payloads.append({'payload': payload[:40], 'success': success, 'diff': diff})
                    except:
                        tech_payloads.append({'payload': payload[:40], 'success': False, 'diff': 0})
                rate = round((success_count / len(tech_data['payloads'])) * 100, 1) if tech_data['payloads'] else 0
                evasion_results[tech_name] = {'payloads_tested': len(tech_data['payloads']), 'evasions': success_count, 'evasion_rate': rate, 'vulnerable': rate > 20, 'details': tech_payloads[:3]}
                if rate > 20:
                    log('warn', f'[FW] {tech_name}: {rate}% evasion rate')
                    add_finding('medium', f'WAF bypass possible via {tech_name}',
                        sub=f'{tech_name} evasion rate: {rate}%', asset=target, cvss='5.5', owasp='A01')
            firewall_data['evasion_testing'] = evasion_results

            case_bypasses = []
            for path in ['/<scrIpt>', '/<sCrIpT>', '/<SCRIPT>', '/%3Cscript%3E', '/..%2fadmin', '/%00admin']:
                try:
                    cr = req_lib.get(f'{url}{path}', timeout=5, verify=False)
                    if cr.status_code == 200:
                        case_bypasses.append({'path': path, 'status': cr.status_code})
                        log('warn', f'[FW] Case bypass: {path} -> {cr.status_code}')
                except Exception:
                    pass
            if case_bypasses:
                firewall_data['case_bypass'] = case_bypasses
            evadable = any(e.get('vulnerable') for e in evasion_results.values())
            firewall_data['summary'] = {
                'waf_count': len(detected),
                'bypass_count': len(bypass_results),
                'case_bypass_count': len(case_bypasses),
                'evasion_techniques_tested': len(evasion_results),
                'evadable_techniques': sum(1 for e in evasion_results.values() if e.get('vulnerable')),
                'overall_evasion_risk': 'High' if evadable else 'Low',
            }
            log('ok', f'[FW] {len(detected)} WAFs, {len(bypass_results)} bypasses, {sum(1 for e in evasion_results.values() if e.get("vulnerable"))} evadable techniques')
        except Exception as e:
            log('err', f'[FW] Module error: {e}')
    with LOCK:
        scan_state['firewall_data'] = firewall_data
    set_progress('firewall', 100)

# ─── BOT DETECTION MODULE ───────────────────────────────────────────────────────


def run_bot_detection_module(target):
    log('info', f'[BOT] Analyzing bot protection on {target}')
    bot_data = {'anti_bot_detected': [], 'challenge_types': [], 'rate_limiting': {}, 'credential_stuffing': {}, 'scraping_test': {}, 'summary': {}}
    if REQUESTS_AVAILABLE:
        url = f'https://{target}'
        try:
            normal_r = req_lib.get(url, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            bot_r = req_lib.get(url, timeout=8, verify=False, headers={'User-Agent': 'curl/7.68.0', 'Accept': '*/*'})
            anti_bot = []
            body = normal_r.text.lower()
            bot_body = bot_r.text.lower() if bot_r.status_code == 200 else ''
            js_challenge_keywords = ['_cf_chl_opt', 'cf-challenge', 'jschl_vc', 'challenge-form', 'turnstile', 'cf-turnstile', '_cf', 'cdn-cgi']
            if any(k in body for k in js_challenge_keywords):
                anti_bot.append('Cloudflare JS Challenge')
                bot_data['challenge_types'] = 'Cloudflare JS Challenge'
                log('warn', '[BOT] Cloudflare JS Challenge detected')
            if 'recaptcha' in body or 'g-recaptcha' in body or 'google.com/recaptcha' in body:
                anti_bot.append('reCAPTCHA')
                bot_data['challenge_types'] = 'reCAPTCHA v2/v3'
                log('warn', '[BOT] reCAPTCHA detected')
            if 'hcaptcha' in body or 'h-captcha' in body:
                anti_bot.append('hCaptcha')
                bot_data['challenge_types'] = 'hCaptcha'
                log('warn', '[BOT] hCaptcha detected')
            if normal_r.status_code == 403 and 'reference' in body and 'error' in body:
                anti_bot.append('Generic WAF Block')
                log('warn', '[BOT] Generic WAF block page detected')
            if normal_r.status_code == 429:
                anti_bot.append('Rate Limiting (429)')
                log('warn', '[BOT] Rate limiting active (429 Too Many Requests)')
            if bot_r.status_code != normal_r.status_code and bot_r.status_code in (403, 429, 503):
                anti_bot.append('User-Agent Based Filtering')
                bot_data['challenge_types'] = 'UA-based blocking'
                log('warn', '[BOT] User-Agent based filtering detected')
            rate_limit_info = {}
            for h in ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After']:
                if h in normal_r.headers:
                    rate_limit_info[h] = normal_r.headers[h]
            if rate_limit_info:
                anti_bot.append('API Rate Limiting')
                bot_data['rate_limiting'] = rate_limit_info
                log('ok', f'[BOT] Rate limiting headers: {rate_limit_info}')
            bot_data['anti_bot_detected'] = anti_bot

            # ── Credential stuffing simulation ──
            stuffing_results = {'total_attempts': 0, 'blocked': 0, 'successful': 0}
            test_users = ['admin', 'administrator', 'root']
            test_pwds = ['password', 'admin', '123456']
            ip_rotations = [{'X-Forwarded-For': '1.2.3.4'}, {'X-Forwarded-For': '5.6.7.8'}, {}, {'True-Client-IP': '9.10.11.12'}]
            login_url = f'{url}/login'
            for user in test_users[:3]:
                for pwd in test_pwds[:3]:
                    for ip_hdrs in ip_rotations:
                        try:
                            hr = req_lib.post(login_url, data={'username': user, 'password': pwd}, headers=ip_hdrs, timeout=5, verify=False)
                            stuffing_results['total_attempts'] += 1
                            if hr.status_code in (429, 403, 503):
                                stuffing_results['blocked'] += 1
                            elif hr.status_code in (301, 302, 303, 307, 308):
                                # Check for session cookie being set AND redirect to authenticated page
                                has_session_cookie = any('session' in c.name.lower() or 'auth' in c.name.lower() or 'token' in c.name.lower() for c in hr.cookies)
                                redirect_loc = hr.headers.get('Location', '').lower()
                                goes_to_dashboard = any(x in redirect_loc for x in ['/dashboard', '/admin', '/panel', '/home', '/account'])
                                if has_session_cookie and goes_to_dashboard:
                                    stuffing_results['successful'] += 1
                                    log('warn', f'[BOT] Credential stuffing: {user}:{pwd} succeeded - session cookie set, redirected to {redirect_loc}')
                            elif hr.status_code == 200:
                                # Check for session cookie AND authenticated content
                                has_session_cookie = any('session' in c.name.lower() or 'auth' in c.name.lower() or 'token' in c.name.lower() for c in hr.cookies)
                                body = hr.text.lower()
                                # Must have authenticated content (not just login page)
                                has_auth_content = ('logout' in body or 'sign out' in body or 'welcome' in body) and 'login' not in body[:500]
                                if has_session_cookie and has_auth_content:
                                    stuffing_results['successful'] += 1
                                    log('warn', f'[BOT] Credential stuffing: {user}:{pwd} succeeded - session cookie set with auth content')
                        except:
                            pass
            block_rate = round((stuffing_results['blocked'] / max(stuffing_results['total_attempts'], 1)) * 100, 1)
            stuffing_results['block_rate'] = block_rate
            stuffing_results['vulnerable'] = block_rate < 30
            bot_data['credential_stuffing'] = stuffing_results
            if stuffing_results['successful'] > 0:
                add_finding('critical', f'Credential stuffing succeeded: {stuffing_results["successful"]} logins',
                    sub=f'Weak login endpoint allowed successful login with test credentials', asset=target, cvss='9.0', owasp='A07')
            elif block_rate < 30 and stuffing_results['blocked'] == 0:
                # Only flag if we got responses (not all timeouts) and zero blocks
                log('info', f'[BOT] Credential stuffing: {block_rate}% blocked (informational - login endpoint may not exist)')
            else:
                log('ok', f'[BOT] Credential stuffing blocked {block_rate}% of attempts')

            # ── Web scraping protection test ──
            scrape_results = {'total_requests': 0, 'blocked': 0}
            for ep in ['/', '/products', '/search', '/api/data']:
                for _ in range(5):
                    try:
                        sr = req_lib.get(f'{url}{ep}', timeout=5, verify=False)
                        scrape_results['total_requests'] += 1
                        if sr.status_code in (429, 403, 503):
                            scrape_results['blocked'] += 1
                    except:
                        pass
            scrape_results['block_rate'] = round((scrape_results['blocked'] / max(scrape_results['total_requests'], 1)) * 100, 1)
            bot_data['scraping_test'] = scrape_results
            # Only flag if server is actively blocking some requests but not all (inconsistent)
            if scrape_results['block_rate'] > 0 and scrape_results['block_rate'] < 50:
                log('info', f'[BOT] Web scraping: {scrape_results["block_rate"]}% blocked (partial protection)')
            else:
                log('info', f'[BOT] Web scraping: {scrape_results["block_rate"]}% blocked (informational)')

            bot_data['summary'] = {
                'mechanisms': len(anti_bot),
                'has_challenge': any('Challenge' in a or 'CAPTCHA' in a for a in anti_bot),
                'has_rate_limit': len(rate_limit_info) > 0,
                'credential_stuffing_block_rate': stuffing_results['block_rate'],
                'scraping_block_rate': scrape_results.get('block_rate', 0),
            }
            # Bot protection detection is logged but not added as finding (it's a positive security control)
            if anti_bot:
                log('ok', f'[BOT] Bot protection detected: {", ".join(anti_bot)}')
            log('ok', f'[BOT] {len(anti_bot)} mechanisms, stuffing block {stuffing_results["block_rate"]}%, scrape block {scrape_results.get("block_rate", 0)}%')
        except Exception as e:
            log('err', f'[BOT] Module error: {e}')
    with LOCK:
        scan_state['botcheck_data'] = bot_data
    set_progress('botcheck', 100)

# ─── DDOS READINESS MODULE ──────────────────────────────────────────────────────


def run_ddos_readiness_module(target):
    log('info', f'[DDOS] Assessing DDoS readiness for {target}')
    ddos_data = {'protection_detected': [], 'cdn_detected': None, 'rate_limits': {}, 'rate_limit_stress': {}, 'resource_exhaustion': {}, 'amplification_risk': {}, 'recommendations': [], 'summary': {}}
    if REQUESTS_AVAILABLE:
        url = f'https://{target}'
        try:
            r = req_lib.get(url, timeout=8, verify=False)
            protection = []
            headers_str = str(r.headers).lower()
            cdn_headers = {
                'Cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
                'Akamai': ['x-akamai', 'akamai-request-id'],
                'Fastly': ['x-served-by', 'fastly'],
                'CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'Incapsula': ['incapsula'],
                'KeyCDN': ['x-keycdn'],
                'StackPath': ['stackpath'],
                'Azure CDN': ['x-azure-ref', 'azurecdn'],
                'Google Cloud CDN': ['x-cloud-trace-context', 'ghost'],
            }
            for name, sigs in cdn_headers.items():
                if any(s in headers_str for s in sigs):
                    protection.append(f'{name} CDN')
                    ddos_data['cdn_detected'] = name
                    log('ok', f'[DDOS] CDN detected: {name}')
                    break
            if not ddos_data['cdn_detected']:
                protection.append('No CDN detected')
                log('info', '[DDOS] No CDN detected - informational only')
            rate_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After']
            rate_found = {h: r.headers[h] for h in rate_headers if h in r.headers}
            ddos_data['rate_limits'] = rate_found
            if rate_found:
                protection.append('Rate limiting detected')
                log('ok', f'[DDOS] Rate limiting: {rate_found}')
            else:
                protection.append('No rate limiting detected')
                log('info', '[DDOS] No rate limiting headers found - informational only')

            # ── Rate limiting stress test (concurrent bursts) ──
            stress_result = {'total': 0, 'blocked': 0, 'status_distribution': {}}
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for _ in range(30):
                    futures.append(executor.submit(lambda: req_lib.get(url, timeout=5, verify=False)))
                for f in futures:
                    try:
                        sr = f.result(timeout=10)
                        stress_result['total'] += 1
                        sc = sr.status_code
                        stress_result['status_distribution'][sc] = stress_result['status_distribution'].get(sc, 0) + 1
                        if sc in (429, 503, 403):
                            stress_result['blocked'] += 1
                    except:
                        pass
            stress_result['block_rate'] = round((stress_result['blocked'] / max(stress_result['total'], 1)) * 100, 1)
            ddos_data['rate_limit_stress'] = stress_result
            # Only flag if there's actual service degradation (5xx errors) or complete blocking
            five_xx = sum(1 for sc in stress_result['status_distribution'] if sc >= 500)
            if five_xx > stress_result['total'] * 0.3:
                add_finding('high', 'Rate limiting stress test: service degradation',
                    sub=f'{five_xx}/{stress_result["total"]} requests returned 5xx errors under load',
                    asset=target, cvss='7.0', owasp='A05')
                log('warn', f'[DDOS] Stress test: {five_xx} 5xx errors detected')
            elif stress_result['block_rate'] > 80:
                log('ok', f'[DDOS] Stress test: strong protection ({stress_result["block_rate"]}% blocked)')
            else:
                log('info', f'[DDOS] Stress test: {stress_result["block_rate"]}% blocked (informational)')

            # ── Resource exhaustion test ──
            exhaustion_results = {}
            for ep_desc, test_url in [('Large search param', f'{url}/search?q={"a"*2000}'), ('Large ID param', f'{url}/?id={"1"*500}')]:
                try:
                    es = time.time()
                    er = req_lib.get(test_url, timeout=10, verify=False)
                    elapsed = time.time() - es
                    exhausted = elapsed > 5 or er.status_code == 500
                    exhaustion_results[ep_desc] = {'status': er.status_code, 'response_time': round(elapsed, 3), 'vulnerable': exhausted}
                except requests.exceptions.Timeout:
                    exhaustion_results[ep_desc] = {'status': 'timeout', 'vulnerable': True}
                except:
                    pass
            ddos_data['resource_exhaustion'] = exhaustion_results
            if any(r.get('vulnerable') for r in exhaustion_results.values()):
                add_finding('medium', 'Resource exhaustion vulnerability detected',
                    sub=f'Large request parameters caused high response time or timeout', asset=target, cvss='5.5', owasp='A05')
                log('warn', '[DDOS] Resource exhaustion detected')

            # ── Amplification risk port scan ──
            amp_ports = {53: 'DNS', 123: 'NTP', 11211: 'Memcached', 1900: 'SSDP', 3478: 'STUN', 5060: 'SIP'}
            amp_results = {}
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            for port, service in amp_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    if sock.connect_ex((domain, port)) == 0:
                        amp_results[service] = {'port': port, 'open': True, 'risk': 'Amplification vector'}
                        log('warn', f'[DDOS] {service} port {port} open - potential amplification vector')
                    sock.close()
                except:
                    pass
            ddos_data['amplification_risk'] = amp_results
            if amp_results:
                add_finding('medium', f'Amplification attack surface: {", ".join(amp_results)}',
                    sub=f'Open amplification ports increase DDoS risk', asset=target, cvss='5.0', owasp='A05')

            recs = []
            if not ddos_data['cdn_detected']:
                recs.append('Deploy a CDN/WAF (Cloudflare, Akamai, AWS CloudFront) to absorb DDoS traffic')
            if not rate_found:
                recs.append('Implement rate limiting with Retry-After headers on all API endpoints')
            if stress_result.get('block_rate', 100) < 60:
                recs.append('Strengthen rate limiting to block concurrent burst traffic')
            if any(r.get('vulnerable') for r in exhaustion_results.values()):
                recs.append('Add request size limits and timeout controls to prevent resource exhaustion')
            for svc in amp_results:
                recs.append(f'Restrict {svc} (port {amp_results[svc]["port"]}) to trusted IPs only to prevent amplification')
            recs.append('Enable DDoS protection services (AWS Shield, Cloudflare DDoS, Google Cloud Armor)')
            recs.append('Configure auto-scaling to handle traffic spikes')
            recs.append('Monitor traffic patterns for volumetric anomalies')
            recs.append('Implement SYN flood protection at the network edge')
            ddos_data['recommendations'] = recs
            ddos_data['protection_detected'] = protection
            exhaustion_vuln = any(r.get('vulnerable') for r in exhaustion_results.values())
            ddos_data['summary'] = {
                'protection_level': 'Good' if ddos_data['cdn_detected'] and stress_result.get('block_rate', 0) >= 60 else 'Poor',
                'has_cdn': bool(ddos_data['cdn_detected']),
                'has_rate_limit': bool(rate_found),
                'stress_block_rate': stress_result.get('block_rate', 0),
                'resource_exhaustion_risk': 'Yes' if exhaustion_vuln else 'No',
                'amplification_services': list(amp_results.keys()),
                'recommendation_count': len(recs),
            }
            log('ok', f'[DDOS] CDN: {ddos_data["cdn_detected"] or "None"}, Stress block: {stress_result.get("block_rate", 0)}%, Exhaustion: {exhaustion_vuln}')
        except Exception as e:
            log('err', f'[DDOS] Module error: {e}')
    with LOCK:
        scan_state['ddos_data'] = ddos_data
    set_progress('ddos', 100)
# ─── RISK SCORING ──────────────────────────────────────────────────────────────


def run_waf_fingerprint_module(target):
    log('info', f'[WAF] Active WAF fingerprinting on {target}')
    waf_data = {'wafs_detected': [], 'confidence': {}, 'probes': [], 'raw_headers': {}, 'summary': {}}
    if not REQUESTS_AVAILABLE:
        with LOCK:
            scan_state['waf_fingerprint_data'] = waf_data
        set_progress('waf', 100)
        return

    url = f'https://{target}'
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

    # WAF signature database with confidence scoring
    waf_signatures = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-apo-via', 'cf-request-id', 'cf-bgj'],
            'cookies': ['__cfduid', '__cflb', '__cf_bm', 'cf_clearance'],
            'body': ['cloudflare', 'ray id:', 'cf-challenge', 'cf-turnstile', '_cf_chl_opt'],
            'codes': [403, 503, 429],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amzn-errortype', 'x-amzn-trace-id'],
            'cookies': ['aws-waf-token'],
            'body': ['request blocked', 'aws waf', 'x-amzn-RequestId'],
            'codes': [403, 400],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'Imperva/Incapsula': {
            'headers': ['x-iinfo', 'x-cdn', 'incap-ses', 'visid_incap', 'x-ariel-score'],
            'cookies': ['incap_ses_', 'visid_incap_', 'nlbi_', 'reese84'],
            'body': ['incapsula', 'imperva', 'incap_ses'],
            'codes': [403, 412, 406],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'Akamai': {
            'headers': ['x-akamai', 'akamai-grn', 'x-akamaitech', 'x-akamai-transformed', 'akamai-request-bc'],
            'cookies': ['ak_bmsc', 'bm_sz', 'akavpau_', 'ab', '_abck'],
            'body': ['akamai', 'reference error', 'access denied'],
            'codes': [403, 400],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-requestid'],
            'cookies': ['sucuri-', 'sucuriclf'],
            'body': ['sucuri', 'cloudproxy', 'access denied - sucuri'],
            'codes': [403, 503],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'Fortinet/FortiWeb': {
            'headers': ['x-fortigate', 'x-fortiadc', 'x-fortiweb'],
            'cookies': ['FORTIWAFSID', 'FORTIWEBSESSIONID'],
            'body': ['fortiweb', 'fortinet', 'blocked by fortigate'],
            'codes': [403, 406],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'F5 BIG-IP ASM': {
            'headers': ['x-wa-info', 'x-asm-version', 'f5-asm', 'server: BIG-IP'],
            'cookies': ['TSxxxxxx', 'ASM', 'BIGipServer', 'f5_cspm', 'f5avraaaaaaaaaaaaaaaa'],
            'body': ['f5', 'the requested url was rejected', 'big-ip'],
            'codes': [403, 404],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'ModSecurity': {
            'headers': ['mod_security', 'modsecurity'],
            'cookies': [],
            'body': ['modsecurity', 'this error was generated by mod_security', 'mod_security rules', 'nothink.org'],
            'codes': [403, 406, 501],
            'weight': {'header': 30, 'cookie': 10, 'body': 25, 'code': 15},
        },
        'Azure Front Door': {
            'headers': ['x-azure-ref', 'x-fd-healthproberesponse', 'x-azure-fdid'],
            'cookies': [],
            'body': ['azure front door', 'afd', 'x-azure-ref'],
            'codes': [403, 429],
            'weight': {'header': 30, 'cookie': 10, 'body': 20, 'code': 10},
        },
        'Fastly': {
            'headers': ['x-fastly', 'fastly-io', 'x-served-by', 'x-cache-hits', 'x-timer'],
            'cookies': ['fastly'],
            'body': ['fastly', 'varnish'],
            'codes': [403, 429],
            'weight': {'header': 30, 'cookie': 20, 'body': 15, 'code': 10},
        },
        'Wordfence': {
            'headers': [],
            'cookies': ['wfvt_', 'wordfence_verifiedHuman', 'wfwaf-authcookie'],
            'body': ['wordfence', 'blocked by wordfence', 'generated by wordfence'],
            'codes': [503, 403],
            'weight': {'header': 10, 'cookie': 30, 'body': 25, 'code': 10},
        },
        'Barracuda': {
            'headers': ['barracuda', 'barra-counter'],
            'cookies': ['barra_counter_session', 'BNI__BARRACUDA_LB_COOKIE'],
            'body': ['barracuda', 'barracuda networks'],
            'codes': [403, 406],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'DDoS-Guard': {
            'headers': ['x-ddos-guard', 'x-guard'],
            'cookies': ['__ddg1', '__ddg2', '__ddgid'],
            'body': ['ddos-guard', 'ddos protection'],
            'codes': [403, 503],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'StackPath': {
            'headers': ['x-stackpath', 'x-sp-url'],
            'cookies': ['sp_'],
            'body': ['stackpath', 'stackpath cdn'],
            'codes': [403],
            'weight': {'header': 30, 'cookie': 25, 'body': 20, 'code': 10},
        },
        'Varnish/Fastly': {
            'headers': ['x-varnish', 'via: varnish', 'x-varnish-cache'],
            'cookies': [],
            'body': ['varnish', 'varnish cache server'],
            'codes': [403, 503],
            'weight': {'header': 30, 'cookie': 10, 'body': 20, 'code': 10},
        },
    }

    # Probe 1: Normal request
    try:
        r_normal = req_lib.get(url, timeout=10, verify=False, headers={'User-Agent': ua})
        headers_str = str(r_normal.headers).lower()
        body = r_normal.text[:10000].lower()
        cookies = {c.name: c.value for c in r_normal.cookies}
        waf_data['raw_headers'] = dict(r_normal.headers)
        waf_data['probes'].append({'name': 'normal', 'status': r_normal.status_code, 'size': len(r_normal.text)})

        # Score each WAF
        for waf_name, sigs in waf_signatures.items():
            score = 0
            evidence = []
            w = sigs['weight']

            for s in sigs['headers']:
                if s.lower() in headers_str:
                    score += w['header']
                    evidence.append(f'header:{s}')
            for s in sigs['cookies']:
                if any(s.lower() in k.lower() for k in cookies.keys()):
                    score += w['cookie']
                    evidence.append(f'cookie:{s}')
            for s in sigs['body']:
                if s.lower() in body:
                    score += w['body']
                    evidence.append(f'body:{s}')
            if r_normal.status_code in sigs['codes']:
                score += w['code']
                evidence.append(f'status:{r_normal.status_code}')

            if score >= 25:
                waf_data['wafs_detected'].append(waf_name)
                waf_data['confidence'][waf_name] = {'score': min(score, 100), 'evidence': evidence[:6]}
                log('ok', f'[WAF] Detected: {waf_name} ({min(score, 100)}% confidence)')

    except Exception as e:
        log('warn', f'[WAF] Normal probe failed: {e}')

    # Probe 2: Malicious request to trigger WAF
    malicious_payloads = [
        ('SQLi', "/?id=1' OR '1'='1--"),
        ('XSS', '/?q=<script>alert(1)</script>'),
        ('Path Traversal', '/?file=../../../etc/passwd'),
        ('CMDi', '/?cmd=;cat /etc/passwd'),
    ]
    for attack_name, path in malicious_payloads:
        try:
            r_mal = req_lib.get(f'{url}{path}', timeout=8, verify=False, headers={'User-Agent': ua})
            waf_data['probes'].append({'name': attack_name, 'status': r_mal.status_code, 'size': len(r_mal.text)})

            if r_mal.status_code in (403, 406, 429, 503):
                blocked_body = r_mal.text[:2000].lower()
                for waf_name, sigs in waf_signatures.items():
                    for s in sigs['body']:
                        if s.lower() in blocked_body and waf_name not in waf_data['wafs_detected']:
                            waf_data['wafs_detected'].append(waf_name)
                            waf_data['confidence'][waf_name] = {'score': 50, 'evidence': [f'blocked:{attack_name}', f'body:{s}']}
                            log('ok', f'[WAF] Detected via blocking: {waf_name}')
        except Exception:
            pass

    # Probe 3: Header manipulation
    try:
        r_xff = req_lib.get(url, timeout=8, verify=False, headers={'User-Agent': ua, 'X-Forwarded-For': '127.0.0.1'})
        if r_xff.status_code != r_normal.status_code:
            waf_data['probes'].append({'name': 'XFF bypass', 'status': r_xff.status_code, 'note': 'Different response with X-Forwarded-For'})
    except Exception:
        pass

    detected = waf_data['wafs_detected']
    if detected:
        # WAF detected is positive - log but don't create a finding
        log('ok', f'[WAF] WAFs detected: {", ".join(detected)} - this is a positive security control')
    else:
        log('info', '[WAF] No WAF detected - informational only (not a vulnerability)')

    # Enhanced WAF detection with wafw00f
    wafw00f_path = _find_tool('wafw00f')
    if wafw00f_path:
        log('info', f'[WAF] Running wafw00f for enhanced WAF detection')
        stdout, stderr, rc = _run_tool([
            wafw00f_path, f'https://{target}', '-a', '-v'
        ], timeout=30)
        if rc == 0 and stdout:
            for line in stdout.split('\n'):
                line = line.strip()
                if 'behind' in line.lower() or 'waf' in line.lower():
                    # Extract WAF name from wafw00f output
                    for waf_name in ['Cloudflare', 'AWS WAF', 'Akamai', 'Imperva', 'Sucuri', 'F5 BIG-IP', 'Azure Front Door']:
                        if waf_name.lower() in line.lower():
                            if waf_name not in detected:
                                detected.append(waf_name)
                                waf_data['confidence'][waf_name] = {'score': 85, 'evidence': ['wafw00f detection']}
                                log('ok', f'[WAF] wafw00f detected: {waf_name}')
            # Check for "No WAF" from wafw00f
            if 'no waf' in stdout.lower() or 'not behind' in stdout.lower():
                if not detected:
                    log('info', f'[WAF] wafw00f confirms no WAF detected')
    
    waf_data['summary'] = {
        'waf_count': len(detected),
        'waf_names': detected,
        'probes_run': len(waf_data['probes']),
        'has_waf': bool(detected),
    }
    log('ok', f'[WAF] Fingerprinting complete: {len(detected)} WAFs detected')
    with LOCK:
        scan_state['waf_fingerprint_data'] = waf_data
    set_progress('waf', 100)


# ─── API SECURITY MODULE ──────────────────────────────────────────────────────


def run_static_hardening_checks(target):
    """
    Dedicated check suite for STATIC sites.
    Runs security hardening checks that are meaningful for static pages/CDN-hosted sites.
    """
    log('info', f'[STATIC-HARDENING] Running static site security checks for {target}')
    base_url = f'https://{target}'

    # ── 1. TLS / Certificate ──
    try:
        import ssl as _ssl, socket as _sock
        ctx = _ssl.create_default_context()
        with _sock.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                tls_ver = ssock.version()
        not_after = cert.get('notAfter', '')
        if not_after:
            import datetime as _dt
            expiry = _dt.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - _dt.datetime.utcnow()).days
            if days_left < 14:
                add_finding('critical', f'TLS certificate expires in {days_left} days',
                    sub='Certificate near expiry — HTTPS will break for all visitors',
                    asset=target, cvss='7.5', owasp='A02', mitre='T1557',
                    details=f'Certificate expires: {not_after}\nDays remaining: {days_left}\n'
                            f'Action: Renew immediately via Let\'s Encrypt or CA')
            elif days_left < 30:
                add_finding('high', f'TLS certificate expires in {days_left} days',
                    sub='Certificate expiry approaching — plan renewal now',
                    asset=target, cvss='5.0', owasp='A02', mitre='T1557',
                    details=f'Certificate expires: {not_after}\nDays remaining: {days_left}')
            else:
                log('ok', f'[STATIC-HARDENING] TLS cert valid for {days_left} days, TLS {tls_ver}')

        if tls_ver in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
            add_finding('high', f'Weak TLS version: {tls_ver}',
                sub='Deprecated TLS version in use — POODLE/BEAST attack risk',
                asset=target, cvss='7.4', owasp='A02', mitre='T1557',
                details=f'Detected: {tls_ver}\nRequired: TLS 1.2 minimum, TLS 1.3 preferred\n'
                        f'Fix: Disable TLS 1.0 and 1.1 in server config')
    except Exception as e:
        log('warn', f'[STATIC-HARDENING] TLS check failed: {e}')

    # ── 2. Security Headers ──
    try:
        r = req_lib.get(base_url, timeout=10, verify=False)
        headers = {k.lower(): v for k, v in r.headers.items()}
        required_headers = {
            'content-security-policy':   ('high',   'CSP missing — XSS payloads execute without restriction',           'A03', 'T1189', '6.5'),
            'x-frame-options':           ('medium', 'X-Frame-Options missing — clickjacking possible',                  'A04', 'T1185', '4.3'),
            'x-content-type-options':    ('medium', 'X-Content-Type-Options: nosniff missing — MIME-type sniffing risk', 'A04', 'T1185', '4.3'),
            'referrer-policy':           ('low',    'Referrer-Policy missing — referrer leakage to third parties',      'A04', 'T1592', '3.1'),
            'permissions-policy':        ('low',    'Permissions-Policy missing — browser APIs unrestricted',            'A04', 'T1592', '3.1'),
        }
        if base_url.startswith('https://'):
            required_headers['strict-transport-security'] = ('high', 'HSTS not set — first visit may be over HTTP (downgrade attack)', 'A02', 'T1557', '6.5')
        for hdr, (sev, desc, owasp, mitre, cvss) in required_headers.items():
            if hdr not in headers:
                add_finding(sev, f'Missing security header: {hdr.title()}',
                    sub=desc, asset=base_url, cvss=cvss, owasp=owasp, mitre=mitre,
                    details=f'Header: {hdr}\nRecommendation: Add this header to all HTTP responses on the CDN/server\n'
                            f'For static sites: configure via CDN response headers (Cloudflare, Fastly, Netlify headers, Vercel headers.json)')

        # HSTS max-age check (only for HTTPS)
        hsts = headers.get('strict-transport-security', '')
        if hsts and base_url.startswith('https://'):
            import re as _re
            m = _re.search(r'max-age\s*=\s*(\d+)', hsts)
            if m and int(m.group(1)) < 31536000:
                add_finding('medium', 'HSTS max-age too short',
                    sub=f'max-age={m.group(1)} is less than 1 year (31536000s)',
                    asset=base_url, cvss='4.0', owasp='A02',
                    details=f'Current: {hsts}\nRecommended: max-age=31536000; includeSubDomains; preload')
            if 'preload' not in hsts:
                add_finding('low', 'HSTS preload not enabled',
                    sub='Domain not eligible for HSTS preload list',
                    asset=base_url, cvss='3.1', owasp='A02',
                    details='Add "preload" directive and submit domain at https://hstspreload.org/')

        # CSP quality check
        csp = headers.get('content-security-policy', '')
        if csp and ('unsafe-inline' in csp or 'unsafe-eval' in csp):
            add_finding('medium', 'Weak Content-Security-Policy: unsafe directives present',
                sub='unsafe-inline or unsafe-eval in CSP negates XSS protection',
                asset=base_url, cvss='5.4', owasp='A03',
                details=f'Current CSP: {csp[:200]}\n'
                        f'Problem: unsafe-inline allows inline JS execution\n'
                        f'Fix: Use nonce-based CSP or hash-based allowlisting instead')

        # Server version disclosure
        server = headers.get('server', '')
        if server and any(c.isdigit() for c in server):
            add_finding('low', f'Server version disclosed: {server}',
                sub='Version string aids fingerprinting and CVE targeting',
                asset=base_url, cvss='3.1', owasp='A05', mitre='T1592',
                details=f'Server header: {server}\nFix: Configure server_tokens off (nginx) or ServerTokens Prod (Apache)')

    except Exception as e:
        log('warn', f'[STATIC-HARDENING] Header check failed: {e}')

    # ── 3. Sensitive file exposure ──
    sensitive_files = [
        '/.git/HEAD', '/.git/config', '/.env', '/.env.backup', '/.htaccess',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/.well-known/security.txt', '/security.txt',
        '/package.json', '/composer.json', '/requirements.txt', '/Gemfile',
        '/config.json', '/config.yaml', '/config.yml', '/app.config.js',
        '/web.config', '/wp-config.php.bak', '/database.yml',
        '/.DS_Store', '/Thumbs.db', '/error_log', '/access.log',
    ]
    for path in sensitive_files:
        try:
            r = req_lib.get(f'{base_url}{path}', timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10:
                body_preview = r.text[:300]
                is_critical = any(kw in path for kw in ['.git', '.env', 'config', '.htaccess', 'database'])
                sev = 'critical' if is_critical else 'medium'
                cvss = '9.1' if is_critical else '5.3'
                add_finding(sev, f'Sensitive file exposed: {path}',
                    sub=f'File accessible at {base_url}{path}',
                    asset=f'{base_url}{path}', cvss=cvss, owasp='A05', mitre='T1552',
                    details=f'URL: {base_url}{path}\nStatus: {r.status_code}\n'
                            f'Content preview: {body_preview[:200]}\n'
                            f'Impact: Information disclosure, credential extraction, source code exposure\n'
                            f'Fix: Remove file or block access via CDN/server config rule')
                log('ok', f'[STATIC-HARDENING] Sensitive file: {path} (HTTP {r.status_code})')
        except Exception:
            pass

    # ── 4. Directory listing check ──
    for test_path in ['/', '/images/', '/assets/', '/static/', '/files/', '/uploads/']:
        try:
            r = req_lib.get(f'{base_url}{test_path}', timeout=5, verify=False)
            if r.status_code == 200:
                body_lower = r.text.lower()
                if ('index of' in body_lower or 'directory listing' in body_lower or
                        ('<title>index of' in body_lower) or
                        ('parent directory' in body_lower and 'href' in body_lower)):
                    add_finding('high', f'Directory listing enabled: {test_path}',
                        sub='Web server lists directory contents — exposes file structure and sensitive files',
                        asset=f'{base_url}{test_path}', cvss='5.3', owasp='A05', mitre='T1592',
                        details=f'URL: {base_url}{test_path}\n'
                                f'Fix: Add "Options -Indexes" (Apache) or "autoindex off" (nginx)\n'
                                f'For CDN: configure custom 403 response for directory URLs')
        except Exception:
            pass

    # ── 5. Mixed content check ──
    try:
        r = req_lib.get(base_url, timeout=8, verify=False)
        import re as _re
        http_resources = _re.findall(r'src=["\']http://[^"\']+["\']', r.text, _re.IGNORECASE)
        http_resources += _re.findall(r'href=["\']http://[^"\']+\.(?:css|js)["\']', r.text, _re.IGNORECASE)
        if http_resources:
            add_finding('medium', f'Mixed content: {len(http_resources)} HTTP resource(s) on HTTPS page',
                sub='HTTP resources on HTTPS page allow man-in-the-middle injection',
                asset=base_url, cvss='4.3', owasp='A02', mitre='T1557',
                details=f'Found {len(http_resources)} insecure resource(s):\n' +
                        '\n'.join(f'  {r[:100]}' for r in http_resources[:10]) +
                        '\nFix: Change all resource URLs to https:// or use protocol-relative //example.com/path')
    except Exception:
        pass

    # ── 6. Clickjacking ──
    try:
        r = req_lib.get(base_url, timeout=8, verify=False)
        headers = {k.lower(): v for k, v in r.headers.items()}
        has_xfo = 'x-frame-options' in headers
        csp_val = headers.get('content-security-policy', '')
        has_fa = 'frame-ancestors' in csp_val
        if not has_xfo and not has_fa:
            add_finding('medium', 'Clickjacking protection missing',
                sub='No X-Frame-Options or CSP frame-ancestors — page can be framed',
                asset=base_url, cvss='4.3', owasp='A04', mitre='T1185',
                details='The page can be loaded in an <iframe> on a malicious site.\n'
                        'Fix: Add X-Frame-Options: DENY or CSP: frame-ancestors \'none\'')
    except Exception:
        pass

    # ── 7. Subresource Integrity (SRI) check ──
    try:
        r = req_lib.get(base_url, timeout=8, verify=False)
        import re as _re
        external_scripts = _re.findall(
            r'<script[^>]+src=["\']https?://(?!' + re.escape(target) + r')[^"\']+["\'][^>]*>',
            r.text, _re.IGNORECASE)
        missing_sri = [s for s in external_scripts if 'integrity=' not in s.lower()]
        if missing_sri:
            add_finding('medium', f'Subresource Integrity (SRI) missing on {len(missing_sri)} external script(s)',
                sub='External CDN scripts load without integrity checks — supply chain attack risk',
                asset=base_url, cvss='5.3', owasp='A08', mitre='T1195',
                details=f'External scripts without SRI: {len(missing_sri)}\n'
                        f'First missing: {missing_sri[0][:200]}\n'
                        f'Fix: Add integrity="sha384-..." crossorigin="anonymous" to each <script src="https://cdn...">.\n'
                        f'Generate hashes at: https://www.srihash.org/')
    except Exception:
        pass

    # ── 8. Email security (SPF/DKIM/DMARC) ──
    if DNS_AVAILABLE:
        try:
            # SPF
            answers = dns.resolver.resolve(target, 'TXT')
            has_spf = any('v=spf1' in str(r) for r in answers)
            if not has_spf:
                add_finding('medium', 'SPF record missing',
                    sub='No SPF TXT record — email spoofing possible from this domain',
                    asset=target, cvss='5.3', owasp='A07',
                    details='Add TXT record: v=spf1 include:your-email-provider.com ~all')
        except Exception:
            pass
        try:
            # DMARC
            dmarc_answers = dns.resolver.resolve(f'_dmarc.{target}', 'TXT')
            has_dmarc = any('v=DMARC1' in str(r) for r in dmarc_answers)
            if not has_dmarc:
                add_finding('medium', 'DMARC record missing',
                    sub='No DMARC policy — phishing emails may pass authentication checks',
                    asset=target, cvss='5.3', owasp='A07',
                    details='Add TXT record: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com')
        except Exception:
            pass

    log('ok', f'[STATIC-HARDENING] Static hardening checks complete for {target}')


# ─── ADAPTIVE ROUTING — CLASSIFIER ───────────────────────────────────────────
