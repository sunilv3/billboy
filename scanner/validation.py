"""15-Rule FP Verification Engine — constants, helpers, and _validate_finding."""
import math
from urllib.parse import urlparse, urlunparse
from core.utils import CVSS3_AVAILABLE, CVSS3

# ── Redirect / HTML detection ─────────────────────────────────────────────────
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HTML_TAGS = ('<html', '<head', '<body', '<div', '<!doctype', '<!DOCTYPE')

# ── Confidence tiers (Rule 3) ─────────────────────────────────────────────────
CONF_TIER_INFORMATIONAL = (0, 39)
CONF_TIER_POTENTIAL     = (40, 69)
CONF_TIER_LIKELY        = (70, 89)
CONF_TIER_CONFIRMED     = (90, 100)

_CONF_STR_TO_SCORE = {
    'confirmed':   95,
    'high':        80,
    'medium':      55,
    'low':         35,
    'speculative': 25,
}

# ── Report categories (Rule 14) ───────────────────────────────────────────────
REPORT_CATEGORY_CONFIRMED = 'Confirmed Vulnerabilities'
REPORT_CATEGORY_LIKELY    = 'Likely Vulnerabilities'
REPORT_CATEGORY_POTENTIAL = 'Potential Findings'
REPORT_CATEGORY_HARDENING = 'Security Hardening Issues'
REPORT_CATEGORY_INFO      = 'Informational Observations'

_HARDENING_KEYWORDS = [
    'missing header', 'csp missing', 'hsts missing', 'x-frame', 'x-content-type',
    'referrer-policy', 'permissions-policy', 'tls version', 'ssl version',
    'weak cipher', 'insecure cookie', 'cookie without', 'clickjacking',
    'cors misconfiguration', 'server version', 'x-powered-by',
]

# ── Evidence requirements ─────────────────────────────────────────────────────
_XSS_EXECUTION_PROOF = [
    'playwright executed', 'alert triggered', 'alert(1)', 'dom mutation',
    'javascript executed', 'event handler fired', 'js executed', 'xss confirmed',
    'script executed', 'onerror fired', 'eval executed',
]
_SSRF_CALLBACK_PROOF = [
    'interactsh callback', 'burp collaborator', 'dns callback', 'http callback',
    'oast.pro', 'oast.me', 'oast.live', 'oast.fun', 'oast.online', 'oast.site',
    'interactsh.com', 'burpcollaborator.net', 'canarytokens.com',
]
_SSRF_METADATA_PROOF = [
    'ami-id', 'ami-launch-index', 'instance-id', 'instance-type',
    'security-credentials', 'iam/', 'local-ipv4', 'public-ipv4',
    'computemetadata', 'google-compute-instance', 'metadata.google.internal',
    '169.254.169.254', 'fd00:ec2::254',
    '"compute":', '"network":', '"azEnvironment"', '"subscriptionId"',
    '"vmid"', '"resourceGroupName"', 'instance-action', 'mac-address',
]

_SECRET_MIN_ENTROPY = 3.5
_FP_SECRET_MARKERS  = ['example', 'your_', 'xxx', 'test', 'dummy',
                        'placeholder', 'sample', 'mock', 'fake', 'changeme', 'change_me',
                        'redacted', 'foobar', 'lorem', 'ipsum', 'notreal', 'donotuse',
                        '<your', 'insert_', 'replace_', 'todo']

# Verbatim example tokens that ship in vendor docs / tutorials — always FPs.
_KNOWN_FP_TOKENS = {
    'akiaiosfodnn7example',                       # AWS docs access key
    'wjalrxutnfemi/k7mdeng/bpxrficyexamplekey',   # AWS docs secret key
    'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'sk_test_4ec6db8e8a2b4b3e9f1a',               # Stripe test-key shape
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '00000000000000000000000000000000',
    '1234567890abcdef1234567890abcdef',
    'deadbeefdeadbeefdeadbeefdeadbeef',
}

_ERROR_INDICATORS = [
    'error', 'invalid', 'unauthorized', 'forbidden', 'denied', 'failed',
    'not found', 'bad request', 'internal server error', 'service unavailable',
    'login', 'sign in', 'log in', 'session expired', 'access denied',
    'permission denied', 'credentials required', 'authentication required',
]

_INFO_PATTERNS = [
    'scan completed', 'scan finished', 'module completed',
    'dark web exposure scan completed', 'github leak scan completed',
    'waf detected:', 'waf fingerprint', 'technology detected',
    'attack graph', 'correlation completed', 'no waf detected',
    'hsts missing preload', 'missing cross-origin', 'no cdn detected',
    'no rate limiting detected', 'api rate limiting missing',
    'weak credential stuffing', 'weak web scraping',
    'rate limiting stress test', 'sensitive information in html comments',
    'compliance gaps detected', 'simulation mode', 'requires api key',
    'currently running in simulation',
]

_TYPE_EVIDENCE = {
    'nosql injection':       ['status changed', 'behavioral change', 'confirmed:'],
    'prototype pollution':   ['status changed', 'behavioral change', 'confirmed:'],
    'ssrf':                  ['ami-id', 'ami-launch-index', 'instance-id', 'instance-type',
                              'security-credentials', 'iam/', 'local-ipv4', 'public-ipv4',
                              'computeMetadata', 'google-compute-instance', 'metadata.google.internal',
                              '169.254.169.254', 'payload reflected', 'confirmed:'],
    'blind ssrf':            ['internal', 'metadata', 'confirmed:'],
    'web cache poisoning':   ['url context', 'reflection', 'confirmed:'],
    'open redirect':         ['confirmed:', 'external redirect'],
    'dom-based xss':         ['confirmed:'],
    'dalfox':                ['confirmed:'],
    'crlf injection':        ['not confirmed'],
    'vulnerable dependency': ['cve-', 'ghsa-', 'osv-', 'pysec'],
    'gitleaks':              ['placeholder', 'example', 'test'],
    'trufflehog':            ['placeholder', 'example', 'test'],
    'semgrep':               ['confidence: low', 'confidence: medium'],
    'directory traversal':   ['evidence: file contents', 'confirmed:'],
    'jwt':                   ['confirmed:', 'forged'],
    'graphql':               ['confirmed:', 'introspection'],
    'xxe':                   ['confirmed:', 'external entity'],
    'csrf':                  ['confirmed:'],
    'cloud metadata':        ['metadata', '169.254.169.254', 'confirmed:'],
    'iam':                   ['accesskeyid', 'role', 'confirmed:'],
    'cloud credential':      ['credential type', 'redacted', 'confirmed:'],
    'cloud service':         ['endpoint:', 'service:', 'confirmed:'],
    'security group':        ['port:', 'service:', 'confirmed:'],
    'xff bypass':            ['endpoint:', 'confirmed:'],
    'sql injection':         ['confirmed:', 'error pattern', 'payload reflected'],
    'xss':                   ['confirmed:', 'payload', 'reflected'],
    'command injection':     ['confirmed:', 'delay:'],
    'default credentials':   ['confirmed:'],
    'auth bypass':           ['confirmed:', 'bypass length', 'admin content', 'header:', 'bypass response'],
    'ssti':                  ['confirmed:', '49'],
    'cache poisoning':       ['cache status', 'via:', 'confirmed:'],
    'file upload':           ['confirmed:', 'executed'],
    'mass assignment':       ['confirmed:'],
    'idor':                  ['confirmed:', 'different data'],
    'race condition':        ['confirmed:', 'inconsistent'],
    'ldap injection':        ['confirmed:', 'error'],
    'header injection':      ['confirmed:', 'header reflected', 'injected header'],
    'deserialization':       ['confirmed:', 'deserialized'],
    'business logic':        ['confirmed:', 'manipulated'],
    'session fixation':      ['confirmed:', 'session id'],
    'jwt advanced':          ['confirmed:', 'forged', 'cracked'],
    'oauth':                 ['confirmed:', 'token', 'redirect_uri'],
    'api abuse':             ['confirmed:', 'different data', 'exposed'],
    'subdomain takeover':    ['confirmed:', 'claimable', 'unclaimed'],
    'dns rebinding':         ['confirmed:', 'rebind'],
    'websocket':             ['confirmed:', 'ws://', 'wss://'],
    'credential stuffing':   ['confirmed:', 'valid credentials'],
    '2fa bypass':            ['confirmed: bypassed', 'bypassed — auth-protected', 'bypassed — common code'],
    'host header':           ['confirmed: injected', 'injected header', 'injected host', 'reset link poisoned'],
    'file inclusion':        ['confirmed:', 'included', 'root:'],
    'cors with credentials': ['confirmed:', 'access-control-allow-credentials'],
    'crypto miner':          ['confirmed:', 'mining'],
    'clickjacking':          ['confirmed:', 'frameable'],
}


# ── Helper functions ──────────────────────────────────────────────────────────

def _shannon_entropy(s):
    if not s or len(s) < 8:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _confidence_score(conf_str):
    return _CONF_STR_TO_SCORE.get(str(conf_str).lower(), 55)


def _apply_severity_confidence_coupling(sev, conf_score, title):
    """Rule 3: severity must never exceed confidence tier.
    Returns (adjusted_sev, adjusted_title, report_category).
    """
    title_lower = title.lower()
    if any(kw in title_lower for kw in _HARDENING_KEYWORDS):
        category = REPORT_CATEGORY_HARDENING
    elif conf_score >= 90:
        category = REPORT_CATEGORY_CONFIRMED
    elif conf_score >= 70:
        category = REPORT_CATEGORY_LIKELY
    elif conf_score >= 40:
        category = REPORT_CATEGORY_POTENTIAL
    else:
        category = REPORT_CATEGORY_INFO

    if conf_score < 40:
        return 'info', title, category
    elif conf_score < 70:
        if sev in ('critical', 'high'):
            new_title = title if title.startswith('Potential') else f'Potential {title}'
            return 'medium', new_title, category
        return sev, title, category
    return sev, title, category


def _validate_finding(sev, title, details='', asset='', response_text='',
                      baseline_text='', response_status=None, confidence='medium'):
    """Universal FP gate — 15-Rule Verification Engine. Returns (allowed, reason)."""
    import re as _re
    title_lower   = title.lower()
    details_lower = details.lower() if details else ''
    conf_score    = _confidence_score(confidence)

    # 1. Info-pattern removal
    for pat in _INFO_PATTERNS:
        if pat in title_lower:
            return False, f'info-pattern: {pat}'

    # 2. Simulation mode
    if 'simulation mode' in details_lower or 'requires api key' in details_lower:
        return False, 'simulation mode'

    # 3. HTML error page without exploitation evidence
    if response_text:
        resp_lower = response_text.lower()
        if any(tag in resp_lower for tag in _HTML_TAGS):
            if sev in ('critical', 'high'):
                has_evidence = any(kw in details_lower for kw in
                                   ['confirmed:', 'payload', 'evidence:', 'reflected', 'executed'])
                if not has_evidence:
                    return False, 'HTML error page with no exploitation evidence'

    # 4. Redirect rejection
    if response_status in _REDIRECT_STATUSES:
        if any(kw in title_lower for kw in ['api', 'swagger', 'docs', 'openapi', 'unauthenticated']):
            return False, f'HTTP {response_status} redirect — endpoint redirects, not real exposure'
        if sev in ('critical', 'high'):
            if any(ind in details_lower for ind in
                   ['login', 'signin', 'sign-in', 'auth', 'unauthorized', 'home', 'index']):
                return False, f'HTTP {response_status} redirect to auth/home endpoint'

    # 5. Generic error indicators only
    if sev in ('critical', 'high') and details_lower:
        error_hits = [ind for ind in _ERROR_INDICATORS if ind in details_lower]
        if len(error_hits) >= 2 and not any(kw in details_lower for kw in
                                            ['confirmed:', 'payload', 'evidence:']):
            return False, f'error indicators only: {", ".join(error_hits[:3])}'

    # 6. Baseline content similarity
    if baseline_text and response_text:
        try:
            from Levenshtein import ratio as _lev_ratio
            sim = _lev_ratio(baseline_text[:3000], response_text[:3000])
        except ImportError:
            t1 = set(baseline_text[:3000].lower().split())
            t2 = set(response_text[:3000].lower().split())
            sim = len(t1 & t2) / max(len(t1 | t2), 1)
        if sim > 0.85 and sev in ('critical', 'high'):
            has_proof = any(kw in details_lower for kw in
                            ['confirmed:', 'payload', 'evidence:', 'reflected', 'executed'])
            if not has_proof:
                return False, f'content too similar to baseline ({sim:.0%})'

    # 7. SSRF requires callback or actual metadata
    if 'ssrf' in title_lower and 'blind' not in title_lower:
        has_callback  = any(kw in details_lower for kw in _SSRF_CALLBACK_PROOF)
        has_metadata  = any(kw in details_lower for kw in _SSRF_METADATA_PROOF)
        has_confirmed = 'confirmed:' in details_lower
        if not (has_callback or has_metadata or has_confirmed):
            return False, 'SSRF: no callback proof or metadata content (Rule 4)'

    # 8. XSS requires execution proof
    if 'xss' in title_lower and 'dom-based' not in title_lower:
        has_execution = any(kw in details_lower for kw in _XSS_EXECUTION_PROOF)
        if not has_execution and conf_score >= 70:
            return False, 'XSS: execution proof required for Likely/Confirmed (Rule 5)'

    # 9. Auth/2FA bypass requires session + access proof
    if any(kw in title_lower for kw in ['auth bypass', '2fa bypass', 'authentication bypass']):
        access_proof = [
            'session created', 'jwt issued', 'dashboard reached', 'admin content',
            'confirmed: bypassed', 'bypassed —', 'protected resource accessed',
            'user data returned', 'access granted',
        ]
        has_proof    = any(kw in details_lower for kw in access_proof)
        has_baseline = any(x in details_lower for x in
                           ['baseline:', '401', '403', 'auth required',
                            'bypass response', 'admin content', 'bypassed'])
        if not (has_proof and has_baseline):
            return False, 'Auth/2FA bypass: requires auth-required baseline + access proof (Rules 6–7)'

    # 10. Secret detection: format + entropy + known-example denylist
    if any(kw in title_lower for kw in ['secret', 'credential', 'api key', 'token exposed', 'password exposed']):
        if any(m in details_lower for m in _FP_SECRET_MARKERS):
            return False, 'placeholder/example secret (Rule 8)'
        val_match = _re.search(r'value[:\s]+([^\s\n]{8,})', details_lower)
        if val_match:
            secret_val = val_match.group(1).strip().strip('"\'')
            if secret_val in _KNOWN_FP_TOKENS:
                return False, 'known vendor/example token (Rule 8)'
            # Single-character or all-same-char runs (e.g. "aaaaaaaa", "********")
            if len(set(secret_val)) <= 2:
                return False, 'secret has near-zero character variety (Rule 8)'
            entropy = _shannon_entropy(secret_val)
            if entropy < _SECRET_MIN_ENTROPY:
                return False, f'secret entropy too low ({entropy:.2f}) (Rule 8)'

    # 11. GraphQL: endpoint + schema required
    if 'graphql introspection' in title_lower:
        needs_schema = any(kw in details_lower for kw in ['schema returned', '__schema', 'custom_types'])
        needs_200    = '200' in details_lower or 'confirmed:' in details_lower
        if not (needs_schema and needs_200):
            return False, 'GraphQL: requires endpoint confirmation + schema data (Rule 9)'

    # 12. Sensitive file exposure: HTTP 200 + actual content
    sensitive_file_titles = [
        '.env', 'config.php', '.git/config', 'web.config', '.htpasswd',
        'database.yml', 'wp-config', '.aws/credentials', 'id_rsa',
        'sensitive file', 'exposed file', 'file exposure',
    ]
    if any(sf in title_lower for sf in sensitive_file_titles):
        has_200     = any(kw in details_lower for kw in ['200', 'http 200', 'status: 200'])
        has_content = any(kw in details_lower for kw in
                          ['content:', 'body:', 'confirmed:', 'file contents', 'retrieved'])
        if not (has_200 and has_content):
            return False, 'Sensitive file: requires HTTP 200 + content retrieval (Rule 10)'

    # 13. Public pages are not vulnerabilities without sensitive data
    if any(kw in title_lower for kw in ['unauthenticated access', 'public endpoint']):
        sensitive_signals = [
            'admin functionality', 'sensitive functionality', '"password":', '"secret":',
            '"api_key":', '"access_token":', '"is_admin":true', '"admin":true',
            'user data exposed', 'private data', 'protected api',
        ]
        if not any(sig in details_lower for sig in sensitive_signals):
            return False, 'Public endpoint without sensitive data (Rule 11)'

    # 14. Type-specific evidence requirements
    for vuln_type, required_keywords in _TYPE_EVIDENCE.items():
        if vuln_type in title_lower:
            if vuln_type in ('gitleaks', 'trufflehog', 'semgrep'):
                if any(kw in details_lower for kw in required_keywords):
                    return False, f'{vuln_type}: FP marker detected'
            elif vuln_type == 'crlf injection':
                if 'not confirmed' in details_lower:
                    return False, 'crlf: not confirmed'
            else:
                if not any(kw in details_lower for kw in required_keywords):
                    return False, f'{vuln_type}: missing required evidence ({required_keywords[0]})'

    # 15. Secret/dependency placeholder rejection
    if any(kw in title_lower for kw in ['secret', 'credential', 'leaked', 'exposed']):
        if any(m in details_lower for m in _FP_SECRET_MARKERS):
            return False, 'placeholder/example secret'
    if any(kw in title_lower for kw in ['vulnerable dependency', 'outdated package', 'cve']):
        if not any(kw in details_lower for kw in ['cve-', 'ghsa-', 'osv-', 'pysec', 'exploit']):
            return False, 'no CVE/GHSA identifier'

    return True, ''


# ── CVSS scoring ──────────────────────────────────────────────────────────────

_CVSS_VECTORS = {
    'sqli':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'xss':           'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    'ssrf':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    'rce':           'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'lfi':           'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    'idor':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    'cors':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
    'ssti':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'cmdi':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'xxe':           'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    'open_redirect': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    'header':        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    'secret':        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'port':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    'jwt':           'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'oauth':         'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
    'csrf':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'deser':         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'upload':        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'smuggle':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'session':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
    'auth':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'nosql':         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'ldap':          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    'redirect':      'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    'proto':         'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    'cache':         'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
    'cloud':         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    'container':     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'graphql':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
}

_CVSS_FALLBACK = {
    'sqli': ('9.8', 'CRITICAL'), 'xss': ('6.1', 'MEDIUM'), 'ssrf': ('8.6', 'HIGH'),
    'rce': ('9.8', 'CRITICAL'), 'lfi': ('7.5', 'HIGH'), 'ssti': ('9.8', 'CRITICAL'),
    'cmdi': ('9.8', 'CRITICAL'), 'secret': ('7.5', 'HIGH'), 'idor': ('7.5', 'HIGH'),
    'cors': ('8.1', 'HIGH'), 'xxe': ('8.6', 'HIGH'), 'open_redirect': ('6.1', 'MEDIUM'),
    'header': ('5.3', 'MEDIUM'), 'port': ('5.3', 'MEDIUM'), 'jwt': ('8.1', 'HIGH'),
    'oauth': ('8.1', 'HIGH'), 'csrf': ('6.5', 'MEDIUM'), 'deser': ('9.8', 'CRITICAL'),
    'upload': ('9.8', 'CRITICAL'), 'smuggle': ('8.1', 'HIGH'), 'session': ('8.1', 'HIGH'),
    'auth': ('8.1', 'HIGH'), 'nosql': ('8.1', 'HIGH'), 'ldap': ('7.5', 'HIGH'),
    'redirect': ('6.1', 'MEDIUM'), 'proto': ('9.0', 'CRITICAL'), 'cache': ('7.4', 'HIGH'),
    'cloud': ('9.1', 'CRITICAL'), 'container': ('9.8', 'CRITICAL'), 'graphql': ('8.1', 'HIGH'),
}


def calculate_cvss(vuln_class, auth_required=False, user_interaction=False, scope_changed=True):
    """Compute CVSS 3.1 score. Returns (score_str, severity_label, vector_string)."""
    if not CVSS3_AVAILABLE:
        score, sev = _CVSS_FALLBACK.get(vuln_class, ('5.0', 'MEDIUM'))
        return score, sev, f'CVSS:3.1 (fallback for {vuln_class})'
    base = _CVSS_VECTORS.get(vuln_class, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N')
    if auth_required:
        base = base.replace('/PR:N', '/PR:L')
    if user_interaction:
        base = base.replace('/UI:N', '/UI:R')
    try:
        c = CVSS3(base)
        return f'{c.scores()[0]:.1f}', c.severity().upper(), base
    except Exception:
        return '5.0', 'MEDIUM', base


# ── Vuln classification & fingerprinting ─────────────────────────────────────

def classify_vuln(title):
    """Map a finding title to a canonical vulnerability class."""
    t = title.lower()
    rules = [
        ('sqli',        ['sql injection', 'sqli', 'database error', 'mysql_fetch', 'sql syntax', 'ora-']),
        ('xss',         ['cross-site scripting', 'xss', 'dom-based xss', 'reflected xss', 'stored xss']),
        ('ssrf',        ['server-side request forgery', 'ssrf', 'internal request', 'cloud metadata']),
        ('xxe',         ['xml external entity', 'xxe', 'xml injection']),
        ('ssti',        ['server-side template injection', 'ssti', 'template injection']),
        ('cmdi',        ['command injection', 'os command', 'cmd injection']),
        ('lfi',         ['local file inclusion', 'lfi', 'file inclusion', 'path traversal', 'directory traversal']),
        ('rfi',         ['remote file inclusion', 'rfi']),
        ('idor',        ['insecure direct object', 'idor', 'object reference']),
        ('auth',        ['authentication bypass', 'auth bypass', 'weak credential', 'default password',
                         'brute force', 'credential stuffing']),
        ('jwt',         ['jwt ', 'json web token']),
        ('oauth',       ['oauth', 'token leakage']),
        ('session',     ['session fixation', 'session hijack', 'session management']),
        ('csrf',        ['cross-site request forgery', 'csrf']),
        ('cors',        ['cross-origin', 'cors misconfiguration', 'cors ']),
        ('redirect',    ['open redirect', 'unvalidated redirect', 'redirect']),
        ('header',      ['missing security header', 'security header', 'header injection',
                         'host header', 'clickjack']),
        ('deser',       ['deserialization', 'insecure deserialization']),
        ('upload',      ['file upload', 'unrestricted upload']),
        ('secret',      ['secret', 'credential', 'api key', 'password', 'token leak',
                         'private key', 'leaked']),
        ('ssl',         ['ssl', 'tls', 'certificate', 'cipher']),
        ('port',        ['open port', 'port scan', 'service detected']),
        ('dns',         ['dns ', 'spf', 'dmarc', 'dkim']),
        ('cloud',       ['s3 bucket', 'cloud storage', 'azure blob', 'gcs', 'cloud vm',
                         'imds', 'metadata endpoint']),
        ('container',   ['docker', 'container', 'kubelet', 'kubernetes', 'k8s', 'etcd']),
        ('smuggle',     ['request smuggling', 'http smuggle']),
        ('cache',       ['cache poison', 'cache deception']),
        ('proto',       ['prototype pollution']),
        ('nosql',       ['nosql injection', 'mongodb injection']),
        ('ldap',        ['ldap injection']),
        ('race',        ['race condition', 'time-of-check']),
        ('mass',        ['mass assignment']),
        ('websocket',   ['websocket']),
        ('graphql',     ['graphql']),
        ('supplychain', ['supply chain', 'dependency', 'cve-']),
        ('waf',         ['waf', 'firewall bypass']),
    ]
    for cls, keywords in rules:
        if any(kw in t for kw in keywords):
            return cls
    return 'other'


def normalize_asset(asset):
    if not asset:
        return ''
    try:
        parsed = urlparse(asset)
        clean = urlunparse(parsed._replace(
            query='', fragment='', path=parsed.path.rstrip('/') or '/'))
        return clean.lower()
    except Exception:
        return asset.lower().split('?')[0].split('#')[0].rstrip('/')


def _extract_param(title, asset, details):
    """Best-effort affected-parameter extraction, consistent across detectors.

    Different modules describe the same vuln differently (some write
    'Parameter: id', some only put '?id=1' in the asset URL, sqlmap-confirmed
    findings sometimes name no parameter at all). Converging on one value here
    is what lets dedup collapse the duplicates those modules would otherwise emit.
    """
    import re as _re
    # 1. explicit "Parameter:"/"param:" line in details
    for line in (details or '').split('\n'):
        ll = line.lower().strip()
        if ll.startswith('parameter:') or 'param:' in ll:
            val = line.split(':', 1)[1].strip().lower()
            # take the first token (handles "id (MySQL)" / "id, cat")
            return _re.split(r'[\s,(]', val, maxsplit=1)[0].strip()
    # 2. "via <param>" / "in <param>" phrasing in the title
    m = _re.search(r'\bvia\s+([A-Za-z0-9_\-\[\]]+)', title or '', _re.I)
    if m:
        return m.group(1).lower()
    # 3. query string on the asset URL (?id=1&page=2 → 'id')
    try:
        q = urlparse(asset).query
        if q:
            first = q.split('&')[0].split('=')[0].strip().lower()
            if first:
                return first
    except Exception:
        pass
    # 4. "?<param>=" anywhere in details
    m = _re.search(r'[?&]([A-Za-z0-9_\-]+)=', details or '')
    if m:
        return m.group(1).lower()
    return ''


def fingerprint(title, asset, details=''):
    """Semantic fingerprint: vuln_class|normalized_asset|param."""
    vuln_class = classify_vuln(title)
    norm_asset = normalize_asset(asset)
    param = _extract_param(title, asset, details)
    return f'{vuln_class}|{norm_asset}|{param}'


# ── Tool output / exploit steps ───────────────────────────────────────────────

def _extract_tool_output(details):
    """Extract tool-specific key:value pairs from finding details."""
    tool_output = {}
    for line in details.split('\n'):
        line = line.strip()
        if ':' in line:
            key, _, val = line.partition(':')
            key = key.strip().lower()
            val = val.strip()
            if key in ('sqlmap', 'nuclei', 'dalfox', 'nmap', 'sslyze', 'ffuf',
                       'gitleaks', 'semgrep', 'crlfuzz', 'osv-scanner', 'httpx',
                       'subfinder', 'amass', 'gau', 'katana', 'wafw00f', 'trufflehog'):
                tool_output[key] = val
            elif 'payload' in key or 'evidence' in key or 'proof' in key:
                tool_output[key] = val
    return tool_output


def _generate_exploit_steps(title, asset, details):
    """Auto-generate step-by-step exploitation commands based on vulnerability type."""
    title_lower = title.lower()
    steps = []
    parsed = urlparse(asset) if asset else None
    base = f'{parsed.scheme}://{parsed.netloc}' if parsed else asset

    def _p(d):
        for ln in d.split('\n'):
            if 'parameter:' in ln.lower():
                return ln.split(':', 1)[1].strip()
        return ''

    if 'sql injection' in title_lower or 'sqli' in title_lower:
        p = _p(details)
        steps = [
            f'1. Confirm: sqlmap -u "{base}/?{p}=1" --batch --risk=2 --level=3',
            f'2. Enumerate DBs: sqlmap -u "{base}/?{p}=1" --batch --dbs',
            f'3. Dump tables: sqlmap -u "{base}/?{p}=1" --batch -D <db> --tables',
            f'4. Extract data: sqlmap -u "{base}/?{p}=1" --batch -D <db> -T <tbl> --dump',
            f'5. OS shell: sqlmap -u "{base}/?{p}=1" --batch --os-shell',
        ]
    elif 'xss' in title_lower or 'cross-site scripting' in title_lower:
        p = _p(details)
        steps = [
            f'1. Basic payload: {base}/?{p}=<script>alert(1)</script>',
            f'2. Event handler: {base}/?{p}="><img src=x onerror=alert(1)>',
            f'3. dalfox: dalfox url "{base}/?{p}=test" --skip-bav',
            f'4. Verify in browser console — check unescaped output',
            f'5. Craft phishing URL with encoded payload',
        ]
    elif 'ssrf' in title_lower and 'cloud metadata' in title_lower:
        steps = [
            f'1. Metadata: {base}/?url=http://169.254.169.254/latest/meta-data/',
            f'2. IAM role: {base}/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            f'3. Credentials: Replace <ROLE> with actual role name',
            f'4. Configure AWS CLI with stolen creds',
            f'5. Enumerate: aws s3 ls && aws iam list-roles',
        ]
    elif 'ssrf' in title_lower:
        p = _p(details)
        steps = [
            f'1. Internal: {base}/?{p}=http://127.0.0.1',
            f'2. Cloud metadata: {base}/?{p}=http://169.254.169.254/latest/meta-data/',
            f'3. File read: {base}/?{p}=file:///etc/passwd',
            f'4. DNS rebinding: {base}/?{p}=http://rebind.it/rebind',
        ]
    elif 'command injection' in title_lower or 'cmdi' in title_lower:
        p = _p(details)
        steps = [
            f'1. Basic: {base}/?{p}=;id',
            f'2. Backticks: {base}/?{p}=`id`',
            f'3. Subshell: {base}/?{p}=$(id)',
            f'4. Blind: {base}/?{p}=;sleep 5',
            f'5. Exfil: {base}/?{p}=;cat /etc/passwd',
        ]
    elif any(kw in title_lower for kw in ('path traversal', 'directory traversal', 'lfi')):
        p = _p(details)
        steps = [
            f'1. Basic: {base}/?{p}=../../../etc/passwd',
            f'2. URL encoded: {base}/?{p}=%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            f'3. Double encoded: {base}/?{p}=%252e%252e%252fetc/passwd',
            f'4. Null byte: {base}/?{p}=../../../etc/passwd%00',
        ]
    elif 'xxe' in title_lower or 'xml external' in title_lower:
        steps = [
            f'1. Send XXE payload to {base}/api/xml with <!DOCTYPE ... SYSTEM "file:///etc/passwd">',
            f'2. Blind XXE via OOB DNS callback',
            f'3. SSRF via XXE: Replace file:/// with http://169.254.169.254/',
        ]
    elif 'open redirect' in title_lower:
        steps = [
            f'1. Test: {base}/redirect?url=https://evil.com',
            f'2. Protocol-relative: {base}/redirect?url=//evil.com',
            f'3. @ bypass: {base}/redirect?url=https://legit.com@evil.com',
        ]
    elif 'jwt' in title_lower:
        steps = [
            '1. Decode token: Parse header.payload.signature',
            '2. Test none alg: jwt_tool.py <token> -X k -S none',
            '3. Crack secret: jwt_tool.py <token> -C -d wordlist.txt',
            '4. Forge admin: jwt_tool.py <token> -X k -S none -pc name -pv admin',
        ]
    elif 'csrf' in title_lower:
        steps = [
            f'1. Craft form: <form action="{base}" method="POST">...<script>document.forms[0].submit()</script></form>',
            f'2. Host on attacker server, send link to victim',
            f'3. Verify state change in victim account',
        ]
    else:
        if asset and base:
            steps = [
                f'1. Verify manually: Open {base} in browser',
                f'2. curl -v "{base}"',
                f'3. Confirm with additional tools',
            ]
    return steps


# ── Context risk scoring ──────────────────────────────────────────────────────

def calculate_finding_context_risk(finding):
    """Context-aware risk score (0-100). Returns (adjusted_score, factors_list)."""
    from scanner.state import scan_state, LOCK
    try:
        base = float(str(finding.get('cvss', 0)))
    except (TypeError, ValueError):
        base = 5.0

    multiplier = 1.0
    factors = []

    if finding.get('exploit') in ('PUBLIC', 'ATTACK'):
        multiplier += 0.20
        factors.append('Public exploit available (+20%)')

    fp = finding.get('fingerprint', '')
    if fp:
        with LOCK:
            dupes = sum(1 for f in scan_state.get('findings', [])
                        if f.get('fingerprint') == fp and f.get('id') != finding.get('id'))
        if dupes > 0:
            multiplier += 0.15
            factors.append(f'Corroborated by {dupes} other finding(s) (+15%)')

    with LOCK:
        is_ext = scan_state.get('is_external_target', True)
    if is_ext:
        multiplier += 0.10
        factors.append('Internet-facing target (+10%)')

    details_lower = (finding.get('details', '') + ' ' + finding.get('title', '')).lower()
    if any(kw in details_lower for kw in
           ['password', 'secret', 'token', 'api_key', 'credit card', 'ssn',
            'pii', 'credentials', 'private key', 'database dump']):
        multiplier += 0.15
        factors.append('Sensitive data exposure (+15%)')

    if not finding.get('verified', True):
        multiplier -= 0.20
        factors.append('Unverified finding (-20%)')
    if finding.get('confidence') == 'speculative':
        multiplier -= 0.10
        factors.append('Speculative confidence (-10%)')

    adjusted = min(100, max(0, round(base * 10 * multiplier)))
    return adjusted, factors
