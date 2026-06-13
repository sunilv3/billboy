"""Post-scan verification: de-dup, confidence scoring, attack chain building, risk scoring."""
import time
import hashlib
import re
from urllib.parse import urlparse
from scanner.state import scan_state, LOCK
from core.logger import log
from core.utils import req_lib, REQUESTS_AVAILABLE, _safe_str, _safe_int, _run_tool
from scanner.findings import op_log
from scanner.validation import (
    classify_vuln, normalize_asset, _confidence_score, fingerprint,
    _HARDENING_KEYWORDS,
    REPORT_CATEGORY_CONFIRMED, REPORT_CATEGORY_LIKELY, REPORT_CATEGORY_POTENTIAL,
    REPORT_CATEGORY_HARDENING, REPORT_CATEGORY_INFO,
)


# Attack chain definitions: (keywords_all_must_match, chain_name, severity)
ATTACK_CHAINS = [
    (['cors', 'xss'],                    'Session theft via CORS + XSS',                'critical'),
    (['sqli', 'auth'],                   'Auth bypass via SQLi + weak credentials',      'critical'),
    (['sqli', 'secret'],                 'Data dump via SQLi + leaked credentials',      'critical'),
    (['ssrf', 'cloud'],                  'Cloud metadata takeover via SSRF',            'critical'),
    (['ssrf', 'secret'],                 'Internal secrets exfil via SSRF',             'high'),
    (['lfi', 'secret'],                  'Credential theft via LFI',                    'high'),
    (['lfi', 'auth'],                    'Auth bypass via LFI + credential file read',  'critical'),
    (['xss', 'session'],                 'Session hijack via stored XSS',               'critical'),
    (['xss', 'redirect'],               'Phishing chain via XSS + open redirect',      'high'),
    (['upload', 'auth'],                 'Server compromise via file upload + auth',    'critical'),
    (['upload', 'cmdi'],                 'Remote code execution via upload',            'critical'),
    (['deser', 'auth'],                  'RCE via insecure deserialization',            'critical'),
    (['ssti', 'auth'],                   'RCE via template injection',                  'critical'),
    (['jwt', 'auth'],                    'Full auth bypass via JWT weakness',           'critical'),
    (['secret', 'cloud'],                'Cloud account compromise via leaked creds',   'critical'),
    (['idor', 'auth'],                   'Privilege escalation via IDOR',              'high'),
    (['cors', 'auth'],                   'Cross-origin credential theft',              'high'),
    (['smuggle', 'auth'],                'Request smuggling → auth bypass',            'critical'),
    (['cache', 'secret'],                'Credential leakage via cache poisoning',     'high'),
    (['nosql', 'auth'],                  'NoSQL auth bypass + data exfil',             'high'),
    (['ldap', 'auth'],                   'LDAP auth bypass',                           'critical'),
    (['proto', 'xss'],                   'XSS via prototype pollution',                'high'),
    (['header', 'redirect'],             'Open redirect via header injection',         'high'),
    (['race', 'upload'],                 'Privilege escalation via race condition',    'high'),
    (['supplychain', 'secret'],          'Supply chain credential exposure',           'high'),
    (['port', 'auth'],                   'Brute force via exposed service',            'medium'),
    (['ssl', 'secret'],                  'Credential interception via weak TLS',       'high'),
    (['graphql', 'auth'],                'GraphQL auth bypass + data leak',            'high'),
    (['websocket', 'auth'],              'WebSocket auth bypass',                      'high'),
]


class AttackPathAnalyzer:
    """Graph-based attack-path analysis.

    Groups findings by host, orders them along the kill-chain
    (entry → exploit → objective), and emits multi-stage paths with an
    aggregate impact score. Returns:
        {paths: [{path:[{finding_id,title,type}], impact, length}],
         total_paths, critical_paths}
    """

    _SEV_WEIGHT = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}

    # kill-chain stage per vuln class (lower = earlier)
    _STAGE = {
        # entry / exposure
        'port': 0, 'dns': 0, 'ssl': 0, 'header': 0, 'waf': 0, 'secret': 0,
        # foothold / exploitation
        'xss': 1, 'csrf': 1, 'redirect': 1, 'cors': 1, 'ssrf': 1, 'lfi': 1,
        'idor': 1, 'auth': 1, 'jwt': 1, 'oauth': 1, 'session': 1, 'nosql': 1,
        'ldap': 1, 'smuggle': 1, 'cache': 1, 'proto': 1, 'graphql': 1,
        # objective / impact
        'sqli': 2, 'rce': 2, 'cmdi': 2, 'ssti': 2, 'xxe': 2, 'deser': 2,
        'upload': 2, 'cloud': 2, 'container': 2, 'supplychain': 2,
    }

    @classmethod
    def _stage(cls, vuln_class):
        return cls._STAGE.get(vuln_class, 1)

    @classmethod
    def analyze(cls, findings):
        # group findings by host
        by_host = {}
        for f in findings or []:
            host = normalize_asset(f.get('asset', '')) or f.get('asset', '') or '_'
            vuln_class = classify_vuln(f.get('title', ''))
            by_host.setdefault(host, []).append({
                'finding_id': f.get('id'),
                'title': f.get('title', ''),
                'type': vuln_class,
                'stage': cls._stage(vuln_class),
                'weight': cls._SEV_WEIGHT.get(f.get('sev', 'info'), 1),
            })

        paths = []
        for host, nodes in by_host.items():
            # need at least two distinct kill-chain stages to form a path
            if len({n['stage'] for n in nodes}) < 2:
                continue
            ordered = sorted(nodes, key=lambda n: (n['stage'], -n['weight']))
            # de-dup by type while preserving order, keep highest-weight per type
            seen, path_nodes = set(), []
            for n in ordered:
                if n['type'] in seen:
                    continue
                seen.add(n['type'])
                path_nodes.append({'finding_id': n['finding_id'],
                                   'title': n['title'], 'type': n['type']})
            if len(path_nodes) < 2:
                continue
            impact = sum(n['weight'] for n in ordered)
            paths.append({'path': path_nodes, 'impact': impact,
                          'length': len(path_nodes), 'host': host})

        paths.sort(key=lambda p: p['impact'], reverse=True)
        return {
            'paths': paths,
            'total_paths': len(paths),
            'critical_paths': sum(1 for p in paths if p['impact'] >= 20),
        }

def verify_findings():
    """Cross-check findings to eliminate false positives with module-specific logic.

    Includes a hard wall-clock timeout so the post-scan verification never
    blocks the orchestrator indefinitely (e.g. when live HTTP re-checks
    for open-redirect findings time out).
    """
    _VERIFY_TIMEOUT = 60  # seconds — max time for the entire verification pass

    log('info', '[VERIFY] Cross-checking findings for false positive elimination...')
    with LOCK:
        findings = list(scan_state.get('findings', []))

    verified_count = 0
    fp_count = 0
    _verify_start = time.time()

    # Patterns that indicate informational/status messages, not real findings
    info_patterns = [
        'scan completed', 'scan finished', 'module completed',
        'dark web exposure scan completed', 'github leak scan completed',
        'waf detected:', 'waf fingerprint', 'technology detected',
        'attack graph', 'correlation completed',
        'no waf detected', 'hsts missing preload', 'missing cross-origin-opener-policy',
        'missing cross-origin-embedder-policy', 'missing cross-origin-resource-policy',
        'no cdn detected', 'no rate limiting detected', 'api rate limiting missing',
        'weak credential stuffing', 'weak web scraping', 'rate limiting stress test',
        'sensitive information in html comments', 'compliance gaps detected',
    ]

    for f in findings:
        # ── Hard timeout guard ──
        if time.time() - _verify_start > _VERIFY_TIMEOUT:
            log('warn', f'[VERIFY] Timeout ({_VERIFY_TIMEOUT}s) reached — stopping verification early')
            break

        title = f.get('title', '').lower()
        asset = f.get('asset', '')
        sev = f.get('sev', 'info')
        details = f.get('details', '')
        details_lower = details.lower()
        verified = True

        # ─── FILTER: Remove informational status messages ───
        if any(pattern in title for pattern in info_patterns):
            verified = False
            fp_count += 1
            log('info', f'[VERIFY] FILTERED status message: {f["title"]}')
            f['verified'] = False
            continue

        # ─── FILTER: Remove findings with "simulation mode" evidence ───
        if 'simulation mode' in details_lower or 'requires api key' in details_lower or 'currently running in simulation' in details_lower:
            verified = False
            fp_count += 1
            log('info', f'[VERIFY] FILTERED simulation finding: {f["title"]}')
            f['verified'] = False
            continue

        # ─── FILTER: Remove info-severity findings (informational, not vulnerabilities) ───
        if sev == 'info':
            verified = False
            fp_count += 1
            log('info', f'[VERIFY] FILTERED info-severity: {f["title"]}')
            f['verified'] = False
            continue

        # ─── NoSQL Injection: must show behavioral change evidence ───
        if 'nosql injection' in title:
            if 'status changed' not in details_lower and 'behavioral change' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No behavioral change evidence')

        # ─── Prototype Pollution: must show behavioral change evidence ───
        elif 'prototype pollution' in title:
            if 'status changed' not in details_lower and 'behavioral change' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No behavioral change evidence')

        # ─── SSRF: must show proof indicators (ami-id, instance-id, etc.) ───
        elif 'ssrf' in title:
            ssrf_proof = ['ami-id', 'ami-launch-index', 'instance-id', 'instance-type',
                          'security-credentials', 'iam/', 'local-ipv4', 'public-ipv4',
                          'computeMetadata', 'google-compute-instance', 'metadata.google.internal',
                          'metadata/computeMetadata', '169.254.169.254']
            if not any(x in details_lower for x in ssrf_proof) and 'payload reflected' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No SSRF proof indicators')

        # ─── Web Cache Poisoning: must show URL-context reflection ───
        elif 'cache poisoning' in title:
            if 'url context' not in details_lower and 'reflection' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No URL-context reflection evidence')

        # ─── Secrets: filter common false positive patterns ───
        elif 'secret exposed' in title:
            fp_secret_patterns = [
                'example', 'your_', 'xxx', 'test', 'dummy', 'placeholder',
                'sample', 'mock', 'fake', 'changeme', 'change_me',
            ]
            match_text = f.get('sub', '').lower() + details_lower
            if any(p in match_text for p in fp_secret_patterns):
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - Placeholder/example value')

        # ─── Open Redirect: quick heuristic check (no live HTTP requests) ───
        elif 'open redirect' in title:
            from urllib.parse import parse_qs
            parsed = urlparse(asset)
            params = parse_qs(parsed.query)
            for param, values in params.items():
                if not values:
                    continue
                payload = values[0]
                # Relative-path redirects are same-origin — mark as FP
                if payload.startswith('/') and not payload.startswith('//'):
                    verified = False
                    fp_count += 1
                    log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - Redirect to relative path {payload}')
                    break
            # NOTE: Live HTTP re-verification removed — it caused the
            # orchestrator to hang when the target was slow/unreachable.
            # The heuristic above catches the most common false-positive
            # case (relative paths); real external redirects are kept.

        # ─── DOM-based XSS: verify the sink is actually dangerous ───
        elif 'dom-based xss' in title:
            if 'manual verification required' in details_lower and 'not reflected' in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No reflection confirmed')

        # ─── Missing header findings: check if it's a duplicate ───
        elif 'missing security header' in title or 'no content-security-policy' in title:
            header_name = title.split(':')[-1].strip() if ':' in title else ''
            is_dup = False
            with LOCK:
                same_header = [x for x in scan_state['findings']
                              if x.get('id') != f.get('id') and
                              (header_name.lower() in x.get('title', '').lower() or
                               x.get('title', '').lower() in title)]
                if len(same_header) > 0:
                    is_dup = True
            if is_dup:
                verified = False
                fp_count += 1
                log('info', f'[VERIFY] DUPLICATE: {f["title"]} (keeping first occurrence)')

        # ═══════════════════════════════════════════════════════════════════
        # NEW MODULE VERIFICATION RULES
        # ═══════════════════════════════════════════════════════════════════

        # ─── Dalfox XSS: must have confirmed PoC ───
        elif 'dalfox' in title.lower() or ('xss' in title and 'dalfox' in details_lower):
            if 'not confirmed' in details_lower or 'no poc' in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - XSS not confirmed by dalfox')

        # ─── OSV Dependency: must have CVE ID ───
        elif 'vulnerable dependency' in title:
            if not any(x in title.lower() for x in ['cve-', 'ghsa-', 'osv-', 'pysec-']):
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No valid CVE/OSV ID')

        # ─── Gitleaks/Trufflehog Secrets: must have verified or high entropy ───
        elif 'leaked secret' in title or 'deep secret' in title:
            if 'placeholder' in details_lower or 'example' in details_lower or 'test' in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - Placeholder/example secret')

        # ─── Semgrep SAST: must have high/medium confidence ───
        elif 'sast:' in title.lower():
            if 'confidence: low' in details_lower or 'confidence: medium' in details_lower:
                # Only keep high-confidence SAST findings
                if 'severity: error' not in details_lower:
                    verified = False
                    fp_count += 1
                    log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - Low/medium confidence SAST finding')

        # ─── CRLF Injection: must be confirmed ───
        elif 'crlf injection' in title:
            if 'not confirmed' in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - CRLF not confirmed')

        # ─── OOB Detection: filter common FP patterns ───
        elif 'blind ssrf' in title or 'oob' in title.lower():
            if 'internal' not in details_lower and 'metadata' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No SSRF proof evidence')

        # ─── Directory Traversal: must have confirmed evidence ───
        elif 'directory traversal' in title:
            if 'evidence: file contents' not in details_lower and 'confirmed' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No file access evidence')

        # ─── JWT vulnerabilities: must have confirmed evidence ───
        elif 'jwt' in title.lower():
            if 'confirmed:' not in details_lower and 'forged' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No JWT attack confirmation')

        # ─── GraphQL: must have confirmed evidence ───
        elif 'graphql' in title.lower():
            if 'confirmed:' not in details_lower and 'introspection' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No GraphQL confirmation')

        # ─── XXE: must have confirmed evidence ───
        elif 'xxe' in title.lower():
            if 'confirmed:' not in details_lower and 'external entity' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No XXE confirmation')

        # ─── CSRF: must have confirmed evidence ───
        elif 'csrf' in title.lower():
            if 'confirmed:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No CSRF confirmation')

        # ─── Cloud VM: must have cloud-specific evidence ───
        elif 'cloud metadata ssrf' in title or 'imds ssrf' in title.lower():
            if 'metadata' not in details_lower and '169.254.169.254' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No IMDS evidence')

        elif 'iam role credentials exposed' in title or 'iam creds' in title.lower():
            if 'accesskeyid' not in details_lower and 'role' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No IAM credential evidence')

        elif 'cloud credential exposed' in title:
            if 'credential type' not in details_lower or 'redacted' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No credential evidence')

        elif 'cloud service exposed' in title:
            if 'endpoint:' not in details_lower and 'service:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No service evidence')

        elif 'security group allows' in title:
            if 'port:' not in details_lower and 'service:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No port evidence')

        elif 'xff bypass' in title.lower() or 'x-forwarded-for' in title.lower():
            if 'endpoint:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No endpoint evidence')

        # ─── Manual SQLi: must have confirmed evidence ───
        elif 'sql injection' in title and 'manual' in title.lower():
            if 'confirmed:' not in details_lower and 'error pattern' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No SQLi confirmation')

        # ─── Manual XSS: must have confirmed reflection ───
        elif 'xss' in title and 'manual' in title.lower():
            if 'confirmed:' not in details_lower and 'payload' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No XSS confirmation')

        # ─── Manual SSRF: must have confirmed evidence ───
        elif 'ssrf' in title and 'manual' in title.lower():
            if 'confirmed:' not in details_lower and 'evidence:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No SSRF confirmation')

        # ─── Command injection: must have confirmed evidence ───
        elif 'command injection' in title:
            if 'confirmed:' not in details_lower and 'delay:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No CMDi confirmation')

        # ─── Default credentials: must have confirmed login ───
        elif 'default credentials' in title:
            if 'confirmed:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No login confirmation')

        # ─── Auth bypass: must have evidence ───
        elif 'auth bypass' in title:
            if 'confirmed:' not in details_lower and 'bypass length' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No auth bypass evidence')

        # ─── 2FA bypass: must show a baseline auth failure AND a successful bypass ───
        elif '2fa bypass' in title or 'two-factor' in title.lower():
            has_baseline = any(x in details_lower for x in ['baseline:', 'baseline =', '401', '403'])
            has_bypass_proof = 'confirmed:' in details_lower or 'bypassed' in details_lower
            if not (has_baseline and has_bypass_proof):
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No baseline auth + bypass proof')

        # ─── Host header injection: must show the injected value in response ───
        elif 'host header injection' in title:
            has_confirmation = ('confirmed:' in details_lower and
                                ('injected' in details_lower or 'reflected' in details_lower or 'poisoned' in details_lower))
            if not has_confirmation:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No injection reflection evidence')

        # ─── BOLA / API abuse: must show auth-required baseline + successful access ───
        elif 'bola' in title.lower() or ('api' in title.lower() and 'auth bypass' in title.lower()):
            has_baseline = any(x in details_lower for x in ['baseline', '401', '403'])
            has_bypass_proof = 'confirmed:' in details_lower or 'bypassed' in details_lower
            if not (has_baseline and has_bypass_proof):
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No auth baseline + bypass proof')

        # ─── SSTI: must have mathematical confirmation ───
        elif 'template injection' in title:
            if 'confirmed:' not in details_lower and '49' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No SSTI confirmation')

        # ─── Cache poisoning: must have cache evidence ───
        elif 'cache poisoning' in title:
            if 'cache status' not in details_lower and 'via:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No cache evidence')

        # ─── File upload: must have execution evidence ───
        elif 'unrestricted file upload' in title:
            if 'confirmed:' not in details_lower and 'executed' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No upload execution evidence')

        # ─── Mass assignment: must have field evidence ───
        elif 'mass assignment' in title:
            if 'confirmed:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No mass assignment evidence')

        # ─── IDOR: must have data evidence ───
        elif 'idor' in title.lower():
            if 'confirmed:' not in details_lower and 'different data' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No IDOR evidence')

        # ─── Race condition: must have response evidence ───
        elif 'race condition' in title:
            if 'confirmed:' not in details_lower and 'inconsistent' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No race condition evidence')

        # ─── NoSQL Injection: must have behavioral change ───
        elif 'nosql' in title.lower() and 'injection' in title.lower():
            if 'status changed' not in details_lower and 'behavioral change' not in details_lower and 'confirmed:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No NoSQL injection evidence')

        # ─── LDAP Injection: must have confirmed evidence ───
        elif 'ldap' in title.lower() and 'injection' in title.lower():
            if 'confirmed:' not in details_lower and 'error' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No LDAP injection evidence')

        # ─── Header Injection: must have header reflection ───
        elif 'header injection' in title:
            if 'confirmed:' not in details_lower and 'header reflected' not in details_lower and 'injected header' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No header injection evidence')

        # ─── Open Redirect: must have external redirect evidence ───
        elif 'open redirect' in title:
            if 'confirmed:' not in details_lower and 'external redirect' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No open redirect confirmation')

        # ─── Insecure Deserialization: must have confirmed evidence ───
        elif 'deserialization' in title or 'insecure deserialization' in title:
            if 'confirmed:' not in details_lower and 'deserialized' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No deserialization evidence')

        # ─── Prototype Pollution: must have behavioral change ───
        elif 'prototype pollution' in title:
            if 'confirmed:' not in details_lower and 'status changed' not in details_lower and 'behavioral change' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No prototype pollution evidence')

        # ─── Advanced XXE: must have confirmed evidence ───
        elif 'xxe' in title.lower() and ('advanced' in title.lower() or 'oob' in title.lower()):
            if 'confirmed:' not in details_lower and 'external entity' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No advanced XXE evidence')

        # ─── Business Logic: must have confirmed evidence ───
        elif 'business logic' in title:
            if 'confirmed:' not in details_lower and 'manipulated' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No business logic flaw evidence')

        # ─── Session Fixation: must have confirmed evidence ───
        elif 'session fixation' in title:
            if 'confirmed:' not in details_lower and 'session id' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No session fixation evidence')

        # ─── JWT Advanced: must have confirmed evidence ───
        elif 'jwt' in title.lower() and ('advanced' in title.lower() or 'none alg' in title.lower() or 'weak secret' in title.lower() or 'algorithm confusion' in title.lower()):
            if 'confirmed:' not in details_lower and 'forged' not in details_lower and 'cracked' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No JWT advanced attack evidence')

        # ─── OAuth: must have confirmed evidence ───
        elif 'oauth' in title.lower():
            if 'confirmed:' not in details_lower and 'token' not in details_lower and 'redirect_uri' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No OAuth vulnerability evidence')

        # ─── API Abuse: must have confirmed evidence ───
        elif 'api abuse' in title or 'bola' in title.lower() or 'excessive data' in title.lower():
            if 'confirmed:' not in details_lower and 'different data' not in details_lower and 'exposed' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No API abuse evidence')

        # ─── Subdomain Takeover Verify: must have confirmed evidence ───
        elif 'subdomain takeover' in title and 'verify' in title.lower():
            if 'confirmed:' not in details_lower and 'claimable' not in details_lower and 'unclaimed' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No subdomain takeover confirmation')

        # ─── DNS Rebinding: must have confirmed evidence ───
        elif 'dns rebinding' in title:
            if 'confirmed:' not in details_lower and 'rebind' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No DNS rebinding evidence')

        # ─── WebSocket: must have confirmed evidence ───
        elif 'websocket' in title.lower():
            if 'confirmed:' not in details_lower and 'ws://' not in details_lower and 'wss://' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No WebSocket vulnerability evidence')

        # ─── Credential Stuffing: filter ───
        elif 'credential stuffing' in title:
            if 'confirmed:' not in details_lower and 'valid credentials' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No credential stuffing evidence')

        # ─── 2FA Bypass: must have confirmed evidence ───
        elif '2fa' in title.lower() or 'two-factor' in title.lower():
            if 'confirmed:' not in details_lower and 'bypassed' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No 2FA bypass evidence')

        # ─── Host Header Injection: must have confirmed evidence ───
        elif 'host header' in title:
            if 'confirmed:' not in details_lower and 'injected' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No host header injection evidence')

        # ─── File Inclusion: must have confirmed evidence ───
        elif 'file inclusion' in title or 'lfi' in title.lower() or 'rfi' in title.lower():
            if 'confirmed:' not in details_lower and 'included' not in details_lower and 'root:' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No file inclusion evidence')

        # ─── CORS with Credentials: must have confirmed evidence ───
        elif 'cors' in title.lower() and ('credential' in title.lower() or 'wildcard' in title.lower()):
            if 'confirmed:' not in details_lower and 'access-control-allow-credentials' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No CORS credentials evidence')

        # ─── Crypto Miner: must have confirmed evidence ───
        elif 'crypto miner' in title or 'cryptocurrency' in title.lower():
            if 'confirmed:' not in details_lower and 'mining' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No crypto miner evidence')

        # ─── Clickjacking Deep: must have confirmed evidence ───
        elif 'clickjack' in title.lower() and 'deep' in title.lower():
            if 'confirmed:' not in details_lower and 'frameable' not in details_lower:
                verified = False
                fp_count += 1
                log('warn', f'[VERIFY] FALSE POSITIVE: {f["title"]} - No clickjacking evidence')

        # ─── Subdomain Enumeration: informational, always keep ───
        elif 'subdomain enumeration' in title:
            pass  # Always keep as-is, these are informational

        f['verified'] = verified
        if verified:
            verified_count += 1

    # Remove unverified findings
    with LOCK:
        scan_state['findings'] = [f for f in scan_state.get('findings', []) if f.get('verified', True)]

    # Rule 14: Assign report categories to surviving findings
    with LOCK:
        for f in scan_state['findings']:
            if 'report_category' not in f:
                cs = f.get('confidence_score', _confidence_score(f.get('confidence', 'medium')))
                title_l = f.get('title', '').lower()
                if any(kw in title_l for kw in _HARDENING_KEYWORDS):
                    f['report_category'] = REPORT_CATEGORY_HARDENING
                elif cs >= 90:
                    f['report_category'] = REPORT_CATEGORY_CONFIRMED
                elif cs >= 70:
                    f['report_category'] = REPORT_CATEGORY_LIKELY
                elif cs >= 40:
                    f['report_category'] = REPORT_CATEGORY_POTENTIAL
                else:
                    f['report_category'] = REPORT_CATEGORY_INFO

    final_count = len(scan_state.get('findings', []))
    # Rule 14: Count by category
    with LOCK:
        cats = {}
        for f in scan_state['findings']:
            cats[f.get('report_category', 'Unknown')] = cats.get(f.get('report_category', 'Unknown'), 0) + 1
    cat_summary = ' | '.join(f'{v} {k}' for k, v in sorted(cats.items()))
    log('ok', f'[VERIFY] Verification complete: {verified_count} verified, {fp_count} false positives removed. {final_count} findings remain. [{cat_summary}]')


# ═══════════════════════════════════════════════════════════════════════════════
# PURE-PYTHON VULNERABILITY DETECTION MODULES (new, 2026)
# Modules: prototype_pollution, smuggling, cache_poisoning, graphql_deep,
#          jwt_deep, lfi, open_redirect_deep, race_condition_deep,
#          bizlogic, subdomain_takeover, ssrf_deep
# ═══════════════════════════════════════════════════════════════════════════════

# ─── MODULE 1: Prototype Pollution ───────────────────────────────────────────


def build_attack_chains():
    """Post-scan: build attack chains using graph-based path analysis.
    
    Combines keyword-matching chains with graph-based attack path discovery.
    """
    log('info', '[CHAINS] Building attack chains from findings')
    
    with LOCK:
        findings = list(scan_state.get('findings', []))
    
    if not findings:
        return
    
    chains_built = []
    
    # ── Phase 1: Keyword-matching chains (fast, backward-compatible) ──
    finding_titles = [(f, f.get('title', '').lower()) for f in findings]
    
    for keywords, chain_name, chain_sev in ATTACK_CHAINS:
        matched_findings = []
        all_matched = True
        
        for kw in keywords:
            kw_found = False
            for f, title in finding_titles:
                f_class = classify_vuln(f.get('title', ''))
                if kw in title or kw in f_class:
                    if f['id'] not in [m['id'] for m in matched_findings]:
                        matched_findings.append(f)
                    kw_found = True
            if not kw_found:
                all_matched = False
                break
        
        if all_matched and len(matched_findings) >= 2:
            chain_id = hashlib.md5(f'{chain_name}_{time.time()}'.encode()).hexdigest()[:10]
            for f in matched_findings:
                with LOCK:
                    for sf in scan_state['findings']:
                        if sf['id'] == f['id']:
                            sf['chain_id'] = chain_id
                            break
            chains_built.append({
                'chain_id': chain_id,
                'name': chain_name,
                'severity': chain_sev,
                'finding_ids': [f['id'] for f in matched_findings],
                'finding_titles': [f.get('title', '')[:60] for f in matched_findings],
                'source': 'keyword_matching',
            })
    
    # ── Phase 2: Graph-based attack path analysis ──
    try:
        path_report = AttackPathAnalyzer.analyze(findings)
        
        for i, attack_path in enumerate(path_report.get('paths', [])[:10]):
            path_nodes = attack_path.get('path', [])
            if len(path_nodes) < 2:
                continue
            
            chain_id = hashlib.md5(f'graph_{i}_{time.time()}'.encode()).hexdigest()[:10]
            path_finding_ids = [n.get('finding_id') for n in path_nodes if n.get('finding_id')]
            path_titles = [n.get('title', '')[:60] for n in path_nodes]
            
            # Determine severity from path impact
            impact = attack_path.get('impact', 0)
            if impact >= 20:
                severity = 'critical'
            elif impact >= 12:
                severity = 'high'
            elif impact >= 6:
                severity = 'medium'
            else:
                severity = 'low'
            
            entry_type = path_nodes[0].get('type', 'unknown')
            obj_type = path_nodes[-1].get('type', 'unknown')
            
            chain_name = f'{entry_type} → ' + ' → '.join(n.get('type', '?') for n in path_nodes[1:])
            if len(chain_name) > 80:
                chain_name = chain_name[:77] + '...'
            
            # Stamp chain_id on findings
            for fid in path_finding_ids:
                with LOCK:
                    for sf in scan_state['findings']:
                        if sf['id'] == fid:
                            sf['chain_id'] = chain_id
                            break
            
            chains_built.append({
                'chain_id': chain_id,
                'name': chain_name,
                'severity': severity,
                'impact_score': impact,
                'finding_ids': path_finding_ids,
                'finding_titles': path_titles,
                'source': 'graph_analysis',
                'entry': entry_type,
                'objective': obj_type,
                'path_length': attack_path.get('length', 0),
            })
        
        # Store full path report
        with LOCK:
            scan_state['attack_path_report'] = path_report
        
        log('ok', f'[CHAINS] Graph analysis: {path_report["total_paths"]} paths found, '
            f'{path_report["critical_paths"]} critical')
    except Exception as e:
        log('warn', f'[CHAINS] Graph analysis failed: {e}')
    
    with LOCK:
        scan_state['attack_chains'] = chains_built
    
    log('ok', f'[CHAINS] {len(chains_built)} attack chains identified')


# ─── OOB (OUT-OF-BAND) CALLBACK VERIFICATION ──────────────────────────────────
import os as _os
_OOB_URL = _os.environ.get('INTERACTSH_URL', '')
_OOB_TOKEN = _os.environ.get('INTERACTSH_TOKEN', '')




def calculate_risk_score():
    with LOCK:
        stats = dict(scan_state.get('stats', {}))
        findings = list(scan_state.get('findings', []))
        ports = list(scan_state.get('port_data', []))
        missing_hdrs = list(scan_state.get('header_data', {}).get('missing_security', []))

    score = 0
    breakdown = []

    # ── Rule 13: Risk score uses ONLY confirmed/likely findings ──────────────────
    # confirmed (score 90+) = full weight, likely (70-89) = 50%, below 70 = 0%
    def _risk_weight(f):
        score = f.get('confidence_score', _confidence_score(f.get('confidence', 'medium')))
        if score >= 90:
            return 1.0
        elif score >= 70:
            return 0.5
        else:
            return 0.0

    # ── CVSS-weighted severity scoring (Rule 13 weighted) ───────────────────────
    cvss_scores = []
    for f in findings:
        if not f.get('verified', True):
            continue
        w = _risk_weight(f)
        if w == 0.0:
            continue  # Potential/informational findings do not affect risk score
        raw = f.get('cvss', '')
        try:
            cvss_scores.append(float(str(raw)) * w)
        except (TypeError, ValueError):
            pass

    if cvss_scores:
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        max_cvss = max(cvss_scores)
        # Scale: avg_cvss contributes up to 25 pts, max_cvss up to 20 pts
        cvss_pts = round(avg_cvss / 10.0 * 25) + round(max_cvss / 10.0 * 20)
        score += cvss_pts
        breakdown.append({'factor': f'CVSS avg={avg_cvss:.1f}/max={max_cvss:.1f}', 'points': cvss_pts})

    # ── Severity count contribution (Rule 13: only confirmed+likely findings) ────
    confirmed_crits  = sum(1 for f in findings if f.get('sev') == 'critical'  and _risk_weight(f) >= 1.0)
    confirmed_highs  = sum(1 for f in findings if f.get('sev') == 'high'      and _risk_weight(f) >= 1.0)
    confirmed_meds   = sum(1 for f in findings if f.get('sev') == 'medium'    and _risk_weight(f) >= 1.0)
    confirmed_lows   = sum(1 for f in findings if f.get('sev') == 'low'       and _risk_weight(f) >= 1.0)
    likely_crits     = sum(1 for f in findings if f.get('sev') == 'critical'  and _risk_weight(f) == 0.5)
    likely_highs     = sum(1 for f in findings if f.get('sev') == 'high'      and _risk_weight(f) == 0.5)

    sev_pts = min(35, (
        confirmed_crits * 10 + confirmed_highs * 5 + confirmed_meds * 2 + confirmed_lows * 1 +
        int(likely_crits * 5) + int(likely_highs * 2)   # 50% contribution
    ))
    if sev_pts:
        score += sev_pts
        breakdown.append({'factor': f'Severity counts (C={stats.get("critical",0)} H={stats.get("high",0)} M={stats.get("medium",0)} L={stats.get("low",0)})', 'points': sev_pts})

    # ── High-risk open ports ─────────────────────────────────────────────────────
    HIGH_RISK_PORTS = {23, 445, 3306, 3389, 6379, 27017, 9200, 2375, 5432, 6443}
    high_risk_ports = [p for p in ports if p.get('port') in HIGH_RISK_PORTS]
    if high_risk_ports:
        pts = min(10, len(high_risk_ports) * 3)
        score += pts
        breakdown.append({'factor': f'{len(high_risk_ports)} high-risk ports exposed', 'points': pts})

    # ── Missing security headers ─────────────────────────────────────────────────
    if missing_hdrs:
        pts = min(5, len(missing_hdrs) * 1)
        score += pts
        breakdown.append({'factor': f'{len(missing_hdrs)} missing security headers', 'points': pts})

    # ── Context-aware multipliers (VulnRisk-inspired) ─────────────────────────
    # Exploit availability: findings with PUBLIC exploit get 1.2x multiplier
    exploit_findings = [f for f in findings if f.get('exploit') in ('PUBLIC', 'ATTACK')]
    if exploit_findings:
        bonus = min(10, len(exploit_findings) * 2)
        score += bonus
        breakdown.append({'factor': f'{len(exploit_findings)} findings with public exploits', 'points': bonus})

    # Corroboration: findings detected by multiple tools get confidence boost
    corroboration_map = {}
    for f in findings:
        fp = f.get('fingerprint', '')
        if fp:
            corroboration_map.setdefault(fp, []).append(f)
    corroborated = {k: v for k, v in corroboration_map.items() if len(v) > 1}
    if corroborated:
        bonus = min(8, len(corroborated) * 3)
        score += bonus
        breakdown.append({'factor': f'{len(corroborated)} findings corroborated by multiple tools', 'points': bonus})

    # Unverified findings penalty: reduces score (fewer false positives)
    unverified = [f for f in findings if not f.get('verified', True)]
    if unverified and len(findings) > 0:
        fp_ratio = len(unverified) / len(findings)
        if fp_ratio > 0.5:
            penalty = min(10, int(fp_ratio * 15))
            score -= penalty
            breakdown.append({'factor': f'{len(unverified)} unverified findings ({fp_ratio:.0%} FP risk)', 'points': -penalty})

    # Internet-facing exposure: if target has public DNS resolution
    with LOCK:
        is_external = scan_state.get('is_external_target', True)
    if is_external:
        bonus = min(5, 5)
        score += bonus
        breakdown.append({'factor': 'Internet-facing target (external exposure)', 'points': bonus})

    score = max(0, min(score, 100))
    with LOCK:
        scan_state['risk_score'] = score
        scan_state['risk_breakdown'] = breakdown
    return score
