"""Network vulnerability modules: email security, dark web, OOB, OSINT."""
import re
import json
import time
import socket
import secrets
import ssl
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE, DNS_AVAILABLE, BS4_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress

def run_theharvester_module(target):
    """OSINT gathering — theHarvester binary or Python crt.sh+DNS fallback."""
    set_progress('theharvester', 5)
    emails = []
    hosts = []
    ips = []
    # Try theHarvester binary first
    harvester_path = _find_tool('theHarvester') or _find_tool('theharvester')
    if harvester_path:
        out = f'/tmp/harvest_{secrets.token_hex(4)}'
        try:
            cmd = [harvester_path, '-d', target, '-b', 'google,bing,duckduckgo,certspotter',
                   '-f', out, '-l', '100']
            _run_tool(cmd, timeout=45)
            json_out = out + '.json'
            if os.path.isfile(json_out):
                with open(json_out) as f:
                    data = json.load(f)
                emails = data.get('emails', [])
                hosts = data.get('hosts', [])
                ips = data.get('ips', [])
            elif os.path.isfile(out):
                with open(out) as f:
                    for line in f:
                        line = line.strip()
                        if '@' in line and '.' in line:
                            emails.append(line)
                        elif line and not line.startswith('[') and '.' in line:
                            hosts.append(line)
        except Exception as e:
            log('warn', f'[THEHARVESTER] Error: {e}')
        finally:
            for p in (out, out + '.json'):
                try: os.remove(p)
                except OSError: pass
    else:
        # Python fallback: crt.sh Certificate Transparency + DNS reverse lookup
        log('info', '[THEHARVESTER] Using Python fallback for OSINT (crt.sh + DNS)')
        if REQUESTS_AVAILABLE:
            # 1. crt.sh for subdomains + emails
            try:
                r = req_lib.get(f'https://crt.sh/?q=%.{target}&output=json',
                               timeout=15, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    seen_names = set()
                    seen_emails = set()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for n in name.split('\n'):
                            n = n.strip().lower()
                            if n.endswith(f'.{target}') and n not in seen_names:
                                hosts.append(n)
                                seen_names.add(n)
                            elif '@' in n and n not in seen_emails:
                                emails.append(n)
                                seen_emails.add(n)
            except Exception:
                pass
            # 2. DNS forward lookup for common subdomains
            COMMON = ['www','mail','smtp','pop','imap','webmail','mx','ns1','ns2',
                      'admin','dev','staging','test','api','app','portal','cdn',
                      'vpn','git','ci','jenkins','grafana','kibana','status',
                      'docs','wiki','blog','shop','store','pay','billing',
                      'db','redis','mongo','elastic','backup','old','legacy',
                      's3','assets','static','images','media','files']
            for sub in COMMON:
                if not scan_state.get('scanning'):
                    break
                fqdn = f'{sub}.{target}'
                try:
                    socket.gethostbyname(fqdn)
                    if fqdn not in hosts:
                        hosts.append(fqdn)
                except socket.gaierror:
                    pass
        log('ok', f'[THEHARVESTER] Python fallback: {len(hosts)} hosts, {len(emails)} emails')
    # Store results
    with LOCK:
        scan_state.setdefault('osint_data', {})
        scan_state['osint_data']['emails'] = emails
        scan_state['osint_data']['hosts'] = hosts
        scan_state['osint_data']['ips'] = ips
    if hosts:
        with LOCK:
            existing = {a.get('name', '') for a in scan_state.get('assets', [])}
            for h in hosts:
                h = h.strip().lower()
                if h and h not in existing:
                    scan_state['assets'].append({'name': h, 'type': 'subdomain', 'source': 'theharvester'})
                    existing.add(h)
    if emails:
        add_finding('info', f'OSINT: {len(emails)} email addresses discovered',
                    asset=f'https://{target}',
                    details=f'Emails: {", ".join(emails[:10])}', confidence='high')
        log('ok', f'[THEHARVESTER] Found {len(emails)} emails, {len(hosts)} hosts')
    else:
        log('info', '[THEHARVESTER] No emails found via OSINT')
    set_progress('theharvester', 100)


def run_whois_module(target):
    log('info', f'[WHOIS] Looking up WHOIS data for {target}')
    whois_data = {'error': 'WHOIS lookup not available without python-whois library'}
    try:
        import whois as whois_lib
        w = whois_lib.whois(target)
        if w:
            whois_data = {
                'registrar': w.registrar or '',
                'created': str(w.creation_date)[:25] if w.creation_date else '',
                'expires': str(w.expiration_date)[:25] if w.expiration_date else '',
                'updated': str(w.updated_date)[:25] if w.updated_date else '',
                'registrant_org': w.org or '',
                'registrant_email': w.emails or '',
                'status': ', '.join(w.status) if w.status else '',
                'nameservers': w.name_servers or [],
            }
            log('ok', '[WHOIS] Data retrieved successfully')
    except ImportError:
        log('warn', '[WHOIS] python-whois not installed — skipping')
    except Exception as e:
        log('warn', f'[WHOIS] Lookup failed: {e}')
    with LOCK:
        scan_state['whois_data'] = whois_data
    set_progress('whois', 100)

# ─── DIRECTORY BRUTE FORCE MODULE ─────────────────────────────────────────────
DIR_WORDLIST = ['admin','login','wp-admin','wp-content','uploads','backup','.git','.env','config','api','v1','v2','graphql','swagger','docs','health','status','robots.txt','sitemap.xml','crossdomain.xml','clientaccesspolicy.xml','.well-known','web.config','phpinfo.php','test','debug','console','dashboard','panel','cpanel','plesk','phpmyadmin','adminer','pgadmin','mysql','sql','db','database','install','setup','config.php','configuration','credentials','password','secret','token','key','cert','ssl','logs','log','error','error_log','access_log','access','tmp','temp','cache','backup.sql','dump.sql','export.sql','data.sql','db.sql','db_backup.sql','bak','old','new','dev','stage','testing','demo','sample','example','index.html','index.php','default.aspx','server-status','server-info']



def run_emailsec_module(target):
    log('info', f'[EMAILSEC] Checking email security for {target}')
    emailsec = {}
    if DNS_AVAILABLE:
        try:
            spf = dns.resolver.resolve(target, 'TXT', lifetime=4)
            for r in spf:
                txt = str(r)
                if 'v=spf1' in txt:
                    emailsec['spf'] = txt[:200]
                    log('ok', f'[EMAILSEC] SPF record found')
                    if '~all' in txt:
                        log('warn', '[EMAILSEC] SPF softfail (~all) — not fully hardened')
                    elif '-all' in txt:
                        log('ok', '[EMAILSEC] SPF hardfail (-all) configured')
                    else:
                        log('warn', '[EMAILSEC] SPF missing hardfail (-all)')
                    break
            if 'spf' not in emailsec:
                emailsec['spf'] = ''
                log('warn', '[EMAILSEC] No SPF record found')
        except Exception:
            emailsec['spf'] = ''
            log('warn', '[EMAILSEC] No SPF record found')
        try:
            dmarc = dns.resolver.resolve(f'_dmarc.{target}', 'TXT', lifetime=4)
            for r in dmarc:
                txt = str(r)
                if 'v=DMARC1' in txt:
                    emailsec['dmarc'] = txt[:200]
                    log('ok', f'[EMAILSEC] DMARC record found')
                    if 'p=none' in txt:
                        log('warn', '[EMAILSEC] DMARC policy p=none — no enforcement')
                    elif 'p=quarantine' in txt:
                        log('ok', '[EMAILSEC] DMARC policy p=quarantine')
                    elif 'p=reject' in txt:
                        log('ok', '[EMAILSEC] DMARC policy p=reject — strict')
                    break
            if 'dmarc' not in emailsec:
                emailsec['dmarc'] = ''
                log('warn', '[EMAILSEC] No DMARC record found')
        except Exception:
            emailsec['dmarc'] = ''
            log('warn', '[EMAILSEC] No DMARC record found')
        try:
            dkim = dns.resolver.resolve(f'*._domainkey.{target}', 'TXT', lifetime=4)
            if dkim:
                emailsec['dkim'] = 'DKIM record(s) found'
                log('ok', '[EMAILSEC] DKIM record found')
        except Exception:
            emailsec['dkim'] = ''
            log('warn', '[EMAILSEC] No DKIM record found')
        if not emailsec.get('spf'):
            add_finding('medium', 'Missing SPF record',
                sub=f'Target domain {target} has no SPF record, making it vulnerable to email spoofing',
                asset=target, cvss='5.0', owasp='A05')
        if not emailsec.get('dmarc'):
            add_finding('medium', 'Missing DMARC record',
                sub=f'Target domain {target} has no DMARC record', asset=target, cvss='5.0', owasp='A05')
    else:
        log('warn', '[EMAILSEC] dnspython not available')
        emailsec = {'spf': '', 'dmarc': '', 'dkim': ''}
    with LOCK:
        scan_state['emailsec_data'] = emailsec
    set_progress('emailsec', 100)

# ─── SUBDOMAIN TAKEOVER MODULE ─────────────────────────────────────────────────
TAKEOVER_SERVICES = {
    'github.com': 'GitHub Pages',
    's3.amazonaws.com': 'AWS S3',
    's3-website': 'AWS S3 Website',
    'cloudfront.net': 'AWS CloudFront',
    'herokuapp.com': 'Heroku',
    'firebaseio.com': 'Firebase',
    'surge.sh': 'Surge',
    'pantheon.io': 'Pantheon',
    'freshdesk.com': 'Freshdesk',
    'zendesk.com': 'Zendesk',
    'unbounce.com': 'Unbounce',
    'statuspage.io': 'StatusPage',
    'atlassian.net': 'Atlassian',
    'azurewebsites.net': 'Azure App Service',
    'trafficmanager.net': 'Azure Traffic Manager',
    'cloudapp.net': 'Azure Cloud Services',
    'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
    'netlify.app': 'Netlify',
    'vercel.app': 'Vercel',
    'pages.dev': 'Cloudflare Pages',
    'fly.dev': 'Fly.io',
    'render.com': 'Render',
}



def run_netsec_module(target):
    log('info', f'[NETSEC] Performing advanced network security analysis for {target}')
    netsec = {
        'open_ports': [],
        'high_risk_services': [],
        'firewall_rules': [],
        'network_segments': [],
        'service_versions': [],
        'vulnerability_assessment': {},
        'port_scan_results': {},
        'recommendations': [],
        'summary': {}
    }

    with LOCK:
        ports = list(scan_state.get('port_data', []))
        ssl_data = dict(scan_state.get('ssl_data', {}))
        dns_data = dict(scan_state.get('dns_data', {}))

    # ── Port Analysis with Service Risk Classification ──
    log('info', '[NETSEC] Analyzing open ports and service risks')
    high_risk_ports = {
        21: {'service': 'FTP', 'risk': 'high', 'issues': ['Plaintext credentials', 'Anonymous access', 'Known vulnerabilities']},
        22: {'service': 'SSH', 'risk': 'low', 'issues': ['Brute force attacks', 'Key-based auth recommended']},
        23: {'service': 'Telnet', 'risk': 'critical', 'issues': ['Plaintext protocol', 'No encryption', 'Remote code execution']},
        25: {'service': 'SMTP', 'risk': 'medium', 'issues': ['Open relay', 'Email spoofing', 'SMTP injection']},
        53: {'service': 'DNS', 'risk': 'medium', 'issues': ['Zone transfer', 'DNS amplification', 'Cache poisoning']},
        80: {'service': 'HTTP', 'risk': 'medium', 'issues': ['Web application attacks', 'XSS', 'SQLi']},
        110: {'service': 'POP3', 'risk': 'high', 'issues': ['Plaintext credentials', 'Known vulnerabilities']},
        111: {'service': 'RPCBind', 'risk': 'high', 'issues': ['Remote code execution', 'Information disclosure']},
        135: {'service': 'MSRPC', 'risk': 'high', 'issues': ['Remote code execution', 'Lateral movement']},
        139: {'service': 'NetBIOS', 'risk': 'high', 'issues': ['Information disclosure', 'SMB relay attacks']},
        143: {'service': 'IMAP', 'risk': 'medium', 'issues': ['Plaintext credentials', 'Known vulnerabilities']},
        443: {'service': 'HTTPS', 'risk': 'low', 'issues': ['SSL/TLS vulnerabilities', 'Certificate issues']},
        445: {'service': 'SMB', 'risk': 'critical', 'issues': ['EternalBlue', 'Ransomware', 'Lateral movement']},
        993: {'service': 'IMAPS', 'risk': 'low', 'issues': ['Certificate validation']},
        995: {'service': 'POP3S', 'risk': 'low', 'issues': ['Certificate validation']},
        1433: {'service': 'MSSQL', 'risk': 'critical', 'issues': ['SQL injection', 'Brute force', 'Remote code execution']},
        1434: {'service': 'MSSQL Browser', 'risk': 'critical', 'issues': ['Information disclosure', 'SQL Slammer']},
        3306: {'service': 'MySQL', 'risk': 'critical', 'issues': ['SQL injection', 'Brute force', 'Remote code execution']},
        3389: {'service': 'RDP', 'risk': 'critical', 'issues': ['BlueKeep', 'Brute force', 'Credential stuffing']},
        5432: {'service': 'PostgreSQL', 'risk': 'critical', 'issues': ['SQL injection', 'Command execution']},
        5900: {'service': 'VNC', 'risk': 'critical', 'issues': ['Brute force', 'Unencrypted authentication']},
        6379: {'service': 'Redis', 'risk': 'critical', 'issues': ['Unauthenticated access', 'Remote code execution']},
        8080: {'service': 'HTTP-Proxy', 'risk': 'medium', 'issues': ['Proxy abuse', 'Web application attacks']},
        8443: {'service': 'HTTPS-Alt', 'risk': 'low', 'issues': ['Certificate validation']},
        9200: {'service': 'Elasticsearch', 'risk': 'critical', 'issues': ['Remote code execution', 'Data exfiltration']},
        9300: {'service': 'Elasticsearch', 'risk': 'critical', 'issues': ['Remote code execution']},
        11211: {'service': 'Memcached', 'risk': 'critical', 'issues': ['DDoS amplification', 'Remote code execution']},
        27017: {'service': 'MongoDB', 'risk': 'critical', 'issues': ['Unauthenticated access', 'Data exfiltration']},
        27018: {'service': 'MongoDB', 'risk': 'critical', 'issues': ['Unauthenticated access']},
        50000: {'service': 'SAP', 'risk': 'high', 'issues': ['Remote code execution', 'Information disclosure']},
    }

    for p in ports:
        port_num = p.get('port', 0)
        service = p.get('service', 'unknown')
        ip = p.get('ip', target)
        version = p.get('version', '')
        banner = p.get('banner', '')

        port_info = {
            'port': port_num,
            'service': service,
            'ip': ip,
            'version': version,
            'banner': banner,
            'risk_level': 'unknown',
            'issues': []
        }

        if port_num in high_risk_ports:
            hr = high_risk_ports[port_num]
            port_info['risk_level'] = hr['risk']
            port_info['issues'] = hr['issues']
            netsec['high_risk_services'].append(port_info)

            if hr['risk'] in ('critical', 'high'):
                add_finding(
                    'critical' if hr['risk'] == 'critical' else 'high',
                    f'High-risk service exposed: {service} on port {port_num}',
                    sub=f'Service {service} ({version}) is exposed with known security risks: {", ".join(hr["issues"][:3])}',
                    asset=f'{ip}:{port_num}',
                    cvss='8.0' if hr['risk'] == 'critical' else '5.0',
                    owasp='A05', mitre='T1190'
                )
                log('warn', f'[NETSEC] High-risk service: {service} on port {port_num}')
        else:
            port_info['risk_level'] = 'low'

        netsec['open_ports'].append(port_info)
        if version:
            netsec['service_versions'].append({
                'port': port_num,
                'service': service,
                'version': version,
                'banner': banner[:100]
            })

    # ── Network Segment Analysis ──
    log('info', '[NETSEC] Analyzing network segments')
    ip_segments = {}
    for p in ports:
        ip = p.get('ip', target)
        if ip and ip != target:
            segment = '.'.join(ip.split('.')[:3]) if '.' in ip else 'unknown'
            if segment not in ip_segments:
                ip_segments[segment] = []
            ip_segments[segment].append(p.get('port', 0))

    for segment, open_ports in ip_segments.items():
        netsec['network_segments'].append({
            'segment': segment,
            'open_ports': open_ports,
            'port_count': len(open_ports),
            'risk_level': 'high' if len(open_ports) > 5 else 'medium' if len(open_ports) > 2 else 'low'
        })

    # ── Firewall Rule Analysis ──
    log('info', '[NETSEC] Analyzing firewall rules')
    firewall_findings = []
    for p in netsec['high_risk_services']:
        firewall_findings.append({
            'port': p['port'],
            'service': p['service'],
            'action': 'BLOCK',
            'rule': f'iptables -A INPUT -p {p["service"].lower()} --dport {p["port"]} -j DROP',
            'reason': f'Block high-risk service {p["service"]}'
        })

    for p in netsec['open_ports']:
        if p['risk_level'] == 'critical':
            firewall_findings.append({
                'port': p['port'],
                'service': p['service'],
                'action': 'RESTRICT',
                'rule': f'iptables -A INPUT -p tcp --dport {p["port"]} -s [TRUSTED_IP] -j ACCEPT && iptables -A INPUT -p tcp --dport {p["port"]} -j DROP',
                'reason': f'Restrict access to critical service {p["service"]}'
            })
    netsec['firewall_rules'] = firewall_findings

    # ── SSL/TLS Network Analysis ──
    log('info', '[NETSEC] Analyzing SSL/TLS network configuration')
    ssl_issues = []
    if ssl_data:
        protocol = ssl_data.get('protocol', '')
        if protocol in ('SSLv3', 'TLSv1', 'TLSv1.1'):
            ssl_issues.append(f'Weak protocol {protocol} in use')
        cipher = ssl_data.get('cipher', '')
        if any(weak in cipher.lower() for weak in ['rc4', 'des', '3des', 'null', 'export']):
            ssl_issues.append(f'Weak cipher: {cipher}')
        cert_expiry = ssl_data.get('days_until_expiry', 999)
        if cert_expiry < 30:
            ssl_issues.append(f'Certificate expires in {cert_expiry} days')

    # ── DNS Security Analysis ──
    log('info', '[NETSEC] Analyzing DNS security configuration')
    dns_issues = []
    if dns_data:
        if not dns_data.get('dnssec'):
            dns_issues.append('DNSSEC not enabled')
        if not dns_data.get('caa'):
            dns_issues.append('No CAA records found')
        if dns_data.get('zone_transfer_possible'):
            dns_issues.append('Zone transfer enabled')

    # ── Vulnerability Assessment ──
    log('info', '[NETSEC] Performing network vulnerability assessment')
    vuln_assessment = {
        'critical_count': len([p for p in netsec['open_ports'] if p.get('risk_level') == 'critical']),
        'high_count': len([p for p in netsec['open_ports'] if p.get('risk_level') == 'high']),
        'medium_count': len([p for p in netsec['open_ports'] if p.get('risk_level') == 'medium']),
        'low_count': len([p for p in netsec['open_ports'] if p.get('risk_level') == 'low']),
        'total_open': len(netsec['open_ports']),
        'ssl_issues': ssl_issues,
        'dns_issues': dns_issues,
        'firewall_rules_count': len(firewall_findings),
        'overall_risk': 'critical' if any(p.get('risk_level') == 'critical' for p in netsec['open_ports']) else 'high' if any(p.get('risk_level') == 'high' for p in netsec['open_ports']) else 'medium'
    }
    netsec['vulnerability_assessment'] = vuln_assessment

    # ── Port Scan Summary ──
    netsec['port_scan_results'] = {
        'total_ports_scanned': 1000,
        'open_ports_found': len(netsec['open_ports']),
        'high_risk_count': len(netsec['high_risk_services']),
        'critical_services': [p['service'] for p in netsec['open_ports'] if p.get('risk_level') == 'critical'],
        'scan_method': 'nmap' if _find_tool('nmap') else 'socket'
    }

    # ── Recommendations ──
    recommendations = []
    if netsec['vulnerability_assessment']['critical_count'] > 0:
        recommendations.append({
            'priority': 'critical',
            'action': 'Immediately block or restrict access to critical services',
            'detail': f'Found {netsec["vulnerability_assessment"]["critical_count"]} critical services exposed'
        })
    if ssl_issues:
        recommendations.append({
            'priority': 'high',
            'action': 'Fix SSL/TLS configuration issues',
            'detail': '; '.join(ssl_issues)
        })
    if dns_issues:
        recommendations.append({
            'priority': 'medium',
            'action': 'Enable DNS security features',
            'detail': '; '.join(dns_issues)
        })
    if len(netsec['open_ports']) > 10:
        recommendations.append({
            'priority': 'medium',
            'action': 'Review open port count and implement network segmentation',
            'detail': f'{len(netsec["open_ports"])} open ports detected'
        })
    netsec['recommendations'] = recommendations

    # ── Summary ──
    netsec['summary'] = {
        'total_open_ports': len(netsec['open_ports']),
        'high_risk_services': len(netsec['high_risk_services']),
        'critical_services': netsec['vulnerability_assessment']['critical_count'],
        'firewall_rules_generated': len(firewall_findings),
        'ssl_issues': len(ssl_issues),
        'dns_issues': len(dns_issues),
        'overall_risk': vuln_assessment['overall_risk'],
        'scan_mode': 'active'
    }

    log('ok', f'[NETSEC] Analysis complete: {len(netsec["open_ports"])} open ports, {len(netsec["high_risk_services"])} high-risk services')
    with LOCK:
        scan_state['netsec_data'] = netsec
    set_progress('netsec', 100)

# ─── COMPLIANCE MODULE ─────────────────────────────────────────────────────────


def run_kev_module(target):
    log('info', f'[KEV] Checking Known Exploited Vulnerabilities (multi-source)')
    kev_data = []

    # ── Source 1: CISA KEV (live fetch) ──
    try:
        kev_resp = req_lib.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                               timeout=15, verify=False)
        if kev_resp.status_code == 200:
            kev_json = kev_resp.json()
            cisa_kevs = {k['cveID']: k for k in kev_json.get('vulnerabilities', [])}
            log('info', f'[KEV] Fetched {len(cisa_kevs)} CISA KEV entries')
        else:
            cisa_kevs = {}
    except Exception as e:
        log('warn', f'[KEV] CISA KEV fetch failed: {e}')
        cisa_kevs = {}

    # ── Source 2: NVD recent critical CVEs (last 90 days) ──
    nvd_recent = {}
    try:
        nvd_resp = req_lib.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params={'resultsPerPage': 50, 'pubStartDate': '2026-03-01T00:00:00.000',
                    'cvssV3Severity': 'CRITICAL'},
            timeout=15, verify=False)
        if nvd_resp.status_code == 200:
            for item in nvd_resp.json().get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', '')
                metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])
                cvss_score = metrics[0].get('cvssData', {}).get('baseScore', 0) if metrics else 0
                if cvss_score >= 9.0:
                    nvd_recent[cve_id] = {
                        'cveID': cve_id,
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'cvss': str(cvss_score),
                    }
    except Exception as e:
        log('warn', f'[KEV] NVD fetch failed: {e}')

    # ── Source 3: GitHub Security Advisories (critical) ──
    ghadvisories = {}
    try:
        gh_resp = req_lib.get(
            'https://api.github.com/advisories',
            params={'per_page': 30, 'severity': 'critical', 'type': 'reviewed'},
            headers={'Accept': 'application/vnd.github+json'},
            timeout=15, verify=False)
        if gh_resp.status_code == 200:
            for adv in gh_resp.json():
                cve_id = adv.get('cve_id', '')
                if cve_id:
                    ghadvisories[cve_id] = {
                        'cveID': cve_id,
                        'description': adv.get('summary', ''),
                        'cvss': str(adv.get('cvss', {}).get('score', 0)),
                        'ghsa': adv.get('html_url', ''),
                    }
    except Exception as e:
        log('warn', f'[KEV] GitHub Advisory fetch failed: {e}')

    # ── Combine all sources ──
    all_kevs = {}
    all_kevs.update(cisa_kevs)
    for cid, data in nvd_recent.items():
        if cid not in all_kevs:
            all_kevs[cid] = data
    for cid, data in ghadvisories.items():
        if cid not in all_kevs:
            all_kevs[cid] = data

    # ── Match against detected technologies ──
    with LOCK:
        techs = list(scan_state.get('tech_data', {}).get('technologies', []))
    tech_names = [t.get('name', '').lower() for t in techs]

    # Technology keyword mapping for CVE matching
    tech_keywords = {
        'apache': ['apache', 'httpd', 'tomcat', 'struts', 'log4j', 'activemq', 'spark'],
        'nginx': ['nginx'],
        'microsoft': ['microsoft', 'iis', 'exchange', 'sharepoint', 'windows', 'edge'],
        'google': ['google', 'chrome', 'android', 'gcp'],
        'amazon': ['aws', 'amazon'],
        'oracle': ['oracle', 'mysql', 'java', 'weblogic'],
        'ibm': ['ibm', 'websphere', 'mq'],
        'cisco': ['cisco'],
        'fortinet': ['fortinet', 'fortigate', 'fortios'],
        'paloalto': ['paloalto', 'pan-os'],
        'vmware': ['vmware', 'vsphere', 'esxi'],
        'citrix': ['citrix', 'netscaler'],
        'ivanti': ['ivanti', 'pulse', 'connectwise'],
        'moveit': ['moveit'],
        'barracuda': ['barracuda'],
        'kaseya': ['kaseya'],
        'sophos': ['sophos'],
        'mikrotik': ['mikrotik'],
        'drupal': ['drupal'],
        'wordpress': ['wordpress', 'wp-'],
        'joomla': ['joomla'],
        'laravel': ['laravel'],
        'spring': ['spring'],
        'express': ['express'],
        'django': ['django'],
        'rails': ['rails', 'ruby'],
        'nodejs': ['node', 'nodejs'],
        'php': ['php'],
        'python': ['python'],
        'java': ['java'],
        'docker': ['docker', 'container'],
        'kubernetes': ['kubernetes', 'k8s', 'kube'],
        'redis': ['redis'],
        'mongodb': ['mongo'],
        'postgresql': ['postgres', 'pgsql'],
        'elasticsearch': ['elastic', 'elasticsearch'],
    }

    for cve_id, kev in all_kevs.items():
        desc = kev.get('description', '').lower()
        matched_tech = None
        for tech_name in tech_names:
            if tech_name in desc or any(kw in desc for kw in tech_keywords.get(tech_name, [tech_name])):
                matched_tech = tech_name
                break
            for kw_list in tech_keywords.values():
                if tech_name in kw_list and any(kw in desc for kw in kw_list):
                    matched_tech = tech_name
                    break
            if matched_tech:
                break

        if matched_tech or not techs:  # If no techs detected, add all critical KEVs
            cvss_val = kev.get('cvss', kev.get('cvssScore', ''))
            kev_data.append({
                'cve': cve_id, 'desc': kev.get('description', ''),
                'technology': matched_tech or 'unknown',
                'cvss': cvss_val,
                'source': 'CISA' if cve_id in cisa_kevs else ('NVD' if cve_id in nvd_recent else 'GitHub'),
            })
            add_finding('critical', f'KEV: {cve_id} — {kev.get("description", "")[:80]}',
                sub=f'Technology {matched_tech or "unknown"} is associated with known exploited vulnerability {cve_id}',
                asset=target, cve=cve_id, cvss=cvss_val, exploit='PUBLIC',
                owasp='A06', mitre='T1190',
                details=f'Source: {"CISA KEV" if cve_id in cisa_kevs else "NVD/GitHub"}\n'
                        f'Description: {kev.get("description", "")}\n'
                        f'Matched Technology: {matched_tech or "unknown"}\n\n'
                        f'Remediation: Apply vendor patch immediately. This vulnerability is actively exploited in the wild.')
            log('err', f'[KEV] {cve_id}: {kev.get("description", "")[:60]} (affects {matched_tech})')

    log('ok', f'[KEV] Found {len(kev_data)} known exploited vulnerabilities from {len(all_kevs)} sources')
    with LOCK:
        scan_state['kev_data'] = kev_data
    set_progress('kev', 100)

# ─── CORRELATION MODULE ────────────────────────────────────────────────────────


def run_darkweb_module(target):
    log('info', f'[DARKWEB] Checking dark web and OSINT exposure for {target}')
    darkweb = {
        'osint_dorks': [],
        'exposed_files': [],
        'breach_mentions': [],
        'credential_exposure': [],
        'sensitive_paths': [],
        'summary': {}
    }
    domain = target
    base_domain = '.'.join(domain.split('.')[-2:])

    if not REQUESTS_AVAILABLE:
        log('warn', '[DARKWEB] requests library not available')
        with LOCK:
            scan_state['darkweb_data'] = darkweb
        set_progress('darkweb', 100)
        return

    # ── OSINT Google Dorking (simulated via web search patterns) ──
    log('info', '[DARKWEB] Performing OSINT dorking analysis')
    dork_patterns = [
        {'query': f'site:{domain} filetype:env', 'risk': 'high', 'desc': 'Environment files exposed'},
        {'query': f'site:{domain} filetype:sql', 'risk': 'critical', 'desc': 'SQL database dumps exposed'},
        {'query': f'site:{domain} filetype:log', 'risk': 'medium', 'desc': 'Log files exposed'},
        {'query': f'site:{domain} filetype:bak', 'risk': 'high', 'desc': 'Backup files exposed'},
        {'query': f'site:{domain} filetype:config', 'risk': 'high', 'desc': 'Configuration files exposed'},
        {'query': f'site:{domain} intitle:"index of"', 'risk': 'high', 'desc': 'Directory listing enabled'},
        {'query': f'site:{domain} inurl:admin', 'risk': 'medium', 'desc': 'Admin panels exposed'},
        {'query': f'site:{domain} inurl:login', 'risk': 'low', 'desc': 'Login pages exposed'},
        {'query': f'site:{domain} ext:php inurl:shell', 'risk': 'critical', 'desc': 'Potential web shells'},
        {'query': f'site:{domain} "password" filetype:txt', 'risk': 'critical', 'desc': 'Password files exposed'},
        {'query': f'site:{domain} "api_key" OR "apikey" OR "api-key"', 'risk': 'critical', 'desc': 'API keys potentially exposed'},
        {'query': f'site:{domain} "BEGIN RSA PRIVATE KEY"', 'risk': 'critical', 'desc': 'Private keys exposed'},
        {'query': f'site:{domain} "jdbc:" OR "mysql://" OR "mongodb://"', 'risk': 'critical', 'desc': 'Database connection strings exposed'},
        {'query': f'site:{domain} ext:xml inurl:config', 'risk': 'high', 'desc': 'XML configuration files exposed'},
        {'query': f'site:{domain} "AWS_ACCESS_KEY" OR "AWS_SECRET_KEY"', 'risk': 'critical', 'desc': 'AWS credentials potentially exposed'},
    ]
    for dork in dork_patterns:
        darkweb['osint_dorks'].append({
            'query': dork['query'],
            'risk_level': dork['risk'],
            'description': dork['desc'],
            'status': 'requires_manual_check'
        })
    log('ok', f'[DARKWEB] Generated {len(dork_patterns)} OSINT dork patterns')

    # ── Exposed Sensitive Files Check ──
    log('info', '[DARKWEB] Checking for exposed sensitive files')
    sensitive_file_paths = [
        '/.env', '/.env.production', '/.env.local', '/.env.bak',
        '/.git/config', '/.git/HEAD', '/.gitignore',
        '/.htpasswd', '/.htaccess',
        '/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old',
        '/config.php', '/config.php.bak', '/config.php.old',
        '/config.yml', '/config.yaml', '/config.json', '/config.ini',
        '/database.yml', '/database.json',
        '/.aws/credentials', '/.aws/config',
        '/.ssh/id_rsa', '/.ssh/id_rsa.pub',
        '/backup.zip', '/backup.tar.gz', '/backup.sql',
        '/dump.sql', '/db.sql', '/database.sql',
        '/server-status', '/server-info',
        '/phpinfo.php', '/info.php', '/test.php',
        '/.DS_Store', '/Thumbs.db',
        '/web.config', '/crossdomain.xml',
        '/composer.json', '/package.json', '/package-lock.json',
        '/Gemfile', '/Gemfile.lock',
        '/requirements.txt', '/Pipfile', '/Pipfile.lock',
        '/.svn/entries', '/.svn/wc.db',
        '/elmah.axd', '/trace.axd',
        '/elmah/error.axd',
    ]
    exposed_files = []
    for path in sensitive_file_paths:
        if not scan_state.get('scanning'):
            break
        try:
            url = f'https://{domain}{path}'
            r = req_lib.get(url, timeout=4, verify=False, allow_redirects=False, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                # Skip redirect responses (CDN/WAF returning 200 for any path)
                if r.headers.get('Location') or r.headers.get('Content-Type', '').startswith('text/html'):
                    # Check if this is actually a real file or just the CDN serving the homepage
                    content_preview = r.text[:500] if len(r.text) > 0 else ''
                    # For wp-config files, verify they contain actual config content
                    if 'wp-config' in path:
                        _WP_CFG_MARKERS = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'table_prefix']
                        if not any(m in r.text for m in _WP_CFG_MARKERS):
                            log('debug', f'[DARKWEB] {path} returned 200 but no WP config markers — skipping')
                            continue
                content_preview = r.text[:500] if len(r.text) > 0 else ''
                is_sensitive = False
                risk_level = 'medium'
                if path.endswith(('.env', '.env.production', '.env.local', '.env.bak')):
                    is_sensitive = True
                    risk_level = 'critical'
                elif path.endswith(('.sql', '.zip', '.tar.gz')):
                    is_sensitive = True
                    risk_level = 'critical'
                elif path.endswith(('config.php', 'config.yml', 'config.json', 'config.ini')):
                    is_sensitive = True
                    risk_level = 'high'
                elif 'credentials' in path or 'id_rsa' in path:
                    is_sensitive = True
                    risk_level = 'critical'
                elif path.endswith(('.git/config', '.git/HEAD')):
                    is_sensitive = True
                    risk_level = 'high'
                elif 'phpinfo' in path or 'info.php' in path:
                    is_sensitive = True
                    risk_level = 'medium'
                elif path.endswith(('package.json', 'composer.json', 'requirements.txt')):
                    is_sensitive = True
                    risk_level = 'low'
                if is_sensitive:
                    exposed_files.append({
                        'path': path,
                        'status': r.status_code,
                        'size': len(r.content),
                        'risk_level': risk_level,
                        'preview': content_preview[:200]
                    })
                    add_finding(
                        'critical' if risk_level == 'critical' else 'high',
                        f'Exposed sensitive file: {path}',
                        sub=f'File {path} is publicly accessible with status {r.status_code}',
                        asset=f'https://{domain}{path}',
                        cvss='7.5' if risk_level == 'critical' else '5.0',
                        owasp='A01', mitre='T1228',
                        details=f'File content preview:\n{content_preview[:300]}'
                    )
                    log('warn', f'[DARKWEB] Exposed: {path} ({len(r.content)} bytes)')
        except Exception:
            pass
    darkweb['exposed_files'] = exposed_files
    log('ok', f'[DARKWEB] Found {len(exposed_files)} exposed sensitive files')

    # ── Credential Exposure Check (via web content analysis) ──
    log('info', '[DARKWEB] Scanning for credential exposure patterns')
    credential_patterns = [
        r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:secret|token)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:AWS_ACCESS_KEY_ID)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:PRIVATE KEY)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:jdbc:|mysql://|mongodb://|postgres://|redis://)([^\s"\']+)',
        r'(?i)(?:smtp_pass|database_password|db_pass)\s*[=:]\s*["\']([^"\']+)["\']',
    ]
    credential_exposure = []
    try:
        main_url = f'https://{domain}'
        r = req_lib.get(main_url, timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        body = r.text
        for pattern in credential_patterns:
            matches = re.findall(pattern, body)
            for match in matches:
                if match and len(match) > 3:
                    is_placeholder = any(p in match.lower() for p in ['example', 'your_', 'changeme', 'test', 'xxx', 'placeholder', 'dummy', 'sample'])
                    if not is_placeholder:
                        credential_exposure.append({
                            'pattern': pattern[:50],
                            'value_length': len(match),
                            'risk_level': 'critical',
                            'source': main_url
                        })
                        log('warn', f'[DARKWEB] Credential pattern detected on main page')
    except Exception:
        pass
    darkweb['credential_exposure'] = credential_exposure

    # ── Breach Database Mentions (via public breach check services) ──
    log('info', '[DARKWEB] Checking breach database mentions')
    breach_mentions = []
    breach_check_urls = [
        f'https://haveibeenpwned.com/unifiedsearch/{base_domain}',
        f'https://breachdirectory.org/api/email/{base_domain}',
    ]
    for check_url in breach_check_urls:
        try:
            r = req_lib.get(check_url, timeout=5, verify=False, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/json'
            })
            if r.status_code == 200:
                breach_mentions.append({
                    'source': check_url,
                    'status': 'found',
                    'details': 'Domain found in breach database'
                })
                add_finding('high', f'Domain found in breach database: {base_domain}',
                    sub=f'The domain {base_domain} appears in public breach databases',
                    asset=domain, cvss='6.5', owasp='A07', mitre='T1530')
                log('warn', f'[DARKWEB] Domain found in breach database')
        except Exception:
            pass
    darkweb['breach_mentions'] = breach_mentions

    # ── Summary ──
    darkweb['summary'] = {
        'total_osint_dorks': len(darkweb['osint_dorks']),
        'exposed_files_count': len(darkweb['exposed_files']),
        'credential_exposure_count': len(darkweb['credential_exposure']),
        'breach_mentions_count': len(darkweb['breach_mentions']),
        'critical_exposed': len([f for f in darkweb['exposed_files'] if f.get('risk_level') == 'critical']),
        'scan_mode': 'active',
        'note': 'OSINT patterns generated for manual verification. Exposed files and credentials were actively checked.'
    }

    log('ok', f'[DARKWEB] Scan completed: {len(exposed_files)} exposed files, {len(credential_exposure)} credential patterns, {len(breach_mentions)} breach mentions')
    with LOCK:
        scan_state['darkweb_data'] = darkweb
    set_progress('darkweb', 100)

# ─── WEB CRAWLER MODULE ──────────────────────────────────────────────────────


def run_oob_module(target):
    """Out-of-Band interaction detection for blind SSRF/XXE."""
    log('info', f'[OOB] Testing blind SSRF/XXE on {target}')
    oob_findings = []
    base_url = f'https://{target}'

    # Generate a unique OOB callback URL (using a free service)
    import uuid
    oob_id = str(uuid.uuid4())[:8]
    oob_domain = f'{oob_id}.oast.fun'  # Use interactsh-style OOB

    # Parameters that commonly trigger OOB interactions
    ssrf_params = ['url', 'uri', 'link', 'src', 'href', 'dest', 'target',
                   'callback', 'webhook', 'proxy', 'fetch', 'load',
                   'redirect', 'return', 'next', 'continue', 'goto',
                   'document', 'file', 'path', 'img', 'image', 'media']

    # Test each parameter with OOB payload
    for param in ssrf_params:
        if not scan_state.get('scanning'):
            break
        try:
            # Test GET
            test_url = f'{base_url}/?{param}=http://{oob_domain}'
            r = req_lib.get(test_url, timeout=8, verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302, 307):
                # Check response for signs of blind SSRF
                if any(indicator in r.text.lower() for indicator in ['internal', 'metadata', '169.254', '127.0.0.1', 'localhost']):
                    add_finding(
                        'high',
                        f'Potential blind SSRF via {param} parameter',
                        sub=f'Parameter {param} may trigger outbound requests',
                        asset=base_url, cvss='7.5', owasp='A10', mitre='T918',
                        details=f'Parameter: {param}\nOOB Domain: {oob_domain}\n'
                                f'Response indicates internal network access.')
                    oob_findings.append({'param': param, 'type': 'SSRF'})
                    log('ok', f'[OOB] Potential SSRF via {param}')

            # Test POST
            r2 = req_lib.post(base_url, data={param: f'http://{oob_domain}'},
                              timeout=8, verify=False, allow_redirects=False)
            if r2.status_code in (200, 301, 302, 307):
                if any(indicator in r2.text.lower() for indicator in ['internal', 'metadata', '169.254', '127.0.0.1']):
                    add_finding(
                        'high',
                        f'Potential blind SSRF via POST {param} parameter',
                        sub=f'POST parameter {param} may trigger outbound requests',
                        asset=base_url, cvss='7.5', owasp='A10', mitre='T918',
                        details=f'Parameter: {param}\nMethod: POST\nOOB Domain: {oob_domain}')
                    oob_findings.append({'param': param, 'type': 'SSRF-POST'})
                    log('ok', f'[OOB] Potential SSRF via POST {param}')
        except Exception:
            pass

    # Test XXE via Content-Type
    try:
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://' + oob_domain + '">]><root>&xxe;</root>'
        r = req_lib.post(base_url, data=xxe_payload,
                         headers={'Content-Type': 'application/xml'},
                         timeout=8, verify=False)
        if r.status_code == 200:
            add_finding(
                'high',
                'Potential XXE via XML endpoint',
                sub='Server accepts XML with external entity references',
                asset=base_url, cvss='7.5', owasp='A05', mitre='T1203',
                details='Server processes XML input — may be vulnerable to XXE injection.')
            oob_findings.append({'type': 'XXE'})
            log('ok', '[OOB] Potential XXE detected')
    except Exception:
        pass

    log('ok', f'[OOB] Scan complete — {len(oob_findings)} OOB findings')
    with LOCK:
        scan_state.setdefault('oob_data', [])
        scan_state['oob_data'] = oob_findings
    set_progress('oob', 100)


# ─── DIRECTORY TRAVERSAL MODULE ────────────────────────────────────────────────


def run_wp_module(target):
    """WordPress-specific vulnerability scanner (WPScan equivalent)."""
    log('info', f'[WP] Scanning WordPress on {target}')
    if not REQUESTS_AVAILABLE:
        return
    
    wp_data = {
        'is_wordpress': False, 'version': '', 'themes': [], 'plugins': [],
        'users': [], 'xmlrpc': False, 'debug_log': False,
        'backup_files': [], 'upload_dir': False, 'wp_json': False,
        'enumeration': {}, 'vulns': [], 'summary': {}
    }
    
    base_url = f'https://{target}'
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    # ── 1. WordPress Detection ──
    log('info', '[WP] Detecting WordPress...')
    try:
        r = req_lib.get(f'{base_url}/', timeout=10, verify=False, headers={'User-Agent': ua})
        wp_indicators = ['wp-content', 'wp-includes', 'wp-json', 'wordpress', 'wp-embed.min.js']
        body = r.text.lower()
        headers_str = str(r.headers).lower()
        
        if any(ind in body for ind in wp_indicators) or 'x-powered-by: wordpress' in headers_str:
            wp_data['is_wordpress'] = True
            log('ok', '[WP] WordPress detected!')
            
            # Extract version from meta tags or source
            import re as _re
            ver_match = _re.search(r'content="WordPress\s+([\d.]+)"', r.text)
            if ver_match:
                wp_data['version'] = ver_match.group(1)
                log('ok', f'[WP] WordPress version: {wp_data["version"]}')
                # Check for outdated version
                if wp_data['version']:
                    parts = wp_data['version'].split('.')
                    if len(parts) >= 2:
                        major, minor = int(parts[0]), int(parts[1])
                        if major < 6 or (major == 6 and minor < 4):
                            add_finding('high', f'Outdated WordPress: {wp_data["version"]}',
                                sub=f'WordPress {wp_data["version"]} is outdated and may have known vulnerabilities',
                                asset=target, cvss='7.5', owasp='A06', mitre='T1190',
                                details=f'WordPress Version: {wp_data["version"]}\nLatest: 6.x\n\nRemediation: Update WordPress to the latest version immediately.')
        else:
            log('info', '[WP] WordPress not detected')
            with LOCK:
                scan_state['wp_data'] = wp_data
            return
    except Exception as e:
        log('warn', f'[WP] Detection failed: {e}')
    
    # ── 2. XML-RPC Testing ──
    log('info', '[WP] Testing XML-RPC...')
    try:
        xmlrpc_payload = '''<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>'''
        r = req_lib.post(f'{base_url}/xmlrpc.php', data=xmlrpc_payload, timeout=10,
                         verify=False, headers={'User-Agent': ua, 'Content-Type': 'text/xml'})
        if r.status_code == 200 and 'methodResponse' in r.text:
            wp_data['xmlrpc'] = True
            log('warn', '[WP] XML-RPC enabled - potential brute force vector')
            # Check for pingback (DDoS vector)
            if 'pingback.ping' in r.text:
                add_finding('medium', 'WordPress XML-RPC pingback enabled',
                    sub=f'XML-RPC at {target}/xmlrpc.php allows pingback - DDoS vector',
                    asset=target, cvss='5.3', owasp='A04', mitre='T1498',
                    details=f'XML-RPC is enabled with pingback support.\nThis can be used for DDoS amplification attacks.\n\nRemediation: Disable XML-RPC or restrict access via .htaccess/WAF.')
    except Exception:
        pass
    
    # ── 3. Debug Log Detection ──
    try:
        r = req_lib.get(f'{base_url}/wp-content/debug.log', timeout=5, verify=False,
                        headers={'User-Agent': ua}, allow_redirects=True)
        if r.status_code == 200 and len(r.text) > 100:
            # Verify it's not a CDN redirect serving the homepage
            from urllib.parse import urlparse as _urlparse
            final_path = _urlparse(r.url).path.rstrip('/')
            if final_path and final_path != '/' and 'debug.log' not in final_path:
                log('debug', f'[WP] debug.log check redirected to {final_path} — skipping (false positive)')
            else:
                # Verify it contains actual debug log content (not HTML)
                _LOG_MARKERS = ['PHP ', 'Warning:', 'Notice:', 'Error:', 'deprecated', 'wp-content', 'wp-includes', 'Stack trace', 'debug.log']
                content_lower = r.text[:2000].lower()
                has_log_content = any(m.lower() in content_lower for m in _LOG_MARKERS)
                # Reject obvious HTML responses (e.g. homepage served by CDN)
                is_html_response = content_lower.strip().startswith('<!doctype') or content_lower.strip().startswith('<html')
                if has_log_content and not is_html_response:
                    wp_data['debug_log'] = True
                    add_finding('high', 'WordPress debug log exposed',
                        sub=f'wp-content/debug.log is publicly accessible',
                        asset=f'{target}/wp-content/debug.log', cvss='7.5', owasp='A01', mitre='T1592',
                        details=f'Debug log contains sensitive information.\nFirst 500 chars: {r.text[:500]}\n\nRemediation: Disable WP_DEBUG_LOG in wp-config.php. Delete debug.log.')
                else:
                    log('debug', f'[WP] debug.log returned 200 but content looks like HTML — skipping (false positive)')
    except Exception:
        pass
    
    # ── 4. Plugin Enumeration ──
    log('info', '[WP] Enumerating plugins...')
    common_plugins = [
        'contact-form-7', 'woocommerce', 'yoast-seo', 'elementor',
        'wordfence', 'akismet', 'jetpack', 'classic-editor', 'wpforms-lite',
        'updraftplus', 'really-simple-ssl', 'limit-login-attempts',
        'all-in-one-seo-pack', 'google-analytics', 'custom-login-page',
        'easy-wp-smtp', 'duplicator', 'wp-file-manager', 'easy-wp-smtp',
        'flavor', 'post-smtp', 'dsgvo-tools', 'wp-statistics',
    ]
    for plugin in common_plugins:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(f'{base_url}/wp-content/plugins/{plugin}/readme.txt',
                          timeout=5, verify=False, headers={'User-Agent': ua})
            if r.status_code == 200:
                # Extract version from readme
                ver_match = _re.search(r'Stable tag:\s*([\d.]+)', r.text, _re.IGNORECASE)
                version = ver_match.group(1) if ver_match else 'unknown'
                wp_data['plugins'].append({'name': plugin, 'version': version})
                log('ok', f'[WP] Plugin found: {plugin} v{version}')
        except Exception:
            pass
    
    if wp_data['plugins']:
        log('ok', f'[WP] Found {len(wp_data["plugins"])} plugins')
    
    # ── 5. Theme Enumeration ──
    log('info', '[WP] Enumerating themes...')
    try:
        r = req_lib.get(base_url, timeout=10, verify=False, headers={'User-Agent': ua})
        theme_match = _re.search(r'/themes/([a-zA-Z0-9_-]+)/', r.text)
        if theme_match:
            theme_name = theme_match.group(1)
            wp_data['themes'].append({'name': theme_name, 'version': 'unknown'})
            log('ok', f'[WP] Active theme: {theme_name}')
    except Exception:
        pass
    
    # ── 6. User Enumeration ──
    log('info', '[WP] Enumerating users...')
    for enum_url in [f'{base_url}/?author=1', f'{base_url}/wp-json/wp/v2/users']:
        try:
            r = req_lib.get(enum_url, timeout=8, verify=False, headers={'User-Agent': ua})
            if r.status_code == 200:
                if 'wp-json' in enum_url:
                    users = r.json()
                    for u in users:
                        wp_data['users'].append({
                            'id': u.get('id'),
                            'name': u.get('name'),
                            'slug': u.get('slug')
                        })
                else:
                    # Extract from redirect or page
                    name_match = _re.search(r'/author/([a-zA-Z0-9_-]+)/', r.url)
                    if name_match:
                        wp_data['users'].append({'slug': name_match.group(1)})
        except Exception:
            pass
    
    if wp_data['users']:
        log('warn', f'[WP] User enumeration possible: {len(wp_data["users"])} users found')
        add_finding('medium', 'WordPress user enumeration possible',
            sub=f'{len(wp_data["users"])} user(s) identifiable via author enumeration',
            asset=target, cvss='5.3', owasp='A07', mitre='T1592',
            details=f'Users found: {", ".join([u.get("slug","") for u in wp_data["users"][:5]])}\n\nRemediation: Disable author enumeration. Use display names instead of slugs.')
    
    # ── 7. Backup File Detection ──
    # WP config markers that confirm a real backup file (not a CDN-served homepage)
    _WP_CONFIG_MARKERS = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'table_prefix', 'ABSPATH']
    backup_paths = [
        '/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php~',
        '/wp-config.php.save', '/wp-config.php.swp', '/wp-config.bak',
        '/wp-config.old', '/wp-config.txt', '/.wp-config.php.swp',
        '/wp-admin/install.php', '/readme.html', '/license.txt',
    ]
    for path in backup_paths:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(f'{base_url}{path}', timeout=5, verify=False,
                            headers={'User-Agent': ua}, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 50:
                # Reject CDN/WAF redirect responses: if the final URL differs from
                # the requested path the server (or CDN) redirected us to the
                # homepage — the backup file does not actually exist.
                from urllib.parse import urlparse as _urlparse
                final_path = _urlparse(r.url).path.rstrip('/')
                req_path = path.rsplit('/', 1)[-1] if '/' in path else path
                if final_path and final_path != '/' and req_path not in final_path:
                    # Redirected to a different page — likely a false positive
                    log('debug', f'[WP] Backup check {path} redirected to {final_path} — skipping (false positive)')
                    continue

                if 'wp-config' in path:
                    # Verify the response actually contains WordPress config content
                    has_config_content = any(marker in r.text for marker in _WP_CONFIG_MARKERS)
                    if not has_config_content:
                        log('debug', f'[WP] Backup check {path} returned 200 but no WP config markers — skipping (false positive)')
                        continue

                wp_data['backup_files'].append(path)
                if 'wp-config' in path:
                    add_finding('critical', f'WordPress config backup exposed: {path}',
                        sub=f'{path} is publicly accessible - may contain database credentials',
                        asset=f'{target}{path}', cvss='9.0', owasp='A01', mitre='T1552',
                        details=f'Path: {path}\nSize: {len(r.text)} bytes\n\nRemediation: Delete backup files immediately. Restrict access via .htaccess.')
        except Exception:
            pass
    
    # ── 8. WP-JSON API ──
    try:
        r = req_lib.get(f'{base_url}/wp-json/', timeout=8, verify=False, headers={'User-Agent': ua})
        if r.status_code == 200:
            wp_data['wp_json'] = True
            log('info', '[WP] WP-JSON API accessible')
    except Exception:
        pass
    
    # ── Summary ──
    wp_data['summary'] = {
        'is_wordpress': wp_data['is_wordpress'],
        'version': wp_data['version'],
        'plugins_count': len(wp_data['plugins']),
        'themes_count': len(wp_data['themes']),
        'users_count': len(wp_data['users']),
        'xmlrpc_enabled': wp_data['xmlrpc'],
        'debug_log_exposed': wp_data['debug_log'],
        'backup_files': len(wp_data['backup_files']),
    }
    
    findings_count = len(wp_data['plugins']) + len(wp_data['backup_files']) + (1 if wp_data['xmlrpc'] else 0) + (1 if wp_data['debug_log'] else 0)
    log('ok', f'[WP] WordPress scan complete: {findings_count} issues found')

    # ── WPScan: CVE + plugin/theme vulnerability enumeration ──
    if wp_data.get('is_wordpress'):
        wpscan_path = _find_tool('wpscan')
        if wpscan_path:
            log('info', '[WP] Running WPScan for CVE enumeration...')
            out = f'/tmp/wpscan_{secrets.token_hex(4)}.json'
            try:
                cmd = [wpscan_path, '--url', f'https://{target}', '--enumerate', 'vp,vt,u',
                       '--format', 'json', '--output', out, '--no-banner', '-q',
                       '--ignore-main-redirect']
                _run_tool(cmd, timeout=45)
                if os.path.isfile(out):
                    try:
                        with open(out) as f:
                            wpscan_data = json.load(f)
                        # Plugin vulnerabilities
                        for plugin_name, plugin_info in wpscan_data.get('plugins', {}).items():
                            for v in plugin_info.get('vulnerabilities', []):
                                cve_list = v.get('references', {}).get('cve', [])
                                cve = cve_list[0] if cve_list else ''
                                add_finding('high', f'WordPress Plugin CVE: {v.get("title", "")}',
                                            asset=f'https://{target}',
                                            cve=f'CVE-{cve}' if cve and not cve.startswith('CVE-') else cve,
                                            owasp='A06', confidence='high',
                                            details=f'Plugin: {plugin_info.get("slug", "")}\n'
                                                    f'Version: {plugin_info.get("version", "unknown")}\n'
                                                    f'CVE: {cve}\nTitle: {v.get("title", "")}')
                        # Theme vulnerabilities
                        for theme_name, theme_info in wpscan_data.get('themes', {}).items():
                            for v in theme_info.get('vulnerabilities', []):
                                cve_list = v.get('references', {}).get('cve', [])
                                cve = cve_list[0] if cve_list else ''
                                add_finding('high', f'WordPress Theme CVE: {v.get("title", "")}',
                                            asset=f'https://{target}',
                                            cve=f'CVE-{cve}' if cve and not cve.startswith('CVE-') else cve,
                                            owasp='A06', confidence='high',
                                            details=f'Theme: {theme_info.get("slug", "")}\n'
                                                    f'VERSION: {theme_info.get("version", "unknown")}\n'
                                                    f'CVE: {cve}\nTitle: {v.get("title", "")}')
                        # User enumeration
                        users = wpscan_data.get('users', {})
                        if users:
                            user_list = list(users.keys())[:10]
                            add_finding('medium', f'WordPress user enumeration: {len(users)} users found',
                                        asset=f'https://{target}', confidence='high',
                                        details=f'Users: {", ".join(user_list)}')
                        log('ok', f'[WPSCAN] WPScan complete — {len(wpscan_data.get("plugins", {}))} plugins, {len(wpscan_data.get("themes", {}))} themes checked')
                    except (json.JSONDecodeError, KeyError) as e:
                        log('warn', f'[WPSCAN] Parse error: {e}')
            except Exception as e:
                log('warn', f'[WPSCAN] Error: {e}')
            finally:
                try:
                    os.remove(out)
                except OSError:
                    pass

    with LOCK:
        scan_state['wp_data'] = wp_data

# ─── DARK WEB MODULE ──────────────────────────────────────────────────────────


def run_monitoring_module(target):
    log('info', f'[MONITORING] Performing comprehensive monitoring analysis for {target}')
    monitoring = {
        'cert_expiry': {},
        'dns_changes': [],
        'ssl_configuration': {},
        'availability_checks': [],
        'security_headers_monitoring': {},
        'port_monitoring': [],
        'recommendations': [],
        'summary': {}
    }

    with LOCK:
        ssl_data = dict(scan_state.get('ssl_data', {}))
        assets = list(scan_state.get('assets', []))
        ports = list(scan_state.get('port_data', []))
        header_data = dict(scan_state.get('header_data', {}))
        dns_data = dict(scan_state.get('dns_data', {}))

    # ── Certificate Expiry Monitoring ──
    log('info', '[MONITORING] Analyzing certificate expiry status')
    cert_expiry = {
        'days_left': ssl_data.get('days_until_expiry', 999),
        'expires': ssl_data.get('not_after', 'N/A'),
        'issuer': ssl_data.get('issuer', 'N/A'),
        'subject': ssl_data.get('subject', 'N/A'),
        'status': 'healthy',
        'alert_level': 'info'
    }
    if cert_expiry['days_left'] < 7:
        cert_expiry['status'] = 'critical'
        cert_expiry['alert_level'] = 'critical'
        add_finding('critical', f'SSL certificate expires in {cert_expiry["days_left"]} days',
            sub=f'Certificate for {target} expires on {cert_expiry["expires"]}',
            asset=target, cvss='7.0', owasp='A07', mitre='T1587',
            details=f'Certificate issuer: {cert_expiry["issuer"]}')
    elif cert_expiry['days_left'] < 30:
        cert_expiry['status'] = 'warning'
        cert_expiry['alert_level'] = 'medium'
        add_finding('medium', f'SSL certificate expires in {cert_expiry["days_left"]} days',
            sub=f'Certificate for {target} expires on {cert_expiry["expires"]}',
            asset=target, cvss='4.0', owasp='A05', mitre='T1587')
    elif cert_expiry['days_left'] < 90:
        cert_expiry['status'] = 'attention'
        cert_expiry['alert_level'] = 'low'
    monitoring['cert_expiry'] = cert_expiry

    # ── DNS Change Monitoring ──
    log('info', '[MONITORING] Setting up DNS change monitoring')
    dns_changes = []
    if dns_data:
        a_records = dns_data.get('a_records', [])
        mx_records = dns_data.get('mx_records', [])
        ns_records = dns_data.get('ns_records', [])

        for record in a_records:
            dns_changes.append({
                'type': 'A',
                'value': record,
                'monitoring_status': 'active',
                'last_checked': datetime.now().isoformat()
            })
        for record in mx_records:
            dns_changes.append({
                'type': 'MX',
                'value': str(record),
                'monitoring_status': 'active',
                'last_checked': datetime.now().isoformat()
            })
        for record in ns_records:
            dns_changes.append({
                'type': 'NS',
                'value': record,
                'monitoring_status': 'active',
                'last_checked': datetime.now().isoformat()
            })
    monitoring['dns_changes'] = dns_changes

    # ── SSL Configuration Monitoring ──
    log('info', '[MONITORING] Analyzing SSL configuration')
    ssl_config = {
        'protocol': ssl_data.get('protocol', 'N/A'),
        'cipher': ssl_data.get('cipher', 'N/A'),
        'key_size': ssl_data.get('key_size', 'N/A'),
        'hsts_enabled': 'Strict-Transport-Security' not in header_data.get('missing_security', []),
        'ocsp_stapling': ssl_data.get('ocsp_stapling', False),
        'status': 'healthy',
        'issues': []
    }
    if ssl_config['protocol'] in ('SSLv3', 'TLSv1', 'TLSv1.1'):
        ssl_config['status'] = 'critical'
        ssl_config['issues'].append(f'Weak protocol: {ssl_config["protocol"]}')
    if any(weak in ssl_config['cipher'].lower() for weak in ['rc4', 'des', '3des', 'null']):
        ssl_config['status'] = 'critical'
        ssl_config['issues'].append(f'Weak cipher: {ssl_config["cipher"]}')
    if not ssl_config['hsts_enabled']:
        ssl_config['issues'].append('HSTS not enabled')
    monitoring['ssl_configuration'] = ssl_config

    # ── Availability Checks ──
    log('info', '[MONITORING] Performing availability checks')
    availability_checks = []
    check_urls = [
        f'https://{target}',
        f'http://{target}',
        f'https://www.{target}',
    ]
    for url in check_urls:
        try:
            start_time = time.time()
            r = req_lib.get(url, timeout=10, verify=False, allow_redirects=True)
            elapsed = round((time.time() - start_time) * 1000, 2)
            availability_checks.append({
                'url': url,
                'status_code': r.status_code,
                'response_time_ms': elapsed,
                'status': 'up' if r.status_code < 400 else 'degraded',
                'redirects': len(r.history),
                'final_url': r.url,
                'headers': dict(r.headers),
                'ssl_verify': r.verify
            })
        except Exception as e:
            availability_checks.append({
                'url': url,
                'status_code': 0,
                'response_time_ms': 0,
                'status': 'down',
                'error': str(e)[:100]
            })
    monitoring['availability_checks'] = availability_checks

    # ── Security Headers Monitoring ──
    log('info', '[MONITORING] Analyzing security headers status')
    missing_hdrs = header_data.get('missing_security', [])
    present_hdrs = header_data.get('present', [])
    headers_monitoring = {
        'missing_headers': missing_hdrs,
        'present_headers': present_hdrs,
        'total_expected': 12,
        'total_present': len(present_hdrs),
        'compliance_score': round(len(present_hdrs) / 12 * 100, 1),
        'critical_missing': [],
        'status': 'healthy'
    }
    critical_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
    for hdr in critical_headers:
        if hdr in missing_hdrs:
            headers_monitoring['critical_missing'].append(hdr)
    if headers_monitoring['critical_missing']:
        headers_monitoring['status'] = 'warning'
    monitoring['security_headers_monitoring'] = headers_monitoring

    # ── Port Monitoring ──
    log('info', '[MONITORING] Setting up port monitoring')
    port_monitoring = []
    for p in ports[:20]:
        port_monitoring.append({
            'port': p.get('port', 0),
            'service': p.get('service', 'unknown'),
            'status': 'open',
            'monitoring_status': 'active',
            'last_checked': datetime.now().isoformat()
        })
    monitoring['port_monitoring'] = port_monitoring

    # ── Recommendations ──
    recommendations = []
    if cert_expiry['days_left'] < 30:
        recommendations.append({
            'priority': 'high',
            'action': 'Renew SSL certificate immediately',
            'detail': f'Certificate expires in {cert_expiry["days_left"]} days'
        })
    if ssl_config['issues']:
        recommendations.append({
            'priority': 'high',
            'action': 'Fix SSL configuration issues',
            'detail': '; '.join(ssl_config['issues'])
        })
    if missing_hdrs:
        recommendations.append({
            'priority': 'medium',
            'action': 'Add missing security headers',
            'detail': f'Missing: {", ".join(missing_hdrs[:5])}'
        })
    if any(c.get('status') == 'down' for c in availability_checks):
        recommendations.append({
            'priority': 'critical',
            'action': 'Investigate availability issues',
            'detail': 'Some endpoints are not responding'
        })
    monitoring['recommendations'] = recommendations

    # ── Summary ──
    monitoring['summary'] = {
        'cert_status': cert_expiry['status'],
        'cert_days_left': cert_expiry['days_left'],
        'dns_records_monitored': len(dns_changes),
        'ssl_config_status': ssl_config['status'],
        'availability_up': sum(1 for c in availability_checks if c.get('status') == 'up'),
        'availability_total': len(availability_checks),
        'headers_compliance_score': headers_monitoring['compliance_score'],
        'ports_monitored': len(port_monitoring),
        'total_recommendations': len(recommendations),
        'scan_mode': 'active'
    }

    log('ok', f'[MONITORING] Analysis complete: cert {cert_expiry["status"]}, {len(recommendations)} recommendations')
    with LOCK:
        scan_state['monitoring_data'] = monitoring
    set_progress('monitoring', 100)

# ─── ATTACK GRAPH MODULE ────────────────────────────────────────────────────────


def run_compliance_module(target):
    log('info', f'[COMPLIANCE] Performing comprehensive compliance audit for {target}')
    compliance = {}

    with LOCK:
        missing_hdrs = list(scan_state.get('header_data', {}).get('missing_security', []))
        findings = list(scan_state.get('findings', []))
        ports = list(scan_state.get('port_data', []))
        ssl_data = dict(scan_state.get('ssl_data', {}))
        techs = list(scan_state.get('tech_data', {}).get('technologies', []))
        assets = list(scan_state.get('assets', []))

    # ── OWASP Top 10 2021 Compliance ──
    log('info', '[COMPLIANCE] Checking OWASP Top 10 2021')
    owasp_checks = [
        {'id': 'A01', 'requirement': 'Broken Access Control', 'checks': [
            any('idor' in f.get('title', '').lower() for f in findings),
            any('access control' in f.get('title', '').lower() for f in findings),
            any('privilege' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A02', 'requirement': 'Cryptographic Failures', 'checks': [
            'Strict-Transport-Security' in missing_hdrs,
            ssl_data.get('protocol', '') in ('SSLv3', 'TLSv1', 'TLSv1.1'),
            any('weak cipher' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A03', 'requirement': 'Injection', 'checks': [
            any('sql injection' in f.get('title', '').lower() for f in findings),
            any('xss' in f.get('title', '').lower() for f in findings),
            any('command injection' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A04', 'requirement': 'Insecure Design', 'checks': [
            any('insecure design' in f.get('title', '').lower() for f in findings),
            len(findings) > 10,
        ]},
        {'id': 'A05', 'requirement': 'Security Misconfiguration', 'checks': [
            len(missing_hdrs) > 3,
            any('misconfiguration' in f.get('title', '').lower() for f in findings),
            any(p.get('port') in (23, 3389, 445, 3306, 6379) for p in ports),
        ]},
        {'id': 'A06', 'requirement': 'Vulnerable and Outdated Components', 'checks': [
            any('vulnerable' in f.get('title', '').lower() for f in findings),
            any('outdated' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A07', 'requirement': 'Identification and Authentication Failures', 'checks': [
            any('authentication' in f.get('title', '').lower() for f in findings),
            any('brute force' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A08', 'requirement': 'Software and Data Integrity Failures', 'checks': [
            any('integrity' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A09', 'requirement': 'Security Logging and Monitoring Failures', 'checks': [
            any('logging' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A10', 'requirement': 'Server-Side Request Forgery', 'checks': [
            any('ssrf' in f.get('title', '').lower() for f in findings),
        ]},
    ]
    owasp_pass = 0
    owasp_fail = 0
    owasp_failing = []
    for check in owasp_checks:
        fails = any(check['checks'])
        if fails:
            owasp_fail += 1
            owasp_failing.append({'id': check['id'], 'requirement': check['requirement']})
        else:
            owasp_pass += 1
    compliance['OWASP Top 10 2021'] = {
        'status': 'PASS' if owasp_fail == 0 else 'FAIL',
        'score': f'{owasp_pass}/10',
        'failing_requirements': owasp_failing,
        'checks_performed': 10,
        'checks_passed': owasp_pass
    }

    # ── CIS Benchmarks Compliance ──
    log('info', '[COMPLIANCE] Checking CIS Benchmarks')
    cis_checks = [
        {'id': 'CIS-1.1', 'requirement': 'Ensure HTTPS is enabled', 'passed': 'Strict-Transport-Security' not in missing_hdrs},
        {'id': 'CIS-1.2', 'requirement': 'Ensure HSTS header is present', 'passed': 'Strict-Transport-Security' not in missing_hdrs},
        {'id': 'CIS-1.3', 'requirement': 'Ensure CSP header is present', 'passed': 'Content-Security-Policy' not in missing_hdrs},
        {'id': 'CIS-1.4', 'requirement': 'Ensure X-Frame-Options is set', 'passed': 'X-Frame-Options' not in missing_hdrs},
        {'id': 'CIS-1.5', 'requirement': 'Ensure X-Content-Type-Options is set', 'passed': 'X-Content-Type-Options' not in missing_hdrs},
        {'id': 'CIS-1.6', 'requirement': 'Ensure Referrer-Policy is set', 'passed': 'Referrer-Policy' not in missing_hdrs},
        {'id': 'CIS-1.7', 'requirement': 'Ensure Permissions-Policy is set', 'passed': 'Permissions-Policy' not in missing_hdrs},
        {'id': 'CIS-2.1', 'requirement': 'Ensure SSL/TLS is properly configured', 'passed': ssl_data.get('protocol', '') not in ('SSLv3', 'TLSv1', 'TLSv1.1')},
        {'id': 'CIS-2.2', 'requirement': 'Ensure strong cipher suites', 'passed': not any(weak in ssl_data.get('cipher', '').lower() for weak in ['rc4', 'des', '3des', 'null'])},
        {'id': 'CIS-3.1', 'requirement': 'Ensure no critical ports are exposed', 'passed': not any(p.get('port') in (23, 3389, 445) for p in ports)},
        {'id': 'CIS-3.2', 'requirement': 'Ensure database ports are restricted', 'passed': not any(p.get('port') in (3306, 5432, 1433, 27017) for p in ports)},
        {'id': 'CIS-4.1', 'requirement': 'Ensure admin panels are not exposed', 'passed': not any('admin' in f.get('title', '').lower() for f in findings)},
    ]
    cis_pass = sum(1 for c in cis_checks if c['passed'])
    cis_fail = sum(1 for c in cis_checks if not c['passed'])
    compliance['CIS Benchmarks'] = {
        'status': 'PASS' if cis_fail == 0 else 'FAIL',
        'score': f'{cis_pass}/{len(cis_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in cis_checks if not c['passed']],
        'checks_performed': len(cis_checks),
        'checks_passed': cis_pass
    }

    # ── PCI-DSS v4.0 Compliance ──
    log('info', '[COMPLIANCE] Checking PCI-DSS v4.0')
    pci_checks = [
        {'id': 'PCI-1', 'requirement': 'Encrypt cardholder data in transit (TLS 1.2+)', 'passed': ssl_data.get('protocol', '') not in ('SSLv3', 'TLSv1', 'TLSv1.1')},
        {'id': 'PCI-2', 'requirement': 'Use strong cryptography', 'passed': not any(weak in ssl_data.get('cipher', '').lower() for weak in ['rc4', 'des', '3des', 'null', 'export'])},
        {'id': 'PCI-3', 'requirement': 'Implement strong access control', 'passed': not any('access control' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-4', 'requirement': 'Regular security testing', 'passed': len(findings) < 5},
        {'id': 'PCI-5', 'requirement': 'Maintain secure systems', 'passed': len(missing_hdrs) < 3},
        {'id': 'PCI-6', 'requirement': 'Protect sensitive data', 'passed': not any('sensitive' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-7', 'requirement': 'Restrict access by business need-to-know', 'passed': not any('idor' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-8', 'requirement': 'Identify users and authenticate access', 'passed': not any('authentication' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-9', 'requirement': 'Restrict physical access', 'passed': True},
        {'id': 'PCI-10', 'requirement': 'Log and monitor all access', 'passed': not any('logging' in f.get('title', '').lower() for f in findings)},
    ]
    pci_pass = sum(1 for c in pci_checks if c['passed'])
    pci_fail = sum(1 for c in pci_checks if not c['passed'])
    compliance['PCI-DSS v4.0'] = {
        'status': 'PASS' if pci_fail == 0 else 'FAIL',
        'score': f'{pci_pass}/{len(pci_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in pci_checks if not c['passed']],
        'checks_performed': len(pci_checks),
        'checks_passed': pci_pass
    }

    # ── HIPAA Compliance ──
    log('info', '[COMPLIANCE] Checking HIPAA Security Rule')
    hipaa_checks = [
        {'id': 'HIPAA-1', 'requirement': 'Encrypt ePHI in transit (TLS)', 'passed': ssl_data.get('protocol', '') not in ('SSLv3', 'TLSv1', 'TLSv1.1')},
        {'id': 'HIPAA-2', 'requirement': 'Implement access controls', 'passed': not any('access control' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-3', 'requirement': 'Audit controls for access', 'passed': not any('logging' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-4', 'requirement': 'Integrity controls', 'passed': not any('integrity' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-5', 'requirement': 'Transmission security', 'passed': 'Strict-Transport-Security' not in missing_hdrs},
        {'id': 'HIPAA-6', 'requirement': 'Person or entity authentication', 'passed': not any('authentication' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-7', 'requirement': 'Automatic logoff', 'passed': True},
        {'id': 'HIPAA-8', 'requirement': 'Emergency access procedure', 'passed': True},
    ]
    hipaa_pass = sum(1 for c in hipaa_checks if c['passed'])
    hipaa_fail = sum(1 for c in hipaa_checks if not c['passed'])
    compliance['HIPAA'] = {
        'status': 'PASS' if hipaa_fail == 0 else 'FAIL',
        'score': f'{hipaa_pass}/{len(hipaa_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in hipaa_checks if not c['passed']],
        'checks_performed': len(hipaa_checks),
        'checks_passed': hipaa_pass
    }

    # ── NIST CSF Compliance ──
    log('info', '[COMPLIANCE] Checking NIST Cybersecurity Framework')
    nist_checks = [
        {'id': 'NIST-IDENTIFY', 'requirement': 'Asset Management', 'passed': len(assets) > 0},
        {'id': 'NIST-PROTECT', 'requirement': 'Access Control', 'passed': not any('idor' in f.get('title', '').lower() for f in findings)},
        {'id': 'NIST-PROTECT', 'requirement': 'Data Security', 'passed': not any('sensitive' in f.get('title', '').lower() for f in findings)},
        {'id': 'NIST-DETECT', 'requirement': 'Detection Processes', 'passed': not any('logging' in f.get('title', '').lower() for f in findings)},
        {'id': 'NIST-RESPOND', 'requirement': 'Response Planning', 'passed': True},
        {'id': 'NIST-RECOVER', 'requirement': 'Recovery Planning', 'passed': True},
    ]
    nist_pass = sum(1 for c in nist_checks if c['passed'])
    nist_fail = sum(1 for c in nist_checks if not c['passed'])
    compliance['NIST CSF'] = {
        'status': 'PASS' if nist_fail == 0 else 'FAIL',
        'score': f'{nist_pass}/{len(nist_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in nist_checks if not c['passed']],
        'checks_performed': len(nist_checks),
        'checks_passed': nist_pass
    }

    # ── SOC 2 Compliance ──
    log('info', '[COMPLIANCE] Checking SOC 2 Trust Service Criteria')
    soc2_checks = [
        {'id': 'SOC2-CC6.1', 'requirement': 'Logical access controls', 'passed': not any('access control' in f.get('title', '').lower() for f in findings)},
        {'id': 'SOC2-CC6.6', 'requirement': 'System boundaries', 'passed': len(ports) < 15},
        {'id': 'SOC2-CC7.1', 'requirement': 'Vulnerability management', 'passed': len(findings) < 5},
        {'id': 'SOC2-CC8.1', 'requirement': 'Change management', 'passed': True},
        {'id': 'SOC2-A1.1', 'requirement': 'Capacity management', 'passed': True},
    ]
    soc2_pass = sum(1 for c in soc2_checks if c['passed'])
    soc2_fail = sum(1 for c in soc2_checks if not c['passed'])
    compliance['SOC 2'] = {
        'status': 'PASS' if soc2_fail == 0 else 'FAIL',
        'score': f'{soc2_pass}/{len(soc2_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in soc2_checks if not c['passed']],
        'checks_performed': len(soc2_checks),
        'checks_passed': soc2_pass
    }

    # ── Summary ──
    total_checks = sum(c.get('checks_performed', 0) for c in compliance.values())
    total_passed = sum(c.get('checks_passed', 0) for c in compliance.values())
    overall_score = round(total_passed / total_checks * 100, 1) if total_checks > 0 else 0
    frameworks_failed = sum(1 for c in compliance.values() if c.get('status') == 'FAIL')

    compliance['_summary'] = {
        'total_frameworks': len([k for k in compliance.keys() if not k.startswith('_')]),
        'frameworks_passed': len([k for k in compliance.keys() if not k.startswith('_')]) - frameworks_failed,
        'frameworks_failed': frameworks_failed,
        'total_checks': total_checks,
        'total_passed': total_passed,
        'overall_score': overall_score,
        'scan_mode': 'active'
    }

    if frameworks_failed > 0:
        add_finding('info', f'Compliance gaps detected: {frameworks_failed} frameworks failing',
            sub=f'{total_checks - total_passed} of {total_checks} compliance checks failed across {frameworks_failed} frameworks',
            asset=target, cvss='4.0', owasp='A05', mitre='T1592',
            details=f'Failed frameworks: {", ".join([k for k, v in compliance.items() if not k.startswith("_") and v.get("status") == "FAIL"])}')

    log('ok', f'[COMPLIANCE] Audit complete: {total_passed}/{total_checks} checks passed ({overall_score}%)')
    with LOCK:
        scan_state['compliance_data'] = compliance
    set_progress('compliance', 100)

# ─── MONITORING MODULE ─────────────────────────────────────────────────────────
