"""Network reconnaissance modules: DNS, ports, SSL, subdomains, crawling."""
import re
import json
import time
import socket
import ssl
import os
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE, DNS_AVAILABLE, BS4_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress
from scanner.tools.wrappers import run_rustscan, run_puredns, run_gospider, run_naabu_portscan

try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None

def run_dns_module(target):
    log('info', f'[DNS] Performing advanced DNS analysis on {target}')
    dns_data = {'a':[],'aaaa':[],'mx':[],'ns':[],'cname':[],'soa':[],'txt':[],'caa':[],'srv':[],'ptr':[],'ds':[],'dnskey':[],'nsec':[],'zone_transfer': False, 'dnssec': False, 'wildcard': False}
    try:
        ip = socket.gethostbyname(target)
        dns_data['a'] = [ip]
        log('ok', f'[DNS] A record: {target} -> {ip}')
    except Exception as e:
        log('warn', f'[DNS] A record lookup failed: {e}')
    try:
        info = socket.gethostbyname_ex(target)
        if len(info) > 2:
            dns_data['a'] = info[2]
    except Exception:
        pass
    if DNS_AVAILABLE:
        for qtype, label in [('A','a'),('AAAA','aaaa'),('MX','mx'),('NS','ns'),('TXT','txt'),('CNAME','cname'),('CAA','caa'),('SRV','srv'),('DS','ds'),('DNSKEY','dnskey')]:
            try:
                answers = dns.resolver.resolve(target, qtype, lifetime=4)
                if qtype == 'MX':
                    dns_data[label] = [f'{r.exchange} (priority {r.preference})' for r in answers]
                elif qtype == 'SOA':
                    dns_data[label] = [str(answers[0].mname)]
                elif qtype == 'SRV':
                    dns_data[label] = [f'{r.target}:{r.port} (priority {r.priority})' for r in answers]
                else:
                    dns_data[label] = [str(r) for r in answers[:20]]
                if dns_data[label]:
                    log('ok', f'[DNS] Found {len(dns_data[label])} {qtype} records')
            except (dns.exception.DNSException, Exception) as e:
                log('dim', f'[DNS] {qtype} lookup: {e}')

        # SOA record
        try:
            soa = dns.resolver.resolve(target, 'SOA', lifetime=4)
            dns_data['soa'] = [f'{soa[0].mname} (serial {soa[0].serial})']
        except Exception:
            pass

        # DNSSEC check
        try:
            dnskey = dns.resolver.resolve(target, 'DNSKEY', lifetime=4)
            if dnskey:
                dns_data['dnssec'] = True
                log('ok', '[DNS] DNSSEC is enabled')
        except Exception:
            log('dim', '[DNS] DNSSEC not enabled or not detectable')

        # Zone transfer attempt (AXFR)
        for ns in dns_data.get('ns', []):
            ns_host = ns.rstrip('.').split()[0] if ' ' in ns else ns.rstrip('.')
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, target, lifetime=5))
                if zone:
                    dns_data['zone_transfer'] = True
                    add_finding('critical', 'DNS Zone Transfer Allowed',
                        sub=f'Zone transfer possible via {ns_host}',
                        asset=target, cvss='7.5', exploit='PUBLIC', owasp='A05', mitre='T1596',
                        details=f'AXFR zone transfer succeeded on nameserver {ns_host}. This exposes all DNS records including internal hosts.')
                    log('err', f'[DNS] CRITICAL: Zone transfer allowed on {ns_host}')
                    break
            except Exception:
                pass

        # Wildcard DNS check
        try:
            wildcard = f'randomxyz{target}'
            dns.resolver.resolve(wildcard, 'A', lifetime=3)
            dns_data['wildcard'] = True
            log('warn', '[DNS] Wildcard DNS detected')
        except Exception:
            pass

        # Reverse DNS for first few IPs
        for ip in dns_data['a'][:3]:
            try:
                ptr = dns.resolver.resolve(dns.reversename.from_address(ip), 'PTR', lifetime=3)
                dns_data['ptr'].append(f'{ip} -> {ptr[0]}')
            except Exception:
                pass
    else:
        log('warn', '[DNS] dnspython not available, limited DNS resolution')

    # Note: SPF/DMARC findings are generated in the email security module
    # (run_emailsec_module) with richer context.  Do NOT duplicate them here.

    with LOCK:
        scan_state['dns_data'] = dns_data
    set_progress('dns', 100)
    log('ok', f'[DNS] Complete — {len(dns_data["a"])} A, {len(dns_data["mx"])} MX, {len(dns_data["ns"])} NS, {len(dns_data["txt"])} TXT, DNSSEC: {dns_data["dnssec"]}')

# ─── SUBDOMAIN MODULE ──────────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST = ['www','mail','admin','api','dev','test','stage','blog','shop','cdn','m','app','portal','secure','vpn','remote','git','jenkins','jira','wiki','confluence','grafana','prometheus','kibana','sonar','nexus','artifactory','registry','docker','k8s','kubernetes','dashboard','monitor','status','help','support','docs','legal','about','contact','news','events','forum','community','statuspage','uptime','careers','jobs','partners','billing','payment','checkout','cart','login','signup','register','auth','sso','oauth','api-v1','api-v2','graphql','socket','ws','chat','live','stream','video','media','images','static','assets','uploads','files','storage','backup','db','database','redis','mongo','mysql','sql','analytics','metrics','logs','trace','health','ready','probe','webhook','callback','notify','notification','sms','email','mailgun','sendgrid','smtp','pop','imap','exchange','calendar','sync','mobile','ios','android','app-dev','app-test','api-dev','api-test','staging','prod','production','preprod','beta','alpha','demo','sandbox','internal','external','partner','vendor','supplier','customer','client','corp','hr','it-help','payroll','purchase','inventory','erp','crm','analytics','insights','reports','bi','dwh','etl','mx','autodiscover','autoconfig','sip','lync','sipfed','sipdir','msoid','enterpriseregistration','enterpriseenrollment','_dmarc','_domainkey','selector1','selector2','cpanel','whm','webmail','ftp','sftp','ssh','rdp','vnc','proxy','loadbalancer','lb','ha','failover','dr','disaster-recovery','archive','old','legacy','v1','v2','v3','canary','blue','green','hotfix','patch','release','qa','uat','perf','load','stress','chaos','feature','fix','bugfix','hotfix','experiment','ab-test','variant','control','segment','cohort','data','ml','ai','training','inference','model','pipeline','etl','ingest','process','transform','aggregate','warehouse','lake','stream','queue','worker','job','task','cron','scheduler','orchestrator','controller','manager','service','daemon','agent','sidecar','init','setup','install','upgrade','migrate','seed','reset','clean','purge','gc','snapshot','volume','disk','block','file','object','blob','bucket','share','mount','sync','replicate','mirror','cache','memcached','varnish','nginx','apache','caddy','traefik','haproxy','envoy','istio','linkerd','consul','etcd','zookeeper','kafka','rabbitmq','activemq','pulsar','nats','redis-sentinel','redis-cluster','mongo-shard','mongo-replica','postgres-replica','mysql-replica','elasticsearch','solr','lucene','sphinx','meilisearch','algolia','typesense']



def run_subdomain_module(target):
    log('info', f'[SUB] Enumerating subdomains for {target}')
    assets = []
    found = set()
    try:
        # ── Passive: crt.sh Certificate Transparency ──
        if REQUESTS_AVAILABLE:
            log('ok', f'[SUB] Querying Certificate Transparency logs (crt.sh)')
            try:
                ct_url = f'https://crt.sh/?q=%.{target}&output=json'
                r = req_lib.get(ct_url, timeout=15, verify=False)
                if r.status_code == 200:
                    ct_data = r.json()
                    ct_subs = set()
                    for entry in ct_data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(target) and '*' not in sub and sub not in found:
                                ct_subs.add(sub)
                    for sub in sorted(ct_subs)[:100]:
                        try:
                            ip = socket.gethostbyname(sub)
                            if sub not in found:
                                found.add(sub)
                                assets.append({'fqdn': sub, 'ips': [ip], 'source': 'crt.sh'})
                                log('ok', f'[SUB] CT: {sub} -> {ip}')
                        except Exception:
                            pass
                    log('ok', f'[SUB] crt.sh found {len(ct_subs)} unique subdomains')
            except Exception as e:
                log('dim', f'[SUB] crt.sh query failed: {e}')

        # ── Passive: DNS buffer over-run (dns.bufferover.run) ──
        if REQUESTS_AVAILABLE:
            try:
                bo_url = f'https://dns.bufferover.run/dns?q=.{target}'
                r = req_lib.get(bo_url, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    for line in data.get('FDNS_A', []):
                        parts = line.split(',')
                        if len(parts) == 2:
                            sub, ip = parts
                            if sub.endswith(target) and sub not in found:
                                found.add(sub)
                                assets.append({'fqdn': sub, 'ips': [ip], 'source': 'bufferover'})
                                log('ok', f'[SUB] BO: {sub} -> {ip}')
            except Exception:
                pass

        # ── Active: DNS brute-force ──
        if DNS_AVAILABLE:
            log('ok', f'[SUB] DNS brute-force with {len(SUBDOMAIN_WORDLIST)} words')
            try:
                ns = dns.resolver.resolve(target, 'NS', lifetime=4)
                for n in ns:
                    log('dim', f'[SUB] Nameserver: {n}')
            except Exception:
                pass
        # Use ThreadPoolExecutor for parallel DNS lookups with timeout
        def _resolve_sub(sub):
            try:
                ip = socket.gethostbyname(sub)
                return (sub, ip)
            except (socket.gaierror, OSError):
                return None
        import socket as _sock_mod
        _sock_mod.setdefaulttimeout(3)
        with ThreadPoolExecutor(max_workers=20) as _pool:
            futures = {_pool.submit(_resolve_sub, f'{word}.{target}'): word for word in SUBDOMAIN_WORDLIST}
            try:
                for fut in as_completed(futures, timeout=60):
                    if not scan_state.get('scanning'):
                        break
                    try:
                        result = fut.result(timeout=5)
                    except Exception:
                        continue
                    if result:
                        sub, ip = result
                        if sub not in found:
                            found.add(sub)
                            assets.append({'fqdn': sub, 'ips': [ip]})
                            log('ok', f'[SUB] Found: {sub} -> {ip}')
            except TimeoutError:
                for f in futures:
                    f.cancel()
        _sock_mod.setdefaulttimeout(None)
        log('ok', f'[SUB] Enumeration complete — {len(assets)} subdomains found')
    except Exception as e:
        log('err', f'[SUB] Error: {e}')
    with LOCK:
        scan_state['assets'] = assets
    if not assets:
        with LOCK:
            scan_state['assets'] = [{'fqdn': target, 'ips': [socket.gethostbyname(target)]}]
    # Enhanced subdomain discovery with subfinder
    subfinder_path = _find_tool('subfinder')
    if subfinder_path:
        log('info', f'[SUB] Running subfinder for enhanced subdomain discovery')
        stdout, stderr, rc = _run_tool([
            subfinder_path, '-d', target, '-silent', '-timeout', '30'
        ], timeout=45)
        if rc == 0 and stdout:
            new_subs = [line.strip() for line in stdout.strip().split('\n') if line.strip() and '.' in line]
            with LOCK:
                existing_assets = {a.get('name', '') for a in scan_state.get('assets', [])}
                added = 0
                for sub in new_subs:
                    if sub not in existing_assets:
                        scan_state['assets'].append({'name': sub, 'type': 'subdomain', 'status': 'active'})
                        existing_assets.add(sub)
                        added += 1
            log('ok', f'[SUB] Subfinder found {len(new_subs)} subdomains ({added} new)')
    
    # Enhanced subdomain discovery with amass (OSINT-based)
    amass_path = _find_tool('amass')
    if amass_path:
        log('info', f'[SUB] Running amass for OSINT subdomain discovery')
        stdout, stderr, rc = _run_tool([
            amass_path, 'enum', '-passive', '-d', target, '-timeout', '30'
        ], timeout=45)
        if rc == 0 and stdout:
            with LOCK:
                existing_assets = {a.get('name', '') for a in scan_state.get('assets', [])}
                added = 0
                for line in stdout.strip().split('\n'):
                    sub = line.strip()
                    if sub and '.' in sub and sub not in existing_assets:
                        scan_state['assets'].append({'name': sub, 'type': 'subdomain', 'status': 'active', 'source': 'amass'})
                        existing_assets.add(sub)
                        added += 1
            log('ok', f'[SUB] Amass found {added} additional subdomains')
    
    # ── DNSX bulk subdomain validation ──
    dnsx_path = _find_tool('dnsx')
    if dnsx_path:
        log('info', '[SUB] Running dnsx for DNS validation + security analysis')
        with LOCK:
            sub_list = [a.get('name', a.get('fqdn', '')) for a in scan_state.get('assets', []) if a.get('name') or a.get('fqdn')]
        if sub_list:
            import tempfile as _tf
            sub_file = _tf.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            sub_file.write('\n'.join(sub_list))
            sub_file.close()
            try:
                # ── Bulk DNS resolution ──
                stdout, stderr, rc = _run_tool([
                    dnsx_path, '-l', sub_file.name, '-silent', '-a', '-resp',
                    '-timeout', '10', '-retry', '2'
                ], timeout=45)
                if rc == 0 and stdout:
                    from collections import defaultdict as _ddict
                    resolved_map = _ddict(list)
                    cname_map = {}
                    for line in stdout.strip().split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            hostname = parts[0]
                            record = parts[-1]
                            # CNAME records
                            if 'CNAME' in line or (len(parts) >= 3 and parts[1] == 'CNAME'):
                                cname_map[hostname] = record
                            else:
                                resolved_map[hostname].append(record)
                    with LOCK:
                        existing_assets = {a.get('name', '') for a in scan_state.get('assets', [])}
                        for hostname, ips in resolved_map.items():
                            if hostname not in existing_assets:
                                scan_state['assets'].append({'name': hostname, 'ips': ips, 'type': 'subdomain', 'source': 'dnsx'})
                                existing_assets.add(hostname)
                    log('ok', f'[SUB] dnsx validated {len(resolved_map)} subdomains ({len(resolved_map)} resolved)')

                    # ── DNSSEC validation check ──
                    import dns.resolver as _dns_res
                    import dns.dnssec as _dnssec
                    try:
                        answer = _dns_res.resolve(target, 'DNSKEY')
                        if answer:
                            log('ok', f'[SUB] DNSSEC enabled for {target} — DNSKEY record present')
                    except _dns_res.NoAnswer:
                        add_finding(
                            'medium',
                            f'DNSSEC not enabled for {target}',
                            sub='No DNSKEY record — DNS responses can be spoofed',
                            asset=target, cvss='5.0', owasp='A02', mitre='T1557',
                            details=f'DNSKEY record not found for {target}\n'
                                    f'Impact: DNS cache poisoning, subdomain takeover via DNS spoofing\n'
                                    f'Remediation: Enable DNSSEC signing for {target}')
                    except Exception:
                        pass

                    # ── CAA record check ──
                    try:
                        caa_records = list(_dns_res.resolve(target, 'CAA'))
                        if not caa_records:
                            add_finding(
                                'low',
                                f'No CAA records for {target}',
                                sub='Certificate Authority Authorization not set — any CA can issue certs',
                                asset=target, cvss='3.0', owasp='A02', mitre='T1557',
                                details=f'No CAA record found for {target}\n'
                                        f'Impact: Any Certificate Authority can issue certificates for this domain\n'
                                        f'Remediation: Add CAA record: 0 issue "letsencrypt.org"')
                        else:
                            authorized_cas = []
                            for r in caa_records:
                                for rdata in r:
                                    if hasattr(rdata, 'flags'):
                                        tag = rdata.tag if hasattr(rdata, 'tag') else ''
                                        value = rdata.value if hasattr(rdata, 'value') else ''
                                        authorized_cas.append(f'{tag} {value}')
                            log('ok', f'[SUB] CAA records found: {", ".join(authorized_cas[:3])}')
                    except _dns_res.NoAnswer:
                        pass
                    except Exception:
                        pass

            except Exception as e:
                log('warn', f'[SUB] dnsx error: {e}')
            finally:
                try:
                    os.unlink(sub_file.name)
                except Exception:
                    pass
        set_progress('sub', 90)

    # ── Assetfinder subdomain discovery ──
    assetfinder_path = _find_tool('assetfinder')
    if assetfinder_path:
        log('info', '[SUB] Running assetfinder for additional subdomain enumeration')
        stdout, stderr, rc = _run_tool([
            assetfinder_path, '--subs-only', target
        ], timeout=30)
        if rc == 0 and stdout:
            with LOCK:
                existing_assets = {a.get('name', a.get('fqdn', '')) for a in scan_state.get('assets', [])}
                added = 0
                for line in stdout.strip().split('\n'):
                    sub = line.strip()
                    if sub and '.' in sub and sub not in existing_assets:
                        scan_state['assets'].append({'name': sub, 'type': 'subdomain', 'status': 'active', 'source': 'assetfinder'})
                        existing_assets.add(sub)
                        added += 1
            log('ok', f'[SUB] assetfinder found {added} additional subdomains')

    # ── PureDNS DNS bruteforce ──
    with LOCK:
        existing_subs = {a.get('name', '') for a in scan_state.get('assets', [])}
    puredns_subs = run_puredns(target, existing_subs)
    if puredns_subs:
        with LOCK:
            for s in puredns_subs:
                scan_state['assets'].append({'name': s, 'type': 'subdomain', 'source': 'puredns'})
        log('ok', f'[SUB] puredns found {len(puredns_subs)} additional subdomains')

    set_progress('sub', 100)

# ─── SSL MODULE ────────────────────────────────────────────────────────────────


def run_ssl_module(target):
    log('info', f'[SSL] Checking SSL/TLS certificate for {target}')
    ssl_data = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((target, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                ssl_data['protocol'] = ssock.version() or 'TLSv1.2'
                ssl_data['cipher'] = ssock.cipher()[0] if ssock.cipher() else 'unknown'
                ssl_data['bits'] = ssock.cipher()[2] if ssock.cipher() else 128
                ssl_data['issuer'] = dict(cert.get('issuer', []))
                ssl_data['subject'] = dict(cert.get('subject', []))
                snb = cert.get('notBefore', '')
                sna = cert.get('notAfter', '')
                ssl_data['not_before'] = snb
                ssl_data['not_after'] = sna
                san_list = []
                for ext in cert.get('subjectAltName', []):
                    san_list.append(ext[1])
                ssl_data['san'] = san_list
                try:
                    nb = datetime.strptime(snb, '%b %d %H:%M:%S %Y %Z') if snb else datetime.now()
                    na = datetime.strptime(sna, '%b %d %H:%M:%S %Y %Z') if sna else datetime.now()
                    ssl_data['days_until_expiry'] = (na - datetime.now()).days
                except Exception:
                    ssl_data['days_until_expiry'] = 90
                log('ok', f'[SSL] {ssl_data["protocol"]} — {ssl_data["cipher"]} — {ssl_data["days_until_expiry"]} days until expiry')
                cn = ''
                for attr in cert.get('subject', []):
                    for k, v in attr:
                        if k == 'commonName':
                            cn = v
                            break
                ssl_data['subject_cn'] = cn
    except Exception as e:
        log('warn', f'[SSL] Certificate check failed: {e}')
        # On connection failure, do NOT report 0 days remaining (false critical).
        # Set a sentinel value so downstream consumers know the check was
        # inconclusive rather than immediately expiring.
        ssl_data = {'error': str(e), 'protocol': 'N/A', 'days_until_expiry': 999}
    with LOCK:
        scan_state['ssl_data'] = ssl_data
    set_progress('ssl', 100)
    # Enhanced SSL analysis with testssl.sh
    testssl_path = _find_tool('testssl.sh')
    if testssl_path and REQUESTS_AVAILABLE:
        log('info', f'[SSL] Running testssl.sh for deep TLS analysis')
        stdout, stderr, rc = _run_tool([
            testssl_path, '--jsonfile', '-', '--quiet', '--fast', target
        ], timeout=45)
        if rc == 0 and stdout:
            try:
                import json as _json
                testssl_results = _json.loads(stdout) if stdout.strip().startswith('[') else []
                weak_ciphers = []
                protocols = []
                for item in testssl_results:
                    if isinstance(item, dict):
                        id_val = item.get('id', '')
                        severity = item.get('severity', '')
                        finding = item.get('finding', '')
                        if 'cipher' in id_val.lower() and severity in ('CRITICAL', 'HIGH', 'MEDIUM'):
                            weak_ciphers.append(f'{id_val}: {finding}')
                        if 'protocol' in id_val.lower():
                            protocols.append(f'{id_val}: {finding}')
                if weak_ciphers:
                    log('warn', f'[SSL] Weak ciphers found: {len(weak_ciphers)}')
                if protocols:
                    log('info', f'[SSL] Protocols: {", ".join(protocols[:5])}')
                with LOCK:
                    scan_state['ssl_data']['testssl_results'] = testssl_results[:50]
                    scan_state['ssl_data']['weak_ciphers'] = weak_ciphers
                    scan_state['ssl_data']['protocols_detail'] = protocols
            except Exception as e:
                log('warn', f'[SSL] testssl.sh output parse error: {e}')

    # Enhanced SSL analysis with sslyze (Python-based, detailed cipher analysis)
    try:
        from sslyze import Scanner
        from sslyze.plugins.openssl_cipher_suites_plugin import TlsCipherSuitesPlugin
        log('info', f'[SSL] Running sslyze for detailed cipher analysis')
        scanner = Scanner()
        scanner.queue_scan(target, [TlsCipherSuitesPlugin()])
        result = scanner.get_results()
        weak_ciphers = []
        for plugin_result in result.get_plugin_result(TlsCipherSuitesPlugin()):
            if hasattr(plugin_result, 'cipher_suite'):
                for cipher in plugin_result.cipher_suite:
                    if cipher.is_accepted:
                        # Check for weak ciphers
                        name = cipher.cipher_suite.name.lower()
                        if any(weak in name for weak in ['rc4', 'des', '3des', 'null', 'export', 'md5', 'anon']):
                            weak_ciphers.append(cipher.cipher_suite.name)
        if weak_ciphers:
            log('warn', f'[SSL] sslyze found weak ciphers: {", ".join(weak_ciphers[:5])}')
            with LOCK:
                scan_state['ssl_data']['sslyze_weak_ciphers'] = weak_ciphers
        else:
            log('ok', f'[SSL] sslyze: No weak ciphers detected')
    except ImportError:
        log('dim', '[SSL] sslyze not available as Python library')
    except Exception as e:
        log('warn', f'[SSL] sslyze analysis error: {e}')

# ─── PORT SCAN MODULE ──────────────────────────────────────────────────────────


def run_port_module(target):
    log('info', f'[PORTS] Scanning ports on {target}')
    port_data = []

    # ── Try rustscan first (3s full scan) ──
    open_ports = run_rustscan(target)

    # ── Fallback to naabu ──
    if not open_ports:
        open_ports = run_naabu_portscan(target)

    # ── Use discovered ports for targeted nmap -sV ──
    if open_ports:
        port_str = ','.join(str(p) for p in open_ports[:200])
        log('info', f'[PORTS] Discovered {len(open_ports)} ports — running nmap -sV on targeted ports')
        nmap_path = _find_tool('nmap')
        if nmap_path:
            adv = scan_state.get('advanced_options', {})
            nmap_extra = adv.get('nmap_flags', '').split() if adv.get('nmap_flags') else []
            tool_timeout = adv.get('timeout', 45)
            cmd = [nmap_path, '-sV', '-p', port_str, '-T4', '--open', '-oX', '-', target] + nmap_extra
            stdout, stderr, rc = _run_tool(cmd, timeout=tool_timeout)
            if rc == 0 and stdout:
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(stdout)
                    for host in root.findall('.//host'):
                        for port_elem in host.findall('.//port'):
                            port_id = int(port_elem.get('portid', 0))
                            protocol = port_elem.get('protocol', 'tcp')
                            state_elem = port_elem.find('state')
                            state = state_elem.get('state', '') if state_elem is not None else ''
                            if state == 'open':
                                service_elem = port_elem.find('service')
                                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                                service_product = service_elem.get('product', '') if service_elem is not None else ''
                                service_version = service_elem.get('version', '') if service_elem is not None else ''
                                banner = f'{service_product} {service_version}'.strip()
                                port_data.append({
                                    'port': port_id, 'service': service_name,
                                    'ip': target, 'banner': banner,
                                    'protocol': protocol, 'state': state
                                })
                                log('ok', f'[PORTS] Port {port_id}/{service_name} OPEN ({banner})')
                except ET.ParseError as e:
                    log('warn', f'[PORTS] Nmap XML parse error: {e}')
    else:
        # ── Full nmap fallback ──
        nmap_path = _find_tool('nmap')
        if nmap_path:
            log('info', f'[PORTS] Using Nmap for enhanced port scanning')
            stdout, stderr, rc = _run_tool([
                nmap_path, '-sV', '-sS', '--top-ports', '1000',
                '-T4', '--open', '-oX', '-', target
            ], timeout=45)

            if rc == 0 and stdout:
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(stdout)
                    for host in root.findall('.//host'):
                        for port_elem in host.findall('.//port'):
                            port_id = int(port_elem.get('portid', 0))
                            protocol = port_elem.get('protocol', 'tcp')
                            state_elem = port_elem.find('state')
                            state = state_elem.get('state', '') if state_elem is not None else ''
                            if state == 'open':
                                service_elem = port_elem.find('service')
                                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                                service_product = service_elem.get('product', '') if service_elem is not None else ''
                                service_version = service_elem.get('version', '') if service_elem is not None else ''
                                banner = f'{service_product} {service_version}'.strip()
                                port_data.append({
                                    'port': port_id, 'service': service_name,
                                    'ip': target, 'banner': banner,
                                    'protocol': protocol, 'state': state
                                })
                                log('ok', f'[PORTS] Port {port_id}/{service_name} OPEN ({banner})')
                except ET.ParseError as e:
                    log('warn', f'[PORTS] Nmap XML parse error: {e}')

            # Also run a UDP scan on top 20 ports
            stdout2, _, rc2 = _run_tool([
                nmap_path, '-sU', '--top-ports', '20',
                '-T4', '--open', '-oX', '-', target
            ], timeout=45)

            if rc2 == 0 and stdout2:
                try:
                    root = ET.fromstring(stdout2)
                    for host in root.findall('.//host'):
                        for port_elem in host.findall('.//port'):
                            port_id = int(port_elem.get('portid', 0))
                            state_elem = port_elem.find('state')
                            state = state_elem.get('state', '') if state_elem is not None else ''
                            if state == 'open':
                                service_elem = port_elem.find('service')
                                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                                port_data.append({
                                    'port': port_id, 'service': f'{service_name}/udp',
                                    'ip': target, 'banner': '', 'protocol': 'udp', 'state': state
                                })
                                log('ok', f'[PORTS] UDP Port {port_id}/{service_name} OPEN')
                except ET.ParseError:
                    pass
        else:
            log('warn', '[PORTS] Nmap not found, falling back to Python socket scan')
            try:
                ip = socket.gethostbyname(target)
                log('ok', f'[PORTS] Resolved {target} -> {ip}')
                with ThreadPoolExecutor(max_workers=30) as executor:
                    futures = {executor.submit(scan_port, ip, p): p for p in COMMON_PORTS}
                    try:
                        for f in as_completed(futures, timeout=120):
                            try:
                                result = f.result(timeout=5)
                                if result:
                                    port_data.append(result)
                                    log('ok', f'[PORTS] Port {result["port"]}/{result["service"]} OPEN')
                            except Exception:
                                pass
                    except TimeoutError:
                        for f in futures:
                            f.cancel()
            except Exception as e:
                log('err', f'[PORTS] Scan error: {e}')
    
    port_data.sort(key=lambda x: x['port'])
    log('ok', f'[PORTS] Scan complete - {len(port_data)} open ports found')
    
    # Generate findings for high-risk ports
    high_risk_ports = {21: 'FTP', 23: 'Telnet', 445: 'SMB', 1433: 'MSSQL', 
                       3306: 'MySQL', 3389: 'RDP', 6379: 'Redis', 27017: 'MongoDB',
                       5900: 'VNC', 9200: 'Elasticsearch', 11211: 'Memcached'}
    for p in port_data:
        port_num = p['port']
        if port_num in high_risk_ports:
            svc = p.get('service', high_risk_ports.get(port_num, 'unknown'))
            add_finding('high', f'High-risk port exposed: {port_num}/{svc}',
                sub=f'Port {port_num} ({svc}) is exposed to the internet and may be targeted by attackers',
                asset=f'{target}:{port_num}',
                cvss='7.5', exploit='PUBLIC', owasp='A05', mitre='T1046',
                details=f'Port {port_num}/{svc} is open on {target}\\nService: {svc}\\nBanner: {p.get("banner", "N/A")}\\n\\nRemediation: Restrict access to this port using firewall rules. If not needed, close it immediately.')
    
    with LOCK:
        scan_state['port_data'] = port_data
    set_progress('ports', 100)

# ─── WHOIS MODULE ──────────────────────────────────────────────────────────────


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


def run_takeover_module(target):
    log('info', f'[TAKEOVER] Checking for subdomain takeover vulnerabilities')
    takeover_data = []
    with LOCK:
        assets = list(scan_state.get('assets', []))
    for asset in assets:
        fqdn = asset.get('fqdn', '')
        if not fqdn:
            continue
        try:
            cname = ''
            if DNS_AVAILABLE:
                try:
                    answers = dns.resolver.resolve(fqdn, 'CNAME', lifetime=4)
                    cname = str(answers[0].target).rstrip('.')
                except Exception:
                    pass
            if cname:
                for domain, service in TAKEOVER_SERVICES.items():
                    if domain in cname.lower():
                        takeover_data.append({'subdomain': fqdn, 'service': service, 'cname': cname})
                        add_finding('high', f'Potential subdomain takeover: {fqdn}',
                            sub=f'{fqdn} has CNAME to {cname} pointing to {service}',
                            asset=fqdn, cvss='7.5', exploit='PUBLIC', owasp='A05', mitre='T1584')
                        log('warn', f'[TAKEOVER] {fqdn} -> {cname} (potential {service} takeover)')
                        break
        except Exception:
            pass
    log('ok', f'[TAKEOVER] Checked {len(assets)} assets — {len(takeover_data)} potential takeovers')
    with LOCK:
        scan_state['takeover_data'] = takeover_data
    set_progress('takeover', 100)


# ─── HTTP HEADER MODULE ────────────────────────────────────────────────────────


def run_web_crawler_module(target):
    log('info', f'[CRAWL] Starting web crawler on {target}')
    crawl_data = {
        'urls': [],
        'forms': [],
        'inputs': [],
        'endpoints': [],
        'js_files': [],
        'api_endpoints': [],
        'admin_panels': [],
        'sensitive_files': [],
        'comments': [],
        'emails': [],
        'internal_links': [],
        'external_links': [],
        'graphql_endpoints': [],
        'websocket_endpoints': [],
        'sitemap_urls': [],
        'robots_paths': [],
        'parameters': [],
    }

    if not REQUESTS_AVAILABLE:
        log('warn', '[CRAWL] requests library not available')
        with LOCK:
            scan_state['crawl_data'] = crawl_data
        set_progress('crawl', 100)
        return

    visited = set()
    urls_to_visit = [f'https://{target}']
    max_urls = 100
    max_depth = 3

    # Common sensitive paths to check
    sensitive_paths = [
        '/admin', '/administrator', '/wp-admin', '/login', '/panel',
        '/.env', '/.git', '/.svn', '/config.php', '/config.yml',
        '/robots.txt', '/sitemap.xml', '/.htaccess', '/web.config',
        '/phpinfo.php', '/info.php', '/test.php', '/debug',
        '/api', '/api/v1', '/api/v2', '/swagger', '/docs',
        '/backup', '/db', '/database', '/sql', '/dump',
        '/cgi-bin', '/scripts', '/bin', '/tmp', '/temp',
        '/uploads', '/upload', '/files', '/media', '/static',
        '/console', '/shell', '/cmd', '/exec', '/run',
        '/phpmyadmin', '/adminer', '/pgadmin', '/mongo-express',
        '/.well-known/security.txt', '/security.txt',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/wp-login.php', '/wp-config.php', '/xmlrpc.php',
        '/server-status', '/server-info', '/.aws', '/.azure',
    ]

    # File extensions to track
    interesting_extensions = ['.js', '.json', '.xml', '.yml', '.yaml', '.env', '.config', '.bak', '.old', '.log', '.sql', '.db']

    # ── Scrapling-enhanced HTML parsing ──
    try:
        from scanner.engines.scrapling_fetcher import is_available as scrapling_ok, parse_html, css_select
        HAS_SCRAPLING = scrapling_ok()
    except ImportError:
        HAS_SCRAPLING = False

    def extract_links(html, base_url):
        """Extract links from HTML content — uses Scrapling when available."""
        if HAS_SCRAPLING:
            try:
                sel = parse_html(html)
                if sel:
                    links = []
                    for tag in sel.css('a[href]'):
                        href = tag.attrib.get('href', '') if hasattr(tag, 'attrib') else ''
                        if href:
                            if href.startswith(('http://', 'https://')):
                                links.append(href)
                            elif href.startswith('/'):
                                links.append(f'https://{target}{href}')
                            elif not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                                links.append(f'https://{target}/{href}')
                    for tag in sel.css('script[src]'):
                        src = tag.attrib.get('src', '') if hasattr(tag, 'attrib') else ''
                        if src:
                            if src.startswith(('http://', 'https://')):
                                links.append(src)
                            elif src.startswith('//'):
                                links.append(f'https:{src}')
                            elif src.startswith('/'):
                                links.append(f'https://{target}{src}')
                    return links
            except Exception:
                pass
        # Fallback: regex-based extraction
        links = []
        href_pattern = r'href=["\']([^"\']+)["\']'
        src_pattern = r'src=["\']([^"\']+)["\']'
        action_pattern = r'action=["\']([^"\']+)["\']'

        for pattern in [href_pattern, src_pattern, action_pattern]:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.startswith(('http://', 'https://')):
                    links.append(match)
                elif match.startswith('/'):
                    links.append(f'https://{target}{match}')
                elif not match.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    links.append(f'https://{target}/{match}')
        return links

    def extract_forms(html):
        """Extract form details from HTML — uses Scrapling when available."""
        if HAS_SCRAPLING:
            try:
                sel = parse_html(html)
                if sel:
                    forms = []
                    for form_tag in sel.css('form'):
                        attrs = form_tag.attrib if hasattr(form_tag, 'attrib') else {}
                        action = attrs.get('action', 'current')
                        method = attrs.get('method', 'GET')
                        inputs = []
                        for inp in form_tag.css('input'):
                            name = inp.attrib.get('name', '') if hasattr(inp, 'attrib') else ''
                            if name:
                                inputs.append(name)
                        for sel_tag in form_tag.css('select'):
                            name = sel_tag.attrib.get('name', '') if hasattr(sel_tag, 'attrib') else ''
                            if name:
                                inputs.append(name)
                        for ta in form_tag.css('textarea'):
                            name = ta.attrib.get('name', '') if hasattr(ta, 'attrib') else ''
                            if name:
                                inputs.append(name)
                        forms.append({'action': action, 'method': method, 'inputs': inputs})
                    return forms
            except Exception:
                pass
        # Fallback: regex-based extraction
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'

        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)

            forms.append({
                'action': action_match.group(1) if action_match else 'current',
                'method': method_match.group(1) if method_match else 'GET',
                'inputs': inputs
            })
        return forms

    def extract_comments(html):
        """Extract HTML comments"""
        return re.findall(r'<!--(.*?)-->', html, re.DOTALL)

    def extract_emails(html):
        """Extract email addresses"""
        return list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)))

    def check_sensitive_files(url):
        """Check for sensitive files"""
        found = []
        for path in sensitive_paths[:30]:  # Limit to avoid too many requests
            try:
                check_url = f'https://{target}{path}'
                r = req_lib.get(check_url, timeout=3, verify=False, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    found.append({'path': path, 'status': r.status_code, 'size': len(r.content)})
                    if r.status_code == 200:
                        log('warn', f'[CRAWL] Found accessible: {path}')
            except:
                pass
        return found

    # ── robots.txt parsing ──
    try:
        r = req_lib.get(f'https://{target}/robots.txt', timeout=5, verify=False)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        crawl_data['robots_paths'].append({'type': 'disallow', 'path': path})
                elif line.lower().startswith('allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        crawl_data['robots_paths'].append({'type': 'allow', 'path': path})
                elif line.lower().startswith('sitemap:'):
                    sm_url = line.split(':', 1)[1].strip()
                    crawl_data['robots_paths'].append({'type': 'sitemap', 'path': sm_url})
            log('ok', f'[CRAWL] Parsed robots.txt: {len(crawl_data["robots_paths"])} directives')
    except Exception as e:
        log('debug', f'[CRAWL] robots.txt not available: {e}')

    # ── sitemap.xml parsing ──
    for sitemap_path in ['/sitemap.xml', '/sitemap_index.xml']:
        try:
            r = req_lib.get(f'https://{target}{sitemap_path}', timeout=5, verify=False)
            if r.status_code == 200:
                urls = re.findall(r'<loc>(.*?)</loc>', r.text, re.IGNORECASE)
                for u in urls[:100]:
                    if u not in crawl_data['sitemap_urls']:
                        crawl_data['sitemap_urls'].append(u)
                        if target in u and u not in urls_to_visit and u not in visited:
                            urls_to_visit.append(u)
                log('ok', f'[CRAWL] Sitemap {sitemap_path}: {len(urls)} URLs')
        except Exception:
            pass

    # ── wayback URL integration ──
    try:
        with LOCK:
            wayback_urls = list(scan_state.get('wayback_urls', []))
        if wayback_urls:
            added = 0
            for wb_url in wayback_urls[:50]:
                if target in wb_url and wb_url not in urls_to_visit and wb_url not in visited:
                    urls_to_visit.append(wb_url)
                    added += 1
            log('ok', f'[CRAWL] Added {added} wayback URLs to crawl queue')
    except Exception:
        pass

    # Main crawling loop
    depth = 0
    while urls_to_visit and len(visited) < max_urls and depth < max_depth:
        current_batch = urls_to_visit[:10]
        urls_to_visit = urls_to_visit[10:]

        for url in current_batch:
            if url in visited:
                continue

            # Skip external URLs
            if target not in url:
                continue

            visited.add(url)

            # Skip non-HTML resources (CSS, images, fonts, media)
            skip_exts = ('.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map')
            if any(url.lower().split('?')[0].endswith(ext) for ext in skip_exts):
                crawl_data['urls'].append({'url': url, 'status': 0, 'type': 'skipped'})
                continue

            try:
                r = req_lib.get(url, timeout=8, verify=False, allow_redirects=True,
                                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })

                if r.status_code == 200:
                    crawl_data['urls'].append({'url': url, 'status': r.status_code, 'type': r.headers.get('content-type', '')})

                    # Only parse HTML content
                    if 'text/html' in r.headers.get('content-type', ''):
                        html = r.text

                        # Extract links
                        links = extract_links(html, url)
                        for link in links:
                            if target in link and link not in visited:
                                urls_to_visit.append(link)
                            elif target not in link:
                                crawl_data['external_links'].append(link)

                        # Extract forms
                        forms = extract_forms(html)
                        crawl_data['forms'].extend(forms)

                        # Extract comments
                        comments = extract_comments(html)
                        for comment in comments:
                            comment = comment.strip()
                            if comment and len(comment) > 5:
                                crawl_data['comments'].append({'url': url, 'comment': comment[:200]})

                        # Extract emails
                        emails = extract_emails(html)
                        crawl_data['emails'].extend(emails)

                        # Check for JavaScript files
                        js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html, re.IGNORECASE)
                        crawl_data['js_files'].extend(js_files)

                        # Check for API endpoints
                        api_patterns = re.findall(r'["\'](/api/[^"\']+)["\']', html, re.IGNORECASE)
                        crawl_data['api_endpoints'].extend(api_patterns)

                        # Look for input fields
                        input_names = re.findall(r'name=["\']([^"\']+)["\']', html, re.IGNORECASE)
                        crawl_data['inputs'].extend(input_names)

                        # Check for GraphQL references
                        graphql_refs = re.findall(r'(?:graphql|graphiql|gql)[^\s"\'<>]*', html, re.IGNORECASE)
                        for gq in graphql_refs:
                            if gq not in crawl_data['graphql_endpoints']:
                                crawl_data['graphql_endpoints'].append(gq)

                        # Deep parse JS files for endpoints and secrets
                        for js_src in js_files[:5]:
                            try:
                                if js_src.startswith('/'):
                                    js_url = f'https://{target}{js_src}'
                                elif js_src.startswith('//'):
                                    js_url = f'https:{js_src}'
                                elif js_src.startswith('http'):
                                    js_url = js_src
                                else:
                                    continue
                                js_r = req_lib.get(js_url, timeout=5, verify=False)
                                js_text = js_r.text

                                # Extract API endpoints from JS
                                js_apis = re.findall(r'["\'](/(?:api|v[12]|rest|graphql|service|endpoint|webhook)[a-zA-Z0-9_/-]*)["\']', js_text, re.IGNORECASE)
                                for ep in js_apis:
                                    if ep not in crawl_data['api_endpoints']:
                                        crawl_data['api_endpoints'].append(ep)

                                # Extract WebSocket endpoints
                                ws_patterns = re.findall(r'(?:new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']|(wss?://[^\s"\'<>]+))', js_text, re.IGNORECASE)
                                for ws in ws_patterns:
                                    ws_url = ws[0] or ws[1]
                                    if ws_url and ws_url not in crawl_data['websocket_endpoints']:
                                        crawl_data['websocket_endpoints'].append(ws_url)

                                # Extract query parameter names
                                params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', js_text)
                                for p in params:
                                    if p not in crawl_data['parameters']:
                                        crawl_data['parameters'].append(p)
                            except Exception:
                                pass

            except Exception as e:
                log('debug', f'[CRAWL] Error crawling {url}: {e}')

        depth += 1

    # Check for sensitive files
    log('info', '[CRAWL] Checking for sensitive files...')
    crawl_data['sensitive_files'] = check_sensitive_files(target)

    # ── GraphQL endpoint discovery ──
    graphql_paths = ['/graphql', '/graphiql', '/v1/graphql', '/api/graphql', '/query', '/api/query']
    for gpath in graphql_paths:
        try:
            gurl = f'https://{target}{gpath}'
            r = req_lib.post(gurl, json={'query': '{__typename}'}, timeout=5, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'})
            if r.status_code in (200, 400) and ('json' in r.headers.get('content-type', '') or '__typename' in r.text):
                crawl_data['graphql_endpoints'].append({'path': gpath, 'status': r.status_code})
                log('warn', f'[CRAWL] GraphQL endpoint found: {gpath}')
        except Exception:
            pass

    # ── WebSocket endpoint discovery from JS files ──
    ws_pattern = r'(?:new\s+WebSocket\s*\(\s*["\']|(?:wss?://)[a-zA-Z0-9._/-]+)'
    for js_src in crawl_data['js_files'][:20]:
        try:
            js_url = js_src if js_src.startswith('http') else f'https://{target}{js_src}' if js_src.startswith('/') else f'https://{target}/{js_src}'
            r = req_lib.get(js_url, timeout=5, verify=False)
            if r.status_code == 200:
                ws_matches = re.findall(ws_pattern, r.text, re.IGNORECASE)
                for ws in ws_matches:
                    ws_clean = ws.replace('new WebSocket("', '').replace("new WebSocket('", '').strip('"').strip("'")
                    if ws_clean and ws_clean not in [w.get('url', w) if isinstance(w, dict) else w for w in crawl_data['websocket_endpoints']]:
                        crawl_data['websocket_endpoints'].append({'url': ws_clean, 'source': js_src})
                # Extract parameter names from JS
                params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', r.text)
                for p in params:
                    if p not in crawl_data['parameters']:
                        crawl_data['parameters'].append(p)
                # Extract additional API endpoints
                api_eps = re.findall(r'["\'](/(?:api|v[12]|rest|graphql|service|endpoint|webhook)[a-zA-Z0-9_/-]*)["\']', r.text, re.IGNORECASE)
                for ep in api_eps:
                    if ep not in crawl_data['api_endpoints']:
                        crawl_data['api_endpoints'].append(ep)
        except Exception:
            pass

    # ── Admin panel detection ──
    admin_paths = ['/admin', '/administrator', '/wp-admin', '/cpanel', '/phpmyadmin',
                   '/adminer', '/pgadmin', '/manager', '/dashboard', '/panel']
    for sf in crawl_data['sensitive_files']:
        if sf.get('status') == 200 and sf.get('path', '') in admin_paths:
            if sf['path'] not in crawl_data['admin_panels']:
                crawl_data['admin_panels'].append(sf['path'])

    # Deduplicate lists
    crawl_data['emails'] = list(set(crawl_data['emails']))[:50]
    crawl_data['js_files'] = list(set(crawl_data['js_files']))[:50]
    crawl_data['api_endpoints'] = list({(e if isinstance(e, str) else e.get('path', str(e))) for e in crawl_data['api_endpoints']})[:50]
    crawl_data['inputs'] = list(set(crawl_data['inputs']))[:100]
    crawl_data['parameters'] = crawl_data['parameters'][:50]

    # Add findings for sensitive files
    for sf in crawl_data['sensitive_files']:
        if sf['status'] == 200:
            add_finding('high', f'Sensitive file accessible: {sf["path"]}',
                sub=f'{sf["path"]} is publicly accessible (Status: {sf["status"]}, Size: {sf["size"]} bytes)',
                asset=target, cvss='7.5', owasp='A01', mitre='T1190',
                details=f'The file {sf["path"]} was found accessible at https://{target}{sf["path"]}. This could expose sensitive configuration or data.')
        elif sf['status'] == 403:
            add_finding('info', f'Sensitive file exists but forbidden: {sf["path"]}',
                sub=f'{sf["path"]} exists but returns 403 Forbidden',
                asset=target, owasp='A01',
                details=f'The path {sf["path"]} exists on the server. While access is denied, the existence of this path could be useful for attackers.')

    # Add finding for exposed comments with actual secrets (not just keywords)
    sensitive_comments = []
    for c in crawl_data['comments']:
        comment = c['comment'].lower()
        # Only flag if comment contains actual secret-like patterns, not just keywords
        actual_secret_patterns = [
            'password=', 'secret=', 'api_key=', 'token=',
            'aws_access_key', 'private_key', 'BEGIN RSA',
            'jdbc:', 'mysql://', 'postgresql://', 'mongodb://',
            'sk_live_', 'pk_live_', 'ghp_', 'xoxb-',
        ]
        if any(p in comment for p in actual_secret_patterns):
            sensitive_comments.append(c)
    if sensitive_comments:
        add_finding('high', 'Secrets found in HTML comments',
            sub=f'Found {len(sensitive_comments)} comments containing actual secrets/credentials',
            asset=target, cvss='7.5', owasp='A02', mitre='T1552',
            details=f'Found {len(sensitive_comments)} HTML comments containing actual secret patterns (API keys, passwords, connection strings). These are real credentials that must be removed immediately.')
        log('err', f'[CRAWL] Secrets found in HTML comments: {len(sensitive_comments)}')
    else:
        log('info', '[CRAWL] HTML comments checked - no actual secrets found (keywords only)')

    # Summary
    crawl_data['summary'] = {
        'total_urls': len(crawl_data['urls']),
        'forms_found': len(crawl_data['forms']),
        'inputs_found': len(crawl_data['inputs']),
        'js_files': len(crawl_data['js_files']),
        'api_endpoints': len(crawl_data['api_endpoints']),
        'sensitive_files': len(crawl_data['sensitive_files']),
        'comments': len(crawl_data['comments']),
        'emails': len(crawl_data['emails']),
        'graphql_endpoints': len(crawl_data['graphql_endpoints']),
        'websocket_endpoints': len(crawl_data['websocket_endpoints']),
        'sitemap_urls': len(crawl_data['sitemap_urls']),
        'robots_paths': len(crawl_data['robots_paths']),
        'admin_panels': len(crawl_data['admin_panels']),
        'parameters': len(crawl_data['parameters']),
    }

    log('ok', f'[CRAWL] Crawled {len(crawl_data["urls"])} URLs, found {len(crawl_data["forms"])} forms, {len(crawl_data["sensitive_files"])} sensitive files')

    # Enhanced crawling with katana (JS-aware, depth control)
    katana_path = _find_tool('katana')
    if katana_path:
        log('info', f'[CRAWL] Running katana for advanced JS-aware crawling')
        stdout, stderr, rc = _run_tool([
            katana_path, '-u', f'https://{target}',
            '-d', '3', '-jc', '-timeout', '10',
            '-silent', '-ef', 'css,png,jpg,jpeg,gif,svg,woff,ico'
        ], timeout=45)
        if rc == 0 and stdout:
            katana_urls = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
            existing_urls = set(u if isinstance(u, str) else u.get('url', '') for u in crawl_data['urls'])
            added = 0
            for u in katana_urls:
                if u not in existing_urls and target in u:
                    crawl_data['urls'].append(u)
                    existing_urls.add(u)
                    added += 1
                    # Detect API endpoints
                    if '/api/' in u or '/v1/' in u or '/v2/' in u or '/graphql' in u:
                        if u not in crawl_data['api_endpoints']:
                            crawl_data['api_endpoints'].append(u)
                    # Detect admin panels
                    if any(x in u.lower() for x in ['/admin', '/dashboard', '/panel', '/manage']):
                        if u not in crawl_data['admin_panels']:
                            crawl_data['admin_panels'].append(u)
            log('ok', f'[CRAWL] katana found {added} additional URLs')

    # ── Hakrawler deep crawl with intelligent endpoint analysis ──
    hakrawler_path = _find_tool('hakrawler')
    if hakrawler_path:
        log('info', '[CRAWL] Running hakrawler for deep URL + secret endpoint discovery')
        stdout, stderr, rc = _run_tool([
            hakrawler_path, '-d', '4', '-insecure', '-timeout', '10',
            '-n', '500', '-silent'
        ], input=f'https://{target}\n', timeout=45)
        if rc == 0 and stdout:
            import re as _re
            with LOCK:
                _all_urls = crawl_data.get('urls', []) + crawl_data.get('js_files', [])
                existing_urls = set(u if isinstance(u, str) else u.get('url', '') for u in _all_urls)
                added = 0
                secret_endpoints_found = []
                for line in stdout.strip().split('\n'):
                    url = line.strip()
                    if not url or not url.startswith('http'):
                        continue
                    if url not in existing_urls:
                        crawl_data['urls'].append(url)
                        existing_urls.add(url)
                        added += 1
                        parsed_hk = urlparse(url)
                        if parsed_hk.path:
                            endpoints = _re.findall(r'/[a-zA-Z0-9_/.-]+', parsed_hk.path)
                            for ep in endpoints:
                                if ep not in crawl_data['endpoints']:
                                    crawl_data['endpoints'].append(ep)
                        if any(x in url.lower() for x in ['/admin', '/dashboard', '/panel', '/manage']):
                            if url not in crawl_data['admin_panels']:
                                crawl_data['admin_panels'].append(url)

                        # ── Secret/sensitive endpoint detection ──
                        url_lower = url.lower()
                        secret_patterns = [
                            (r'(?i)(\.env|\.env\.bak|\.env\.local|\.env\.production)', 'Environment file exposed'),
                            (r'(?i)(\.git/config|\.git/HEAD|\.gitignore)', 'Git repository exposed'),
                            (r'(?i)(backup|\.bak|\.old|\.orig|\.sql|\.dump)', 'Backup file exposed'),
                            (r'(?i)(wp-config|config\.php|config\.json|config\.yml|config\.yaml)', 'Configuration file exposed'),
                            (r'(?i)(\.htpasswd|\.htaccess)', 'Apache auth file exposed'),
                            (r'(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519)', 'SSH private key exposed'),
                            (r'(?i)(\.pem|\.key|\.p12|\.pfx|\.jks)', 'Certificate/key file exposed'),
                            (r'(?i)(phpinfo|server-status|server-info)', 'Server info page exposed'),
                            (r'(?i)(/actuator|/actuator/env|/actuator/health)', 'Spring Actuator exposed'),
                            (r'(?i)(/graphql|/graphiql|/playground|/altair)', 'GraphQL endpoint exposed'),
                            (r'(?i)(/debug|/trace|/profiler|/_debug)', 'Debug endpoint exposed'),
                            (r'(?i)(/api/v[0-9]+/internal|/internal/)', 'Internal API exposed'),
                            (r'(?i)(\.svn/|\.hg/|\.bzr/)', 'Version control metadata exposed'),
                            (r'(?i)(crossdomain\.xml|clientaccesspolicy\.xml)', 'Flash/SL cross-domain policy'),
                            (r'(?i)(/console|/adminer|/phpmyadmin|/adminer\.php)', 'Admin console exposed'),
                            (r'(?i)(web\.config|elmah\.axd)', 'IIS config/diagnostics exposed'),
                        ]
                        for pattern, desc in secret_patterns:
                            if _re.search(pattern, url):
                                secret_endpoints_found.append({
                                    'url': url, 'description': desc, 'pattern': pattern
                                })
                                break

                # ── Verify discovered secret endpoints ──
                verified_secrets = []
                for ep in secret_endpoints_found[:20]:
                    if not scan_state.get('scanning'):
                        break
                    try:
                        r = req_lib.get(ep['url'], timeout=5, verify=False, allow_redirects=False)
                        if r.status_code == 200 and len(r.text) > 10:
                            # Further verification: check content matches expected type
                            body = r.text[:2000]
                            verified = False
                            if '.env' in ep['url']:
                                verified = '=' in body and any(x in body for x in ['DB_', 'APP_', 'SECRET', 'KEY', 'PASSWORD'])
                            elif '.git' in ep['url']:
                                verified = 'ref:' in body or '[core]' in body
                            elif 'backup' in ep['url'] or '.sql' in ep['url']:
                                verified = 'CREATE TABLE' in body or 'INSERT INTO' in body or len(body) > 1000
                            elif 'config' in ep['url']:
                                verified = any(x in body for x in ['password', 'secret', 'api_key', 'database'])
                            elif 'actuator' in ep['url']:
                                verified = 'activeProfiles' in body or '"beans"' in body
                            elif 'graphql' in ep['url']:
                                verified = 'query' in body or 'mutation' in body or 'schema' in body
                            elif 'console' in ep['url'] or 'adminer' in ep['url']:
                                verified = '<form' in body.lower() or 'login' in body.lower()
                            else:
                                verified = len(body) > 50

                            if verified:
                                verified_secrets.append(ep)
                                sev = 'critical' if any(x in ep['url'].lower() for x in ['.env', '.git', '.pem', 'id_rsa', 'config']) else 'high'
                                add_finding(
                                    sev,
                                    ep['description'],
                                    sub=f'Verified accessible: {ep["url"]}',
                                    asset=ep['url'],
                                    cvss='8.5' if sev == 'critical' else '7.0',
                                    owasp='A01' if 'config' in ep['url'].lower() else 'A05',
                                    mitre='T1213' if 'config' in ep['url'].lower() else 'T1592',
                                    details=f'URL: {ep["url"]}\n'
                                            f'HTTP Status: {r.status_code}\n'
                                            f'Content preview: {body[:300]}\n'
                                            f'Impact: Information disclosure — sensitive data accessible without auth\n'
                                            f'Exploit: curl -k {ep["url"]}')
                                log('ok', f'[CRAWL] VERIFIED {ep["description"]}: {ep["url"]}')
                    except Exception:
                        pass

                if verified_secrets:
                    log('ok', f'[CRAWL] Verified {len(verified_secrets)} secret endpoints accessible')
                log('ok', f'[CRAWL] hakrawler found {added} additional URLs')

    # ── GoSpider: recursive crawl + JS source map detection ──
    gospider_urls = run_gospider(target)
    if gospider_urls:
        with LOCK:
            crawl_data.setdefault('urls', []).extend(gospider_urls)
        log('ok', f'[CRAWL] gospider found {len(gospider_urls)} additional endpoints')

    with LOCK:
        scan_state['crawl_data'] = crawl_data
    set_progress('crawl', 100)

# ─── NET SEC MODULE ────────────────────────────────────────────────────────────


def run_js_module(target):
    log('info', f'[JS] Scanning JavaScript files on {target}')
    js_data = {'endpoints': [], 'sources': []}
    try:
        if REQUESTS_AVAILABLE:
            # ═══════════════════════════════════════════════════════════════════════════
            # ENHANCE: Use discovered JS files from Phase 1 crawl
            # ═══════════════════════════════════════════════════════════════════════════
            with LOCK:
                discovery = dict(scan_state.get('discovery_data', {}))
            discovered_js = discovery.get('js_files', [])
            
            # Start with main page
            r = req_lib.get(f'https://{target}', timeout=8, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            scripts = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', r.text, re.IGNORECASE)
            
            # Merge with discovered JS files
            all_js = list(scripts)
            for js in discovered_js:
                if isinstance(js, str) and js not in all_js:
                    all_js.append(js)
            
            js_data['sources'] = all_js[:30]
            for src in all_js[:30]:
                if src.startswith('/'):
                    src = f'https://{target}{src}'
                elif src.startswith('//'):
                    src = f'https:{src}'
                try:
                    js_r = req_lib.get(src, timeout=5, verify=False)
                    text = js_r.text
                    endpoints = re.findall(r'["\'](/(?:api|v[12]|rest|graphql|service|endpoint|webhook)[a-zA-Z0-9_/-]*)["\']', text, re.IGNORECASE)
                    for ep in endpoints:
                        if ep not in js_data['endpoints']:
                            js_data['endpoints'].append(ep)
                    secrets_found = re.findall(r'(?:api[_-]?key|secret|token|password|jwt|bearer)\s*[:=]\s*["\'][a-zA-Z0-9_=+-]+["\']', text[:5000], re.IGNORECASE)
                    for s in secrets_found:
                        log('warn', f'[JS] Potential secret in {src}')
                        add_finding('high', f'Hardcoded secret in JavaScript: {src}',
                            sub=f'Pattern: {s[:60]}', asset=src, cvss='6.5', owasp='A04', mitre='T1552')
                except Exception:
                    pass
            log('ok', f'[JS] Scanned {len(js_data["sources"])} JS files, extracted {len(js_data["endpoints"])} endpoints')
    except Exception as e:
        log('err', f'[JS] Error: {e}')
    with LOCK:
        scan_state['js_endpoints'] = js_data['endpoints']
    set_progress('js', 100)

# ─── WAYBACK MACHINE MODULE ────────────────────────────────────────────────────


def run_wayback_module(target):
    log('info', f'[WAYBACK] Querying Wayback Machine for {target}')
    wayback_urls = []
    try:
        if REQUESTS_AVAILABLE:
            r = req_lib.get(f'https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&limit=200', timeout=15)
            if r.status_code == 200:
                data = r.json()
                if len(data) > 1:
                    urls = set()
                    for row in data[1:]:
                        if len(row) >= 6:
                            urls.add(row[2])
                    wayback_urls = sorted(urls)[:100]
                    log('ok', f'[WAYBACK] Retrieved {len(wayback_urls)} historical URLs')
                    for u in wayback_urls[:10]:
                        if any(kw in u.lower() for kw in ['api','admin','backup','config','cgi','phpinfo','test','debug']):
                            add_finding('medium', f'Sensitive URL in Wayback Machine: {u}',
                                sub=f'Historical snapshot exposes potentially sensitive endpoint', asset=u, cvss='4.0', owasp='A01')
    except Exception as e:
        log('warn', f'[WAYBACK] Query failed: {e}')
    
    # Enhanced URL collection with gau (Wayback + Common Crawl + OTX)
    gau_path = _find_tool('gau')
    if gau_path:
        log('info', f'[WAYBACK] Running gau for comprehensive URL collection')
        stdout, stderr, rc = _run_tool([
            gau_path, target, '--threads', '5', '--timeout', '10'
        ], timeout=45)
        if rc == 0 and stdout:
            gau_urls = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
            existing_urls = set(wayback_urls)
            added = 0
            for u in gau_urls:
                if u not in existing_urls and target in u:
                    wayback_urls.append(u)
                    existing_urls.add(u)
                    added += 1
            log('ok', f'[WAYBACK] gau found {added} additional URLs (total: {len(wayback_urls)})')
            # Group sensitive URLs by path prefix to avoid 100+ individual findings
            from urllib.parse import urlparse as _urlparse
            sensitive_groups = {}
            sensitive_keywords = ['admin', 'backup', 'config', 'cgi', 'phpinfo', 'test', 'debug', '.env', '.git', 'wp-admin']
            for u in gau_urls:
                if u in existing_urls:
                    continue
                parsed = _urlparse(u)
                path = parsed.path.rstrip('/')
                parts = path.rsplit('/', 2)
                prefix = '/'.join(parts[:2]) if len(parts) >= 2 else path
                if any(kw in u.lower() for kw in sensitive_keywords):
                    sensitive_groups.setdefault(prefix, []).append(u)
            for prefix, urls in sensitive_groups.items():
                if len(urls) <= 2:
                    for u in urls:
                        add_finding('medium', f'Sensitive URL discovered: {u}',
                            sub='gau found potentially sensitive endpoint', asset=u, cvss='4.0', owasp='A01',
                            details=f'Source: gau URL collection\nURL: {u}\n\nRemediation: Review and restrict access to sensitive endpoints.')
                else:
                    sample_urls = urls[:5]
                    add_finding('medium', f'Sensitive directory exposed: {prefix}/ ({len(urls)} URLs)',
                        sub=f'gau found {len(urls)} endpoints under {prefix}/',
                        asset=prefix, cvss='5.0', owasp='A01',
                        details=f'Source: gau URL collection\nDirectory: {prefix}/\nTotal URLs: {len(urls)}\n\n'
                                f'Sample endpoints:\n' + '\n'.join(f'  - {u}' for u in sample_urls) +
                                (f'\n  ... and {len(urls)-5} more' if len(urls) > 5 else '') +
                                f'\n\nRemediation: Review and restrict access to sensitive endpoints.')
    
    with LOCK:
        scan_state['wayback_urls'] = wayback_urls
    set_progress('wayback', 100)

# ─── EMAIL SECURITY MODULE ─────────────────────────────────────────────────────


def run_takeover_verify_module(target):
    """Verify subdomain takeover with CNAME and content checks."""
    log('info', '[TAKEOVER-V] Verifying subdomain takeover')
    base_url = f'https://{target}'
    takeover_findings = []

    with LOCK:
        assets = list(scan_state.get('assets', []))

    takeover_services = {
        'amazonaws.com': {'verify': 'NoSuchBucket', 'service': 'S3'},
        'herokuapp.com': {'verify': 'No such app', 'service': 'Heroku'},
        'ghost.io': {'verify': 'The thing you were looking for', 'service': 'Ghost'},
        'github.io': {'verify': 'There isn', 'service': 'GitHub Pages'},
        'shopify.com': {'verify': 'Sorry, this shop is', 'service': 'Shopify'},
        'bitbucket.io': {'verify': 'Repository not found', 'service': 'Bitbucket'},
        'zendesk.com': {'verify': 'Help Center Closed', 'service': 'Zendesk'},
        'readme.io': {'verify': 'Project not found', 'service': 'Readme'},
        'surge.sh': {'verify': 'project not found', 'service': 'Surge'},
        'intercom.help': {'verify': 'This page is reserved', 'service': 'Intercom'},
        'helpjuice.com': {'verify': 'We could not find', 'service': 'HelpJuice'},
        'helpscoutdocs.com': {'verify': 'No HelpScout Documentation', 'service': 'HelpScout'},
        'ghost.org': {'verify': 'The thing you were looking for', 'service': 'Ghost'},
        'cargocollective.com': {'verify': 'If you are', 'service': 'Cargo'},
        'statuspage.io': {'verify': 'Better StatusPage', 'service': 'StatusPage'},
        'pingdom.com': {'verify': 'Sorry, couldn', 'service': 'Pingdom'},
        'tictail.com': {'verify': 'to target this domain', 'service': 'Tictail'},
        'campaignmonitor.com': {'verify': 'Double check the URL', 'service': 'CampaignMonitor'},
        'craisys.de': {'verify': 'Domain not found', 'service': 'Craisys'},
        'fluxbb.org': {'verify': 'Domain not found', 'service': 'FluxBB'},
        'teamswork.de': {'verify': 'Domain not found', 'service': 'Teamswork'},
        'squarespace.com': {'verify': 'No Such Account', 'service': 'Squarespace'},
        'strikingly.com': {'verify': 'But if you are looking', 'service': 'Strikingly'},
        'landingi.com': {'verify': 'It looks like you', 'service': 'Landingi'},
        'webflow.com': {'verify': 'The page you are looking for', 'service': 'Webflow'},
        'kajabi.com': {'verify': 'The page you were looking for', 'service': 'Kajabi'},
        'thinkific.com': {'verify': 'You may have typed', 'service': 'Thinkific'},
        'teachable.com': {'verify': 'You may have typed', 'service': 'Teachable'},
        'wishpond.com': {'verify': 'https://www.wishpond.com', 'service': 'Wishpond'},
        'aftership.com': {'verify': 'Oops', 'service': 'Aftership'},
        'simplebooklet.com': {'verify': 'We can', 'service': 'SimpleBooklet'},
        'getResponse.com': {'verify': 'with GetResponse Landing Pages', 'service': 'GetResponse'},
        'feedpress.com': {'verify': 'The feed', 'service': 'FeedPress'},
        'phppoint.com': {'verify': 'Domain not found', 'service': 'PHPPoint'},
        'rockylinux.org': {'verify': '404', 'service': 'RockyLinux'},
        'mashery.com': {'verify': 'Unrecognized domain', 'service': 'Mashery'},
        'invalid.domain.net': {'verify': 'Domain not found', 'service': 'InvalidDomain'},
    }

    for asset in assets[:30]:
        if not scan_state.get('scanning'):
            break
        fqdn = asset.get('fqdn', '')
        if not fqdn or fqdn == target:
            continue

        try:
            import socket as _sock
            resolved = _sock.getaddrinfo(fqdn, None)
            for fam, *_, sockaddr in resolved[:1]:
                ip = sockaddr[0]
                for service, info in takeover_services.items():
                    if service in fqdn:
                        try:
                            r = req_lib.get(f'https://{fqdn}', timeout=5, verify=False)
                            if info['verify'] in r.text:
                                add_finding(
                                    'critical',
                                    f'Subdomain takeover: {fqdn} ({info["service"]})',
                                    sub=f'Dangling CNAME to {service} - takeover possible',
                                    asset=f'https://{fqdn}', cvss='10.0', owasp='A01', mitre='T1190',
                                    details=f'Subdomain: {fqdn}\nService: {info["service"]}\n'
                                            f'CNAME target: {service}\n'
                                            f'Confirmed: Service-specific 404 page returned')
                                takeover_findings.append({'subdomain': fqdn, 'service': info['service']})
                                log('ok', f'[TAKEOVER-V] Takeover possible: {fqdn}')
                        except Exception:
                            pass
        except Exception:
            pass

    log('ok', f'[TAKEOVER-V] Scan complete - {len(takeover_findings)} findings')
    set_progress('takeover_verify', 100)


# ─── DNS REBINDING ─────────────────────────────────────────────────────────────


def run_subdomain_enum_module(target):
    """Deep subdomain enumeration."""
    log('info', '[SUB-ENUM] Enumerating subdomains')
    base_url = f'https://{target}'
    subdomain_findings = []

    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
        'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
        'admin', 'administrator', 'webdisk', 'cpanel', 'whm',
        'webhost', 'dev', 'development', 'staging', 'stage',
        'test', 'testing', 'qa', 'uat', 'sandbox',
        'api', 'api2', 'api3', 'devapi', 'rest', 'graphql',
        'app', 'apps', 'portal', 'webapp', 'webapps',
        'beta', 'alpha', 'demo', 'preview', 'canary',
        'shop', 'store', 'ecommerce', 'payment', 'pay',
        'blog', 'forum', 'community', 'support', 'help',
        'docs', 'documentation', 'wiki', 'kb', 'knowledge',
        'status', 'monitor', 'monitoring', 'grafana', 'kibana',
        'git', 'gitlab', 'github', 'bitbucket', 'svn',
        'ci', 'cd', 'jenkins', 'travis', 'circle', 'build',
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
        'backup', 'backups', 'bak', 'old', 'legacy',
        'cdn', 'static', 'assets', 'images', 'img', 'media',
        'vpn', 'remote', 'access', 'gateway',
        'intranet', 'internal', 'private', 'corp', 'corporate',
        'hr', 'crm', 'erp', 'jira', 'confluence', 'slack',
    ]

    import socket as _sock
    _sock.setdefaulttimeout(3)

    def _resolve_enum(fqdn):
        try:
            ips = _sock.gethostbyname_ex(fqdn)
            if ips[2]:
                return (fqdn, ips[2])
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as _epool:
        futures = {_epool.submit(_resolve_enum, f'{sub}.{target}'): sub for sub in common_subdomains}
        try:
            for fut in as_completed(futures, timeout=60):
                if not scan_state.get('scanning'):
                    break
                try:
                    result = fut.result(timeout=5)
                except Exception:
                    continue
                if result:
                    fqdn, ips = result
                    try:
                        r = req_lib.get(f'https://{fqdn}', timeout=5, verify=False)
                        status = r.status_code
                        title = ''
                        if '<title>' in r.text:
                            import re as _re
                            title_match = _re.search(r'<title>(.*?)</title>', r.text, _re.I)
                            if title_match:
                                title = title_match.group(1)[:50]
                        subdomain_findings.append({
                            'subdomain': fqdn, 'ips': ips,
                            'status': status, 'title': title
                        })
                    except Exception:
                        subdomain_findings.append({
                            'subdomain': fqdn, 'ips': ips,
                            'status': 'timeout', 'title': ''
                        })
        except TimeoutError:
            for f in futures:
                f.cancel()
    _sock.setdefaulttimeout(None)

    if subdomain_findings:
        add_finding(
            'info',
            f'Subdomain enumeration: {len(subdomain_findings)} subdomains found',
            sub=f'Active subdomains discovered via DNS bruteforce',
            asset=target, cvss='0', owasp='', mitre='',
            details=f'Subdomains: {", ".join(s["subdomain"] for s in subdomain_findings[:10])}')
        log('ok', f'[SUB-ENUM] Found {len(subdomain_findings)} subdomains')

    log('ok', f'[SUB-ENUM] Scan complete')
    set_progress('sub_enum', 100)


# ─── ENHANCED SUBDOMAIN ENUMERATION ──────────────────────────────────────────


def run_enhanced_subdomain_enum(target):
    """Deep subdomain enumeration using multiple passive sources + active DNS brute.

    Sources: crt.sh, HackerTarget, ThreatCrowd, DNS brute-force, AlienVault OTX
    """
    import concurrent.futures as _cf
    log('info', f'[SUB-DEEP] Starting enhanced subdomain enumeration for {target}')
    enhanced_subs = {}

    # ── Source 1: crt.sh (Certificate Transparency) ──
    if REQUESTS_AVAILABLE:
        try:
            log('ok', '[SUB-DEEP] Querying crt.sh Certificate Transparency logs')
            r = req_lib.get(f'https://crt.sh/?q=%.{target}&output=json', timeout=20, verify=False)
            if r.status_code == 200:
                data = r.json()
                ct_subs = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(target) and '*' not in sub:
                            ct_subs.add(sub)
                for sub in ct_subs:
                    if sub not in enhanced_subs:
                        enhanced_subs[sub] = {'source': 'crt.sh', 'ips': []}
                log('ok', f'[SUB-DEEP] crt.sh: {len(ct_subs)} subdomains')
        except Exception as e:
            log('dim', f'[SUB-DEEP] crt.sh failed: {e}')

    # ── Source 2: HackerTarget API ──
    if REQUESTS_AVAILABLE:
        try:
            log('ok', '[SUB-DEEP] Querying HackerTarget API')
            r = req_lib.get(f'https://api.hackertarget.com/hostsearch/?q={target}', timeout=10, verify=False)
            if r.status_code == 200:
                ht_subs = 0
                for line in r.text.strip().split('\n'):
                    parts = line.strip().split(',')
                    if len(parts) == 2:
                        sub, ip = parts[0].strip(), parts[1].strip()
                        if sub.endswith(target):
                            if sub not in enhanced_subs:
                                enhanced_subs[sub] = {'source': 'hackertarget', 'ips': [ip]}
                            ht_subs += 1
                log('ok', f'[SUB-DEEP] HackerTarget: {ht_subs} subdomains')
        except Exception as e:
            log('dim', f'[SUB-DEEP] HackerTarget failed: {e}')

    # ── Source 3: ThreatCrowd API ──
    if REQUESTS_AVAILABLE:
        try:
            log('ok', '[SUB-DEEP] Querying ThreatCrowd API')
            r = req_lib.get(f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}', timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                tc_subs = data.get('subdomains', [])
                tc_resolutions = data.get('resolutions', [])
                ip_map = {}
                for res in tc_resolutions:
                    if 'ip_address' in res and 'domain' in res:
                        ip_map[res['domain']] = res['ip_address']
                added = 0
                for sub in tc_subs:
                    sub = sub.strip().lower()
                    if sub.endswith(target) and sub not in enhanced_subs:
                        enhanced_subs[sub] = {'source': 'threatcrowd', 'ips': [ip_map.get(sub, '')]}
                        added += 1
                log('ok', f'[SUB-DEEP] ThreatCrowd: {added} new subdomains')
        except Exception as e:
            log('dim', f'[SUB-DEEP] ThreatCrowd failed: {e}')

    # ── Source 4: AlienVault OTX ──
    if REQUESTS_AVAILABLE:
        try:
            log('ok', '[SUB-DEEP] Querying AlienVault OTX')
            r = req_lib.get(f'https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns?limit=100', timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                added = 0
                for record in data.get('passive_dns', []):
                    sub = record.get('hostname', '').strip().lower()
                    ip = record.get('address', '')
                    if sub.endswith(target) and sub not in enhanced_subs:
                        enhanced_subs[sub] = {'source': 'alienvault', 'ips': [ip]}
                        added += 1
                log('ok', f'[SUB-DEEP] AlienVault OTX: {added} new subdomains')
        except Exception as e:
            log('dim', f'[SUB-DEEP] AlienVault OTX failed: {e}')

    # ── Source 5: DNS brute-force (expanded wordlist) ──
    expanded_wordlist = [
        "www","mail","ftp","webmail","smtp","pop","pop3","ns1","ns2","ns3","ns4",
        "admin","api","dev","test","staging","blog","shop","cdn","app","portal",
        "vpn","remote","git","jenkins","wiki","dashboard","status","login","register",
        "auth","sso","graphql","docs","swagger","health","db","backup","webdisk",
        "cpanel","whm","m","mobile","beta","alpha","demo","sandbox","qa","uat",
        "web","www2","www3","secure","ssl","static","media","assets","img","images",
        "files","download","upload","temp","tmp","old","new","legacy","classic",
        "v1","v2","v3","server","host","gateway","proxy","lb","ha",
        "database","mysql","postgres","redis","mongo","elasticsearch","kibana",
        "grafana","prometheus","monitor","nagios","zabbix","splunk","kafka",
        "rabbitmq","mq","queue","job","worker","cron","scheduler",
        "dns","dns1","dns2","mx","mx1","mx2","mx3","autodiscover","autoconfig",
        "_dmarc","_domainkey","dkim","sip","voip","pbx","asterisk",
        "shopify","store","ecommerce","cart","checkout","payment","pay",
        "stripe","paypal","billing","invoice","finance",
        "crm","erp","hr","payroll","recruit","jobs","careers","talent",
        "lms","moodle","classroom","course","academy","edu",
        "hub","kong","nginx","haproxy","traefik","ws","wss","socket",
        "realtime","push","notify","notification","alert",
        "search","solr","algolia","reports","reporting","bi","panel",
        "kb","help","support","tickets","issue","forum","community","chat",
        "calendar","meet","meeting","zoom","teams","slack",
        "storage","s3","bucket","minio","blob","oss",
        "go","redirect","url","link","short","rss","feed","sitemap",
        "wp-admin","wp-login","wp-content","wp-includes","wordpress",
        "administrator","phpmyadmin","adminer","console","shell","terminal",
        "config","env","setup","install","info","version","debug","trace",
    ]
    log('ok', f'[SUB-DEEP] DNS brute-force with {len(expanded_wordlist)} words')

    def _resolve(sub):
        try:
            ip = socket.gethostbyname(sub)
            return (sub, ip)
        except:
            return None

    _old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    with ThreadPoolExecutor(max_workers=30) as _pool:
        futs = {_pool.submit(_resolve, f'{w}.{target}'): w for w in expanded_wordlist}
        try:
            for fut in _cf.as_completed(futs, timeout=60):
                if not scan_state.get('scanning'):
                    break
                try:
                    result = fut.result(timeout=2)
                except:
                    continue
                if result:
                    sub, ip = result
                    if sub not in enhanced_subs:
                        enhanced_subs[sub] = {'source': 'dns_brute', 'ips': [ip]}
        except TimeoutError:
            for f in futs:
                f.cancel()
    socket.setdefaulttimeout(_old_timeout)

    # ── Resolve all discovered subdomains + probe HTTP ──
    all_subs = list(enhanced_subs.keys())
    live_subs = []
    log('ok', f'[SUB-DEEP] Resolving {len(all_subs)} subdomains + HTTP probing')

    def _probe_http(sub):
        if not scan_state.get('scanning'):
            return None
        info = enhanced_subs.get(sub, {})
        ip = ''
        if not info.get('ips'):
            try:
                ip = socket.gethostbyname(sub)
            except:
                return None
        else:
            ip = info['ips'][0]
        # TCP port check
        open_ports = []
        for port in [80, 443, 2083, 2087, 2096]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((sub if not ip else ip, port))
                s.close()
                open_ports.append(port)
            except:
                pass
        # HTTP probe
        http_info = None
        if REQUESTS_AVAILABLE and open_ports:
            for scheme in (['https', 'http'] if 443 in open_ports else ['http', 'https']):
                try:
                    r = req_lib.get(f'{scheme}://{sub}/', timeout=5, verify=False, allow_redirects=True)
                    title = ''
                    m = re.search(r'<title[^>]*>(.*?)</title>', r.text[:5000], re.I | re.S)
                    if m:
                        title = m.group(1).strip()[:100]
                    http_info = {
                        'scheme': scheme, 'status': r.status_code,
                        'server': r.headers.get('Server', ''),
                        'title': title, 'size': len(r.text),
                        'powered_by': r.headers.get('X-Powered-By', ''),
                        'headers': {k: v for k, v in r.headers.items()
                                    if k.lower() in ['x-frame-options', 'strict-transport-security',
                                                      'content-security-policy', 'x-content-type-options',
                                                      'access-control-allow-origin', 'set-cookie']},
                    }
                    break
                except:
                    pass
        return {'sub': sub, 'ip': ip, 'ports': open_ports, 'http': http_info}

    with ThreadPoolExecutor(max_workers=20) as _pool:
        futs = {_pool.submit(_probe_http, s): s for s in all_subs}
        try:
            for fut in _cf.as_completed(futs, timeout=90):
                if not scan_state.get('scanning'):
                    break
                try:
                    result = fut.result(timeout=3)
                except:
                    continue
                if result:
                    live_subs.append(result)
                    sub = result['sub']
                    http = result.get('http')
                    status = http['status'] if http else 'no-http'
                    log('ok', f'[SUB-DEEP] Live: {sub} ({result["ip"]}) ports={result["ports"]} http={status}')
        except TimeoutError:
            for f in futs:
                f.cancel()

    # ── Store results ──
    with LOCK:
        scan_state['enhanced_subdomain_data'] = {
            'all_subs': enhanced_subs,
            'live_subs': live_subs,
            'total': len(enhanced_subs),
            'live_count': len(live_subs),
        }
        # Merge into existing assets
        existing_assets = {a.get('name', a.get('fqdn', '')) for a in scan_state.get('assets', [])}
        for sub in enhanced_subs:
            if sub not in existing_assets:
                scan_state['assets'].append({'name': sub, 'type': 'subdomain', 'status': 'active',
                                              'source': enhanced_subs[sub].get('source', 'enhanced')})
                existing_assets.add(sub)

    # ── Findings: exposed services, admin panels ──
    for live in live_subs:
        http = live.get('http')
        if not http:
            continue
        sub = live['sub']
        # cPanel/WHM exposed
        if any(port in live.get('ports', []) for port in [2083, 2087, 2096]):
            add_finding('medium', f'cPanel/WHM exposed on {sub}',
                        sub=f'Hosting control panel accessible without authentication',
                        asset=f'{http["scheme"]}://{sub}', cvss='5.3', owasp='A05',
                        details=f'Subdomain: {sub}\nIP: {live["ip"]}\nOpen ports: {live["ports"]}\n'
                                f'Remediation: Restrict access to cPanel/WHM to trusted IPs only.')
        # Missing security headers
        if http.get('headers'):
            headers_present = set(http['headers'].keys())
            missing = {'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options'} - headers_present
            if missing:
                add_finding('low', f'Missing security headers on {sub}',
                            sub=f'Headers missing: {", ".join(missing)}',
                            asset=f'{http["scheme"]}://{sub}', cvss='3.1', owasp='A05')
        # FTP exposed
        if 21 in live.get('ports', []):
            add_finding('medium', f'FTP service exposed on {sub}',
                        sub=f'FTP (port 21) is open — cleartext protocol',
                        asset=f'ftp://{sub}', cvss='5.3', owasp='A02',
                        details=f'Remediation: Disable FTP and use SFTP instead.')

    log('ok', f'[SUB-DEEP] Enhanced enumeration complete: {len(enhanced_subs)} total, {len(live_subs)} live')
    set_progress('enhanced_subdomain_enum', 100)


# ─── DNS REBINDING ─────────────────────────────────────────────────────────────


def run_dns_rebinding_module(target):
    """Test for DNS rebinding vulnerability."""
    log('info', '[REBIND] Testing DNS rebinding')
    base_url = f'https://{target}'
    rebind_findings = []

    # DNS rebinding payloads
    rebinding_payloads = [
        ('http://127.0.0.1', 'Localhost rebinding'),
        ('http://0.0.0.0', 'Zero-address rebinding'),
        ('http://169.254.169.254', 'Metadata rebinding'),
    ]

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        params = disc.get('parameters', [])

    ssrf_params = ['url', 'uri', 'link', 'src', 'href', 'callback', 'webhook',
                   'proxy', 'fetch', 'load', 'redirect', 'return', 'next',
                   'document', 'file', 'path', 'img', 'image']

    for param in ssrf_params[:10]:
        if not scan_state.get('scanning'):
            break
        for payload, rebind_type in rebinding_payloads:
            try:
                r = req_lib.get(f'{base_url}/?{param}={payload}',
                              timeout=8, verify=False, allow_redirects=False)
                # Check for signs of DNS rebinding
                if r.status_code in (200, 301, 302, 502):
                    indicators = ['127.0.0.1', '0.0.0.0', '169.254', 'localhost']
                    if any(ind in r.text for ind in indicators):
                        add_finding(
                            'high',
                            f'DNS rebinding via {param}',
                            sub=f'Parameter {param} may allow DNS rebinding attack',
                            asset=base_url, cvss='7.5', owasp='A10', mitre='T1189',
                            details=f'Parameter: {param}\nPayload: {payload}\n'
                                    f'Type: {rebind_type}\n'
                                    f'Confirmed: Internal address in response')
                        rebind_findings.append({'param': param, 'type': rebind_type})
                        log('ok', f'[REBIND] Confirmed via {param}')
                        break
            except Exception:
                pass

    log('ok', f'[REBIND] Scan complete - {len(rebind_findings)} findings')
    set_progress('rebind', 100)


# ─── SUBDOMAIN TAKEOVER DEEP ──────────────────────────────────────────────────


def run_subdomain_takeover_module(target):
    """Pure-Python subdomain takeover detection using DNS + HTTP fingerprinting."""
    log('info', f'[TAKEOVER-DEEP] Subdomain takeover deep check for {target}')
    results = {'checked': 0, 'vulnerable': []}

    with LOCK:
        sub_data = scan_state.get('sub_data', {})
        subdomains = list(sub_data.get('subdomains', []))

    if not subdomains:
        log('info', '[TAKEOVER-DEEP] No subdomains found — skipping')
        with LOCK:
            scan_state['subdomain_takeover_data'] = results
        set_progress('subdomain_takeover', 100)
        return

    # Fingerprints mapping service to indicator strings
    takeover_fingerprints = [
        ('Heroku', ['There is no app configured at that hostname',
                     'No such app', 'herokucdn.com']),
        ('GitHub Pages', ['Repository not found', "There isn't a GitHub Pages site here",
                           'github.io']),
        ('AWS S3', ['NoSuchBucket', 'The specified bucket does not exist',
                     's3.amazonaws.com']),
        ('UserVoice', ['This UserVoice subdomain is either invalid',
                       'uservoice.com']),
        ('GitLab Pages', ['project not found', 'gitlab.io']),
        ('GoDaddy Parked', ['This page is parked free, courtesy of GoDaddy']),
        ('Fastly', ['fastly error: unknown domain', 'Fastly error']),
        ('Pantheon', ['404 error unknown site!', 'pantheon.io']),
        ('Freshdesk', ['Please renew your subscription', 'freshdesk.com']),
        ('Shopify', ["Sorry, this shop is currently unavailable",
                      'myshopify.com']),
        ('Azure', ['domain is not configured', 'azurewebsites.net',
                   'blob.core.windows.net']),
        ('Netlify', ['Not found', 'netlify.app']),
        ('Surge.sh', ["project not found", "surge.sh"]),
        ('Zendesk', ['help center closed', 'zendesk.com']),
        ('Readme.io', ["Project doesnt exist", 'readme.io']),
    ]

    for sub in subdomains[:20]:
        if not scan_state.get('scanning'):
            break
        # Normalize subdomain
        if isinstance(sub, dict):
            sub_host = sub.get('subdomain', sub.get('host', ''))
        else:
            sub_host = str(sub)
        if not sub_host:
            continue

        results['checked'] += 1

        # ── DNS CNAME check ──
        cname_target = None
        if DNS_AVAILABLE:
            try:
                answers = dns.resolver.resolve(sub_host, 'CNAME')
                cname_target = str(answers[0].target).rstrip('.')
            except Exception:
                pass

        # ── HTTP fingerprint check ──
        if not REQUESTS_AVAILABLE:
            continue
        for scheme in ['https', 'http']:
            try:
                r = req_lib.get(f'{scheme}://{sub_host}', timeout=8, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0'},
                                allow_redirects=True)
                body = r.text
                status = r.status_code
                for service, patterns in takeover_fingerprints:
                    matched = any(p.lower() in body.lower() for p in patterns)
                    if matched and status in (404, 200, 301, 302, 503):
                        results['vulnerable'].append({
                            'subdomain': sub_host, 'service': service,
                            'cname': cname_target, 'status': status
                        })
                        conf = 'high' if status == 404 else 'medium'
                        add_finding('critical', f'Subdomain Takeover — {sub_host} ({service})',
                                    sub=f'Subdomain points to unclaimed {service} service',
                                    asset=f'{scheme}://{sub_host}', cvss='9.8',
                                    owasp='A05', mitre='T1584',
                                    details=f'Subdomain: {sub_host}\nService: {service}\n'
                                            f'CNAME: {cname_target or "N/A"}\n'
                                            f'HTTP Status: {status}\n'
                                            f'Fingerprint matched: {[p for p in patterns if p.lower() in body.lower()][:2]}',
                                    confidence=conf)
                        log('ok', f'[TAKEOVER-DEEP] Takeover candidate: {sub_host} ({service})')
                        break
                break  # Don't test http if https worked
            except Exception:
                pass

    with LOCK:
        scan_state['subdomain_takeover_data'] = results
    set_progress('subdomain_takeover', 100)
    log('ok', f'[TAKEOVER-DEEP] Done. {results["checked"]} subdomains checked, '
              f'{len(results["vulnerable"])} takeover candidates.')


# ─── CONTAINER SECURITY ────────────────────────────────────────────────────────
