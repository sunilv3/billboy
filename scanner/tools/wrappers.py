"""Wrappers for optional external tools — each has a pure-Python fallback."""
import os
import re
import json
import socket
import secrets
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress, op_log
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.modules.web.auth import _levenshtein_ratio

def run_arjun_module(target):
    """Discover hidden HTTP parameters — arjun binary or Python fallback."""
    set_progress('arjun', 5)
    params = []
    # Try arjun binary first
    arjun_path = _find_tool('arjun') or shutil.which('arjun')
    if arjun_path:
        out = f'/tmp/arjun_{secrets.token_hex(4)}.json'
        try:
            cmd = [arjun_path, '-u', f'https://{target}', '-oJ', out, '--stable', '-t', '5', '-d', '2', '-q']
            _run_tool(cmd, timeout=45)
            if os.path.isfile(out):
                with open(out) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            params.extend(entry.get('params', []))
                elif isinstance(data, dict):
                    params.extend(data.get('params', []))
        except Exception:
            pass
        finally:
            try: os.remove(out)
            except OSError: pass
    else:
        # Python fallback: discover hidden params via response differential analysis
        log('info', '[ARJUN] Using Python fallback for hidden parameter discovery')
        if not REQUESTS_AVAILABLE:
            set_progress('arjun', 100)
            return
        common_params = [
            'debug','test','admin','api','token','key','id','user','pass','page',
            'search','query','action','cmd','exec','file','path','url','redirect',
            'callback','webhook','proxy','source','dest','target','data','json',
            'xml','csv','limit','offset','sort','order','filter','type','format',
            'mode','lang','version','v','ref','next','prev','start','end','name',
            'email','phone','address','zip','ssn','cc','credit','card','pin',
            'amount','price','qty','quantity','discount','code','coupon','promo',
            'category','tag','status','state','role','perm','access','auth',
            'select','where','table','column','field','insert','update','delete',
            'load','import','export','upload','download','config','setting',
            'env','flags','options','params','args','input','output','log',
            'session','cookie','jwt','nonce','csrf','csrf_token','_token',
            'hash','sig','signature','verify','validate','check','confirm',
        ]
        base_url = f'https://{target}'
        try:
            r_base = req_lib.get(base_url, timeout=8, verify=False)
            base_len = len(r_base.text)
        except Exception:
            set_progress('arjun', 100)
            return
        # A meaningful response differential: require >10% change in length AND
        # at least 50 bytes difference to avoid noise from dynamic nonces/timestamps.
        _min_diff = max(50, int(base_len * 0.10))

        def _test_param(name):
            if not scan_state.get('scanning'):
                return None
            try:
                r1 = req_lib.get(f'{base_url}/?{name}=arjun_test', timeout=5, verify=False)
                if r1.status_code in (404, 400, 500):
                    return None
                diff1 = abs(len(r1.text) - base_len)
                if diff1 < _min_diff:
                    return None
                # Second request with different value — if length also changes, it is dynamic
                # content (not a real parameter), so skip it.
                r2 = req_lib.get(f'{base_url}/?{name}=arjun_probe2', timeout=5, verify=False)
                diff2 = abs(len(r2.text) - base_len)
                # Both requests changed AND their lengths are similar → real parameter
                if diff2 >= _min_diff and abs(len(r1.text) - len(r2.text)) < 20:
                    return name
            except Exception:
                pass
            return None
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_test_param, p): p for p in common_params}
            try:
                for f in as_completed(futures, timeout=120):
                    try:
                        result = f.result(timeout=5)
                        if result:
                            params.append(result)
                    except Exception:
                        pass
            except TimeoutError:
                for f in futures:
                    f.cancel()
        # Also check HTML forms for hidden inputs
        try:
            r = req_lib.get(base_url, timeout=8, verify=False)
            for match in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', r.text, re.I):
                tag = match.group(0)
                name_match = re.search(r'name=["\']([^"\']+)', tag)
                if name_match and name_match.group(1) not in params:
                    params.append(name_match.group(1))
        except Exception:
            pass
    params = list(dict.fromkeys(params))
    if params:
        with LOCK:
            scan_state.setdefault('discovery_data', {}).setdefault('hidden_params', [])
            for p in params:
                if p not in scan_state['discovery_data']['hidden_params']:
                    scan_state['discovery_data']['hidden_params'].append(p)
        add_finding('medium', 'Hidden Parameters Discovered',
                    asset=f'https://{target}', details=f'Parameters: {", ".join(params[:20])}',
                    owasp='A01', confidence='high')
        log('ok', f'[ARJUN] {len(params)} hidden params: {", ".join(params[:10])}')
    else:
        log('info', '[ARJUN] No hidden parameters found')
    set_progress('arjun', 100)


# ─── TOOL 2: NAABU — Fast Port Discovery ─────────────────────────────────────


def run_naabu_portscan(target):
    """Fast port scan — naabu binary or Python socket fallback. Returns list of open port ints."""
    # Try naabu binary first
    naabu_path = _find_tool('naabu')
    if naabu_path:
        out = f'/tmp/naabu_{secrets.token_hex(4)}.txt'
        try:
            cmd = [naabu_path, '-host', target, '-p', '-', '-rate', '1000',
                   '-c', '25', '-silent', '-o', out, '-exclude-ports', '0']
            _run_tool(cmd, timeout=45)
            ports = []
            if os.path.isfile(out):
                with open(out) as f:
                    for line in f:
                        line = line.strip()
                        if ':' in line:
                            try:
                                port = int(line.rsplit(':', 1)[1])
                                if port not in ports:
                                    ports.append(port)
                            except ValueError:
                                pass
            log('ok', f'[NAABU] {len(ports)} open ports found')
            return ports
        except Exception as e:
            log('warn', f'[NAABU] Error: {e}')
        finally:
            try: os.remove(out)
            except OSError: pass
    # Python fallback: fast TCP connect scan on common + top ports
    log('info', '[NAABU] Using Python fallback for port scanning')
    TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                 1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,
                 8888,9090,9200,9300,10000,27017,50000,27018,11211,15672,
                 5601,9092,2181,8161,1883,5672,15671,61616,5222,5269]
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        log('warn', f'[NAABU] Cannot resolve {target}')
        return []
    open_ports = []
    def _check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return port
            s.close()
        except Exception:
            pass
        return None
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_check_port, p): p for p in TOP_PORTS}
        try:
            for f in as_completed(futures, timeout=120):
                try:
                    result = f.result(timeout=5)
                    if result and result not in open_ports:
                        open_ports.append(result)
                except Exception:
                    pass
        except TimeoutError:
            for f in futures:
                f.cancel()
    open_ports.sort()
    log('ok', f'[NAABU] {len(open_ports)} open ports (Python fallback)')
    return open_ports


# ─── TOOL 3: RUSTSCAN — Full Port Scanner ────────────────────────────────────


def run_rustscan(target):
    """Full port scan — rustscan binary or Python socket fallback. Returns list of open port ints."""
    # Try rustscan binary first
    rustscan_path = _find_tool('rustscan')
    if rustscan_path:
        try:
            stdout, _, rc = _run_tool([
                rustscan_path, '-a', target, '-r', '1-65535', '-b', '500',
                '--timeout', '2000', '--no-nmap', '-q', '--accessible'
            ], timeout=30)
            ports = []
            if stdout:
                for line in stdout.strip().split('\n'):
                    line = line.strip()
                    if ':' in line:
                        try:
                            port = int(line.rsplit(':', 1)[1].strip())
                            if port not in ports:
                                ports.append(port)
                        except ValueError:
                            pass
            log('ok', f'[RUSTSCAN] {len(ports)} ports in ~3s')
            return ports
        except Exception as e:
            log('warn', f'[RUSTSCAN] Error: {e}')
    # Python fallback: parallel connect scan on ALL well-known ports (0-10000)
    log('info', '[RUSTSCAN] Using Python fallback for full port scan')
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return []
    open_ports = []
    def _scan(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, p)) == 0:
                s.close()
                return p
            s.close()
        except Exception:
            pass
        return None
    with ThreadPoolExecutor(max_workers=200) as pool:
        futures = {pool.submit(_scan, p): p for p in range(1, 10001)}
        try:
            for f in as_completed(futures, timeout=300):
                try:
                    r = f.result(timeout=5)
                    if r and r not in open_ports:
                        open_ports.append(r)
                except Exception:
                    pass
        except TimeoutError:
            for f in futures:
                f.cancel()
    open_ports.sort()
    log('ok', f'[RUSTSCAN] {len(open_ports)} ports scanned (Python fallback)')
    return open_ports


# ─── TOOL 6: PUREDNS — DNS Bruteforce with Wildcard Filtering ────────────────


def run_puredns(target, existing_set):
    """DNS bruteforce — puredns binary or Python dnspython fallback. Returns list of new subdomain strings."""
    # Try puredns binary first
    puredns_path = _find_tool('puredns')
    if puredns_path:
        wordlist = '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
        if not os.path.isfile(wordlist):
            wordlist = '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
        if os.path.isfile(wordlist):
            resolvers_file = f'/tmp/resolvers_{secrets.token_hex(4)}.txt'
            out = f'/tmp/puredns_{secrets.token_hex(4)}.txt'
            try:
                with open(resolvers_file, 'w') as f:
                    f.write('8.8.8.8\n1.1.1.1\n9.9.9.9\n208.67.222.222\n')
                cmd = [puredns_path, 'bruteforce', wordlist, target,
                       '-r', resolvers_file, '-w', out, '--quiet']
                _run_tool(cmd, timeout=45)
                new_subs = []
                if os.path.isfile(out):
                    with open(out) as f:
                        for line in f:
                            sub = line.strip().lower()
                            if sub.endswith(f'.{target}') and sub not in existing_set:
                                new_subs.append(sub)
                                existing_set.add(sub)
                log('ok', f'[PUREDNS] {len(new_subs)} subdomains via DNS bruteforce')
                return new_subs
            except Exception as e:
                log('warn', f'[PUREDNS] Error: {e}')
            finally:
                for f in (resolvers_file, out):
                    try: os.remove(f)
                    except OSError: pass
    # Python fallback: DNS resolution with built-in wordlist
    log('info', '[PUREDNS] Using Python fallback for DNS bruteforce')
    BUILTIN_WORDLIST = [
        'www','mail','ftp','smtp','pop','imap','ns1','ns2','ns3','ns4','dns',
        'admin','administrator','webmail','cpanel','whm','webdisk','autodiscover',
        'dev','development','staging','stage','test','testing','qa','uat','sandbox',
        'api','api2','api3','devapi','rest','graphql','beta','alpha','demo','preview',
        'app','apps','portal','webapp','webapps','shop','store','payment','pay',
        'blog','forum','community','support','help','docs','wiki','kb','knowledge',
        'status','monitor','monitoring','grafana','kibana','prometheus','alertmanager',
        'git','gitlab','github','bitbucket','svn','ci','cd','jenkins','travis',
        'build','db','database','mysql','postgres','mongo','redis','elastic','mssql',
        'backup','backups','bak','old','legacy','cdn','static','assets','images',
        'vpn','remote','access','gateway','intranet','internal','private','corp',
        'hr','crm','erp','jira','confluence','slack','mx','mx1','mx2','relay',
        'webdisk','autoconfig','autodiscover','m','mobile','wap','secure',
        'shopify','s3','s3-us','s3-eu','azure','gcp','cloud','k8s','kubernetes',
        'docker','registry','harbor','nexus','sonarqube','artifactory',
        'proxy','squid','haproxy','nginx','apache','traefik','istio',
        'ldap','kerberos','sso','oauth','saml','radius','tacacs',
        'elasticsearch','logstash','kibana','filebeat','fluentd','splunk',
        'zabbix','nagios','datadog','newrelic','dynatrace','pagerduty',
        'ntp','ntp1','ntp2','ntp3','time','chrony','ntpdate',
        'ns','dns1','dns2','dns3','dns4','auth','login','sso','signin',
        'secure','ssl','tls','cert','pki','ca','ocsp','crl',
        'mx0','mx1','mx2','mx3','mail1','mail2','mail3','imap4','pop3',
        'smtp2','relay1','relay2','bounces','feedback','abuse','postmaster',
        'webmin','phpmyadmin','adminer','pgadmin','admin-console',
    ]
    new_subs = []
    def _resolve(sub):
        if not scan_state.get('scanning'):
            return None
        fqdn = f'{sub}.{target}'
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(_resolve, w): w for w in BUILTIN_WORDLIST}
        try:
            for f in as_completed(futures, timeout=120):
                try:
                    result = f.result(timeout=5)
                    if result and result.lower() not in existing_set:
                        new_subs.append(result.lower())
                        existing_set.add(result.lower())
                except Exception:
                    pass
        except TimeoutError:
            for f in futures:
                f.cancel()
    log('ok', f'[PUREDNS] {len(new_subs)} subdomains (Python fallback)')
    return new_subs


# ─── TOOL 7: SEARCHSPLOIT — ExploitDB Lookup for CVEs ────────────────────────


def run_searchsploit(cve_id='', product='', version=''):
    """Look up public exploits — searchsploit binary or NVD/ExploitDB API fallback."""
    query = cve_id if cve_id else f'{product} {version}'.strip()
    if not query:
        return []
    # Try searchsploit binary first
    ss_path = _find_tool('searchsploit')
    if ss_path:
        try:
            stdout, _, rc = _run_tool([ss_path, '--json', query], timeout=15)
            if rc == 0 and stdout:
                data = json.loads(stdout)
                exploits = []
                for item in data.get('RESULTS_EXPLOIT', []):
                    exploits.append({
                        'title': item.get('Title', ''),
                        'path': item.get('Path', ''),
                        'type': item.get('Type', ''),
                        'edb_id': item.get('EDB-ID', ''),
                    })
                return exploits
        except Exception:
            pass
    # Python fallback: query ExploitDB API via searchsploit.sh mirror or direct scraping
    if cve_id and cve_id.startswith('CVE-'):
        try:
            r = req_lib.get(f'https://www.exploit-db.com/search?cve={cve_id}',
                           timeout=10, verify=False,
                           headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                exploits = []
                for match in re.finditer(r'href="/exploits/(\d+)"[^>]*>([^<]+)', r.text):
                    exploits.append({
                        'title': match.group(2).strip(),
                        'path': f'/exploits/{match.group(1)}',
                        'type': 'webapps',
                        'edb_id': match.group(1),
                    })
                if exploits:
                    return exploits
        except Exception:
            pass
    # Fallback: use NVD to at least confirm CVE exists
    if cve_id:
        try:
            r = req_lib.get('https://services.nvd.nist.gov/rest/json/cves/2.0',
                           params={'cveId': cve_id}, timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                if data.get('vulnerabilities'):
                    return [{'title': f'CVE confirmed: {cve_id}',
                             'path': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                             'type': 'cve', 'edb_id': ''}]
        except Exception:
            pass
    return []


# ─── TOOL 8: GOSPIDER — Recursive Crawler + JS Source Map Detection ──────────


def run_gospider(target):
    """Recursive crawler — gospider binary or Python fallback. Returns list of URLs."""
    urls = []
    # Try gospider binary first
    gospider_path = _find_tool('gospider')
    if gospider_path:
        try:
            stdout, _, rc = _run_tool([
                gospider_path, '-s', f'https://{target}', '-c', '5', '-d', '2',
                '--robots', '--sitemap', '--other-source', '--js', '-q', '-t', '3'
            ], timeout=45)
            if stdout:
                for line in stdout.strip().split('\n'):
                    line = line.strip()
                    if ' - ' in line and 'http' in line:
                        url = line.rsplit(' - ', 1)[-1].strip()
                        if url.startswith('http') and target in url:
                            urls.append(url)
                            if url.endswith('.js.map'):
                                add_finding('medium', 'JS Source Map Exposed',
                                            asset=url, confidence='high', owasp='A05',
                                            details=f'Source map exposes original source: {url}')
        except Exception as e:
            log('warn', f'[GOSPIDER] Error: {e}')
        log('ok', f'[GOSPIDER] {len(urls)} endpoints discovered')
        return urls
    # Python fallback: fetch robots.txt, sitemap.xml, extract links + JS source maps
    log('info', '[GOSPIDER] Using Python fallback for recursive crawling')
    if not REQUESTS_AVAILABLE:
        return []
    visited = set()
    base_url = f'https://{target}'
    def _crawl(url, depth=0):
        if depth > 2 or len(urls) > 200 or not scan_state.get('scanning'):
            return
        if url in visited:
            return
        visited.add(url)
        try:
            r = req_lib.get(url, timeout=6, verify=False, allow_redirects=True)
            urls.append(url)
            # Detect JS source maps
            if url.endswith('.js.map'):
                add_finding('medium', 'JS Source Map Exposed',
                            asset=url, confidence='high', owasp='A05',
                            details=f'Source map exposes original source: {url}')
            # Extract links from HTML
            for match in re.finditer(r'(?:href|src)=["\']([^"\']+)["\']', r.text, re.I):
                link = match.group(1)
                if link.startswith('/'):
                    link = f'{base_url}{link}'
                elif not link.startswith('http'):
                    link = f'{url}/{link}'
                if target in link and link not in visited:
                    _crawl(link, depth + 1)
        except Exception:
            pass
    # Crawl robots.txt and sitemap.xml first
    for path in ['/robots.txt', '/sitemap.xml']:
        try:
            _crawl(f'{base_url}{path}', 0)
        except Exception:
            pass
    _crawl(base_url, 0)
    log('ok', f'[GOSPIDER] {len(urls)} URLs crawled (Python fallback)')
    return urls


# ─── TOOL 9: SSRFMAP — SSRF Exploitation Verification ────────────────────────


def run_ssrfmap(target_url, param):
    """SSRF exploitation — ssrfmap binary or Python cloud metadata fallback."""
    # Try ssrfmap binary first
    ssrfmap_path = _find_tool('ssrfmap') or shutil.which('ssrfmap.py')
    if ssrfmap_path:
        try:
            if ssrfmap_path.endswith('.py'):
                cmd = ['python3', ssrfmap_path, '-u', f'{target_url}?{param}=SSRF',
                       '-p', param, '--level', '1', '-m', 'readfiles,networkscan,cloud']
            else:
                cmd = [ssrfmap_path, '-u', f'{target_url}?{param}=SSRF',
                       '-p', param, '--level', '1', '-m', 'readfiles,networkscan,cloud']
            stdout, _, _ = _run_tool(cmd, timeout=30)
            if stdout:
                indicators = ['aws', 'gcp', 'azure', 'metadata', 'found', '169.254']
                if any(ind in stdout.lower() for ind in indicators):
                    add_finding('critical', 'SSRF Exploitation Confirmed (ssrfmap)',
                                asset=target_url,
                                details=f'ssrfmap confirmed exploitable SSRF on param: {param}\n{stdout[:600]}',
                                confidence='high', owasp='A10', mitre='T1552')
                    op_log('auto_verify', target_url, f'SSRF exploit confirmed: {param}')
                    return
        except Exception:
            pass
    # Python fallback: probe cloud metadata endpoints via the SSRF param
    log('info', f'[SSRFMAP] Using Python fallback to verify SSRF on {param}')
    if not REQUESTS_AVAILABLE:
        return
    cloud_payloads = [
        ('http://169.254.169.254/latest/meta-data/', 'AWS'),
        ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS IAM'),
        ('http://metadata.google.internal/computeMetadata/v1/', 'GCP'),
        ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'Azure'),
        ('http://169.254.169.254/latest/user-data/', 'AWS User Data'),
    ]
    for payload, cloud in cloud_payloads:
        if not scan_state.get('scanning'):
            return
        try:
            r = req_lib.get(f'{target_url}?{param}={payload}', timeout=8, verify=False)
            body = r.text.lower()
            if any(ind in body for ind in ['ami-id', 'instance-id', 'hostname', 'project-id', 'subscription-id']):
                add_finding('critical', f'SSRF → {cloud} Metadata Confirmed',
                            asset=target_url,
                            details=f'SSRF on {param} leaks {cloud} metadata\n'
                                    f'Payload: {payload}\nResponse (first 500 chars):\n{r.text[:500]}',
                            confidence='high', owasp='A10', mitre='T1552')
                op_log('auto_verify', target_url, f'SSRF→{cloud} metadata confirmed: {param}')
                log('ok', f'[SSRFMAP] {cloud} metadata leaked via {param}')
                return
        except Exception:
            pass
    # Test for internal port scan via SSRF
    internal_leak = False
    for port in [80, 443, 8080, 3306, 6379, 27017]:
        try:
            r = req_lib.get(f'{target_url}?{param}=http://127.0.0.1:{port}/',
                           timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 0:
                internal_leak = True
                log('ok', f'[SSRFMAP] Internal port {port} accessible via {param}')
        except Exception:
            pass
    if internal_leak:
        add_finding('high', f'SSRF Internal Network Access via {param}',
                    asset=target_url,
                    details=f'SSRF on {param} can reach internal services\n'
                            f'Tested ports: 80, 443, 8080, 3306, 6379, 27017',
                    confidence='medium', owasp='A10')


# ─── TOOL 10: THEHARVESTER — OSINT: Emails + Subdomains + Employees ──────────


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


# ─── TOOL 12: FEROXBUSTER — Recursive Directory Bruteforce ───────────────────


def run_feroxbuster(target, wordlist):
    """Recursive dir brute — feroxbuster binary or Python ThreadPool fallback."""
    # Try feroxbuster binary first
    ferox_path = _find_tool('feroxbuster')
    if ferox_path:
        out = f'/tmp/ferox_{secrets.token_hex(4)}.json'
        try:
            cmd = [ferox_path, '-u', f'https://{target}', '-w', wordlist,
                   '-d', '3', '--silent', '-o', out, '--json', '--no-state',
                   '-t', '10', '--rate-limit', '50', '-q',
                   '--filter-status', '404,403,400,500']
            _run_tool(cmd, timeout=45)
            urls = []
            if os.path.isfile(out):
                with open(out) as f:
                    for line in f:
                        line = line.strip()
                        if not line: continue
                        try:
                            entry = json.loads(line)
                            url = entry.get('url', '')
                            status = entry.get('status', 0)
                            if entry.get('type') == 'response' and status in (200, 201, 301, 302) and url:
                                urls.append(url)
                        except json.JSONDecodeError:
                            pass
            log('ok', f'[FEROXBUSTER] {len(urls)} URLs (recursive depth 3)')
            return urls
        except Exception as e:
            log('warn', f'[FEROXBUSTER] Error: {e}')
        finally:
            try: os.remove(out)
            except OSError: pass
    # Python fallback: recursive ThreadPool directory bruteforce
    log('info', '[FEROXBUSTER] Using Python fallback for recursive dir bruteforce')
    if not REQUESTS_AVAILABLE:
        return []
    if not os.path.isfile(wordlist):
        log('warn', f'[FEROXBUSTER] Wordlist not found: {wordlist}')
        return []
    found_urls = []
    scanned = set()
    # Load wordlist
    try:
        with open(wordlist) as f:
            words = [w.strip() for w in f.readlines() if w.strip()]
    except Exception:
        return []
    base_url = f'https://{target}'
    def _check(path, depth=0):
        if depth > 2 or not scan_state.get('scanning'):
            return
        url = f'{base_url}{path}'
        if url in scanned:
            return
        scanned.add(url)
        try:
            r = req_lib.get(url, timeout=4, verify=False, allow_redirects=False)
            if r.status_code in (200, 201, 301, 302):
                found_urls.append(url)
                # Recurse into directories (depth 2)
                if depth < 2 and r.status_code in (200, 301):
                    for w in words[:20]:
                        sub = f'{path.rstrip("/")}/{w}'
                        _check(sub, depth + 1)
        except Exception:
            pass
    # Check root wordlist entries
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = []
        for w in words:
            futures.append(pool.submit(_check, f'/{w}', 0))
        try:
            for f in as_completed(futures, timeout=120):
                try: f.result(timeout=5)
                except Exception: pass
        except TimeoutError:
            for f in futures:
                f.cancel()
    log('ok', f'[FEROXBUSTER] {len(found_urls)} URLs (Python fallback)')
    return found_urls


# ─── TOOL 13: NIKTO — Web Server Misconfiguration Scanner ────────────────────


def run_nikto_module(target):
    """Server misconfig scanner — nikto binary or Python checks fallback."""
    set_progress('nikto', 5)
    count = 0
    # Try nikto binary first
    nikto_path = _find_tool('nikto')
    if nikto_path:
        out = f'/tmp/nikto_{secrets.token_hex(4)}.json'
        try:
            cmd = [nikto_path, '-h', f'https://{target}', '-Format', 'json', '-o', out,
                   '-timeout', '10', '-maxtime', '45s', '-nointeractive',
                   '-Plugins', 'headers,files,outdated']
            _run_tool(cmd, timeout=45)
            if os.path.isfile(out):
                with open(out) as f:
                    data = json.load(f)
                results = data if isinstance(data, list) else data.get('vulnerabilities', data.get('results', []))
                for item in results:
                    if not isinstance(item, dict): continue
                    msg = item.get('msg', item.get('message', ''))
                    uri = item.get('uri', item.get('url', '/'))
                    vuln_id = str(item.get('id', '0'))
                    if vuln_id.startswith('7'): sev = 'high'
                    elif vuln_id.startswith('6'): sev = 'medium'
                    elif vuln_id.startswith('1'): sev = 'low'
                    else: sev = 'info'
                    if msg:
                        add_finding(sev, f'Nikto: {msg[:80]}',
                                    asset=f'https://{target}{uri}',
                                    confidence='medium', owasp='A05')
                        count += 1
        except Exception as e:
            log('warn', f'[NIKTO] Error: {e}')
        finally:
            try: os.remove(out)
            except OSError: pass
    else:
        # Python fallback: server misconfiguration checks
        log('info', '[NIKTO] Using Python fallback for server misconfiguration checks')
        if not REQUESTS_AVAILABLE:
            set_progress('nikto', 10)
            return
        base_url = f'https://{target}'
        try:
            r = req_lib.get(base_url, timeout=8, verify=False)
        except Exception:
            set_progress('nikto', 100)
            return
        headers = r.headers
        body = r.text.lower()
        # 1. Server header disclosure
        server = headers.get('Server', '')
        if server and any(v in server.lower() for v in ['apache/2.2', 'apache/2.4.4', 'nginx/1.0', 'iis/6', 'iis/7']):
            add_finding('medium', f'Outdated server version disclosed: {server}',
                        asset=base_url, confidence='high', owasp='A05',
                        details=f'Server header reveals version: {server}\nRemediation: Remove or obfuscate Server header.')
            count += 1
        # 2. X-Powered-By disclosure
        powered = headers.get('X-Powered-By', '')
        if powered:
            add_finding('low', f'X-Powered-By header disclosed: {powered}',
                        asset=base_url, confidence='high', owasp='A05',
                        details=f'X-Powered-By reveals: {powered}\nRemediation: Remove this header.')
            count += 1
        # 3. Missing security headers
        security_headers = {
            'X-Frame-Options': ('Clickjacking possible', 'medium', 'A05'),
            'X-Content-Type-Options': ('MIME sniffing possible', 'low', 'A05'),
            'X-XSS-Protection': ('Legacy XSS filter missing', 'info', 'A05'),
            'Strict-Transport-Security': ('HSTS not configured', 'medium', 'A02'),
            'Content-Security-Policy': ('CSP not configured', 'medium', 'A05'),
            'Referrer-Policy': ('Referrer leakage possible', 'info', 'A05'),
            'Permissions-Policy': ('Permissions policy missing', 'info', 'A05'),
        }
        for hdr, (desc, sev, owasp) in security_headers.items():
            if hdr.lower() not in [k.lower() for k in headers]:
                add_finding(sev, f'Missing security header: {hdr}',
                            asset=base_url, confidence='high', owasp=owasp,
                            details=f'{desc}. {hdr} header not present.')
                count += 1
        # 4. Directory listing
        sensitive_dirs = ['/admin', '/backup', '/config', '/db', '/debug', '/logs',
                          '/phpmyadmin', '/server-status', '/server-info', '/.git',
                          '/.env', '/wp-admin', '/cgi-bin', '/scripts', '/tmp']
        for d in sensitive_dirs:
            if not scan_state.get('scanning'): break
            try:
                r2 = req_lib.get(f'{base_url}{d}/', timeout=4, verify=False, allow_redirects=False)
                if r2.status_code == 200 and ('index of' in r2.text.lower() or 'parent directory' in r2.text.lower()):
                    add_finding('medium', f'Directory listing enabled: {d}/',
                                asset=f'{base_url}{d}/', confidence='high', owasp='A05',
                                details=f'Directory listing at {d}/ exposes file structure.')
                    count += 1
                elif r2.status_code == 200 and len(r2.text) > 100:
                    # Check if sensitive files are accessible
                    for sf in ['/config.php', '/config.yml', '/wp-config.php', '/.htaccess']:
                        if sf.lower() in r2.text.lower():
                            add_finding('high', f'Sensitive file referenced in {d}/',
                                        asset=f'{base_url}{d}/', confidence='medium', owasp='A05')
                            count += 1
                            break
            except Exception:
                pass
        # 5. HTTP methods
        try:
            r2 = req_lib.options(base_url, timeout=5, verify=False)
            allow = r2.headers.get('Allow', '')
            dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] if m in allow.upper()]
            if dangerous:
                add_finding('medium', f'Dangerous HTTP methods enabled: {", ".join(dangerous)}',
                            asset=base_url, confidence='high', owasp='A05',
                            details=f'Allow header: {allow}\nRemediation: Disable unnecessary HTTP methods.')
                count += 1
        except Exception:
            pass
        # 6. TRACE method (XST)
        try:
            r2 = req_lib.request('TRACE', base_url, timeout=5, verify=False)
            if r2.status_code == 200:
                add_finding('medium', 'TRACE method enabled (Cross-Site Tracing)',
                            asset=base_url, confidence='high', owasp='A05',
                            details='TRACE method reflects headers, enabling XST attacks.')
                count += 1
        except Exception:
            pass
        # 7. Outdated JavaScript libraries
        js_libs = {
            'jquery': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '2.0', '2.1', '2.2', '3.0', '3.1', '3.2', '3.3'],
            'bootstrap': ['3.0', '3.1', '3.2', '3.3', '3.4'],
            'angular': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7'],
            'prototype': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7'],
        }
        for match in re.finditer(r'(jquery|bootstrap|angular|prototype)[/-](\d+\.\d+(?:\.\d+)?)', r.text, re.I):
            lib = match.group(1).lower()
            ver = match.group(2)
            if lib in js_libs and any(ver.startswith(v) for v in js_libs[lib]):
                add_finding('medium', f'Outdated JS library: {lib} {ver}',
                            asset=base_url, confidence='high', owasp='A06',
                            details=f'{lib} version {ver} is outdated and may have known vulnerabilities.')
                count += 1
        # 8. Cookie security
        for cookie in r.cookies:
            issues = []
            if not cookie.secure: issues.append('missing Secure flag')
            if 'httponly' not in str(r.headers).lower() and cookie.name.lower() in ('session', 'sid', 'token', 'auth'):
                issues.append('missing HttpOnly flag')
            if issues:
                add_finding('medium', f'Insecure cookie: {cookie.name} ({", ".join(issues)})',
                            asset=base_url, confidence='high', owasp='A05',
                            details=f'Cookie {cookie.name} has: {", ".join(issues)}')
                count += 1
        # 9. Backup files
        backup_exts = ['.bak', '.old', '.orig', '.save', '.swp', '.tmp', '~']
        for ext in backup_exts:
            if not scan_state.get('scanning'): break
            try:
                r2 = req_lib.get(f'{base_url}/{r.url.split("/")[-1]}{ext}', timeout=3, verify=False)
                if r2.status_code == 200 and len(r2.text) > 50:
                    # False-positive guard: compare with baseline to ensure it's not just the normal homepage
                    content_similar = _levenshtein_ratio(r.text[:2000], r2.text[:2000]) > 0.80
                    if not content_similar:
                        add_finding('medium', f'Backup file accessible: {ext}',
                                    asset=f'{base_url}{ext}', confidence='high', owasp='A05',
                                    details=f'Backup file {ext} is publicly accessible and contains different content from homepage.')
                        count += 1
            except Exception:
                pass
        # 10. PHP info disclosure
        for path in ['/phpinfo.php', '/info.php', '/test.php', '/pi.php']:
            if not scan_state.get('scanning'): break
            try:
                r2 = req_lib.get(f'{base_url}{path}', timeout=3, verify=False)
                if r2.status_code == 200 and ('php version' in r2.text.lower() or 'phpinfo()' in r2.text.lower()):
                    add_finding('high', f'PHP info disclosure at {path}',
                                asset=f'{base_url}{path}', confidence='high', owasp='A05',
                                details=f'PHP info page exposes server configuration.')
                    count += 1
            except Exception:
                pass
    log('ok', f'[NIKTO] {count} server-level findings')
    set_progress('nikto', 100)


# Background verification thread pool
_verify_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='auto-verify')
