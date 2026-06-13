"""
Wazuh-style Security Detection Module
Implements: FIM, Rootkit Detection, Vulnerability Detection, Log Analysis, Compliance
"""
import re
import json
import time
import hashlib
import secrets
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: FILE INTEGRITY MONITORING (FIM)
# ═══════════════════════════════════════════════════════════════════════════════

CRITICAL_FILES = {
    '/etc/passwd': 'System user database',
    '/etc/shadow': 'Password hashes',
    '/etc/hosts': 'Host resolution',
    '/etc/resolv.conf': 'DNS configuration',
    '/etc/ssh/sshd_config': 'SSH daemon config',
    '/etc/nginx/nginx.conf': 'Nginx config',
    '/etc/apache2/apache2.conf': 'Apache config',
    '/var/log/auth.log': 'Authentication log',
    '/var/log/syslog': 'System log',
    '/proc/version': 'Kernel version',
    '/proc/self/status': 'Process status',
    '/proc/cpuinfo': 'CPU information',
    '/etc/crontab': 'Cron jobs',
    '/root/.bash_history': 'Root command history',
    '/root/.ssh/authorized_keys': 'SSH authorized keys',
    '/root/.ssh/id_rsa': 'SSH private key',
    '/var/log/apache2/access.log': 'Apache access log',
    '/var/log/nginx/access.log': 'Nginx access log',
    '/etc/mysql/my.cnf': 'MySQL config',
    '/etc/redis/redis.conf': 'Redis config',
}

# Local File Inclusion paths
LFI_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/hosts',
    '/proc/self/environ', '/proc/version', '/proc/cmdline',
    '/var/log/apache2/access.log', '/var/log/nginx/access.log',
    '/var/log/auth.log', '/var/log/syslog',
    '/root/.bash_history', '/root/.ssh/authorized_keys',
    '/etc/mysql/my.cnf', '/etc/redis/redis.conf',
    '/etc/nginx/nginx.conf', '/etc/apache2/apache2.conf',
    '/home/.env', '/var/www/html/.env', '/opt/.env',
]

LFI_MARKERS = [
    (r'root:x:0:0', '/etc/passwd'),
    (r'root:\$[0-9]', '/etc/shadow'),
    (r'127\.0\.0\.1.*localhost', '/etc/hosts'),
    (r'nameserver\s+\d+\.\d+\.\d+\.\d+', '/etc/resolv.conf'),
    (r'Linux version\s+\d+\.\d+', '/proc/version'),
    (r'PASSWD=|HOME=|PATH=|LANG=', '/proc/self/environ'),
    (r'SSH-2\.0|ssh-rsa', 'SSH key'),
    (r'mysqld|mysql_config', 'MySQL config'),
    (r'redis_version|bind\s+', 'Redis config'),
    (r'daemon|worker_processes', 'Nginx/Apache config'),
]

LFI_PATH_MARKERS = {
    '/etc/passwd': ['root:', '/bin/bash', '/bin/sh'],
    '/etc/shadow': ['root:', '$6$', '$5$'],
    '/proc/version': ['Linux version', 'gcc version', 'Ubuntu'],
    '/proc/self/environ': ['PATH=', 'HOME=', 'USER=', 'LANG='],
    '/var/log/apache2/access.log': ['GET ', 'POST ', 'HTTP/1'],
    '/var/log/nginx/access.log': ['GET ', 'POST ', 'HTTP/1'],
    '/root/.ssh/authorized_keys': ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2'],
    '/root/.bash_history': ['sudo', 'cd ', 'rm ', 'ssh '],
}


def run_fim_module(target):
    """Wazuh-style File Integrity Monitoring via LFI/path traversal"""
    log('ok', f'[WAZUH-FIM] Starting File Integrity Monitoring for {target}')
    base_url = f'https://{target}'

    # Probe for SPA catch-all
    spa_hash = None
    try:
        probe_url = f'{base_url}/__fim_probe_{secrets.token_hex(4)}__.txt'
        r = req_lib.get(probe_url, timeout=5, verify=False)
        if r and r.status_code == 200:
            spa_hash = hash(r.text)
    except Exception:
        pass

    # Get homepage for fallback SPA check
    homepage_hash = None
    try:
        r_home = req_lib.get(base_url, timeout=5, verify=False)
        if r_home:
            homepage_hash = hash(r_home.text)
    except Exception:
        pass

    # Known injection endpoints from discovery
    endpoints = []
    try:
        disc = scan_state.get('discovery_data', {})
        for ep in disc.get('urls', []):
            url = ep if isinstance(ep, str) else ep.get('url', '')
            if url and '?' in url:
                endpoints.append(url)
    except Exception:
        pass

    if not endpoints:
        endpoints = [base_url, f'{base_url}/', f'{base_url}/index.html']

    fim_findings = 0

    # Test each endpoint with LFI payloads
    for ep in endpoints[:20]:
        if not scan_state.get('scanning'):
            break
        parsed = urlparse(ep)
        base = f'{parsed.scheme}://{parsed.netloc}'

        for lfi_path in LFI_PATHS[:10]:
            try:
                # Try common injection points
                params_to_try = []
                if '?' in ep:
                    params_to_try.append(ep.replace('=', f'={lfi_path}', 1))
                params_to_try.append(f'{base}/?page={lfi_path}')
                params_to_try.append(f'{base}/?file={lfi_path}')
                params_to_try.append(f'{base}/?path={lfi_path}')
                params_to_try.append(f'{base}/?include={lfi_path}')
                params_to_try.append(f'{base}/{lfi_path}')

                for test_url in params_to_try:
                    r = req_lib.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    if not r or r.status_code != 200:
                        continue

                    # Filter SPA catch-all
                    if spa_hash and hash(r.text) == spa_hash:
                        continue
                    if homepage_hash and hash(r.text) == homepage_hash:
                        continue

                    body = r.text
                    for pattern, marker_name in LFI_MARKERS:
                        if re.search(pattern, body, re.I):
                            # Verify it's actual file content
                            severity = 'critical' if any(s in lfi_path for s in ['shadow', 'ssh', 'private']) else 'high'
                            add_finding(severity,
                                        f'File Integrity Monitoring: {marker_name} exposed via path traversal',
                                        sub=f'Sensitive file content readable at {test_url}',
                                        asset=test_url, cvss='8.6', owasp='A01', mitre='T1005',
                                        details=f'File: {lfi_path}\nURL: {test_url}\n'
                                                f'Marker: {marker_name}\n'
                                                f'Remediation: Restrict file access permissions, disable path traversal',
                                        confidence='high')
                            fim_findings += 1
                            break

            except Exception:
                pass

    log('ok', f'[WAZUH-FIM] Complete: {fim_findings} file integrity issues found')
    set_progress('fim', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: ROOTKIT DETECTION — Web Shell Scanning
# ═══════════════════════════════════════════════════════════════════════════════

# Known web shell signatures
WEB_SHELL_SIGNATURES = [
    # c99shell
    (r'c99\s*shell|c99_madnet|c99\.php|c99\.txt', 'c99 Shell'),
    # r57shell
    (r'r57\s*shell|r57shell|r57\.php', 'r57 Shell'),
    # b374k
    (r'b374k|b374k\.php', 'b374k Shell'),
    # Weevely
    (r'Weevely|weevely|w3llb0y', 'Weevely Shell'),
    # WSO
    (r'WSO\s*\d|wso\s*\d|WSO2\.8|wso2\.8', 'WSO Shell'),
    # PHP Webshell patterns
    (r'eval\s*\(\s*base64_decode|eval\s*\(\s*gzinflate|eval\s*\(\s*gzuncompress', 'PHP Obfuscated Webshell'),
    (r'system\s*\(\s*\$_(GET|POST|REQUEST)|exec\s*\(\s*\$_(GET|POST|REQUEST)', 'PHP Command Execution Shell'),
    (r'passthru\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec\s*\(\s*\$_(GET|POST|REQUEST)', 'PHP Shell Execution'),
    (r'assert\s*\(\s*\$_(GET|POST|REQUEST)|preg_replace\s*\(\s*[\'"]/e', 'PHP Dangerous Functions'),
    # JSP Shells
    (r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder.*start\(\)', 'JSP Command Execution'),
    (r'<%.*request\.getParameter.*Runtime\.getRuntime', 'JSP Webshell'),
    # ASP Shells
    (r'execute\s*\(\s*request|ExecuteGlobal\s*\(\s*request', 'ASP Webshell'),
    (r'Scripting\.FileSystemObject.*CreateTextFile', 'ASP File System Access'),
    # Generic backdoor indicators
    (r'c99r57shell|FilesMan|File Manager.*shell', 'Known Webshell Manager'),
    (r'phpspy|chopper|china chopper|chopper\.php', 'China Chopper'),
    (r'eval\s*\(\s*\$\_', 'One-line PHP Shell'),
    (r'assert\s*\(\s*\$\_', 'PHP Assert Backdoor'),
    (r'preg_replace\s*\(\s*[\'"][^"\']*/e[\'"]', 'PHP preg_replace /e Backdoor'),
]

# Web shell file paths to probe
WEB_SHELL_PATHS = [
    '/shell.php', '/cmd.php', '/c99.php', '/r57.php', '/b374k.php',
    '/wso.php', '/backdoor.php', '/hack.php', '/webshell.php', '/virus.php',
    '/config.php.bak', '/config.php~', '/config.php.old', '/config.php.orig',
    '/admin/shell.php', '/uploads/shell.php', '/images/shell.php',
    '/tmp/shell.php', '/temp/shell.php', '/cache/shell.php',
    '/assets/shell.php', '/static/shell.php', '/lib/shell.php',
    '/shell.jsp', '/cmd.jsp', '/backdoor.jsp',
    '/shell.asp', '/cmd.asp', '/backdoor.asp',
    '/shell.aspx', '/cmd.aspx', '/backdoor.aspx',
    '/.htaccess', '/.htpasswd', '/web.config.bak',
    '/backup.zip', '/backup.tar.gz', '/db.sql',
    '/debug.log', '/error.log', '/access.log',
    '/phpinfo.php', '/info.php', '/test.php',
    '/.git/config', '/.git/HEAD', '/.svn/entries',
    '/composer.json', '/package.json', '/package-lock.json',
    '/.env', '/.env.local', '/.env.backup',
    '/config.json', '/config.js', '/config.yml',
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
]


def run_rootkit_module(target):
    """Wazuh-style rootkit detection via web shell scanning"""
    log('ok', f'[WAZUH-ROOTKIT] Starting rootkit detection for {target}')
    base_url = f'https://{target}'

    # Probe for SPA catch-all
    spa_hash = None
    try:
        probe_url = f'{base_url}/__rootkit_probe_{secrets.token_hex(4)}__.txt'
        r = req_lib.get(probe_url, timeout=5, verify=False)
        if r and r.status_code == 200:
            spa_hash = hash(r.text)
    except Exception:
        pass

    homepage_hash = None
    try:
        r_home = req_lib.get(base_url, timeout=5, verify=False)
        if r_home:
            homepage_hash = hash(r_home.text)
    except Exception:
        pass

    rootkit_findings = 0

    def _check_path(path):
        if not scan_state.get('scanning'):
            return None
        try:
            url = f'{base_url}{path}'
            r = req_lib.get(url, timeout=5, verify=False, allow_redirects=False)
            if not r or r.status_code not in (200, 301, 302, 403):
                return None

            # Filter SPA catch-all
            if spa_hash and hash(r.text) == spa_hash:
                return None
            if homepage_hash and hash(r.text) == homepage_hash:
                return None

            body = r.text

            # Check for web shell signatures
            for pattern, shell_name in WEB_SHELL_SIGNATURES:
                if re.search(pattern, body, re.I):
                    return ('critical', f'Rootkit: {shell_name} detected at {path}',
                            f'Web shell signature match', url)

            # Check for suspicious file extensions in 200 responses
            if r.status_code == 200:
                content_type = r.headers.get('Content-Type', '').lower()
                body_len = len(r.text)

                # PHP file with code execution output
                if path.endswith('.php') and body_len > 0:
                    if any(func in body for func in ['eval(', 'exec(', 'system(', 'passthru(', 'shell_exec(']):
                        return ('critical', f'Rootkit: PHP code execution at {path}',
                                f'PHP file contains dangerous functions', url)

                # Backup files exposed
                if any(path.endswith(ext) for ext in ['.bak', '.old', '.orig', '.save', '.swp']):
                    return ('high', f'Rootkit: Backup file exposed at {path}',
                            f'Backup file accessible (size: {body_len} bytes)', url)

                # Log files exposed
                if any(log_name in path.lower() for log_name in ['access.log', 'error.log', 'debug.log', 'php_error.log']):
                    return ('medium', f'Rootkit: Log file exposed at {path}',
                            f'Log file accessible (size: {body_len} bytes)', url)

            # Check for directory listing
            if r.status_code == 200 and 'text/html' in r.headers.get('Content-Type', ''):
                if any(kw in body.lower() for kw in ['index of', 'directory listing', '<pre>', 'parent directory']):
                    return ('high', f'Rootkit: Directory listing at {path}',
                            f'Directory listing enabled', url)

            return None
        except Exception:
            return None

    # Scan web shell paths in parallel
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_path, path): path for path in WEB_SHELL_PATHS}
        for future in as_completed(futures, timeout=60):
            try:
                result = future.result(timeout=5)
                if result:
                    severity, title, detail, asset = result
                    add_finding(severity, title, sub=detail, asset=asset,
                                cvss='9.8' if severity == 'critical' else '7.5',
                                owasp='A01', mitre='T1190',
                                details=f'{detail}\nRemediation: Remove web shell files and investigate compromise',
                                confidence='high')
                    rootkit_findings += 1
            except Exception:
                pass

    # Check process hollowing indicators via response timing
    try:
        response_times = []
        for _ in range(10):
            r = req_lib.get(base_url, timeout=5, verify=False)
            response_times.append(len(r.text) if r else 0)
            time.sleep(0.1)

        avg = sum(response_times) / len(response_times)
        if avg > 0 and max(response_times) / avg > 3:
            add_finding('medium',
                        'Rootkit: Unusual response size variance',
                        sub='Response sizes vary >3x from average — possible process injection',
                        asset=base_url, cvss='5.0', owasp='A01', mitre='T1055',
                        details=f'Average size: {avg:.0f}, Max: {max(response_times)}, '
                                f'Min: {min(response_times)}\n'
                                f'Remediation: Investigate server for process injection',
                        confidence='low')
            rootkit_findings += 1
    except Exception:
        pass

    log('ok', f'[WAZUH-ROOTKIT] Complete: {rootkit_findings} rootkit indicators found')
    set_progress('rootkit', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: VULNERABILITY DETECTION — CVE Mapping
# ═══════════════════════════════════════════════════════════════════════════════

# Known CVE patterns for common software
CVE_SIGNATURES = [
    # Log4j
    (r'log4j|log4j-core|log4j-api', 'Log4j', [
        ('CVE-2021-44228', 'Log4Shell RCE', 'critical', 'JNDI injection in Log4j 2.x allows RCE'),
        ('CVE-2021-45046', 'Log4j RCE Bypass', 'critical', 'Incomplete fix for CVE-2021-44228'),
        ('CVE-2021-45105', 'Log4j DoS', 'high', 'Denial of Service via uncontrolled recursion'),
        ('CVE-2021-44832', 'Log4j RCE via JDBC', 'high', 'RCE via JDBC Appender with JNDI lookup'),
    ]),
    # Spring Framework
    (r'spring-framework|spring-boot|spring-core|spring\.framework|Spring Framework', 'Spring Framework', [
        ('CVE-2022-22965', 'Spring4Shell RCE', 'critical', 'RCE via data binding in Spring Framework 5.3.x'),
        ('CVE-2022-22950', 'Spring Expression DoS', 'high', 'DoS via SpEL expression evaluation'),
        ('CVE-2023-20863', 'Spring Expression DoS', 'high', 'DoS via Spring Expression evaluation'),
    ]),
    # Apache Struts
    (r'struts|org\.apache\.struts', 'Apache Struts', [
        ('CVE-2023-50164', 'Struts Upload RCE', 'critical', 'File upload RCE via path traversal'),
        ('CVE-2017-5638', 'Struts2 RCE', 'critical', 'RCE via Content-Type header OGNL injection'),
    ]),
    # PHPUnit
    (r'phpunit|phpunit\.php', 'PHPUnit', [
        ('CVE-2017-9841', 'PHPUnit RCE', 'critical', 'RCE via eval-stdin.php'),
        ('CVE-2020-15148', 'PHPUnit RCE', 'critical', 'RCE via bootstrap.php'),
    ]),
    # WordPress
    (r'wordpress|wp-content|wp-includes', 'WordPress', [
        ('CVE-2023-52435', 'WordPress DoS', 'high', 'Denial of Service via parsed HTML content'),
        ('CVE-2024-28000', 'WordPress Brute Force Bypass', 'medium', 'Weak hash allows brute-force bypass'),
    ]),
    # Laravel
    (r'laravel|illuminate', 'Laravel', [
        ('CVE-2021-3129', 'Laravel RCE', 'critical', 'RCE via Ignition log viewer'),
        ('CVE-2023-31410', 'Laravel API Rate Limiting Bypass', 'medium', 'API rate limiting bypass'),
    ]),
    # Django
    (r'django|csrfmiddleware', 'Django', [
        ('CVE-2023-31047', 'Django File Upload Bypass', 'high', 'File upload validation bypass'),
        ('CVE-2022-28346', 'Django SQL Injection', 'critical', 'SQL injection in QuerySet.annotate()'),
    ]),
    # Express.js
    (r'express|expressjs', 'Express.js', [
        ('CVE-2024-29041', 'Express Open Redirect', 'medium', 'Open redirect via URL parsing'),
    ]),
    # Nginx
    (r'nginx', 'Nginx', [
        ('CVE-2021-23017', 'Nginx DNS Resolver RCE', 'critical', 'RCE via DNS resolver'),
        ('CVE-2022-41741', 'Nginx mp4 Module RCE', 'critical', 'RCE via mp4 module'),
    ]),
    # Apache
    (r'apache|httpd', 'Apache HTTPD', [
        ('CVE-2021-41773', 'Apache Path Traversal', 'critical', 'Path traversal and RCE'),
        ('CVE-2021-42013', 'Apache Path Traversal Bypass', 'critical', 'Bypass of CVE-2021-41773 fix'),
    ]),
    # OpenSSL
    (r'openssl', 'OpenSSL', [
        ('CVE-2023-5678', 'OpenSSL DoS', 'medium', 'Denial of Service via DH key generation'),
        ('CVE-2023-5363', 'OpenSSL Key Handling', 'medium', 'Uninitialized memory during key derivation'),
    ]),
    # jQuery
    (r'jquery', 'jQuery', [
        ('CVE-2020-11022', 'jQuery XSS', 'medium', 'XSS in jQuery.extend()'),
        ('CVE-2020-11023', 'jQuery XSS', 'medium', 'XSS in jQuery.html()'),
    ]),
]


def run_vuln_detect_module(target):
    """Wazuh-style vulnerability detection via software fingerprinting"""
    log('ok', f'[WAZUH-VULN] Starting vulnerability detection for {target}')
    base_url = f'https://{target}'

    # Probe for SPA catch-all
    spa_hash = None
    try:
        probe_url = f'{base_url}/__vuln_probe_{secrets.token_hex(4)}__.txt'
        r = req_lib.get(probe_url, timeout=5, verify=False)
        if r and r.status_code == 200:
            spa_hash = hash(r.text)
    except Exception:
        pass

    homepage_hash = None
    try:
        r_home = req_lib.get(base_url, timeout=5, verify=False)
        if r_home:
            homepage_hash = hash(r_home.text)
    except Exception:
        pass

    vuln_findings = 0
    scanned_files = set()

    # Collect URLs to scan
    urls_to_scan = []
    try:
        disc = scan_state.get('discovery_data', {})
        for ep in disc.get('urls', []):
            url = ep if isinstance(ep, str) else ep.get('url', '')
            if url:
                urls_to_scan.append(url)
    except Exception:
        pass

    urls_to_scan.extend([base_url, f'{base_url}/'])
    urls_to_scan = list(set(urls_to_scan))[:50]

    def _scan_url(url):
        if not scan_state.get('scanning'):
            return []
        results = []
        try:
            r = req_lib.get(url, timeout=8, verify=False)
            if not r or r.status_code != 200:
                return results

            # Filter SPA catch-all
            if spa_hash and hash(r.text) == spa_hash:
                return results
            if homepage_hash and hash(r.text) == homepage_hash:
                return results

            body = r.text
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Check for software signatures
            for pattern, software, cves in CVE_SIGNATURES:
                if re.search(pattern, body, re.I):
                    for cve_id, cve_name, severity, cve_desc in cves:
                        results.append({
                            'severity': severity,
                            'title': f'{software}: {cve_name} ({cve_id})',
                            'asset': url,
                            'cvss': '9.8' if severity == 'critical' else '7.5' if severity == 'high' else '5.0',
                            'details': f'CVE: {cve_id}\nSoftware: {software}\n'
                                      f'Description: {cve_desc}\n'
                                      f'Remediation: Update to latest patched version',
                        })
                    break  # Only match once per software

            # Check for version disclosure
            version_patterns = [
                (r'X-Powered-By:\s*(\S+)', 'Server technology version'),
                (r'Server:\s*(\S+)', 'Server version'),
                (r'X-AspNet-Version:\s*(\S+)', 'ASP.NET version'),
                (r'X-Generator:\s*(\S+)', 'CMS generator'),
            ]
            for pattern, desc in version_patterns:
                match = re.search(pattern, str(headers), re.I)
                if match:
                    version_info = match.group(1)
                    results.append({
                        'severity': 'info',
                        'title': f'Version disclosure: {desc}',
                        'asset': url,
                        'cvss': '0.0',
                        'details': f'Version: {version_info}\n'
                                  f'Remediation: Remove version headers',
                    })

            # Check for debug mode indicators
            debug_patterns = [
                (r'DEBUG\s*=\s*True|debug.*mode.*enabled', 'Django debug mode'),
                (r'APP_DEBUG|laravel_debug|debug.*true', 'Application debug mode'),
                (r'Stack Trace:|Exception in|Traceback \(most recent', 'Error stack trace exposed'),
                (r'mysql_connect|mysqli_connect|pg_connect', 'Database connection string'),
                (r'DB_PASSWORD|DB_HOST|DB_USER|DATABASE_URL', 'Database credentials in HTML'),
            ]
            for pattern, desc in debug_patterns:
                if re.search(pattern, body, re.I):
                    results.append({
                        'severity': 'high',
                        'title': f'Debug information exposed: {desc}',
                        'asset': url,
                        'cvss': '7.5',
                        'details': f'Pattern: {desc}\n'
                                  f'Remediation: Disable debug mode in production',
                    })

            # Check for insecure headers
            security_headers = {
                'strict-transport-security': 'HSTS',
                'x-content-type-options': 'X-Content-Type-Options',
                'x-frame-options': 'X-Frame-Options',
                'content-security-policy': 'Content-Security-Policy',
                'x-xss-protection': 'X-XSS-Protection',
            }
            for header, name in security_headers.items():
                if header not in headers:
                    results.append({
                        'severity': 'low',
                        'title': f'Missing security header: {name}',
                        'asset': url,
                        'cvss': '3.0',
                        'details': f'Header: {name}\n'
                                  f'Remediation: Add {name} header to response',
                    })

        except Exception:
            pass
        return results

    # Scan URLs in parallel
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_scan_url, url): url for url in urls_to_scan}
        for future in as_completed(futures, timeout=120):
            try:
                results = future.result(timeout=10)
                for r in results:
                    add_finding(r['severity'], r['title'],
                                sub=r.get('details', ''), asset=r['asset'],
                                cvss=r['cvss'], owasp='A06', mitre='T1190',
                                details=r.get('details', ''),
                                confidence='medium')
                    vuln_findings += 1
            except Exception:
                pass

    log('ok', f'[WAZUH-VULN] Complete: {vuln_findings} vulnerability indicators found')
    set_progress('vuln_detect', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: LOG ANALYSIS — Error Log Exposure
# ═══════════════════════════════════════════════════════════════════════════════

LOG_PATHS = [
    '/var/log/apache2/access.log', '/var/log/apache2/error.log',
    '/var/log/nginx/access.log', '/var/log/nginx/error.log',
    '/var/log/auth.log', '/var/log/syslog',
    '/var/log/mysql/mysql.log', '/var/log/mysql/error.log',
    '/var/log/postgresql/postgresql.log',
    '/var/log/php_errors.log', '/var/log/php7.4-fpm.log',
    '/var/log/tomcat/catalina.out', '/var/log/tomcat/localhost_access_log.txt',
    '/var/log/jenkins/jenkins.log',
    '/var/log/redis/redis-server.log',
    '/var/log/mongodb/mongod.log',
    '/proc/self/environ', '/proc/version',
    '/tmp/debug.log', '/tmp/error.log',
]

LOG_MARKERS = [
    (r'GET\s+/\S+\s+\d{3}', 'Apache/Nginx access log'),
    (r'\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2}', 'Timestamped log entry'),
    (r'ERROR|WARN|FATAL|CRITICAL', 'Log level indicator'),
    (r'PHP\s+(Fatal|Parse|Warning)\s+error', 'PHP error log'),
    (r'mysqld|mysql_error|MySQL.*error', 'MySQL error log'),
    (r'postgresql.*ERROR|psql.*error', 'PostgreSQL error log'),
    (r'segfault|core dumped|signal\s+\d+', 'System crash log'),
    (r'password|passwd|credential|token', 'Sensitive data in logs'),
    (r'\d+\.\d+\.\d+\.\d+', 'IP address in logs'),
    (r'SSH|sshd|login.*failed', 'Authentication log'),
    (r'Exception|Traceback|stack trace', 'Application error log'),
]


def run_log_analysis_module(target):
    """Wazuh-style log analysis — check for exposed log files"""
    log('ok', f'[WAZUH-LOG] Starting log analysis for {target}')
    base_url = f'https://{target}'

    # Probe for SPA catch-all
    spa_hash = None
    try:
        probe_url = f'{base_url}/__log_probe_{secrets.token_hex(4)}__.txt'
        r = req_lib.get(probe_url, timeout=5, verify=False)
        if r and r.status_code == 200:
            spa_hash = hash(r.text)
    except Exception:
        pass

    homepage_hash = None
    try:
        r_home = req_lib.get(base_url, timeout=5, verify=False)
        if r_home:
            homepage_hash = hash(r_home.text)
    except Exception:
        pass

    log_findings = 0

    def _check_log_path(path):
        if not scan_state.get('scanning'):
            return None
        try:
            url = f'{base_url}{path}'
            r = req_lib.get(url, timeout=5, verify=False, allow_redirects=False)
            if not r or r.status_code != 200:
                return None

            # Filter SPA catch-all
            if spa_hash and hash(r.text) == spa_hash:
                return None
            if homepage_hash and hash(r.text) == homepage_hash:
                return None

            body = r.text
            content_type = r.headers.get('Content-Type', '').lower()

            # Check if it's actually a log file
            is_log = False
            log_type = 'Unknown'
            for pattern, ltype in LOG_MARKERS:
                if re.search(pattern, body, re.I):
                    is_log = True
                    log_type = ltype
                    break

            if is_log:
                severity = 'critical' if any(s in body.lower() for s in ['password', 'credential', 'token', 'secret']) else 'high'
                return {
                    'severity': severity,
                    'title': f'Log file exposed: {path}',
                    'asset': url,
                    'details': f'Log type: {log_type}\nSize: {len(body)} bytes\n'
                              f'Remediation: Restrict access to log files',
                }

            return None
        except Exception:
            return None

    # Check log paths in parallel
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_log_path, path): path for path in LOG_PATHS}
        for future in as_completed(futures, timeout=60):
            try:
                result = future.result(timeout=5)
                if result:
                    add_finding(result['severity'], result['title'],
                                sub=result['details'], asset=result['asset'],
                                cvss='7.5', owasp='A01', mitre='T1005',
                                details=result['details'],
                                confidence='high')
                    log_findings += 1
            except Exception:
                pass

    log('ok', f'[WAZUH-LOG] Complete: {log_findings} exposed log files found')
    set_progress('log_analysis', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5: COMPLIANCE CHECKS — PCI DSS, HIPAA, GDPR
# ═══════════════════════════════════════════════════════════════════════════════

COMPLIANCE_RULES = {
    'PCI-DSS': [
        ('PCI-DSS 1.3.1', 'Direct database access from internet', 'critical',
         r'(?:mysql|postgres|mongodb|redis)://[^\s]+|:\d{4,5}/\?password=|DB_PASSWORD|DATABASE_URL'),
        ('PCI-DSS 2.1', 'Default credentials', 'high',
         r'(?:admin|root|password|default)\s*[:=]\s*["\'](?:admin|root|password|default|1234|test)["\']'),
        ('PCI-DSS 2.2.1', 'Unnecessary services', 'medium',
         r'(?:telnet|ftp|smtp)\s+["\']?\d+\.\d+\.\d+\.\d+'),
        ('PCI-DSS 3.4', 'PAN storage', 'critical',
         r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
        ('PCI-DSS 4.1', 'Weak encryption', 'high',
         r'(?:SSL|TLS)\s*(?:v?2|v?3|1\.0)\b|DES|RC4|MD5'),
        ('PCI-DSS 6.5.1', 'SQL injection', 'critical',
         r'SELECT.*FROM.*WHERE.*=.*\'|INSERT.*INTO.*VALUES|UNION.*SELECT'),
        ('PCI-DSS 6.5.6', 'Information leakage', 'high',
         r'X-Powered-By|Server:\s*\S+|X-AspNet-Version'),
        ('PCI-DSS 10.2', 'Audit logging disabled', 'medium',
         r'AUDIT.*OFF|LOG.*NONE|logging.*disabled'),
    ],
    'HIPAA': [
        ('HIPAA §164.312', 'Encryption required', 'high',
         r'patient|health|medical|diagnosis|treatment|PHI'),
        ('HIPAA §164.312', 'Access controls', 'high',
         r'admin\s*[:=]\s*["\'].*["\']|default.*password'),
        ('HIPAA §164.312', 'Audit controls', 'medium',
         r'audit.*log.*disabled|logging.*off'),
        ('HIPAA §164.312', 'Data integrity', 'high',
         r'checksum.*mismatch|integrity.*failed|tampered'),
    ],
    'GDPR': [
        ('GDPR Art. 5', 'Data minimization', 'medium',
         r'collect.*all.*data|store.*everything|log.*all'),
        ('GDPR Art. 25', 'Privacy by design', 'medium',
         r'debug.*mode.*true|DEBUG\s*=\s*True'),
        ('GDPR Art. 32', 'Security of processing', 'high',
         r'(?:mysql|postgres|mongodb)://[^\s]+|:\d{4,5}/\?password='),
        ('GDPR Art. 33', 'Breach notification', 'medium',
         r'error.*log.*exposed|stack.*trace.*exposed'),
    ],
    'OWASP Top 10': [
        ('A01:2021', 'Broken Access Control', 'critical',
         r'admin.*panel|/admin|/debug|/console'),
        ('A02:2021', 'Cryptographic Failures', 'high',
         r'(?:SSL|TLS)\s*(?:v?2|v?3|1\.0)\b|DES|RC4|MD5'),
        ('A03:2021', 'Injection', 'critical',
         r'SELECT.*FROM|UNION.*SELECT|<script>|javascript:'),
        ('A05:2021', 'Security Misconfiguration', 'high',
         r'debug.*mode.*true|default.*password|admin.*password'),
        ('A06:2021', 'Vulnerable Components', 'high',
         r'log4j|spring-framework|jquery|phpunit'),
        ('A07:2021', 'Auth Failures', 'high',
         r'brute.*force|rate.*limit.*bypass|no.*captcha'),
        ('A08:2021', 'Integrity Failures', 'high',
         r'unsigned.*update|no.*checksum|integrity.*check.*disabled'),
        ('A09:2021', 'Logging Failures', 'medium',
         r'log.*disabled|audit.*off|logging.*none'),
        ('A10:2021', 'SSRF', 'high',
         r'127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254'),
    ],
}


def run_compliance_check_module(target):
    """Wazuh-style compliance checks — PCI DSS, HIPAA, GDPR, OWASP"""
    log('ok', f'[WAZUH-COMPLIANCE] Starting compliance checks for {target}')
    base_url = f'https://{target}'

    # Probe for SPA catch-all
    spa_hash = None
    try:
        probe_url = f'{base_url}/__compliance_probe_{secrets.token_hex(4)}__.txt'
        r = req_lib.get(probe_url, timeout=5, verify=False)
        if r and r.status_code == 200:
            spa_hash = hash(r.text)
    except Exception:
        pass

    homepage_hash = None
    try:
        r_home = req_lib.get(base_url, timeout=5, verify=False)
        if r_home:
            homepage_hash = hash(r_home.text)
    except Exception:
        pass

    compliance_findings = 0
    urls_to_scan = []

    try:
        disc = scan_state.get('discovery_data', {})
        for ep in disc.get('urls', []):
            url = ep if isinstance(ep, str) else ep.get('url', '')
            if url:
                urls_to_scan.append(url)
    except Exception:
        pass

    urls_to_scan.extend([base_url, f'{base_url}/'])
    urls_to_scan = list(set(urls_to_scan))[:30]

    def _check_compliance(url):
        if not scan_state.get('scanning'):
            return []
        results = []
        try:
            r = req_lib.get(url, timeout=8, verify=False)
            if not r or r.status_code != 200:
                return results

            # Filter SPA catch-all
            if spa_hash and hash(r.text) == spa_hash:
                return results
            if homepage_hash and hash(r.text) == homepage_hash:
                return results

            body = r.text
            headers = {k.lower(): v for k, v in r.headers.items()}

            for framework, rules in COMPLIANCE_RULES.items():
                for rule_id, rule_name, severity, pattern in rules:
                    if re.search(pattern, body, re.I):
                        results.append({
                            'severity': severity,
                            'title': f'{framework} {rule_id}: {rule_name}',
                            'asset': url,
                            'details': f'Framework: {framework}\nRule: {rule_id} - {rule_name}\n'
                                      f'Pattern matched: {pattern[:50]}...\n'
                                      f'Remediation: Address {rule_name} compliance requirement',
                        })

            # Check security headers for compliance
            required_headers = {
                'strict-transport-security': ('PCI-DSS 4.1', 'HSTS required'),
                'x-content-type-options': ('PCI-DSS 6.5.6', 'MIME type sniffing prevention'),
                'content-security-policy': ('PCI-DSS 6.5.7', 'XSS prevention'),
                'x-frame-options': ('OWASP A01', 'Clickjacking prevention'),
            }
            for header, (rule_id, desc) in required_headers.items():
                if header not in headers:
                    results.append({
                        'severity': 'medium',
                        'title': f'{rule_id}: Missing {desc}',
                        'asset': url,
                        'details': f'Header: {header}\nRule: {rule_id}\n'
                                  f'Remediation: Add {header} header',
                    })

        except Exception:
            pass
        return results

    # Check URLs in parallel
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_compliance, url): url for url in urls_to_scan}
        for future in as_completed(futures, timeout=120):
            try:
                results = future.result(timeout=10)
                for r in results:
                    add_finding(r['severity'], r['title'],
                                sub=r['details'], asset=r['asset'],
                                cvss='9.8' if r['severity'] == 'critical' else '7.5' if r['severity'] == 'high' else '5.0',
                                owasp='A01', mitre='T1190',
                                details=r['details'],
                                confidence='medium')
                    compliance_findings += 1
            except Exception:
                pass

    log('ok', f'[WAZUH-COMPLIANCE] Complete: {compliance_findings} compliance violations found')
    set_progress('compliance', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN WAZUH ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════
