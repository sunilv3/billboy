"""Confirmation Protocol (FULL) — deterministic repro, T-test, minimization, scoring, evidence bundle."""
import time
import math
from core.logger import log
from core.utils import req_lib, REQUESTS_AVAILABLE

CONFIDENCE_WEIGHTS = {
    'deterministic': 20, 'strong_oracle': 30, 'minimized': 10,
    'no_rate_limit': 10, 'no_known_pattern': 10, 'manual_verify': -20,
}
KNOWN_PATTERNS = {
    'sqli': ['sqlmap', 'sqli-error'], 'xss': ['dalfox', 'xss-reflected'],
    'ssrf': ['ssrf-internal'], 'command_injection': ['commix', 'cmdi'],
    'xxe': ['xxe-basic'], 'path_traversal': ['lfi-basic'],
}

def _test_determinism(url, param, payload, method='GET', max_attempts=3):
    if not REQUESTS_AVAILABLE or not req_lib: return False, 0, []
    results = []
    for i in range(max_attempts):
        try:
            start = time.time()
            if method == 'GET':
                resp = req_lib.get(url, params={param: payload}, timeout=10, verify=False)
            else:
                resp = req_lib.post(url, json={param: payload}, timeout=10, verify=False)
            elapsed = (time.time() - start) * 1000
            results.append({'status': resp.status_code, 'length': len(resp.text or ''),
                           'time_ms': elapsed, 'body': resp.text[:5000] if resp.text else ''})
            time.sleep(0.5)
        except Exception as e:
            results.append({'error': str(e)})
    valid = [r for r in results if 'error' not in r and r.get('status')]
    if len(valid) < max_attempts: return False, len(valid), results
    statuses = [r['status'] for r in valid]
    lengths = [r['length'] for r in valid]
    is_det = len(set(statuses)) == 1 and max(lengths) - min(lengths) < 100
    return is_det, len(valid), results

def _welch_t_test(sample1, sample2):
    """Welch's t-test for two independent samples. Returns (t_stat, p_value_approx)."""
    n1, n2 = len(sample1), len(sample2)
    if n1 < 2 or n2 < 2: return 0, 1.0
    m1 = sum(sample1) / n1
    m2 = sum(sample2) / n2
    v1 = sum((x - m1) ** 2 for x in sample1) / (n1 - 1) if n1 > 1 else 0
    v2 = sum((x - m2) ** 2 for x in sample2) / (n2 - 1) if n2 > 1 else 0
    se = math.sqrt(v1 / n1 + v2 / n2) if (v1 / n1 + v2 / n2) > 0 else 1
    t_stat = (m1 - m2) / se if se > 0 else 0
    # Approximate p-value using t-distribution (simplified)
    df = n1 + n2 - 2
    # Use normal approximation for large df
    if df > 30:
        z = abs(t_stat)
        p = 2 * (1 - 0.5 * (1 + math.erf(z / math.sqrt(2))))
    else:
        # Rough approximation
        p = max(0.001, 1.0 - min(abs(t_stat) / 3, 0.999))
    return round(t_stat, 3), round(p, 4)

def _minimize_payload(url, param, full_payload, method='GET'):
    if not REQUESTS_AVAILABLE or not req_lib: return full_payload
    def is_vulnerable(p):
        try:
            if method == 'GET':
                resp = req_lib.get(url, params={param: p}, timeout=10, verify=False)
            else:
                resp = req_lib.post(url, json={param: p}, timeout=10, verify=False)
            return resp.status_code >= 400 or len(resp.text or '') > 100
        except: return False
    best = full_payload
    for i in range(len(full_payload) - 1, max(0, len(full_payload) // 2), -1):
        candidate = full_payload[:i] + full_payload[i+1:]
        if is_vulnerable(candidate):
            best = candidate
            break
    return best

def _check_known_pattern(vuln_type, title, details):
    title_lower = (title or '').lower()
    if vuln_type in KNOWN_PATTERNS:
        for sig in KNOWN_PATTERNS[vuln_type]:
            if sig in title_lower: return 'KNOWN_PATTERN', sig
    return 'CANDIDATE_NOVEL', None

def confirm_finding(finding, url, param, payload, method='GET', oracle_callback=None):
    log('info', f'[CONFIRM] Starting: {finding.get("title","")[:60]}')
    result = {
        'finding_id': finding.get('id', ''), 'classification': 'INCONCLUSIVE',
        'novelty': 'CANDIDATE_NOVEL', 'known_reference': None,
        'confidence': 0, 'reproducible_count': 0,
        'evidence_bundle': {}, 'minimized_poc': None,
    }
    is_det, success_count, reproduction_results = _test_determinism(url, param, payload, method, 3)
    result['reproducible_count'] = success_count
    if not is_det:
        result['confidence'] = 20
        return result
    oracle_verified = False
    oracle_type = None
    if oracle_callback:
        oracle_verified = oracle_callback()
        oracle_type = 'oob'
    if not oracle_verified and reproduction_results:
        body = reproduction_results[0].get('body', '').lower()
        for markers, otype in [
            (['sql syntax', 'mysql', 'sqlite', 'ora-', 'sqlstate'], 'error_based'),
            (['<script>alert', 'onerror=alert', 'javascript:'], 'reflected'),
            (['uid=', 'gid=', 'root:'], 'command_output'),
            (['root:x:0:0', '/bin/bash'], 'file_content'),
            (['ami-id', 'instance-id', 'security-credentials'], 'metadata'),
        ]:
            if any(m in body for m in markers):
                oracle_verified = True
                oracle_type = otype
                break
    # T-test: 5 normal + 5 trigger samples
    normal_times = []
    trigger_times = []
    for _ in range(5):
        try:
            start = time.time()
            if method == 'GET': req_lib.get(url, timeout=10, verify=False)
            else: req_lib.post(url, json={param: 'normal'}, timeout=10, verify=False)
            normal_times.append((time.time() - start) * 1000)
            time.sleep(0.3)
        except: pass
    for _ in range(5):
        try:
            start = time.time()
            if method == 'GET': req_lib.get(url, params={param: payload}, timeout=10, verify=False)
            else: req_lib.post(url, json={param: payload}, timeout=10, verify=False)
            trigger_times.append((time.time() - start) * 1000)
            time.sleep(0.3)
        except: pass
    t_stat, p_value = _welch_t_test(trigger_times, normal_times)
    if p_value < 0.05 and not oracle_verified:
        oracle_verified = True
        oracle_type = 'time_based'
    minimized = _minimize_payload(url, param, payload, method)
    result['minimized_poc'] = minimized
    vuln_type = finding.get('type', 'unknown')
    novelty, known_ref = _check_known_pattern(vuln_type, finding.get('title', ''), finding.get('details', ''))
    result['novelty'] = novelty
    result['known_reference'] = known_ref
    score = 0
    score += CONFIDENCE_WEIGHTS['deterministic']
    if oracle_verified: score += CONFIDENCE_WEIGHTS['strong_oracle']
    if minimized != payload: score += CONFIDENCE_WEIGHTS['minimized']
    score += CONFIDENCE_WEIGHTS['no_rate_limit']
    if novelty == 'CANDIDATE_NOVEL': score += CONFIDENCE_WEIGHTS['no_known_pattern']
    if not oracle_verified: score += CONFIDENCE_WEIGHTS['manual_verify']
    result['confidence'] = max(0, min(100, score))
    result['classification'] = 'CONFIRMED' if result['confidence'] >= 80 else ('POTENTIAL' if result['confidence'] >= 50 else 'INCONCLUSIVE')
    result['evidence_bundle'] = {
        'raw_request': f'{method} {url} {param}={payload}',
        'raw_response': reproduction_results[0] if reproduction_results else {},
        'oob_callback': oracle_callback() if oracle_callback and oracle_verified else None,
        'minimized_poc': minimized,
        'reproduction_script': f"curl -s '{url}?{param}={payload}'" if method == 'GET' else f"curl -s -X POST '{url}' -d '{{\"{param}\":\"{payload}\"}}'",
        'reproduction_results': reproduction_results,
        't_test': {'t_statistic': t_stat, 'p_value': p_value, 'normal_mean_ms': round(sum(normal_times)/max(1,len(normal_times)),1), 'trigger_mean_ms': round(sum(trigger_times)/max(1,len(trigger_times)),1)},
    }
    log('ok', f'[CONFIRM] {result["classification"]} (conf={result["confidence"]}, oracle={oracle_type}, p={p_value})')
    return result

def confirm_findings_batch(findings, target):
    confirmed = []
    for finding in findings:
        url = finding.get('asset', target)
        param = finding.get('param', '')
        payload = finding.get('payload', '')
        if not url or not payload: continue
        result = confirm_finding(finding, url, param, payload)
        if result['classification'] in ('CONFIRMED', 'POTENTIAL'):
            finding['confirmation'] = result
            finding['confidence_score'] = result['confidence']
            confirmed.append(finding)
    return confirmed
