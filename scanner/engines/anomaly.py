"""ENGINE 2: Differential / Anomaly Detection.

Builds statistical baselines per endpoint and flags anomalies based on
response time, length, status code, and error patterns.
"""
import time
import statistics
import threading
from collections import defaultdict
from core.logger import log
from core.utils import req_lib, REQUESTS_AVAILABLE
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding

# ── Statistical baseline ───────────────────────────────────────────────────────

class EndpointBaseline:
    """Statistical baseline for a single endpoint."""

    def __init__(self, url, method='GET', param=None):
        self.url = url
        self.method = method
        self.param = param
        self.samples = []
        self.status_codes = defaultdict(int)
        self.error_count = 0
        self.total_count = 0
        self._lock = threading.Lock()

    def add_sample(self, status, elapsed_ms, length, has_error=False):
        with self._lock:
            self.samples.append({
                'status': status,
                'time_ms': elapsed_ms,
                'length': length,
                'has_error': has_error,
            })
            self.status_codes[status] += 1
            self.total_count += 1
            if has_error:
                self.error_count += 1

    @property
    def ready(self):
        return self.total_count >= 30

    def get_stats(self):
        with self._lock:
            if not self.samples:
                return None
            times = [s['time_ms'] for s in self.samples]
            lengths = [s['length'] for s in self.samples]
            return {
                'time_mean': statistics.mean(times),
                'time_std': statistics.stdev(times) if len(times) > 1 else 0,
                'length_mean': statistics.mean(lengths),
                'length_std': statistics.stdev(lengths) if len(lengths) > 1 else 0,
                'status_codes': dict(self.status_codes),
                'error_rate': self.error_count / max(1, self.total_count),
                'total_samples': self.total_count,
            }

    def detect_anomaly(self, status, elapsed_ms, length, has_error=False):
        """Check if a new observation is an anomaly (Z-score > 3.0)."""
        stats = self.get_stats()
        if not stats or stats['total_samples'] < 10:
            return None

        anomalies = []

        # Time anomaly
        if stats['time_std'] > 0:
            time_z = (elapsed_ms - stats['time_mean']) / stats['time_std']
            if abs(time_z) > 3.0:
                anomalies.append(('time', time_z, f'Response time {elapsed_ms:.0f}ms '
                               f'(baseline: {stats["time_mean"]:.0f}ms ± {stats["time_std"]:.0f}ms)'))

        # Length anomaly
        if stats['length_std'] > 0:
            length_z = (length - stats['length_mean']) / stats['length_std']
            if abs(length_z) > 3.0:
                anomalies.append(('length', length_z, f'Response length {length} '
                                f'(baseline: {stats["length_mean"]:.0f} ± {stats["length_std"]:.0f})'))

        # New status code
        known_statuses = set(stats['status_codes'].keys())
        if status not in known_statuses and stats['total_samples'] >= 20:
            anomalies.append(('status', 0, f'New status code {status} '
                            f'(known: {sorted(known_statuses)})'))

        # Error rate spike
        if has_error and stats['error_rate'] < 0.1:
            anomalies.append(('error', 0, f'Error response (baseline error rate: '
                            f'{stats["error_rate"]:.1%})'))

        return anomalies if anomalies else None


# ── Anomaly investigation ──────────────────────────────────────────────────────

def _investigate_anomaly(engine, url, param, anomaly_type, method='GET'):
    """Run targeted follow-up tests on an anomalous endpoint."""
    if not REQUESTS_AVAILABLE or not req_lib:
        return None

    log('info', f'[ANOMALY] Investigating {anomaly_type} anomaly on {url} param={param}')

    # Re-test with normal input (5 times)
    normal_samples = []
    for _ in range(5):
        try:
            start = time.time()
            if method == 'GET':
                resp = req_lib.get(url, timeout=10, verify=False)
            else:
                resp = req_lib.post(url, json={param: 'test'} if param else {},
                                   timeout=10, verify=False)
            elapsed = (time.time() - start) * 1000
            normal_samples.append({
                'status': resp.status_code,
                'time_ms': elapsed,
                'length': len(resp.text or ''),
            })
            time.sleep(0.3)
        except Exception:
            pass

    if len(normal_samples) < 3:
        return None

    # Re-test with suspected trigger
    trigger_samples = []
    trigger_payloads = {
        'sqli': "' OR '1'='1",
        'xss': '<script>alert(1)</script>',
        'cmdi': '; id',
        'ssrf': 'http://127.0.0.1',
        'traversal': '../../../../etc/passwd',
    }
    payload = trigger_payloads.get(anomaly_type, 'test_payload')

    for _ in range(5):
        try:
            start = time.time()
            if method == 'GET':
                resp = req_lib.get(url, params={param: payload} if param else {},
                                  timeout=10, verify=False)
            else:
                resp = req_lib.post(url, json={param: payload} if param else {},
                                   timeout=10, verify=False)
            elapsed = (time.time() - start) * 1000
            trigger_samples.append({
                'status': resp.status_code,
                'time_ms': elapsed,
                'length': len(resp.text or ''),
                'body': resp.text[:5000] if resp.text else '',
            })
            time.sleep(0.3)
        except Exception:
            pass

    if len(trigger_samples) < 3:
        return None

    # Statistical comparison
    normal_times = [s['time_ms'] for s in normal_samples]
    trigger_times = [s['time_ms'] for s in trigger_samples]
    normal_lengths = [s['length'] for s in normal_samples]
    trigger_lengths = [s['length'] for s in trigger_samples]

    # Check for deterministic difference
    if len(normal_times) >= 3 and len(trigger_times) >= 3:
        time_diff = abs(statistics.mean(trigger_times) - statistics.mean(normal_times))
        length_diff = abs(statistics.mean(trigger_lengths) - statistics.mean(normal_lengths))

        # Check if trigger consistently produces different results
        trigger_statuses = [s['status'] for s in trigger_samples]
        normal_statuses = [s['status'] for s in normal_samples]

        # Deterministic = all trigger samples differ from all normal samples
        deterministic = (
            (trigger_statuses[0] != normal_statuses[0] and
             all(s == trigger_statuses[0] for s in trigger_statuses)) or
            (time_diff > 500 and statistics.stdev(trigger_times) < 200) or
            (length_diff > 1000 and statistics.stdev(trigger_lengths) < 500)
        )

        if deterministic:
            # Check for vulnerability indicators in response
            body = trigger_samples[0].get('body', '')
            body_lower = body.lower()
            evidence = []

            if anomaly_type == 'sqli':
                sqli_markers = ['sql syntax', 'mysql', 'sqlite', 'ora-', 'sqlstate']
                if any(m in body_lower for m in sqli_markers):
                    evidence.append(f'SQL error: {[m for m in sqli_markers if m in body_lower][0]}')

            elif anomaly_type == 'xss':
                if '<script>' in body_lower or 'alert(' in body_lower:
                    evidence.append('Reflected XSS payload in response')

            elif anomaly_type == 'cmdi':
                cmdi_markers = ['uid=', 'gid=', 'root:']
                if any(m in body for m in cmdi_markers):
                    evidence.append(f'Command output: {[m for m in cmdi_markers if m in body][0]}')

            elif anomaly_type == 'traversal':
                traversal_markers = ['root:x:0:0', '/bin/bash', 'etc/passwd']
                if any(m in body for m in traversal_markers):
                    evidence.append('File content disclosed')

            if evidence:
                return {
                    'deterministic': True,
                    'evidence': evidence,
                    'normal_stats': {
                        'mean_time': statistics.mean(normal_times),
                        'mean_length': statistics.mean(normal_lengths),
                        'statuses': normal_statuses,
                    },
                    'trigger_stats': {
                        'mean_time': statistics.mean(trigger_times),
                        'mean_length': statistics.mean(trigger_lengths),
                        'statuses': trigger_statuses,
                    },
                    'body': body[:1000],
                }

    return {'deterministic': False}


# ── Engine core ────────────────────────────────────────────────────────────────

class AnomalyEngine:
    """Differential / anomaly detection engine.

    Builds statistical baselines per endpoint (minimum 30 samples) and flags
    anomalies with Z-score > 3.0 for time, length, status, or error rate.
    """

    def __init__(self, target, max_endpoints=50, baseline_samples=30):
        self.target = target
        self.max_endpoints = max_endpoints
        self.baseline_samples = baseline_samples
        self.baselines = {}  # url -> EndpointBaseline
        self.request_count = 0
        self.findings = []
        self._lock = threading.Lock()

    def _probe_endpoint(self, url, method='GET', param=None):
        """Send a probe request and record the sample."""
        if not REQUESTS_AVAILABLE or not req_lib:
            return

        try:
            start = time.time()
            if method == 'GET':
                resp = req_lib.get(url, timeout=10, verify=False)
            else:
                resp = req_lib.post(url, json={param: 'baseline'} if param else {},
                                   timeout=10, verify=False)
            elapsed = (time.time() - start) * 1000
            body = resp.text or ''
            has_error = any(m in body.lower() for m in ['traceback', 'exception', 'error in'])

            with self._lock:
                if url not in self.baselines:
                    self.baselines[url] = EndpointBaseline(url, method, param)
                self.baselines[url].add_sample(resp.status_code, elapsed, len(body), has_error)
                self.request_count += 1

        except Exception:
            pass

    def _build_baseline(self, endpoints):
        """Build statistical baseline for each endpoint (minimum 30 samples)."""
        log('info', f'[ANOMALY] Building baseline for {len(endpoints)} endpoints '
                    f'({self.baseline_samples} samples each)')

        for url, method, param in endpoints:
            if len(self.baselines) >= self.max_endpoints:
                break
            for _ in range(self.baseline_samples):
                self._probe_endpoint(url, method, param)
                time.sleep(0.05)  # gentle pacing

        ready_count = sum(1 for b in self.baselines.values() if b.ready)
        log('ok', f'[ANOMALY] Baseline complete: {ready_count}/{len(self.baselines)} endpoints ready')

    def run(self, endpoints):
        """Run anomaly detection engine.

        Args:
            endpoints: list of (url, method, param) tuples

        Returns:
            dict with anomalies found, findings, request count
        """
        if not REQUESTS_AVAILABLE:
            log('warn', '[ANOMALY] requests library not available — skipping')
            return {'anomalies': [], 'findings': [], 'requests': 0}

        log('info', f'[ANOMALY] Starting anomaly detection against {len(endpoints)} endpoints')

        # Phase 1: Build baseline
        self._build_baseline(endpoints[:self.max_endpoints])

        # Phase 2: Test with mutations and detect anomalies
        anomalies_found = []
        for url, method, param in self.baselines.keys():
            baseline = self.baselines[url]
            if not baseline.ready:
                continue

            # Send 10 mutated requests
            for i in range(10):
                test_payloads = [
                    "' OR '1'='1",
                    '<script>alert(1)</script>',
                    '../../../../etc/passwd',
                    '; id',
                    'http://127.0.0.1',
                    'None',
                    '',
                    '999999999',
                    '\x00',
                    'A' * 10000,
                ]
                payload = test_payloads[i % len(test_payloads)]

                try:
                    start = time.time()
                    if method == 'GET':
                        resp = req_lib.get(url, params={param: payload} if param else {},
                                          timeout=10, verify=False)
                    else:
                        resp = req_lib.post(url, json={param: payload} if param else {},
                                           timeout=10, verify=False)
                    elapsed = (time.time() - start) * 1000
                    body = resp.text or ''
                    has_error = any(m in body.lower() for m in ['traceback', 'exception', 'error in'])

                    # Check for anomaly
                    anomaly_list = baseline.detect_anomaly(
                        resp.status_code, elapsed, len(body), has_error
                    )

                    if anomaly_list:
                        for anom_type, z_score, description in anomaly_list:
                            anomaly_key = f'{url}|{param}|{anom_type}'
                            with self._lock:
                                if anomaly_key not in [a['key'] for a in anomalies_found]:
                                    anomaly_info = {
                                        'key': anomaly_key,
                                        'url': url,
                                        'param': param,
                                        'type': anom_type,
                                        'z_score': z_score,
                                        'description': description,
                                        'trigger': payload,
                                        'status': resp.status_code,
                                        'body': body[:1000],
                                    }
                                    anomalies_found.append(anomaly_info)

                                    # Investigate
                                    result = _investigate_anomaly(
                                        self, url, param, anom_type, method
                                    )
                                    if result and result.get('deterministic'):
                                        # Confirmed finding
                                        evidence_text = '\n'.join(result.get('evidence', []))
                                        try:
                                            add_finding(
                                                sev='high' if anom_type != 'status' else 'medium',
                                                title=f'Anomaly confirmed: {anom_type} on {param or "endpoint"}',
                                                sub=f'Anomaly engine — {anom_type}',
                                                asset=url,
                                                details=f'Description: {description}\n'
                                                        f'Evidence: {evidence_text}\n'
                                                        f'Normal: mean_time={result["normal_stats"]["mean_time"]:.0f}ms, '
                                                        f'length={result["normal_stats"]["mean_length"]:.0f}\n'
                                                        f'Trigger: mean_time={result["trigger_stats"]["mean_time"]:.0f}ms, '
                                                        f'length={result["trigger_stats"]["mean_length"]:.0f}\n'
                                                        f'Body: {result.get("body", "")[:500]}',
                                                confidence='high',
                                            )
                                            self.findings.append(anomaly_info)
                                        except Exception:
                                            pass

                    time.sleep(0.05)
                except Exception:
                    pass

        log('ok', f'[ANOMALY] Complete: {len(anomalies_found)} anomalies, '
                  f'{len(self.findings)} confirmed findings, {self.request_count} requests')

        return {
            'anomalies': anomalies_found,
            'findings': self.findings,
            'requests': self.request_count,
        }
