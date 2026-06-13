"""Target Health Monitoring (FULL) — error rate, response time trend, connection resets, auto-pause."""
import time
import threading
from collections import deque
from core.logger import log
from scanner.state import scan_state, LOCK

class HealthMonitor:
    def __init__(self, target, error_threshold=0.10, window_seconds=60):
        self.target = target
        self.error_threshold = error_threshold
        self.window_seconds = window_seconds
        self.responses = deque()
        self.connection_resets = 0
        self.paused = False
        self.pause_count = 0
        self._lock = threading.Lock()
        self._callbacks = []
        self._time_samples = deque()  # (timestamp, elapsed_ms)
        self._baseline_time_mean = 0
        self._baseline_time_std = 0
        self._baseline_established = False

    def record_response(self, status, elapsed_ms, is_error=False, is_connection_reset=False):
        now = time.time()
        with self._lock:
            self.responses.append((now, status, elapsed_ms))
            cutoff = now - self.window_seconds
            while self.responses and self.responses[0][0] < cutoff:
                self.responses.popleft()
            if is_connection_reset:
                self.connection_resets += 1
            self._time_samples.append((now, elapsed_ms))
            time_cutoff = now - self.window_seconds * 2
            while self._time_samples and self._time_samples[0][0] < time_cutoff:
                self._time_samples.popleft()

    def _compute_time_trend(self):
        """Compute response time Z-score vs baseline."""
        with self._lock:
            if len(self._time_samples) < 20:
                return 0.0, 'insufficient_data'
            recent = [t for _, t in list(self._time_samples)[-10:]]
            older = [t for _, t in list(self._time_samples)[:-10]] if len(self._time_samples) > 10 else recent
            import statistics
            if len(older) < 5 or len(recent) < 5:
                return 0.0, 'insufficient_data'
            mean_old = statistics.mean(older)
            std_old = statistics.stdev(older) if len(older) > 1 else 1
            mean_new = statistics.mean(recent)
            if std_old == 0:
                return 0.0, 'no_variance'
            z_score = (mean_new - mean_old) / std_old
            return z_score, 'degraded' if z_score > 3.0 else 'normal'

    def get_error_rate(self):
        with self._lock:
            if not self.responses: return 0.0
            errors = sum(1 for _, status, _ in self.responses if status >= 500)
            return errors / len(self.responses)

    def get_avg_response_time(self):
        with self._lock:
            if not self.responses: return 0.0
            return sum(elapsed for _, _, elapsed in self.responses) / len(self.responses)

    def get_status(self):
        error_rate = self.get_error_rate()
        avg_time = self.get_avg_response_time()
        time_z, trend = self._compute_time_trend()
        with self._lock:
            total = len(self.responses)
            errors = sum(1 for _, status, _ in self.responses if status >= 500)
        return {
            'target': self.target, 'total_responses': total,
            'error_count': errors, 'error_rate': error_rate,
            'avg_response_time_ms': avg_time,
            'time_trend_zscore': round(time_z, 2),
            'time_trend_status': trend,
            'connection_resets': self.connection_resets,
            'paused': self.paused, 'pause_count': self.pause_count,
            'healthy': error_rate < self.error_threshold and not self.paused and trend != 'degraded',
        }

    def check_health(self):
        error_rate = self.get_error_rate()
        _, trend = self._compute_time_trend()
        with self._lock:
            was_paused = self.paused
        should_pause = error_rate >= self.error_threshold or trend == 'degraded'
        if should_pause and not was_paused:
            reason = f'Error rate {error_rate:.1%}' if error_rate >= self.error_threshold else f'Response time degraded (Z={trend})'
            log('warn', f'[HEALTH] {reason} — PAUSING scan')
            with self._lock:
                self.paused = True
                self.pause_count += 1
            with LOCK:
                scan_state['health_paused'] = True
                scan_state['health_error_rate'] = error_rate
            for cb in self._callbacks:
                try: cb('pause', {'reason': reason, 'error_rate': error_rate})
                except: pass
            return False
        if was_paused and error_rate < self.error_threshold * 0.5 and trend != 'degraded':
            log('ok', f'[HEALTH] Recovered (error={error_rate:.1%}, trend={trend}) — RESUMING')
            with self._lock:
                self.paused = False
            with LOCK:
                scan_state['health_paused'] = False
            for cb in self._callbacks:
                try: cb('resume', {'error_rate': error_rate})
                except: pass
            return True
        return not was_paused

    def on_pause(self, callback):
        self._callbacks.append(callback)

    def is_paused(self):
        self.check_health()
        return self.paused

_health_monitor = None
def get_health_monitor(target=None):
    global _health_monitor
    if _health_monitor is None and target:
        _health_monitor = HealthMonitor(target)
    return _health_monitor
def reset_health_monitor():
    global _health_monitor
    _health_monitor = None
