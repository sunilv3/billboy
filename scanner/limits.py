"""Hard Limits Enforcement (FULL) — rate limiter, semaphores, kill switch, per-request checks."""
import time
import os
import threading
from core.logger import log

class TokenBucket:
    def __init__(self, rate=10, capacity=10):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = threading.Lock()
    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
    def acquire(self, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
            time.sleep(0.01)
        return False
    @property
    def available(self):
        with self._lock:
            self._refill()
            return int(self.tokens)

class ConnectionLimiter:
    def __init__(self, max_concurrent=5):
        self.semaphore = threading.Semaphore(max_concurrent)
        self.active = 0
        self._lock = threading.Lock()
    def acquire(self, timeout=30):
        acquired = self.semaphore.acquire(timeout=timeout)
        if acquired:
            with self._lock:
                self.active += 1
        return acquired
    def release(self):
        with self._lock:
            self.active = max(0, self.active - 1)
        self.semaphore.release()
    def __enter__(self):
        self.acquire()
        return self
    def __exit__(self, *args):
        self.release()

class KillSwitch:
    """Kill switch: checks /tmp/stop_scan_{scan_id} before EVERY request."""
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.file_path = f'/tmp/stop_scan_{scan_id}'
        self._triggered = False
    def check(self):
        if self._triggered: return True
        if os.path.exists(self.file_path):
            self._triggered = True
            log('warn', f'[KILL-SWITCH] Scan {self.scan_id} terminated')
            return True
        return False
    def trigger(self):
        self._triggered = True
        try:
            with open(self.file_path, 'w') as f:
                f.write(f'Kill switch triggered at {time.time()}\n')
        except Exception:
            pass
    def reset(self):
        self._triggered = False
        try:
            if os.path.exists(self.file_path):
                os.remove(self.file_path)
        except Exception:
            pass

class RequestCounter:
    def __init__(self, max_requests=10000):
        self.max_requests = max_requests
        self.count = 0
        self._lock = threading.Lock()
    def increment(self):
        with self._lock:
            self.count += 1
            return self.count
    @property
    def exceeded(self):
        with self._lock:
            return self.count >= self.max_requests
    @property
    def remaining(self):
        with self._lock:
            return max(0, self.max_requests - self.count)

def truncate_payload(data, max_size=10240):
    if isinstance(data, str):
        encoded = data.encode('utf-8', errors='ignore')
        if len(encoded) > max_size:
            return encoded[:max_size].decode('utf-8', errors='ignore')
        return data
    elif isinstance(data, bytes):
        return data[:max_size]
    elif isinstance(data, dict):
        import json
        try:
            serialized = json.dumps(data)
            if len(serialized.encode('utf-8')) > max_size:
                truncated = {}
                for k, v in data.items():
                    if isinstance(v, str):
                        truncated[k] = v[:max_size // max(1, len(data))]
                    else:
                        truncated[k] = v
                return truncated
        except Exception:
            pass
    return data

class ScanLimits:
    """Unified hard limits — pre_request() checks kill switch, rate, connections, request count."""
    def __init__(self, scan_id, config=None):
        cfg = config or {}
        self.scan_id = scan_id
        self.max_requests = cfg.get('max_requests', 10000)
        self.max_payload_size = cfg.get('max_payload_size', 10240)
        self.rate_limiter = TokenBucket(rate=cfg.get('max_rate', 10), capacity=cfg.get('max_rate', 10))
        self.connection_limiter = ConnectionLimiter(max_concurrent=cfg.get('max_concurrent', 5))
        self.kill_switch = KillSwitch(scan_id)
        self.request_counter = RequestCounter(max_requests=self.max_requests)

    def pre_request(self):
        """Check ALL limits before EVERY request. Returns True if allowed."""
        if self.kill_switch.check():
            return False
        if self.request_counter.exceeded:
            log('warn', f'[LIMITS] Max requests ({self.max_requests}) reached')
            return False
        if not self.rate_limiter.acquire(timeout=5):
            log('warn', '[LIMITS] Rate limit timeout')
            return False
        if not self.connection_limiter.acquire(timeout=10):
            log('warn', '[LIMITS] Connection limit timeout')
            return False
        return True

    def post_request(self):
        self.connection_limiter.release()
        self.request_counter.increment()

    def sanitize_payload(self, data):
        return truncate_payload(data, self.max_payload_size)

    def get_status(self):
        return {
            'scan_id': self.scan_id,
            'requests_used': self.request_counter.count,
            'requests_remaining': self.request_counter.remaining,
            'rate_available': self.rate_limiter.available,
            'connections_active': self.connection_limiter.active,
            'kill_switch_active': self.kill_switch.check(),
        }
