"""Logging and SSE (Server-Sent Events) infrastructure."""
import json
import time
import queue
import threading

_sse_queue = queue.Queue(maxsize=500)
_sse_clients = []
_sse_lock = threading.Lock()


def log(level, message):
    """Emit a structured log line. level: info | ok | warn | err."""
    prefix = {'info': '[INFO]', 'ok': '[OK]', 'warn': '[WARN]', 'err': '[ERR]'}.get(level, '[INFO]')
    ts = time.strftime('%H:%M:%S')
    line = f'[{ts}] {prefix} {message}'
    print(line)
    try:
        from scanner.state import scan_state, LOCK
        with LOCK:
            # 'type'/'message' match the frontend terminal renderer; 'level'/'msg'
            # kept for any legacy reader.
            scan_state.setdefault('logs', []).append({
                'type': level, 'message': message,
                'level': level, 'msg': message, 'ts': ts,
            })
    except Exception:
        pass


def push_sse(event, data):
    """Push an SSE event to all connected clients."""
    try:
        payload = json.dumps({'event': event, 'data': data})
        with _sse_lock:
            for q in list(_sse_clients):
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    pass
    except Exception:
        pass


def sse_stream():
    """Generator: yields SSE-formatted events for a client connection."""
    q = queue.Queue(maxsize=200)
    with _sse_lock:
        _sse_clients.append(q)
    try:
        while True:
            try:
                payload = q.get(timeout=30)
                yield f'data: {payload}\n\n'
            except queue.Empty:
                yield ': heartbeat\n\n'
    finally:
        with _sse_lock:
            if q in _sse_clients:
                _sse_clients.remove(q)
