"""Self-learning false-positive suppression.

When an analyst marks a finding as a false positive, its semantic fingerprint
(vuln_class|normalized_asset|param — see scanner.validation.fingerprint) is
persisted. The FP gate then auto-rejects any future finding that shares that
fingerprint, so a dismissed false positive never resurfaces on later scans.

Backed by the fp_suppressions SQLite table, mirrored in an in-memory set for
zero-cost lookups on the hot add_finding() path.
"""
import threading
from datetime import datetime, timezone
from core.database import DB_PATH
from core.logger import log
from core.utils import SQLITE_AVAILABLE, sqlite3_mod

_LOCK = threading.Lock()
_SUPPRESSED = set()      # in-memory fingerprint cache
_LOADED = False


def load_suppressions():
    """Hydrate the in-memory cache from the DB. Idempotent; safe to call often."""
    global _LOADED
    if not SQLITE_AVAILABLE:
        _LOADED = True
        return
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            rows = conn.execute('SELECT fingerprint FROM fp_suppressions').fetchall()
        with _LOCK:
            _SUPPRESSED.clear()
            _SUPPRESSED.update(r[0] for r in rows if r[0])
            _LOADED = True
        if _SUPPRESSED:
            log('info', f'[FP-SUPPRESS] Loaded {len(_SUPPRESSED)} suppressed fingerprint(s)')
    except Exception as e:
        log('warn', f'[FP-SUPPRESS] Load failed: {e}')
        _LOADED = True


def is_suppressed(fingerprint):
    """Return True if this fingerprint was previously dismissed as a false positive."""
    if not fingerprint:
        return False
    if not _LOADED:
        load_suppressions()
    with _LOCK:
        return fingerprint in _SUPPRESSED


def add_suppression(fingerprint, title='', asset='', reason='analyst-marked', note=''):
    """Persist a fingerprint as a known false positive. Returns True on success."""
    if not fingerprint:
        return False
    with _LOCK:
        _SUPPRESSED.add(fingerprint)
    if not SQLITE_AVAILABLE:
        return True
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute(
                'INSERT OR REPLACE INTO fp_suppressions '
                '(fingerprint, title, asset, reason, note, created_at) VALUES (?,?,?,?,?,?)',
                (fingerprint, title, asset, reason, note, datetime.now(timezone.utc).isoformat()),
            )
        log('info', f'[FP-SUPPRESS] Suppressed fingerprint for: {title[:60]}')
        return True
    except Exception as e:
        log('warn', f'[FP-SUPPRESS] Persist failed: {e}')
        return False


def remove_suppression(fingerprint):
    """Un-suppress a fingerprint (analyst reversed a false-positive decision)."""
    if not fingerprint:
        return False
    with _LOCK:
        _SUPPRESSED.discard(fingerprint)
    if not SQLITE_AVAILABLE:
        return True
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute('DELETE FROM fp_suppressions WHERE fingerprint = ?', (fingerprint,))
        return True
    except Exception as e:
        log('warn', f'[FP-SUPPRESS] Remove failed: {e}')
        return False


def list_suppressions():
    """Return all suppression records (for the management UI / API)."""
    if not SQLITE_AVAILABLE:
        with _LOCK:
            return [{'fingerprint': fp} for fp in _SUPPRESSED]
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            rows = conn.execute(
                'SELECT fingerprint, title, asset, reason, note, created_at '
                'FROM fp_suppressions ORDER BY created_at DESC'
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        log('warn', f'[FP-SUPPRESS] List failed: {e}')
        return []
