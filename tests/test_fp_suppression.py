"""Tests for the self-learning false-positive suppression list."""
import sys
import os
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner.suppression as supp


def _fresh_db():
    """Point the suppression module at a throwaway SQLite file."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    import sqlite3
    with sqlite3.connect(path) as conn:
        conn.execute("""
            CREATE TABLE fp_suppressions (
                fingerprint TEXT PRIMARY KEY,
                title TEXT, asset TEXT, reason TEXT, note TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    return path


@pytest.fixture(autouse=True)
def _isolate_db():
    # Isolate each test: fresh DB + cleared in-memory cache
    original = supp.DB_PATH
    path = _fresh_db()
    supp.DB_PATH = path
    supp._SUPPRESSED.clear()
    supp._LOADED = False
    yield
    supp.DB_PATH = original          # restore so later test modules see the real DB
    supp._SUPPRESSED.clear()
    supp._LOADED = False
    try:
        os.remove(path)
    except OSError:
        pass


class TestSuppressionRoundTrip:

    def test_add_then_suppressed(self):
        fp = 'sqli|http://x.com/a|id'
        supp.add_suppression(fp, title='SQLi', asset='http://x.com/a')
        assert supp.is_suppressed(fp)

    def test_unknown_fingerprint_not_suppressed(self):
        assert not supp.is_suppressed('xss|http://y.com|q')

    def test_empty_fingerprint_never_suppressed(self):
        assert not supp.is_suppressed('')

    def test_remove_suppression(self):
        fp = 'ssrf|http://x.com/fetch|url'
        supp.add_suppression(fp)
        assert supp.is_suppressed(fp)
        supp.remove_suppression(fp)
        assert not supp.is_suppressed(fp)

    def test_persists_across_reload(self):
        fp = 'idor|http://x.com/user|id'
        supp.add_suppression(fp)
        supp._SUPPRESSED.clear()
        supp._LOADED = False
        supp.load_suppressions()
        assert supp.is_suppressed(fp)

    def test_list_returns_records(self):
        supp.add_suppression('xss|http://z.com|q', title='XSS', asset='http://z.com')
        items = supp.list_suppressions()
        assert len(items) == 1
        assert items[0]['fingerprint'] == 'xss|http://z.com|q'
        assert items[0]['title'] == 'XSS'
