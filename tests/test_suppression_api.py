"""End-to-end API tests for the FP suppression lifecycle.

Guards against regressions like the missing `datetime` import in scanner.routes
that crashed verify_finding / update_finding_status.
"""
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def client():
    from app import app
    app.config['TESTING'] = True
    import scanner.suppression as supp
    import core.database as db
    # restore the canonical DB path (other test modules repoint it at temp files)
    supp.DB_PATH = db.DB_PATH
    # isolate: clear persisted + in-memory suppressions
    try:
        from core.utils import sqlite3_mod
        with sqlite3_mod.connect(supp.DB_PATH) as conn:
            conn.execute('DELETE FROM fp_suppressions')
    except Exception:
        pass
    supp._SUPPRESSED.clear()
    supp._LOADED = False
    c = app.test_client()
    with c.session_transaction() as s:
        s['logged_in'] = True
        s['user'] = 'pytest'
    return c


def _seed_finding():
    from scanner.state import scan_state
    from scanner.findings import add_finding
    scan_state.setdefault('finding_status', {})
    return add_finding('high', 'SQL Injection Confirmed: api',
                       asset='http://demo.test/item',
                       details='parameter: id\nConfirmed: error-based SQLi',
                       confidence='high')


def test_suppression_lifecycle(client):
    f = _seed_finding()
    assert f is not None
    fid, fp = f['id'], f['fingerprint']

    # mark false positive — must not 500 (datetime regression guard)
    r = client.post(f'/api/findings/{fid}/verify', json={'action': 'false_positive'})
    assert r.status_code == 200
    assert r.get_json()['status'] == 'ok'

    # appears in the suppression list
    j = client.get('/api/fp_suppressions').get_json()
    assert any(s['fingerprint'] == fp for s in j['suppressions'])

    # identical finding is now auto-rejected by the gate
    from scanner.findings import add_finding
    dup = add_finding('high', 'SQL Injection Confirmed: api',
                      asset='http://demo.test/item',
                      details='parameter: id\nConfirmed: error-based SQLi',
                      confidence='high')
    assert dup is None

    # restore removes it
    r = client.delete('/api/fp_suppressions', json={'fingerprint': fp})
    assert r.status_code == 200
    j = client.get('/api/fp_suppressions').get_json()
    assert not any(s['fingerprint'] == fp for s in j['suppressions'])


def test_update_status_does_not_crash(client):
    """update_finding_status path also references datetime."""
    f = _seed_finding()
    r = client.post(f'/api/findings/{f["id"]}/status', json={'status': 'accepted'})
    assert r.status_code == 200


def test_delete_requires_fingerprint(client):
    r = client.delete('/api/fp_suppressions', json={})
    assert r.status_code == 400
