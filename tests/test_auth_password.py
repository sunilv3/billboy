"""IRON RULE 4 — default-password kill, argon2 hashing, forced first-run change.

Covers:
  * argon2id hashing + transparent legacy (werkzeug) verification + rehash
  * no hardcoded default credential is ever auto-created
  * production refuses to boot with default / no admin
  * dev downgrades a detected default to a forced password change
  * must_change is enforced on protected routes and cleared by change_password
"""
import os
import sys

import pytest
from werkzeug.security import generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.passwords as pw
import core.database as db


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Isolate each test: fresh SQLite file, clean USERS cache, clean env."""
    p = str(tmp_path / 'auth_test.db')
    monkeypatch.setattr(db, 'DB_PATH', p)
    monkeypatch.delenv('ADMIN_PASSWORD', raising=False)
    monkeypatch.delenv('INFOSEC_ENV', raising=False)
    db.init_db()
    db.USERS.clear()
    yield p
    db.USERS.clear()


# ── Password primitives ───────────────────────────────────────────────────────

class TestPasswordHashing:

    def test_argon2_roundtrip(self):
        h = pw.hash_password('correct horse battery staple')
        if pw.ARGON2_AVAILABLE:
            assert h.startswith('$argon2')
        assert pw.verify_password(h, 'correct horse battery staple')
        assert not pw.verify_password(h, 'wrong password')

    def test_legacy_hash_still_verifies(self):
        legacy = generate_password_hash('legacy-pass-123456')
        assert not legacy.startswith('$argon2')
        assert pw.verify_password(legacy, 'legacy-pass-123456')
        assert not pw.verify_password(legacy, 'nope')

    def test_needs_rehash_true_for_legacy_false_for_argon2(self):
        legacy = generate_password_hash('legacy-pass-123456')
        assert pw.needs_rehash(legacy) is True
        if pw.ARGON2_AVAILABLE:
            assert pw.needs_rehash(pw.hash_password('x-strong-pass')) is False

    def test_empty_inputs_fail_closed(self):
        assert pw.verify_password('', 'x') is False
        assert pw.verify_password(pw.hash_password('x'), None) is False


# ── Provisioning: no hardcoded default ────────────────────────────────────────

class TestNoDefaultCredential:

    def test_dev_provisions_random_must_change_admin(self, temp_db):
        db.init_users()
        assert 'admin' in db.USERS
        # The known legacy default must NOT work.
        assert not pw.verify_password(db.USERS['admin'], '12345678')
        # And the auto-provisioned account is forced to change on first login.
        assert db.get_must_change('admin') is True

    def test_env_password_is_used_without_must_change(self, temp_db, monkeypatch):
        monkeypatch.setenv('ADMIN_PASSWORD', 'env-supplied-strong-secret')
        db.USERS.clear()
        db.init_users()
        assert pw.verify_password(db.USERS['admin'], 'env-supplied-strong-secret')
        assert db.get_must_change('admin') is False


# ── Boot enforcement ──────────────────────────────────────────────────────────

class TestProductionBootGate:

    def test_production_refuses_default_password(self, temp_db, monkeypatch):
        db._upsert_user('admin', '12345678', must_change=False)
        monkeypatch.setenv('INFOSEC_ENV', 'production')
        with pytest.raises(RuntimeError):
            db.enforce_admin_security()

    def test_production_refuses_when_no_admin_and_no_env(self, temp_db, monkeypatch):
        db.USERS.clear()
        monkeypatch.setenv('INFOSEC_ENV', 'production')
        with pytest.raises(RuntimeError):
            db.enforce_admin_security()

    def test_production_ok_with_strong_env_password(self, temp_db, monkeypatch):
        monkeypatch.setenv('INFOSEC_ENV', 'production')
        monkeypatch.setenv('ADMIN_PASSWORD', 'a-very-strong-production-secret')
        db.USERS.clear()
        db.enforce_admin_security()  # must not raise
        assert pw.verify_password(db.USERS['admin'], 'a-very-strong-production-secret')

    def test_dev_default_downgraded_to_must_change(self, temp_db):
        db._upsert_user('admin', '12345678', must_change=False)
        db.enforce_admin_security()  # dev, must not raise
        assert db.get_must_change('admin') is True


# ── Forced first-run change ───────────────────────────────────────────────────

class TestMustChangeLifecycle:

    def test_set_password_clears_must_change(self, temp_db):
        db._upsert_user('admin', 'one-time-strong-xyz', must_change=True)
        assert db.get_must_change('admin') is True
        assert db.set_user_password('admin', 'brand-new-strong-pass')
        assert db.get_must_change('admin') is False
        assert pw.verify_password(db.USERS['admin'], 'brand-new-strong-pass')

    def test_login_required_blocks_must_change_session(self):
        from app import app
        c = app.test_client()
        with c.session_transaction() as s:
            s['user'] = 'admin'
            s['must_change'] = True
        r = c.get('/api/fp_suppressions')
        assert r.status_code == 403
        assert r.get_json().get('code') == 'password_change_required'

    def test_change_password_allowed_during_must_change(self, monkeypatch, tmp_path):
        from app import app
        p = str(tmp_path / 'change_test.db')
        monkeypatch.setattr(db, 'DB_PATH', p)
        db.init_db()
        db.USERS.clear()
        db._upsert_user('admin', 'one-time-strong-xyz', must_change=True)
        c = app.test_client()
        with c.session_transaction() as s:
            s['user'] = 'admin'
            s['must_change'] = True
        r = c.post('/api/auth/change_password', json={
            'current_password': 'one-time-strong-xyz',
            'new_password': 'my-new-strong-password',
        })
        assert r.status_code == 200, r.get_data(as_text=True)
        assert db.get_must_change('admin') is False

    def test_change_password_rejects_short_password(self, monkeypatch, tmp_path):
        from app import app
        p = str(tmp_path / 'change_short.db')
        monkeypatch.setattr(db, 'DB_PATH', p)
        db.init_db()
        db.USERS.clear()
        db._upsert_user('admin', 'one-time-strong-xyz', must_change=True)
        c = app.test_client()
        with c.session_transaction() as s:
            s['user'] = 'admin'
            s['must_change'] = True
        r = c.post('/api/auth/change_password', json={
            'current_password': 'one-time-strong-xyz',
            'new_password': 'short',
        })
        assert r.status_code == 400
