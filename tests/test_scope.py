"""IRON RULE 1 — scope-contract authorization gate.

Covers contract matching (domain/wildcard/IP/CIDR/deny), time window, intensity
ceiling, signature integrity, private-target gating, the management API, and the
hard gate on /api/start_scan (no scope → refuse; out-of-scope → refuse; in-scope
→ allow), plus the audit trail.
"""
import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.scope as scope
import core.database as db
from core.scope import ScopeContract, sign_contract, verify_signature


def _contract(**over):
    c = {
        'scope_id': 'eng-001',
        'operator': 'tester@example.com',
        'client': 'ACME',
        'allowed_domains': ['acme.com', '*.acme.com'],
        'allowed_ips': ['1.1.1.1'],
        'allowed_cidrs': ['8.8.8.0/24'],
        'denied': ['secret.acme.com'],
        'not_before': None,
        'not_after': None,
        'intensity_ceiling': 'balanced',
        'allow_private_targets': False,
        'created_at': datetime.now(timezone.utc).isoformat(),
    }
    c.update(over)
    return c


# ── Matching ──────────────────────────────────────────────────────────────────

class TestTargetMatching:

    def test_exact_domain_in_scope(self):
        ok, _ = ScopeContract(_contract()).target_in_scope('acme.com')
        assert ok

    def test_wildcard_subdomain_in_scope(self):
        ok, _ = ScopeContract(_contract()).target_in_scope('https://api.acme.com/login')
        assert ok

    def test_unrelated_domain_out_of_scope(self):
        ok, why = ScopeContract(_contract()).target_in_scope('evil.com')
        assert not ok and 'allowed_domains' in why

    def test_explicit_deny_wins_over_allow(self):
        ok, why = ScopeContract(_contract()).target_in_scope('secret.acme.com')
        assert not ok and 'denied' in why

    def test_exact_ip_in_scope(self):
        ok, _ = ScopeContract(_contract()).target_in_scope('1.1.1.1')
        assert ok

    def test_cidr_ip_in_scope(self):
        ok, _ = ScopeContract(_contract()).target_in_scope('8.8.8.8')
        assert ok

    def test_ip_outside_cidr_out_of_scope(self):
        ok, _ = ScopeContract(_contract()).target_in_scope('9.9.9.9')
        assert not ok

    def test_imds_never_in_scope(self):
        c = _contract(allowed_ips=['169.254.169.254'], allow_private_targets=True)
        ok, why = ScopeContract(c).target_in_scope('169.254.169.254')
        assert not ok and 'metadata' in why.lower()

    def test_private_ip_blocked_unless_allowed(self):
        c = _contract(allowed_cidrs=['10.0.0.0/8'])
        ok, _ = ScopeContract(c).target_in_scope('10.1.2.3')
        assert not ok
        c2 = _contract(allowed_cidrs=['10.0.0.0/8'], allow_private_targets=True)
        ok2, _ = ScopeContract(c2).target_in_scope('10.1.2.3')
        assert ok2


# ── Window + intensity ──────────────────────────────────────────────────────

class TestWindowAndIntensity:

    def test_window_not_yet_open(self):
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        ok, _ = ScopeContract(_contract(not_before=future)).within_window()
        assert not ok

    def test_window_closed(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        ok, _ = ScopeContract(_contract(not_after=past)).within_window()
        assert not ok

    def test_window_open(self):
        nb = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        na = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        ok, _ = ScopeContract(_contract(not_before=nb, not_after=na)).within_window()
        assert ok

    def test_intensity_at_ceiling_allowed(self):
        ok, _ = ScopeContract(_contract(intensity_ceiling='balanced')).allows_intensity('balanced')
        assert ok

    def test_intensity_above_ceiling_denied(self):
        ok, why = ScopeContract(_contract(intensity_ceiling='balanced')).allows_intensity('aggressive')
        assert not ok and 'ceiling' in why

    def test_intensity_below_ceiling_allowed(self):
        ok, _ = ScopeContract(_contract(intensity_ceiling='aggressive')).allows_intensity('stealth')
        assert ok


# ── Signing ───────────────────────────────────────────────────────────────────

class TestSignature:

    def test_sign_then_verify(self):
        c = _contract()
        c['signature'] = sign_contract(c)
        assert verify_signature(c)

    def test_tamper_breaks_signature(self):
        c = _contract()
        c['signature'] = sign_contract(c)
        c['allowed_domains'] = ['attacker.com']  # tamper after signing
        assert not verify_signature(c)

    def test_missing_signature_fails(self):
        assert not verify_signature(_contract())

    def test_production_requires_valid_signature(self, monkeypatch):
        monkeypatch.setenv('INFOSEC_ENV', 'production')
        c = _contract()  # unsigned
        decision = ScopeContract(c).authorize('acme.com', 'balanced')
        assert not decision.allowed and 'signature' in decision.reason


# ── Full authorize() gate ──────────────────────────────────────────────────

class TestAuthorize:

    def test_in_scope_allows(self):
        d = ScopeContract(_contract()).authorize('api.acme.com', 'balanced')
        assert d.allowed

    def test_out_of_scope_denies(self):
        d = ScopeContract(_contract()).authorize('evil.com', 'balanced')
        assert not d.allowed

    def test_intensity_violation_denies_even_if_target_ok(self):
        d = ScopeContract(_contract(intensity_ceiling='stealth')).authorize('acme.com', 'aggressive')
        assert not d.allowed and 'ceiling' in d.reason


# ── DB persistence + audit ────────────────────────────────────────────────────

class TestScopePersistence:

    @pytest.fixture
    def temp_db(self, monkeypatch, tmp_path):
        p = str(tmp_path / 'scope.db')
        monkeypatch.setattr(db, 'DB_PATH', p)
        db.init_db()
        yield p

    def test_save_get_roundtrip(self, temp_db):
        c = _contract()
        c['signature'] = sign_contract(c)
        assert db.save_scope_contract(c)
        loaded = db.get_scope_contract('eng-001')
        assert loaded and loaded['scope_id'] == 'eng-001'
        assert verify_signature(loaded)

    def test_deactivate_hides_from_active_lookup(self, temp_db):
        c = _contract(); c['signature'] = sign_contract(c)
        db.save_scope_contract(c)
        assert db.set_scope_active('eng-001', False)
        assert db.get_scope_contract('eng-001') is None              # active-only
        assert db.get_scope_contract('eng-001', active_only=False)   # still retrievable

    def test_authz_log_records_decisions(self, temp_db):
        c = _contract(); c['signature'] = sign_contract(c)
        db.save_scope_contract(c)
        d = ScopeContract(c).authorize('acme.com', 'balanced')
        d.operator = 'tester'
        db.log_authz(d, action='start_scan', justification='unit test')
        rows = db.get_authz_log(scope_id='eng-001')
        assert rows and rows[0]['decision'] == 'allow'


# ── Hard gate on /api/start_scan ────────────────────────────────────────────

class TestStartScanGate:

    @pytest.fixture
    def client(self, monkeypatch, tmp_path):
        from app import app
        p = str(tmp_path / 'gate.db')
        monkeypatch.setattr(db, 'DB_PATH', p)
        db.init_db()
        c = app.test_client()
        with c.session_transaction() as s:
            s['user'] = 'tester'
        return c

    def test_no_scope_id_refused(self, client):
        r = client.post('/api/start_scan', json={'target': 'acme.com', 'scan_type': 'web'})
        assert r.status_code == 403
        assert r.get_json().get('code') == 'scope_required'

    def test_unknown_scope_refused(self, client):
        r = client.post('/api/start_scan', json={'target': 'acme.com', 'scope_id': 'nope'})
        assert r.status_code == 403
        assert r.get_json().get('code') == 'scope_unknown'

    def test_out_of_scope_target_refused(self, client):
        c = _contract(); c['signature'] = sign_contract(c)
        db.save_scope_contract(c)
        r = client.post('/api/start_scan',
                        json={'target': 'evil.com', 'scope_id': 'eng-001', 'scan_profile': 'balanced'})
        assert r.status_code == 403
        assert r.get_json().get('code') == 'out_of_scope'
        # and the denial was audited
        assert any(x['decision'] == 'deny' for x in db.get_authz_log(scope_id='eng-001'))

    def test_intensity_over_ceiling_refused(self, client):
        c = _contract(intensity_ceiling='stealth'); c['signature'] = sign_contract(c)
        db.save_scope_contract(c)
        r = client.post('/api/start_scan',
                        json={'target': 'acme.com', 'scope_id': 'eng-001', 'scan_profile': 'aggressive'})
        assert r.status_code == 403
        assert r.get_json().get('code') == 'out_of_scope'
