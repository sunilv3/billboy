"""Scope-contract enforcement (IRON RULE 1: authorization is a gate, not a flag).

A scope contract is the signed, per-engagement authorization boundary. No active
scan — and, later, no AI-planned action — may touch anything outside it. The
contract pins:

    scope_id            unique engagement id
    operator            who is authorized to run it
    client              engagement owner (for the record)
    allowed_domains     exact ("acme.com") or wildcard ("*.acme.com")
    allowed_ips         exact IPv4/IPv6 literals
    allowed_cidrs       CIDR ranges ("203.0.113.0/24")
    denied              explicit exclusions (domains or IPs) — always win
    not_before/after    ISO-8601 UTC engagement window
    intensity_ceiling   max scan profile: stealth < quick = balanced < aggressive
    allow_private_targets  whether RFC1918/loopback targets are in-scope
    signature           HMAC-SHA256 over the canonical contract (integrity)

Matching is deny-first, then explicit allow. A target that matches nothing is
OUT of scope and hard-refused. IMDS endpoints are never in scope.
"""
import os
import hmac
import json
import hashlib
import ipaddress
from datetime import datetime, timezone

from core.utils import _is_private_ip, _IMDS_IPS

# Intensity ranking — a requested profile must rank <= the contract ceiling.
_INTENSITY_RANK = {'stealth': 1, 'quick': 2, 'balanced': 2, 'aggressive': 3}
_DEFAULT_RANK = 3  # unknown profiles are gated conservatively (treated as most intrusive)

# Fields that are NOT part of the signed payload.
_UNSIGNED_FIELDS = {'signature'}


class AuthDecision:
    """Result of an authorization check. `allowed` is the gate; `reason` explains."""
    __slots__ = ('allowed', 'reason', 'scope_id', 'target', 'intensity', 'operator')

    def __init__(self, allowed, reason, scope_id='', target='', intensity='', operator=''):
        self.allowed = allowed
        self.reason = reason
        self.scope_id = scope_id
        self.target = target
        self.intensity = intensity
        self.operator = operator

    def as_dict(self):
        return {'allowed': self.allowed, 'reason': self.reason, 'scope_id': self.scope_id,
                'target': self.target, 'intensity': self.intensity, 'operator': self.operator}


# ── Signing ───────────────────────────────────────────────────────────────────

def _signing_key():
    """HMAC key for contract integrity. Prefers SCOPE_SIGNING_KEY; falls back to
    the app's .secret_key so a single-host deploy still gets integrity."""
    env = os.environ.get('SCOPE_SIGNING_KEY')
    if env:
        return env.encode()
    key_file = os.path.join(os.path.dirname(__file__), '..', '.secret_key')
    try:
        with open(key_file, 'rb') as f:
            return f.read()
    except Exception:
        return b'insecure-dev-scope-key'


def canonical_payload(contract):
    """Deterministic serialization of the signable fields."""
    payload = {k: contract[k] for k in sorted(contract) if k not in _UNSIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()


def sign_contract(contract):
    """Return the HMAC-SHA256 signature hex for a contract dict."""
    return hmac.new(_signing_key(), canonical_payload(contract), hashlib.sha256).hexdigest()


def verify_signature(contract):
    """True iff the contract carries a signature matching its canonical payload."""
    sig = contract.get('signature')
    if not sig:
        return False
    expected = sign_contract(contract)
    return hmac.compare_digest(str(sig), expected)


def signature_required():
    """In production, an unsigned/invalid contract must be rejected."""
    return os.environ.get('INFOSEC_ENV', '').strip().lower() == 'production'


# ── Target normalization ────────────────────────────────────────────────────

def normalize_target(target):
    """Strip scheme/path/port → bare host or IP, lowercased."""
    t = str(target or '').strip().lower()
    if '://' in t:
        t = t.split('://', 1)[1]
    t = t.split('/')[0].split('?')[0]
    # strip :port but keep IPv6 brackets intact
    if t.startswith('['):
        host = t[1:].split(']')[0]
        return host
    if t.count(':') == 1:  # host:port (not IPv6)
        t = t.split(':')[0]
    return t


def _domain_matches(host, pattern):
    """Exact or single-level wildcard ('*.acme.com' matches a.acme.com and acme.com)."""
    host = host.lower().rstrip('.')
    pattern = pattern.lower().rstrip('.')
    if pattern.startswith('*.'):
        base = pattern[2:]
        return host == base or host.endswith('.' + base)
    return host == pattern


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ip_in_cidr(ip_str, cidr):
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


# ── Contract ──────────────────────────────────────────────────────────────────

class ScopeContract:
    """Wraps a contract dict and answers authorization questions."""

    def __init__(self, data):
        self.data = data or {}
        self.scope_id = self.data.get('scope_id', '')
        self.operator = self.data.get('operator', '')

    # --- individual checks ---

    def within_window(self, now=None):
        now = now or datetime.now(timezone.utc)
        nb = self.data.get('not_before')
        na = self.data.get('not_after')
        try:
            if nb and now < _parse_iso(nb):
                return False, f'engagement window has not opened (not_before={nb})'
            if na and now > _parse_iso(na):
                return False, f'engagement window has closed (not_after={na})'
        except Exception as e:
            return False, f'invalid engagement window: {e}'
        return True, ''

    def allows_intensity(self, profile):
        ceiling = self.data.get('intensity_ceiling', 'aggressive')
        c_rank = _INTENSITY_RANK.get(str(ceiling).lower(), _DEFAULT_RANK)
        p_rank = _INTENSITY_RANK.get(str(profile).lower(), _DEFAULT_RANK)
        if p_rank > c_rank:
            return False, f"profile '{profile}' exceeds intensity ceiling '{ceiling}'"
        return True, ''

    def target_in_scope(self, target):
        host = normalize_target(target)
        if not host:
            return False, 'empty target'

        # Deny list always wins.
        for d in self.data.get('denied', []):
            if (_is_ip(host) and (host == d or _ip_in_cidr(host, d))) or \
               (not _is_ip(host) and _domain_matches(host, d)):
                return False, f'target explicitly denied by contract ({d})'

        # IMDS is never in scope.
        if host in _IMDS_IPS:
            return False, 'cloud metadata endpoint is never in scope'

        allow_private = bool(self.data.get('allow_private_targets', False))

        if _is_ip(host):
            if (_is_private_ip(host)) and not allow_private:
                return False, 'private/reserved IP not authorized by contract'
            if host in self.data.get('allowed_ips', []):
                return True, 'matched allowed_ips'
            for cidr in self.data.get('allowed_cidrs', []):
                if _ip_in_cidr(host, cidr):
                    return True, f'matched allowed_cidrs ({cidr})'
            return False, 'IP not in any allowed_ips/allowed_cidrs'

        # Hostname path — scope is decided by NAME match against the contract.
        # Resolution-to-private/IMDS is enforced separately and defensively by
        # the SSRF guard (core.utils._check_target_for_ssrf), which start_scan
        # invokes with this contract's allow_private_targets. Keeping DNS out of
        # the scope decision makes authorization deterministic and offline-safe.
        matched = any(_domain_matches(host, p) for p in self.data.get('allowed_domains', []))
        if not matched:
            return False, 'host not in allowed_domains'
        return True, 'matched allowed_domains'

    # --- combined gate ---

    def authorize(self, target, intensity, now=None):
        """Full authorization: signature (prod) + window + intensity + target."""
        if signature_required() and not verify_signature(self.data):
            return AuthDecision(False, 'contract signature missing or invalid',
                                self.scope_id, normalize_target(target), intensity, self.operator)
        ok, why = self.within_window(now)
        if not ok:
            return AuthDecision(False, why, self.scope_id, normalize_target(target), intensity, self.operator)
        ok, why = self.allows_intensity(intensity)
        if not ok:
            return AuthDecision(False, why, self.scope_id, normalize_target(target), intensity, self.operator)
        ok, why = self.target_in_scope(target)
        if not ok:
            return AuthDecision(False, why, self.scope_id, normalize_target(target), intensity, self.operator)
        return AuthDecision(True, why or 'in scope', self.scope_id,
                            normalize_target(target), intensity, self.operator)


def _parse_iso(s):
    """Parse ISO-8601, tolerating a trailing 'Z'. Returns tz-aware UTC datetime."""
    s = str(s).strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
