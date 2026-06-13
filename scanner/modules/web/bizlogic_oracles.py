"""Business-logic vulnerability ORACLES — pure decision functions.

Business-logic flaws are what get paid on real engagements, and they are the
easiest to report as false positives ("status 200, must be vulnerable!"). To
keep precision high we separate the *decision* (these pure functions) from the
*request I/O* (the runner). Every oracle:

  * takes already-collected evidence (status codes, bodies, lengths),
  * compares the tampered behaviour against a baseline / control,
  * returns a Verdict(vuln, confidence, evidence) — never just "2xx → vuln".

This module imports nothing from the app, so the oracles are unit-testable in
isolation and the confirmation logic is auditable.
"""
import re

# Markers that indicate the *application accepted/processed* a request.
_SUCCESS_MARKERS = (
    'success', 'thank you', 'order placed', 'confirmed', 'added to cart',
    'updated', 'saved', 'created', 'approved', 'completed', 'welcome',
    'congratulations', 'your order', 'payment received',
)
# Markers that indicate the application REJECTED the request (so NOT a finding).
_REJECT_MARKERS = (
    'error', 'invalid', 'not allowed', 'forbidden', 'denied', 'unauthorized',
    'must be', 'cannot be negative', 'minimum', 'out of range', 'rejected',
    'failed', 'bad request', 'try again', 'not permitted', 'insufficient',
)
# Markers that indicate privileged / sensitive content was returned (broad —
# used for forced-browsing where the whole page is privileged).
_PRIVILEGED_MARKERS = (
    'admin', 'dashboard', 'all users', 'manage', 'privilege',
    'delete user', 'audit log', 'api key', 'secret',
    'ssn', 'credit card', 'salary',
)
# Strict elevated-state markers — these should NOT appear in a normal user
# response, so their *appearance after tampering* is a real escalation signal.
# Deliberately excludes bare 'role'/'settings' which occur in benign responses.
_ELEVATED_MARKERS = (
    'admin', 'superuser', 'is_admin', 'isadmin', 'root', 'all users',
    'privilege', 'access_level', 'role": "admin', 'role: admin',
)


class Verdict:
    __slots__ = ('vuln', 'confidence', 'evidence')

    def __init__(self, vuln, confidence='medium', evidence=''):
        self.vuln = vuln
        self.confidence = confidence
        self.evidence = evidence

    def __repr__(self):
        return f'Verdict(vuln={self.vuln}, confidence={self.confidence!r}, evidence={self.evidence!r})'


def _has(text, markers):
    t = (text or '').lower()
    return any(m in t for m in markers)


def _accepted(status, text):
    """Did the app accept the request? 2xx/redirect AND no explicit rejection."""
    if status not in (200, 201, 202, 204, 301, 302, 303, 307, 308):
        return False
    if _has(text, _REJECT_MARKERS):
        return False
    return True


# ── 1. Price / amount tampering ───────────────────────────────────────────────

def price_tampering_verdict(status, text, original_value, tampered_value):
    """A lowered or negative price/amount that the app ACCEPTS (and does not
    reject) is a confirmed flaw. Reflecting the tampered value back raises
    confidence to high."""
    try:
        orig = float(original_value)
        tamp = float(tampered_value)
    except (TypeError, ValueError):
        return Verdict(False)
    if tamp >= orig:
        return Verdict(False)                      # not actually lowered
    if not _accepted(status, text):
        return Verdict(False, evidence='request rejected — control working')
    reflected = str(tampered_value) in (text or '')
    success = _has(text, _SUCCESS_MARKERS)
    if reflected and success:
        return Verdict(True, 'high',
                       f'tampered value {tamp} accepted, reflected, and order succeeded')
    if success or reflected:
        return Verdict(True, 'medium',
                       f'tampered value {tamp} (< {orig}) accepted (status {status})')
    return Verdict(True, 'low', f'tampered value {tamp} accepted but no success/echo confirmation')


def negative_value_verdict(status, text, value):
    """Negative quantity/amount accepted → refund/credit abuse."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return Verdict(False)
    if v >= 0:
        return Verdict(False)
    if not _accepted(status, text):
        return Verdict(False, evidence='negative value rejected — control working')
    if _has(text, _SUCCESS_MARKERS):
        return Verdict(True, 'high', f'negative value {v} accepted and processed')
    return Verdict(True, 'medium', f'negative value {v} accepted (status {status})')


# ── 2. Coupon / discount reuse ────────────────────────────────────────────────

def coupon_reuse_verdict(first_status, first_text, second_status, second_text):
    """Same single-use coupon applied twice, both accepted → reuse abuse."""
    first_ok = _accepted(first_status, first_text) and _has(first_text, _SUCCESS_MARKERS + ('discount', 'applied'))
    second_ok = _accepted(second_status, second_text) and not _has(second_text, _REJECT_MARKERS + ('already', 'used', 'expired'))
    if first_ok and second_ok:
        return Verdict(True, 'medium', 'coupon accepted on both first and second application')
    return Verdict(False, evidence='second application rejected — single-use enforced')


# ── 3. IDOR ────────────────────────────────────────────────────────────────────

def idor_verdict(self_status, self_text, other_status, other_text):
    """Requesting another principal's object returns 200 with DIFFERENT,
    non-trivial content (and not an error page) → IDOR."""
    if other_status != 200 or self_status != 200:
        return Verdict(False)
    if _has(other_text, _REJECT_MARKERS):
        return Verdict(False, evidence='access denied on other object — control working')
    if len(other_text or '') < 50:
        return Verdict(False, evidence='other-object response too small to be data')
    if (other_text or '') == (self_text or ''):
        return Verdict(False, evidence='identical content (likely shared/public)')
    return Verdict(True, 'medium', 'distinct authorised-looking data returned for another principal id')


# ── 4. Function-level access control / forced browsing ────────────────────────

def forced_browse_verdict(unauth_status, unauth_text):
    """An unauthenticated request to a privileged endpoint that returns 200 with
    privileged content → broken function-level access control."""
    if unauth_status != 200:
        return Verdict(False, evidence=f'status {unauth_status} (likely protected)')
    if _has(unauth_text, _REJECT_MARKERS) or _has(unauth_text, ('login', 'sign in', 'authenticate')):
        return Verdict(False, evidence='redirected to auth / rejected — control working')
    if _has(unauth_text, _PRIVILEGED_MARKERS):
        return Verdict(True, 'high', 'privileged content served without authentication')
    return Verdict(False, evidence='no privileged markers in response')


# ── 5. Parameter-tampering privilege escalation ───────────────────────────────

def escalation_verdict(baseline_status, baseline_text, tampered_status, tampered_text):
    """Injecting role=admin / isAdmin=true changes the response to expose
    privileged state that the baseline did NOT contain → escalation."""
    if not _accepted(tampered_status, tampered_text):
        return Verdict(False, evidence='tampered request rejected — control working')
    base_priv = _has(baseline_text, _ELEVATED_MARKERS)
    tamp_priv = _has(tampered_text, _ELEVATED_MARKERS)
    if tamp_priv and not base_priv:
        return Verdict(True, 'high', 'elevated state appeared only after role/admin tampering')
    return Verdict(False, evidence='no new elevated state vs baseline')


# ── 6. Workflow / step bypass ─────────────────────────────────────────────────

def workflow_bypass_verdict(direct_status, direct_text):
    """Hitting a terminal step (e.g. /checkout/complete, /order/confirm) directly
    succeeds without the prerequisite step → workflow bypass."""
    if not _accepted(direct_status, direct_text):
        return Verdict(False, evidence='terminal step rejected without prerequisite — control working')
    if _has(direct_text, _SUCCESS_MARKERS):
        return Verdict(True, 'medium', 'terminal workflow step succeeded without prerequisite step')
    return Verdict(False, evidence='no success confirmation on direct step access')


# ── helper: candidate field/endpoint classifiers (used by the runner) ─────────

_PRICE_FIELDS = re.compile(r'(amount|price|cost|total|qty|quantity|count|balance|credit|fee|discount)', re.I)
_WORKFLOW_TERMINALS = ('/checkout/complete', '/checkout/confirm', '/order/confirm',
                       '/order/complete', '/payment/success', '/cart/finalize',
                       '/confirm', '/complete', '/success')
_PRIVILEGED_PATHS = ('/admin', '/api/admin', '/manage', '/dashboard/admin',
                     '/api/users', '/api/v1/users', '/settings/admin', '/console')


def is_price_field(name):
    return bool(_PRICE_FIELDS.search(name or ''))


def looks_like_workflow_terminal(path):
    p = (path or '').lower()
    return any(t in p for t in _WORKFLOW_TERMINALS)


def looks_like_privileged_path(path):
    p = (path or '').lower()
    return any(t in p for t in _PRIVILEGED_PATHS)
