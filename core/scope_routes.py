"""Scope-contract management API (IRON RULE 1).

Operators define the per-engagement authorization boundary here. Contracts are
signed (HMAC) on save so their integrity can be verified at authorization time.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, session
from core.auth import login_required
from core.logger import log
from core.scope import (ScopeContract, sign_contract, verify_signature,
                        normalize_target, _parse_iso)
from core.database import (save_scope_contract, get_scope_contract,
                           list_scope_contracts, set_scope_active, get_authz_log)
from core.utils import _safe_str

scope_bp = Blueprint('scope', __name__)

_VALID_INTENSITY = {'stealth', 'quick', 'balanced', 'aggressive'}


def _validate_contract(data):
    """Return (clean_contract_dict, error_or_None)."""
    if not isinstance(data, dict):
        return None, 'body must be a JSON object'
    scope_id = _safe_str(data.get('scope_id')).strip()
    operator = _safe_str(data.get('operator')).strip()
    if not scope_id:
        return None, 'scope_id is required'
    if not operator:
        return None, 'operator is required'

    def _strlist(key):
        v = data.get(key, [])
        if not isinstance(v, list):
            return None
        return [_safe_str(x).strip().lower() for x in v if _safe_str(x).strip()]

    allowed_domains = _strlist('allowed_domains')
    allowed_ips = _strlist('allowed_ips')
    allowed_cidrs = _strlist('allowed_cidrs')
    denied = _strlist('denied') or []
    if allowed_domains is None or allowed_ips is None or allowed_cidrs is None:
        return None, 'allowed_domains/allowed_ips/allowed_cidrs must be lists'
    if not (allowed_domains or allowed_ips or allowed_cidrs):
        return None, 'at least one of allowed_domains/allowed_ips/allowed_cidrs is required'

    intensity = _safe_str(data.get('intensity_ceiling', 'balanced')).strip().lower()
    if intensity not in _VALID_INTENSITY:
        return None, f'intensity_ceiling must be one of {sorted(_VALID_INTENSITY)}'

    nb = _safe_str(data.get('not_before')).strip()
    na = _safe_str(data.get('not_after')).strip()
    for label, val in (('not_before', nb), ('not_after', na)):
        if val:
            try:
                _parse_iso(val)
            except Exception:
                return None, f'{label} must be ISO-8601 (e.g. 2026-06-30T23:59:59Z)'

    contract = {
        'scope_id': scope_id,
        'operator': operator,
        'client': _safe_str(data.get('client')).strip(),
        'allowed_domains': allowed_domains,
        'allowed_ips': allowed_ips,
        'allowed_cidrs': allowed_cidrs,
        'denied': denied,
        'not_before': nb or None,
        'not_after': na or None,
        'intensity_ceiling': intensity,
        'allow_private_targets': bool(data.get('allow_private_targets', False)),
        'created_at': datetime.now(timezone.utc).isoformat(),
    }
    return contract, None


@scope_bp.route('/api/scope', methods=['POST'])
@login_required
def create_scope():
    """Create/replace a scope contract. The server signs it on save."""
    data = request.get_json(silent=True) or {}
    contract, err = _validate_contract(data)
    if err:
        return jsonify({'status': 'error', 'message': err}), 400
    contract['signature'] = sign_contract(contract)
    if not save_scope_contract(contract):
        return jsonify({'status': 'error', 'message': 'could not persist contract'}), 500
    log('info', f'[SCOPE] contract created: {contract["scope_id"]} by {session.get("user","?")}')
    return jsonify({'status': 'ok', 'scope_id': contract['scope_id'],
                    'signature': contract['signature']})


@scope_bp.route('/api/scope', methods=['GET'])
@login_required
def list_scopes():
    items = list_scope_contracts()
    for it in items:
        it['signature_valid'] = verify_signature(it.get('contract', {}))
    return jsonify({'status': 'ok', 'count': len(items), 'scopes': items})


@scope_bp.route('/api/scope/<scope_id>', methods=['GET'])
@login_required
def get_scope(scope_id):
    contract = get_scope_contract(scope_id, active_only=False)
    if not contract:
        return jsonify({'status': 'error', 'message': 'not found'}), 404
    return jsonify({'status': 'ok', 'contract': contract,
                    'signature_valid': verify_signature(contract)})


@scope_bp.route('/api/scope/<scope_id>/deactivate', methods=['POST'])
@login_required
def deactivate_scope(scope_id):
    if not set_scope_active(scope_id, False):
        return jsonify({'status': 'error', 'message': 'not found'}), 404
    log('info', f'[SCOPE] contract deactivated: {scope_id} by {session.get("user","?")}')
    return jsonify({'status': 'ok', 'scope_id': scope_id, 'active': False})


@scope_bp.route('/api/scope/<scope_id>/audit', methods=['GET'])
@login_required
def scope_audit(scope_id):
    return jsonify({'status': 'ok', 'scope_id': scope_id,
                    'decisions': get_authz_log(scope_id=scope_id)})


@scope_bp.route('/api/scope/check', methods=['POST'])
@login_required
def scope_check():
    """Dry-run: would (target, intensity) be authorized under scope_id? No side effects."""
    data = request.get_json(silent=True) or {}
    scope_id = _safe_str(data.get('scope_id')).strip()
    target = _safe_str(data.get('target')).strip()
    intensity = _safe_str(data.get('intensity', 'balanced')).strip().lower()
    contract = get_scope_contract(scope_id)
    if not contract:
        return jsonify({'status': 'error', 'message': 'unknown or inactive scope_id'}), 404
    decision = ScopeContract(contract).authorize(target, intensity)
    return jsonify({'status': 'ok', 'decision': decision.as_dict()})
