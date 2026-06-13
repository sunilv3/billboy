"""Risk calculation engine: FAIR, CVSS, DREAD, custom methodologies."""
import math
import hashlib
import time
import secrets
import json
import threading
from core.utils import SQLITE_AVAILABLE, sqlite3_mod
from core.logger import log
from core.database import DB_PATH
from scanner.state import scan_state

RISK_LEVELS = [
    (0,  'Info',     'var(--t3)'),
    (1,  'Low',      'var(--green)'),
    (4,  'Medium',   'var(--yellow)'),
    (10, 'High',     'var(--orange)'),
    (16, 'Critical', 'var(--red)'),
]

_RISK_ID_LOCK = threading.Lock()


def _level_from_score(score):
    for threshold, name, _ in reversed(RISK_LEVELS):
        if score >= threshold:
            return name
    return 'Info'


def _color_for_level(level):
    for _, name, color in RISK_LEVELS:
        if name == level:
            return color
    return 'var(--t3)'


def _next_risk_id():
    with _RISK_ID_LOCK:
        if not SQLITE_AVAILABLE:
            return f'RSK-{int(time.time())}-{secrets.token_hex(2)}'
        with sqlite3_mod.connect(DB_PATH) as conn:
            row = conn.execute("SELECT risk_id FROM risks ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return 'RSK-0001'
        try:
            n = int(row[0].split('-')[-1]) + 1
            return f'RSK-{n:04d}'
        except Exception:
            return f'RSK-{int(time.time())}-{secrets.token_hex(2)}'


def _apply_control(l, i, eff_pct):
    """Reduce likelihood and/or impact by control effectiveness 0-100."""
    eff = max(0, min(100, int(eff_pct or 0)))
    # Apply 70% to likelihood, 30% to impact — common heuristic
    l_red = eff * 0.7 / 100
    i_red = eff * 0.3 / 100
    rl = max(1, int(round(l - (l - 1) * l_red)))
    ri = max(1, int(round(i - (i - 1) * i_red)))
    return rl, ri


def compute_risk(methodology, likelihood, impact, asset_value=None, control_eff=0, sle=None, aro=None):
    """
    Returns dict with inherent and residual scores for the given methodology.
    - NIST / ISO: qualitative 5x5 matrix
    - FAIR-lite:  quantitative (ALE = SLE * ARO)
    """
    l = max(1, min(5, int(likelihood)))
    i = max(1, min(5, int(impact)))
    inherent = l * i
    rl, ri = _apply_control(l, i, control_eff)
    residual = rl * ri
    result = {
        'methodology': methodology,
        'inherent_likelihood': l,
        'inherent_impact': i,
        'inherent_score': inherent,
        'inherent_level': _level_from_score(inherent),
        'control_effectiveness': int(control_eff or 0),
        'residual_likelihood': rl,
        'residual_impact': ri,
        'residual_score': residual,
        'residual_level': _level_from_score(residual),
    }
    if methodology == 'FAIR':
        try:
            s = float(sle) if sle else float(asset_value or 0)
            a = float(aro) if aro else (l / 5.0)  # ARO proxy from likelihood
            result['fair_sle'] = round(s, 2)
            result['fair_aro'] = round(a, 3)
            result['fair_inherent_ale'] = round(s * a, 2)
            result['fair_residual_ale'] = round(s * a * (1 - (int(control_eff or 0) / 100.0)), 2)
        except Exception:
            result['fair_inherent_ale'] = 0
            result['fair_residual_ale'] = 0
    return result


def _risk_row_to_dict(r):
    """Convert a sqlite3 Row risk record to a JSON-friendly dict."""
    d = dict(r)
    # Parse JSON-encoded list fields
    for f in ('linked_findings', 'framework_refs'):
        try:
            d[f] = json.loads(d.get(f) or '[]')
        except Exception:
            d[f] = []
    return d
