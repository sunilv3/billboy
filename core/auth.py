"""Authentication: login_required decorator, login/logout/auth-check routes."""
import time
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template
from functools import wraps
from core.logger import log
from core.passwords import verify_password, needs_rehash
from core.database import (_load_users_from_db, USERS, DB_PATH, init_users,
                           get_must_change, set_user_password)
from core.utils import SQLITE_AVAILABLE, sqlite3_mod, _safe_str

# Endpoints a must-change session may still reach before setting a new password.
_MUST_CHANGE_ALLOWED = {'auth.change_password', 'auth.logout', 'auth.auth_check'}
MIN_PASSWORD_LEN = 12

try:
    from flask_limiter import Limiter
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

# Warn loudly if rate limiter is unavailable — all rate limits become no-ops
if not LIMITER_AVAILABLE:
    import logging as _logging
    _logging.critical('[SECURITY] flask-limiter is NOT installed — all rate limits are DISABLED. '
                      'Install it: pip install flask-limiter')

auth_bp = Blueprint('auth', __name__)

LOGIN_ATTEMPTS = {}
_LOGIN_ATTEMPTS_MAX_IPS = 10000  # cap dict size to prevent memory DoS


def login_required(f):
    """Decorator: redirect to /login if not authenticated; enforce forced
    first-run password change (IRON RULE 4) on every protected route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            if request.is_json or request.headers.get('Accept') == 'application/json':
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login'))
        # A flagged session can only reach change-password / logout / auth-check.
        if session.get('must_change') and request.endpoint not in _MUST_CHANGE_ALLOWED:
            return jsonify({
                'status': 'error',
                'code': 'password_change_required',
                'message': 'You must set a new password before continuing.',
            }), 403
        return f(*args, **kwargs)
    return decorated


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    init_users()
    if 'user' in session:
        return redirect(url_for('main_routes.index'))
    error = None
    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        now = time.time()
        LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < 60]
        if len(LOGIN_ATTEMPTS[ip]) >= 10:
            return jsonify({'status': 'error', 'message': 'Too many attempts. Try again in 60 seconds.'}), 429
        # SECURITY: evict oldest IPs when dict grows too large (prevent unbounded memory growth)
        if len(LOGIN_ATTEMPTS) > _LOGIN_ATTEMPTS_MAX_IPS:
            oldest_ip = min(LOGIN_ATTEMPTS, key=lambda k: min(LOGIN_ATTEMPTS[k]) if LOGIN_ATTEMPTS[k] else 0)
            LOGIN_ATTEMPTS.pop(oldest_ip, None)
        data = request.get_json(silent=True) or request.form
        if not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid request body'}), 400
        username = _safe_str(data.get('username')).strip().lower()
        password = _safe_str(data.get('password'))
        if username in USERS and verify_password(USERS[username], password):
            session['user'] = username
            # Transparently migrate legacy (pbkdf2/scrypt) hashes to argon2id.
            if needs_rehash(USERS[username]):
                try:
                    set_user_password(username, password)
                except Exception:
                    pass
            must_change = get_must_change(username)
            session['must_change'] = must_change
            if SQLITE_AVAILABLE:
                try:
                    with sqlite3_mod.connect(DB_PATH) as conn:
                        conn.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE username=?", (username,))
                except Exception:
                    pass
            if request.is_json:
                return jsonify({'status': 'ok', 'user': username, 'must_change': must_change})
            if must_change:
                return redirect(url_for('auth.login'))
            return redirect(url_for('main_routes.index'))
        # Only count failed attempts
        LOGIN_ATTEMPTS[ip].append(now)
        error = 'Invalid credentials'
        if request.is_json:
            return jsonify({'status': 'error', 'message': error}), 401
    return render_template('login.html', error=error)


@auth_bp.route('/api/auth/change_password', methods=['POST'])
@login_required
def change_password():
    """Set a new password for the current user (also clears must_change)."""
    user = session.get('user')
    data = request.get_json(silent=True) or request.form
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'Invalid request body'}), 400
    current = _safe_str(data.get('current_password'))
    new = _safe_str(data.get('new_password'))
    if user not in USERS or not verify_password(USERS[user], current):
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 401
    if len(new) < MIN_PASSWORD_LEN:
        return jsonify({'status': 'error',
                        'message': f'New password must be at least {MIN_PASSWORD_LEN} characters'}), 400
    if verify_password(USERS[user], new):
        return jsonify({'status': 'error', 'message': 'New password must differ from the current one'}), 400
    if not set_user_password(user, new):
        return jsonify({'status': 'error', 'message': 'Could not update password'}), 500
    session['must_change'] = False
    log('info', f'[AUTH] Password changed for user: {user}')
    return jsonify({'status': 'ok', 'message': 'Password updated'})


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


@auth_bp.route('/api/auth/check')
def auth_check():
    if 'user' in session:
        return jsonify({'authenticated': True, 'user': session['user']})
    # F-13: return 401 for unauthenticated to avoid username-enumeration / fingerprinting
    return jsonify({'authenticated': False}), 401


@auth_bp.route('/api/auth/bypass_results')
@login_required
def auth_bypass_results():
    """Return auth bypass scan results with full test details."""
    from scanner.state import scan_state, LOCK
    with LOCK:
        data = dict(scan_state.get('auth_bypass_data', {}))
    return jsonify({
        'status': 'ok',
        'confirmed_bypasses': data.get('confirmed_bypasses', []),
        'false_positives': data.get('false_positives', {}),
        'total_tests': data.get('total_tests', 0),
        'endpoints_tested': data.get('endpoints_tested', 0),
        'results': data.get('results', []),
    })
