"""Modular Flask application factory.

Run dev server:  python app_new.py
Run production:  gunicorn 'app_new:create_app()' --bind 0.0.0.0:8080 --workers 1
"""
import os
import secrets
import threading
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False
    Limiter = None

import core.extensions as _ext


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    _key_file = os.path.join(os.path.dirname(__file__), '.secret_key')
    if os.environ.get('SECRET_KEY'):
        app.secret_key = os.environ['SECRET_KEY']
    elif os.path.exists(_key_file):
        app.secret_key = open(_key_file, 'rb').read()
    else:
        raw = secrets.token_bytes(32)
        app.secret_key = raw
        try:
            with open(_key_file, 'wb') as f:
                f.write(raw)
            os.chmod(_key_file, 0o600)
        except Exception:
            pass

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=os.environ.get('ALLOW_INSECURE_COOKIE', '1') != '1',
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        JSON_SORT_KEYS=False,
    )

    allowed = [o.strip() for o in os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if o.strip()]
    CORS(app, supports_credentials=True, origins=allowed if allowed else [])

    if LIMITER_AVAILABLE:
        _ext.limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=[],
            storage_uri='memory://',
        )
    else:
        _ext.limiter = None

    @app.after_request
    def _security_headers(response):
        h = response.headers
        h.setdefault('X-Content-Type-Options', 'nosniff')
        h.setdefault('X-Frame-Options', 'DENY')
        h.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        h.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
        csp = (
            "default-src 'self' blob:; "
            "img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com https://d3js.org https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        h.setdefault('Content-Security-Policy', csp)
        h.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
        h.pop('Server', None)
        h.pop('X-Powered-By', None)
        return response

    _SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}

    @app.before_request
    def _check_same_origin():
        if request.method in _SAFE_METHODS:
            return None
        if request.path in ('/login', '/logout') and request.method == 'GET':
            return None
        origin  = request.headers.get('Origin')
        referer = request.headers.get('Referer')
        host    = request.host_url.rstrip('/')
        if origin:
            if origin.rstrip('/') != host:
                return jsonify({'status': 'error', 'message': 'Cross-origin request blocked'}), 403
        elif referer:
            ref = urlparse(referer)
            if f'{ref.scheme}://{ref.netloc}' != host.rstrip('/'):
                return jsonify({'status': 'error', 'message': 'Cross-origin request blocked'}), 403
        return None

    @app.errorhandler(Exception)
    def _exc(e):
        import traceback, uuid as _uuid
        cid = _uuid.uuid4().hex[:8]
        app.logger.error(f'[{cid}] {e}\n{traceback.format_exc()}')
        return jsonify({'status': 'error', 'message': 'An internal error occurred.', 'ref': cid}), 500

    @app.errorhandler(404)
    def _404(e):
        return jsonify({'status': 'error', 'message': 'Not found'}), 404

    @app.errorhandler(500)
    def _500(e):
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

    from core.auth          import auth_bp
    from core.main_routes   import main_routes_bp
    from core.misc_routes   import misc_bp
    from core.tool_routes   import tools_bp
    from core.scope_routes  import scope_bp
    from scanner.routes     import scan_bp
    from reports.routes     import reports_bp
    from risk.routes        import risk_bp
    from recon.routes       import recon_bp
    from ai.routes          import ai_bp

    for bp in (auth_bp, main_routes_bp, misc_bp, tools_bp, scope_bp,
               scan_bp, reports_bp, risk_bp, recon_bp, ai_bp):
        app.register_blueprint(bp)

    from core.database import init_db
    with app.app_context():
        init_db()

    # IRON RULE 4: refuse to boot an insecure production instance (default
    # password, no admin, or missing argon2). Raises in production; in dev it
    # forces a first-run password change instead.
    from core.database import enforce_admin_security
    enforce_admin_security()

    try:
        from scanner.suppression import load_suppressions
        load_suppressions()
    except Exception:
        pass

    return app


if __name__ == '__main__':
    application = create_app()
    application.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 8080)),
        debug=os.environ.get('FLASK_DEBUG', '0') == '1',
        threaded=True,
    )
