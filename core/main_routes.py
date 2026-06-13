"""Main routes: index, SSE stream, health."""
import time
from flask import Blueprint, render_template, Response, request, session, jsonify
from core.auth import login_required
from core.logger import log, sse_stream
from scanner.state import scan_state, LOCK

main_routes_bp = Blueprint('main_routes', __name__)

@main_routes_bp.route('/')
@login_required
def index():
    return render_template('infosec_platform.html', username=session.get('user', 'admin'))


@main_routes_bp.route('/api/health')
def health():
    """Liveness probe for Docker/K8s."""
    with LOCK:
        scanning = scan_state.get('scanning', False)
        findings_count = len(scan_state.get('findings', []))
    return jsonify({
        'status': 'ok',
        'scanning': scanning,
        'findings': findings_count,
        'ts': time.time(),
    })

