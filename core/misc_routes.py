"""Miscellaneous routes not covered by other blueprints."""
import json, time, re, hashlib, threading
from datetime import datetime
from flask import Blueprint, request, jsonify, Response
from core.auth import login_required
from core.logger import log, push_sse, sse_stream
from core.database import DB_PATH
from core.utils import (_safe_str, _check_target_for_ssrf,
                        SQLITE_AVAILABLE, sqlite3_mod)
from scanner.state import scan_state, LOCK, SCAN_JOBS
from scanner.orchestrator import run_full_scan

misc_bp = Blueprint('misc', __name__)

@misc_bp.route('/api/stream')
@login_required
def sse_stream_route():
    return Response(sse_stream(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache', 'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no', 'Access-Control-Allow-Origin': request.host_url.rstrip('/')
    })



@misc_bp.route('/api/scan/trigger', methods=['POST'])
def scan_trigger():
    """CI/CD webhook — accepts X-API-Key header and target param"""
    api_key = request.headers.get('X-API-Key', '')
    if not api_key or api_key != scan_state.get('webhook_api_key', ''):
        return jsonify({'status': 'error', 'message': 'Invalid API key'}), 401
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'Invalid request body'}), 400
    target = _safe_str(data.get('target')).strip().lower()
    target = re.sub(r'^https?://', '', target).split('/')[0]
    if not target:
        return jsonify({'status': 'error', 'message': 'No target'}), 400
    # F-04: SSRF guard
    err, warn = _check_target_for_ssrf(target)
    if err:
        return jsonify({'status': 'error', 'message': err}), 400
    if warn:
        log('warn', f'[SSRF] {warn}')
    # Atomic check-and-set
    with LOCK:
        if scan_state['scanning']:
            return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 409
        scan_id = hashlib.md5(f'{target}_{time.time()}'.encode()).hexdigest()[:12]
        SCAN_JOBS[scan_id] = {'target': target, 'status': 'queued', 'started_at': None, 'completed_at': None, 'findings': 0, 'score': 0}
    def ci_worker():
        with LOCK:
            SCAN_JOBS[scan_id]['status'] = 'running'
            SCAN_JOBS[scan_id]['started_at'] = datetime.now().isoformat()
            scan_state.update({
                'scanning': True, 'scan_start': time.time(),
                'progress': {k: 0 for k in scan_state['progress']},
                'logs': [], 'elapsed': '00:00:00', 'target': target,
                'findings': [], 'finding_status': {},
                'stats': {k: 0 for k in ('critical','high','medium','low','info')},
                'assets': [], 'dir_data': [], 'js_endpoints': [], 'wayback_urls': [], 'emailsec_data': {}
            })
        push_sse('scan_start', {'target': target})
        run_full_scan(target)
        with LOCK:
            SCAN_JOBS[scan_id]['status'] = 'complete'
            SCAN_JOBS[scan_id]['findings'] = len(scan_state['findings'])
            SCAN_JOBS[scan_id]['score'] = scan_state['risk_score']
            SCAN_JOBS[scan_id]['completed_at'] = datetime.now().isoformat()
            # Vuln mgmt snapshot
            fs = scan_state['finding_status']
            open_cnt = sum(1 for v in fs.values() if v.get('status') in ('open', 'in_progress'))
            resolved_cnt = sum(1 for v in fs.values() if v.get('status') in ('mitigated', 'accepted', 'false_positive'))
            scan_state['status_history'].append({
                'date': datetime.now().strftime('%Y-%m-%d'),
                'open': open_cnt,
                'mitigated': resolved_cnt,
                'total': len(scan_state['findings'])
            })
            if len(scan_state['status_history']) > 365:
                scan_state['status_history'] = scan_state['status_history'][-365:]
    threading.Thread(target=ci_worker, daemon=True).start()
    return jsonify({'status': 'started', 'scan_id': scan_id, 'target': target, 'message': 'Scan initiated via CI/CD webhook'})


@misc_bp.route('/api/scan/<scan_id>/status')
@login_required
def scan_status(scan_id):
    job = SCAN_JOBS.get(scan_id)
    if not job:
        return jsonify({'status': 'not_found'}), 404
    return jsonify(job)


@misc_bp.route('/api/scan/<scan_id>/findings')
@login_required
def scan_findings(scan_id):
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'DB not available'}), 500
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            rows = conn.execute('SELECT * FROM findings WHERE scan_id=?', (scan_id,)).fetchall()
        return jsonify({'status': 'ok', 'count': len(rows), 'findings': [dict(r) for r in rows]})
    except Exception as e:
        log('err', f'[HISTORY] scan_findings error: {e}')
        return jsonify({'status': 'error', 'message': 'Failed to retrieve findings'}), 500


@misc_bp.route('/api/history')
@login_required
def scan_history_api():
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'DB not available'}), 500
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            rows = conn.execute('SELECT * FROM scan_history ORDER BY created_at DESC LIMIT 20').fetchall()
        return jsonify({'status': 'ok', 'scans': [dict(r) for r in rows]})
    except Exception as e:
        log('err', f'[HISTORY] scan_history error: {e}')
        return jsonify({'status': 'error', 'message': 'Failed to retrieve scan history'}), 500

