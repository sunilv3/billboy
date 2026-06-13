"""Flask Blueprint for /api/recon/* endpoints."""
import json
import re
import time
import threading
from flask import Blueprint, request, jsonify, Response
from core.auth import login_required
from core.utils import _safe_str, _check_target_for_ssrf
from core.logger import log, sse_stream
from scanner.state import scan_state, LOCK
from recon.agent import (
    run_intelligent_recon_agent,
    RECON_STATE,
    RECON_LOCK,
    _recon_log,
)

recon_bp = Blueprint('recon', __name__, url_prefix='/api/recon')


@recon_bp.route('/start', methods=['POST'])
@login_required
def recon_start():
    """Kick off the intelligent recon workflow."""
    data = request.get_json(silent=True) or {}
    target = _safe_str(data.get('target', '')).strip().lower()
    target = re.sub(r'^https?://', '', target).split('/')[0]
    if not target:
        return jsonify({'status': 'error', 'message': 'Missing target'}), 400
    err, warn = _check_target_for_ssrf(target)
    if err:
        return jsonify({'status': 'error', 'message': err}), 400
    if warn:
        _recon_log(f'[SSRF] {warn}', 'warn')
    with RECON_LOCK:
        if RECON_STATE['running']:
            return jsonify({'status': 'error', 'message': 'Recon already running'}), 409
    threading.Thread(target=run_intelligent_recon_agent, args=(target,), daemon=True).start()
    return jsonify({'status': 'started', 'target': target})



@recon_bp.route('/status')
@login_required
def recon_status():
    """Return current recon state (phase, progress, logs)."""
    with RECON_LOCK:
        return jsonify({
            'running': RECON_STATE['running'],
            'target': RECON_STATE['target'],
            'phase': RECON_STATE['phase'],
            'phase_num': RECON_STATE['phase_num'],
            'started_at': RECON_STATE['started_at'],
            'completed_at': RECON_STATE['completed_at'],
            'log_count': len(RECON_STATE['logs']),
            'recent_logs': RECON_STATE['logs'][-20:],
            'has_report': bool(RECON_STATE['report']),
        })



@recon_bp.route('/report')
@login_required
def recon_report():
    """Return the full structured recon report."""
    with RECON_LOCK:
        if not RECON_STATE['report']:
            return jsonify({'status': 'no_report',
                            'message': 'No recon report available. Run /api/recon/start first.'}), 404
        return jsonify({'status': 'ok', 'report': RECON_STATE['report']})



@recon_bp.route('/stream')
@login_required
def recon_stream():
    """SSE endpoint — streams recon log lines as they are produced."""
    def _generate():
        seen = 0
        yield 'data: {"type":"connected"}\n\n'
        while True:
            with RECON_LOCK:
                logs = RECON_STATE['logs']
                phase = RECON_STATE['phase']
                running = RECON_STATE['running']
                new_entries = logs[seen:]
                seen = len(logs)
            for entry in new_entries:
                yield f'data: {json.dumps({"type": "log", "phase": phase, "entry": entry})}\n\n'
            if not running and seen > 0:
                with RECON_LOCK:
                    has_report = bool(RECON_STATE['report'])
                yield f'data: {json.dumps({"type": "complete", "has_report": has_report})}\n\n'
                break
            time.sleep(0.4)
    return Response(_generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})



@recon_bp.route('/stop', methods=['POST'])
@login_required
def recon_stop():
    """Signal the running recon agent to stop gracefully."""
    with RECON_LOCK:
        if RECON_STATE['running']:
            RECON_STATE['running'] = False
            RECON_STATE['phase'] = 'Stopped'
            _recon_log('Recon stopped by user request.', 'warn')
            return jsonify({'status': 'ok', 'message': 'Stop signal sent'})
    return jsonify({'status': 'ok', 'message': 'No recon running'})


@recon_bp.route('/ai-analyze', methods=['POST'])
@login_required
def recon_ai_analyze():
    """Run AI analysis on existing recon findings (standalone, no recon needed)."""
    import json as _json
    import re as _re
    from ai.ollama import _ollama_generate, _ollama_available, OLLAMA_MODEL

    if not _ollama_available():
        return jsonify({'status': 'error', 'message': f'Ollama not available or model {OLLAMA_MODEL} not pulled'}), 503

    with RECON_LOCK:
        report = RECON_STATE.get('report', {})
    if not report:
        return jsonify({'status': 'error', 'message': 'No recon report available. Run recon first.'}), 400

    findings = report.get('scan_results', {}).get('findings', [])
    if not findings:
        return jsonify({'status': 'error', 'message': 'No findings in report to analyze'}), 400

    target = report.get('target', '')
    site_type = report.get('website_classification', {}).get('type', 'unknown')
    tech = report.get('technology_stack', {})

    finding_summaries = []
    for f in findings[:60]:
        finding_summaries.append({
            'id': f.get('id', f.get('title', '')[:40]),
            'severity': f.get('severity', 'info'),
            'title': f.get('title', ''),
            'affected_url': f.get('affected_url', ''),
            'evidence': (f.get('evidence', '') or '')[:200],
        })

    tech_summary = ', '.join(k for k, v in tech.items() if v)[:100] or 'unknown'

    # Triage
    triage_prompt = f"""Analyze these security findings for target: {target}
Site type: {site_type}
Technologies: {tech_summary}

Classify each finding as TRUE, FALSE_POSITIVE, or UNCERTAIN.

Findings:
{_json.dumps(finding_summaries, indent=1)}

Respond in EXACTLY this JSON format (no markdown fences):
{{
  "triage": [{{"id": "finding-id", "verdict": "TRUE|FALSE_POSITIVE|UNCERTAIN", "confidence": 0.0-1.0, "reason": "brief reason"}}],
  "false_positive_count": N,
  "true_positive_count": N,
  "executive_summary": "2-3 sentence risk assessment"
}}"""

    triage_raw = _ollama_generate(triage_prompt, system='You are an expert penetration tester. Respond ONLY in valid JSON.')
    triage_result = None
    if triage_raw:
        try:
            json_match = _re.search(r'\{[\s\S]*"triage"[\s\S]*\}', triage_raw)
            if json_match:
                triage_result = _json.loads(json_match.group())
        except Exception:
            pass

    # Attack paths
    attack_prompt = f"""Target: {target}
Site type: {site_type}
Findings: {_json.dumps([{'sev': f['severity'], 'title': f['title']} for f in finding_summaries[:25]], indent=1)}

Identify attack chains and prioritized remediation.
Respond in EXACTLY this JSON format (no markdown fences):
{{
  "attack_paths": [{{"name": "path", "description": "steps", "impact": "critical|high|medium", "likelihood": "high|medium|low"}}],
  "prioritized_remediation": [{{"priority": 1, "action": "fix", "effort": "low|medium|high"}}]
}}"""

    attack_raw = _ollama_generate(attack_prompt, system='You are a red team operator. Respond ONLY in valid JSON.')
    attack_result = None
    if attack_raw:
        try:
            json_match = _re.search(r'\{[\s\S]*"attack_paths"[\s\S]*\}', attack_raw)
            if json_match:
                attack_result = _json.loads(json_match.group())
        except Exception:
            pass

    return jsonify({
        'status': 'ok',
        'analysis': {
            'model': OLLAMA_MODEL,
            'triage': triage_result,
            'attack_paths': attack_result,
        }
    })


