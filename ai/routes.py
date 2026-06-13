"""AI/LLM analysis routes — enhanced with real-time triage and better prompts."""
import json
import re
import time
import threading
from flask import Blueprint, request, jsonify
from core.auth import login_required
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, op_log
from ai.ollama import _ollama_generate, _ollama_available, OLLAMA_MODEL, OLLAMA_BASE

ai_bp = Blueprint('ai', __name__, url_prefix='/api/ai')

# Background triage thread control
_triage_thread = None
_triage_running = False


@ai_bp.route('/status')
@login_required
def ai_status():
    """Check if Ollama + model are available."""
    available = _ollama_available()
    return jsonify({
        'status': 'ok',
        'available': available,
        'model': OLLAMA_MODEL,
        'base_url': OLLAMA_BASE,
    })


@ai_bp.route('/analyze', methods=['POST'])
@login_required
def ai_analyze():
    """
    AI post-scan analysis. Sends findings to LLM for:
    1. False positive triage
    2. Attack path identification
    3. Executive summary
    4. Remediation prioritization
    5. Risk scoring
    """
    if not _ollama_available():
        return jsonify({
            'status': 'error',
            'message': f'Ollama not available or model {OLLAMA_MODEL} not pulled. Run: ollama pull {OLLAMA_MODEL}'
        }), 503

    with LOCK:
        findings = list(scan_state.get('findings', []))
        target = scan_state.get('target', '')
        scan_type = scan_state.get('scan_type', 'full')
        tech_data = dict(scan_state.get('tech_data', {}))
        discovery_data = dict(scan_state.get('discovery_data', {}))

    if not findings:
        return jsonify({'status': 'error', 'message': 'No findings to analyze. Run a scan first.'}), 400

    # Build compact finding summary for the LLM
    finding_summaries = []
    for f in findings[:80]:
        finding_summaries.append({
            'id': f.get('id', ''),
            'severity': f.get('sev', 'info'),
            'title': f.get('title', ''),
            'cvss': f.get('cvss', ''),
            'asset': f.get('asset', ''),
            'details': (f.get('details', '') or '')[:300],
            'verified': f.get('verified', True),
            'tool': f.get('tool', ''),
        })

    tech_summary = ', '.join(sorted(tech_data.keys())[:20]) if tech_data else 'unknown'

    # ── Analysis 1: FP Triage (improved prompt) ──
    fp_prompt = f"""You are a senior penetration tester reviewing scan results for {target}.
Technology stack: {tech_summary}
Scan type: {scan_type}

Analyze each finding and classify it. Be strict — most automated scanner findings are false positives.

FALSE_POSITIVE (mark if ANY of these apply):
- Response is SPA shell (same HTML for all URLs, <div id="root">, webpack bundles)
- Finding is in minified JS bundle (webpack chunk, CDN asset)
- Status 200 but content is generic/error page, not actual sensitive data
- "Admin panel" on SPA (all routes return 200 with same shell)
- Header missing on HTTP site (HSTS only applies to HTTPS)
- Port open but service is benign (HTTP on port 80)
- Keyword match without context (e.g., "password" in JS source code)

TRUE (mark if ANY of these apply):
- Response body contains actual sensitive data (passwords, keys, tokens, database content)
- File content differs from baseline (real /etc/passwd content, config files)
- Actual login bypass (different response after auth attempt)
- Confirmed injection (sqlmap/dalfox output with proof)
- Real stack trace or debug output in response

Findings to analyze:
{json.dumps(finding_summaries, indent=1)}

Respond with ONLY valid JSON (no markdown, no explanation):
{{"triage": [{{"id": "finding-id", "verdict": "TRUE", "confidence": 0.95, "reason": "specific evidence"}}, {{"id": "finding-id", "verdict": "FALSE_POSITIVE", "confidence": 0.90, "reason": "specific reason"}}], "false_positive_count": 0, "true_positive_count": 0, "uncertain_count": 0, "overall_risk": "critical"}}"""

    triage_raw = _ollama_generate(fp_prompt, system='You are an expert security analyst with 10+ years of penetration testing experience. You specialize in identifying false positives in automated scans. Respond ONLY in valid JSON. No markdown, no explanation outside the JSON.')
    triage_result = None
    if triage_raw:
        try:
            json_match = re.search(r'\{[\s\S]*"triage"[\s\S]*\}', triage_raw)
            if json_match:
                triage_result = json.loads(json_match.group())
        except Exception as e:
            log('warn', f'[AI] Triage JSON parse failed: {e}')

    # ── Analysis 2: Attack Paths (improved prompt) ──
    attack_prompt = f"""You are a red team operator who has compromised {target}.
Technology stack: {tech_summary}

Your mission: Identify the shortest path from initial access to full compromise.

Available findings (your footholds):
{json.dumps([{'id': f['id'], 'sev': f['severity'], 'title': f['title'], 'asset': f['asset']} for f in finding_summaries[:30]], indent=1)}

Think step by step:
1. Which finding gives you initial access?
2. What can you see from inside?
3. What credentials/tokens can you extract?
4. How do you escalate privileges?
5. What's your final objective?

Be specific — name actual endpoints, parameters, and exploitation techniques.

Respond with ONLY valid JSON:
{{"attack_paths": [{{"name": "Path Name", "description": "Step 1: Use [finding] to access... Step 2: Extract... Step 3: Escalate via...", "findings": ["id1", "id2"], "impact": "critical", "likelihood": "high", "mitigation": "Specific fix to break this chain"}}], "executive_summary": "Overall risk assessment in 2-3 sentences", "risk_score": 75, "top_3_actions": ["Fix 1", "Fix 2", "Fix 3"]}}"""

    attack_raw = _ollama_generate(attack_prompt, system='You are a red team operator with OSCP/OSCE certification. Think like an attacker. Be specific about exploitation steps. Respond ONLY in valid JSON.')
    attack_result = None
    if attack_raw:
        try:
            json_match = re.search(r'\{[\s\S]*"attack_paths"[\s\S]*\}', attack_raw)
            if json_match:
                attack_result = json.loads(json_match.group())
        except Exception as e:
            log('warn', f'[AI] Attack path JSON parse failed: {e}')

    # ── Analysis 3: Remediation Priority (improved prompt) ──
    remed_prompt = f"""You are a security engineer creating a fix plan for {target}.

Vulnerabilities found:
{json.dumps([{'sev': f['severity'], 'title': f['title'], 'cvss': f['cvss'], 'asset': f['asset']} for f in finding_summaries[:40]], indent=1)}

Create a prioritized remediation plan. Group related fixes together.

Priority order:
1. CRITICAL: Known exploits, data exposure, auth bypass
2. HIGH: Injection flaws, broken access control, sensitive data exposure
3. MEDIUM: Security misconfigurations, missing headers, weak crypto
4. LOW/INFO: Information disclosure, best practice violations

For each fix group, specify:
- Exact action (e.g., "Add Content-Security-Policy header with default-src 'self'")
- Which findings this fixes
- Time estimate
- Business impact if not fixed

Respond with ONLY valid JSON:
{{"remediation": [{{"priority": 1, "action": "Specific fix description", "findings": ["title1", "title2"], "effort": "low", "impact": "Prevents X attack", "deadline": "immediate"}}], "compliance_gaps": ["PCI-DSS: Missing HSTS", "OWASP: No CSP"], "security_posture": "Overall assessment in 2-3 sentences"}}"""

    remed_raw = _ollama_generate(remed_prompt, system='You are a CISO preparing a remediation report for the board. Be practical, specific, and prioritize by business impact. Respond ONLY in valid JSON.')
    remed_result = None
    if remed_raw:
        try:
            json_match = re.search(r'\{[\s\S]*"remediation"[\s\S]*\}', remed_raw)
            if json_match:
                remed_result = json.loads(json_match.group())
        except Exception as e:
            log('warn', f'[AI] Remediation JSON parse failed: {e}')

    # Store results in scan_state
    ai_analysis = {
        'model': OLLAMA_MODEL,
        'timestamp': time.time(),
        'target': target,
        'total_findings': len(findings),
        'triage': triage_result,
        'attack_paths': attack_result,
        'remediation': remed_result,
        'raw': {
            'triage': triage_raw[:2000] if triage_raw else None,
            'attack': attack_raw[:2000] if attack_raw else None,
            'remediation': remed_raw[:2000] if remed_raw else None,
        },
    }
    with LOCK:
        scan_state['ai_analysis'] = ai_analysis

    op_log('ai_analysis', target=target, detail=f'triage={triage_result is not None}, attack={attack_result is not None}, remed={remed_result is not None}')

    return jsonify({'status': 'ok', 'analysis': ai_analysis})


@ai_bp.route('/triage', methods=['POST'])
@login_required
def ai_apply_triage():
    """Apply AI triage verdicts to findings (mark false positives)."""
    data = request.get_json(silent=True) or {}
    verdicts = data.get('triage', [])
    if not verdicts:
        return jsonify({'status': 'error', 'message': 'No triage verdicts provided'}), 400

    applied = 0
    with LOCK:
        findings = scan_state.get('findings', [])
        for verdict in verdicts:
            fid = verdict.get('id', '')
            v = verdict.get('verdict', '')
            for f in findings:
                if f.get('id') == fid and v == 'FALSE_POSITIVE':
                    f['verified'] = False
                    f['ai_triaged'] = True
                    f['status'] = 'false_positive'
                    applied += 1

    log('ok', f'[AI] Applied {applied} false positive verdicts')
    op_log('ai_triage', target=scan_state.get('target', ''), detail=f'applied={applied}')
    return jsonify({'status': 'ok', 'applied': applied})


@ai_bp.route('/realtime-triage', methods=['POST'])
@login_required
def ai_realtime_triage():
    """
    Real-time AI triage during scan. Analyzes batches of findings
    as they come in, marking false positives automatically.
    """
    global _triage_thread, _triage_running

    if _triage_running:
        return jsonify({'status': 'error', 'message': 'Triage already running'}), 409

    if not _ollama_available():
        return jsonify({'status': 'error', 'message': 'Ollama not available'}), 503

    def _run_triage():
        global _triage_running
        _triage_running = True
        try:
            with LOCK:
                findings = list(scan_state.get('findings', []))
                target = scan_state.get('target', '')

            # Process in batches of 10
            batch_size = 10
            total_triaged = 0
            for i in range(0, len(findings), batch_size):
                if not scan_state.get('scanning') and not scan_state.get('findings'):
                    break

                batch = findings[i:i+batch_size]
                batch_summaries = []
                for f in batch:
                    batch_summaries.append({
                        'id': f.get('id', ''),
                        'severity': f.get('sev', 'info'),
                        'title': f.get('title', ''),
                        'asset': f.get('asset', ''),
                        'details': (f.get('details', '') or '')[:200],
                    })

                prompt = f"""Review these findings for {target}. For each, classify as TRUE or FALSE_POSITIVE.

FALSE_POSITIVE signs:
- SPA catch-all (same HTML shell for all URLs)
- JS bundle keyword match (password in minified code)
- Generic error page or timeout
- Header missing on HTTP site (HSTS)
- "Admin panel" on SPA (all routes return 200)

TRUE signs:
- Actual sensitive data in response (passwords, keys, DB content)
- File content differs from baseline (real /etc/passwd)
- Confirmed injection with proof
- Real stack trace or debug output

Findings:
{json.dumps(batch_summaries, indent=1)}

Respond with ONLY valid JSON:
{{"triage": [{{"id": "x", "verdict": "TRUE", "confidence": 0.9}}, {{"id": "y", "verdict": "FALSE_POSITIVE", "confidence": 0.85}}]}}"""

                raw = _ollama_generate(prompt, system='Security analyst. Respond ONLY in valid JSON.')
                if raw:
                    try:
                        json_match = re.search(r'\{[\s\S]*"triage"[\s\S]*\}', raw)
                        if json_match:
                            result = json.loads(json_match.group())
                            with LOCK:
                                for v in result.get('triage', []):
                                    for f in scan_state.get('findings', []):
                                        if f.get('id') == v.get('id') and v.get('verdict') == 'FALSE_POSITIVE':
                                            f['verified'] = False
                                            f['ai_triaged'] = True
                                            total_triaged += 1
                    except Exception:
                        pass

            log('ok', f'[AI] Real-time triage complete: {total_triaged} false positives marked')
            op_log('ai_realtime_triage', target=target, detail=f'triaged={total_triaged}')
        finally:
            _triage_running = False

    _triage_thread = threading.Thread(target=_run_triage, daemon=True)
    _triage_thread.start()

    return jsonify({'status': 'ok', 'message': 'Real-time triage started'})


@ai_bp.route('/risk-summary')
@login_required
def ai_risk_summary():
    """Get AI-generated risk summary from last analysis."""
    with LOCK:
        analysis = scan_state.get('ai_analysis', {})

    if not analysis:
        return jsonify({'status': 'error', 'message': 'No AI analysis available. Run /api/ai/analyze first.'}), 404

    summary = {
        'target': analysis.get('target', ''),
        'total_findings': analysis.get('total_findings', 0),
        'model': analysis.get('model', ''),
        'timestamp': analysis.get('timestamp', 0),
    }

    # Extract triage stats
    triage = analysis.get('triage', {})
    if triage:
        summary['triage'] = {
            'true_positives': triage.get('true_positive_count', 0),
            'false_positives': triage.get('false_positive_count', 0),
            'uncertain': triage.get('uncertain_count', 0),
        }

    # Extract attack paths
    attack = analysis.get('attack_paths', {})
    if attack:
        summary['attack_paths'] = attack.get('attack_paths', [])
        summary['executive_summary'] = attack.get('executive_summary', '')
        summary['risk_score'] = attack.get('risk_score', 0)
        summary['top_3_actions'] = attack.get('top_3_actions', [])

    # Extract remediation
    remed = analysis.get('remediation', {})
    if remed:
        summary['remediation'] = remed.get('remediation', [])
        summary['security_posture'] = remed.get('security_posture', '')

    return jsonify({'status': 'ok', 'summary': summary})
