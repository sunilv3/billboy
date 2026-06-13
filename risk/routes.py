"""Risk management routes: register, assets, heatmap, KRIs, controls."""
from flask import Blueprint, request, jsonify, Response
import json, time, secrets, hashlib
from datetime import datetime
from core.auth import login_required
from core.logger import log
from core.database import DB_PATH
from core.utils import SQLITE_AVAILABLE, sqlite3_mod, _safe_str, _safe_int
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding
from scanner.validation import calculate_finding_context_risk
from risk.engine import (compute_risk, _level_from_score, _color_for_level,
                          _next_risk_id, _apply_control, _risk_row_to_dict)

risk_bp = Blueprint('risk', __name__, url_prefix='/api/risk')

@risk_bp.route('/prediction')
@login_required
def risk_prediction():
    with LOCK:
        score = scan_state.get('risk_score', 0)
        breakdown = list(scan_state.get('risk_breakdown', []))
        stats = dict(scan_state.get('stats', {}))
    recs = []
    if stats.get('critical', 0):
        recs.append(f'Remediate {stats["critical"]} critical findings immediately')
    if stats.get('high', 0):
        recs.append(f'Address {stats["high"]} high-severity issues within 1 week')
    if not recs and score > 0:
        recs.append('Continue monitoring for new vulnerabilities')
    if not recs:
        recs.append('No risk factors identified — maintain current security posture')
    return jsonify({'status': 'ok', 'predicted_score': score, 'breakdown': breakdown, 'recommendations': recs})


@risk_bp.route('/finding_context')
@login_required
def risk_finding_context():
    """Return context-aware risk score for each finding."""
    with LOCK:
        findings = list(scan_state.get('findings', []))
    results = []
    for f in findings:
        adjusted, factors = calculate_finding_context_risk(f)
        results.append({
            'id': f.get('id', ''),
            'title': f.get('title', ''),
            'base_cvss': f.get('cvss', ''),
            'adjusted_score': adjusted,
            'context_factors': factors,
            'severity': f.get('sev', 'info'),
            'verified': f.get('verified', True),
        })
    results.sort(key=lambda x: x['adjusted_score'], reverse=True)
    return jsonify({'status': 'ok', 'findings': results})


@risk_bp.route('/history')
@login_required
def risk_history():
    history = []
    if SQLITE_AVAILABLE:
        try:
            with sqlite3_mod.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3_mod.Row
                rows = conn.execute('SELECT created_at, risk_score, target FROM scan_history ORDER BY created_at ASC LIMIT 30').fetchall()
                history = [{'date': (r['created_at'] or '')[:10], 'score': r['risk_score'], 'target': r['target']} for r in rows if r['risk_score'] is not None]
        except Exception:
            pass
    return jsonify({'status': 'ok', 'history': history})


@risk_bp.route('/methodologies')
@login_required
def risk_methodologies():
    return jsonify({
        'status': 'ok',
        'methodologies': [
            {'id': 'NIST',  'name': 'NIST SP 800-30',  'type': 'qualitative', 'scale': '5x5 matrix',         'output': 'Likelihood x Impact (1-25)'},
            {'id': 'ISO',   'name': 'ISO/IEC 27005',   'type': 'qualitative', 'scale': '5x5 matrix',         'output': 'Likelihood x Impact (1-25)'},
            {'id': 'FAIR',  'name': 'FAIR (lite)',     'type': 'quantitative','scale': 'USD / year',         'output': 'Annual Loss Expectancy (SLE x ARO)'},
        ]
    })


@risk_bp.route('/assets', methods=['GET', 'POST'])
@login_required
def risk_assets():
    if request.method == 'POST':
        d = request.get_json(silent=True) or {}
        if not d.get('name'):
            return jsonify({'status': 'error', 'message': 'Asset name required'}), 400
        if not SQLITE_AVAILABLE:
            return jsonify({'status': 'error', 'message': 'DB unavailable'}), 500
        with sqlite3_mod.connect(DB_PATH) as conn:
            try:
                conn.execute(
                    "INSERT INTO assets(name,asset_type,criticality,data_class,business_owner,environment,notes) VALUES (?,?,?,?,?,?,?)",
                    (d['name'].strip(), d.get('asset_type', 'application'),
                     _safe_int(d.get('criticality'), 3), d.get('data_class', 'internal'),
                     d.get('business_owner', ''), d.get('environment', 'production'),
                     d.get('notes', ''))
                )
            except sqlite3_mod.IntegrityError:
                return jsonify({'status': 'error', 'message': 'Asset name must be unique'}), 400
        return jsonify({'status': 'ok'})
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'ok', 'assets': []})
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        rows = conn.execute("SELECT * FROM assets ORDER BY criticality DESC, name ASC").fetchall()
    return jsonify({'status': 'ok', 'assets': [dict(r) for r in rows]})


@risk_bp.route('/assets/<int:asset_id>', methods=['PUT', 'DELETE'])
@login_required
def risk_asset_modify(asset_id):
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'DB unavailable'}), 500
    if request.method == 'DELETE':
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
        return jsonify({'status': 'ok'})
    d = request.get_json(silent=True) or {}
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE assets SET name=?, asset_type=?, criticality=?, data_class=?, business_owner=?, environment=?, notes=? WHERE id=?",
            (d.get('name', '').strip(), d.get('asset_type', 'application'),
             _safe_int(d.get('criticality'), 3), d.get('data_class', 'internal'),
             d.get('business_owner', ''), d.get('environment', 'production'),
             d.get('notes', ''), asset_id)
        )
    return jsonify({'status': 'ok'})


@risk_bp.route('/register', methods=['GET', 'POST'])
@login_required
def risk_register():
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'ok', 'risks': []})
    if request.method == 'POST':
        d = request.get_json(silent=True) or {}
        if not isinstance(d, dict):
            return jsonify({'status': 'error', 'message': 'Invalid request body'}), 400
        methodology = _safe_str(d.get('methodology'), 'NIST')
        likelihood = _safe_int(d.get('likelihood'), 3)
        impact = _safe_int(d.get('impact'), 3)
        eff = _safe_int(d.get('control_effectiveness'), 0)
        calc = compute_risk(methodology, likelihood, impact,
                            asset_value=d.get('asset_value'),
                            control_eff=eff,
                            sle=d.get('sle'), aro=d.get('aro'))
        risk_id = d.get('risk_id') or _next_risk_id()
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO risks(risk_id,title,description,asset_id,asset_name,threat,vulnerability,
                    methodology,likelihood,impact,inherent_score,inherent_level,
                    control_effectiveness,residual_likelihood,residual_impact,residual_score,residual_level,
                    treatment,treatment_plan,treatment_cost,owner,review_date,status,linked_findings,framework_refs)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                risk_id, d.get('title', ''), d.get('description', ''),
                d.get('asset_id'), d.get('asset_name', ''),
                d.get('threat', ''), d.get('vulnerability', ''),
                methodology, likelihood, impact,
                calc['inherent_score'], calc['inherent_level'],
                eff, calc['residual_likelihood'], calc['residual_impact'],
                calc['residual_score'], calc['residual_level'],
                d.get('treatment', 'mitigate'), d.get('treatment_plan', ''),
                float(d.get('treatment_cost', 0) or 0),
                d.get('owner', ''), d.get('review_date', ''),
                d.get('status', 'open'),
                json.dumps(d.get('linked_findings', [])),
                json.dumps(d.get('framework_refs', []))
            ))
        log('info', f'[RISK] Created {risk_id} ({calc["inherent_level"]}->{calc["residual_level"]})')
        return jsonify({'status': 'ok', 'risk_id': risk_id, 'score': calc})
    sev_filter = request.args.get('level', 'all')
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        rows = conn.execute("SELECT * FROM risks ORDER BY residual_score DESC, id DESC").fetchall()
    risks = [_risk_row_to_dict(r) for r in rows]
    if sev_filter != 'all':
        risks = [r for r in risks if r['residual_level'].lower() == sev_filter.lower()]
    return jsonify({'status': 'ok', 'risks': risks, 'total': len(risks)})


@risk_bp.route('/register/<risk_pk>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def risk_modify(risk_pk):
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'DB unavailable'}), 500
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        if request.method == 'GET':
            row = conn.execute("SELECT * FROM risks WHERE id=?", (risk_pk,)).fetchone()
            if not row:
                return jsonify({'status': 'error', 'message': 'Not found'}), 404
            d = _risk_row_to_dict(row)
            treatments = conn.execute("SELECT * FROM risk_treatments WHERE risk_pk=? ORDER BY id", (risk_pk,)).fetchall()
            accs = conn.execute("SELECT * FROM risk_acceptances WHERE risk_pk=? ORDER BY id DESC", (risk_pk,)).fetchall()
            d['treatments'] = [dict(t) for t in treatments]
            d['acceptances'] = [dict(a) for a in accs]
            return jsonify({'status': 'ok', 'risk': d})
        if request.method == 'DELETE':
            conn.execute("DELETE FROM risk_treatments WHERE risk_pk=?", (risk_pk,))
            conn.execute("DELETE FROM risk_acceptances WHERE risk_pk=?", (risk_pk,))
            conn.execute("DELETE FROM risks WHERE id=?", (risk_pk,))
            return jsonify({'status': 'ok'})
        # PUT
        d = request.get_json(silent=True) or {}
        # Prevent risk_id overwrite — identity must not change via PUT
        d.pop('risk_id', None)
        d.pop('id', None)
        row = conn.execute("SELECT * FROM risks WHERE id=?", (risk_pk,)).fetchone()
        if not row:
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        cur = _risk_row_to_dict(row)
        merged = {**cur, **d}
        methodology = _safe_str(merged.get('methodology'), 'NIST')
        likelihood = _safe_int(merged.get('likelihood'), 3)
        impact = _safe_int(merged.get('impact'), 3)
        eff = _safe_int(merged.get('control_effectiveness'), 0)
        calc = compute_risk(methodology, likelihood, impact,
                            asset_value=merged.get('asset_value'),
                            control_eff=eff,
                            sle=merged.get('sle'), aro=merged.get('aro'))
        conn.execute("""
            UPDATE risks SET title=?, description=?, asset_id=?, asset_name=?, threat=?, vulnerability=?,
                methodology=?, likelihood=?, impact=?, inherent_score=?, inherent_level=?,
                control_effectiveness=?, residual_likelihood=?, residual_impact=?, residual_score=?, residual_level=?,
                treatment=?, treatment_plan=?, treatment_cost=?, owner=?, review_date=?, status=?,
                linked_findings=?, framework_refs=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
        """, (
            merged.get('title', ''), merged.get('description', ''),
            merged.get('asset_id'), merged.get('asset_name', ''),
            merged.get('threat', ''), merged.get('vulnerability', ''),
            methodology, likelihood, impact,
            calc['inherent_score'], calc['inherent_level'],
            eff, calc['residual_likelihood'], calc['residual_impact'],
            calc['residual_score'], calc['residual_level'],
            merged.get('treatment', 'mitigate'), merged.get('treatment_plan', ''),
            float(merged.get('treatment_cost', 0) or 0),
            merged.get('owner', ''), merged.get('review_date', ''),
            merged.get('status', 'open'),
            json.dumps(merged.get('linked_findings', cur['linked_findings'])),
            json.dumps(merged.get('framework_refs', cur['framework_refs'])),
            risk_pk
        ))
        return jsonify({'status': 'ok', 'score': calc})


@risk_bp.route('/register/<risk_pk>/treatment', methods=['POST'])
@login_required
def risk_add_treatment(risk_pk):
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error'}), 500
    d = request.get_json(silent=True) or {}
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO risk_treatments(risk_pk,task,assignee,due_date,status,cost_estimate) VALUES (?,?,?,?,?,?)",
            (risk_pk, d.get('task', ''), d.get('assignee', ''),
             d.get('due_date', ''), d.get('status', 'pending'),
             float(d.get('cost_estimate', 0) or 0))
        )
    return jsonify({'status': 'ok'})


@risk_bp.route('/register/<risk_pk>/accept', methods=['POST'])
@login_required
def risk_accept(risk_pk):
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error'}), 500
    d = request.get_json(silent=True) or {}
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO risk_acceptances(risk_pk,approved_by,approver_role,justification,expiry_date,compensating_controls)
            VALUES (?,?,?,?,?,?)
        """, (risk_pk, d.get('approved_by', ''), d.get('approver_role', ''),
              d.get('justification', ''), d.get('expiry_date', ''),
              d.get('compensating_controls', '')))
        conn.execute("UPDATE risks SET treatment='accept', status='accepted' WHERE id=?", (risk_pk,))
    return jsonify({'status': 'ok'})


@risk_bp.route('/heatmap')
@login_required
def risk_heatmap():
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'ok', 'cells': []})
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        rows = conn.execute("SELECT residual_likelihood, residual_impact, residual_level FROM risks").fetchall()
    grid = {}
    for r in rows:
        key = (r['residual_likelihood'], r['residual_impact'])
        grid[key] = grid.get(key, 0) + 1
    cells = []
    for l in range(1, 6):
        for i in range(1, 6):
            cells.append({
                'likelihood': l, 'impact': i,
                'count': grid.get((l, i), 0),
                'score': l * i,
                'level': _level_from_score(l * i),
            })
    return jsonify({'status': 'ok', 'cells': cells, 'grid_size': 5})


@risk_bp.route('/kris', methods=['GET', 'POST'])
@login_required
def risk_kris():
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'ok', 'kris': []})
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        rows = conn.execute("SELECT * FROM kris ORDER BY id").fetchall()
        kris = [dict(r) for r in rows]
    # Compute current values from live data
    with LOCK:
        findings = list(scan_state.get('findings', []))
        ports = list(scan_state.get('port_data', []))
        stats = dict(scan_state.get('stats', {}))
    today = datetime.now()
    cutoff_30d = (today - __import__('datetime').timedelta(days=30)).isoformat()
    for k in kris:
        kid = k['kri_id']
        if kid == 'KRI-01':
            # Count critical findings older than 30 days (matches KRI description)
            v = sum(1 for f in findings if f.get('sev') == 'critical' and (f.get('ts') or '') < cutoff_30d)
        elif kid == 'KRI-02':
            v = 14  # placeholder; would need mitigation timestamps
        elif kid == 'KRI-03':
            v = 75  # placeholder; would track actual scan coverage
        elif kid == 'KRI-04':
            v = len([p for p in ports if p.get('port') in (23, 445, 3389, 3306, 6379, 27017)])
        elif kid == 'KRI-05':
            with sqlite3_mod.connect(DB_PATH) as conn:
                v = conn.execute("SELECT COUNT(*) FROM risks WHERE residual_score >= 12").fetchone()[0]
        elif kid == 'KRI-06':
            with sqlite3_mod.connect(DB_PATH) as conn:
                v = conn.execute("SELECT COUNT(*) FROM risk_acceptances WHERE expiry_date IS NOT NULL AND expiry_date < date('now')").fetchone()[0]
        else:
            v = 0
        k['current_value'] = v
        if v <= k['threshold_green']:
            k['status'] = 'green'
        elif v <= k['threshold_amber']:
            k['status'] = 'amber'
        else:
            k['status'] = 'red'
        # record to history — only once per day per KRI to avoid write amplification
        try:
            with sqlite3_mod.connect(DB_PATH) as conn:
                today_str = today.strftime('%Y-%m-%d')
                existing = conn.execute(
                    "SELECT id FROM kri_history WHERE kri_id=? AND date(created_at)=?",
                    (kid, today_str)
                ).fetchone()
                if not existing:
                    conn.execute("INSERT INTO kri_history(kri_id,value,status) VALUES (?,?,?)", (kid, v, k['status']))
        except Exception:
            pass
    return jsonify({'status': 'ok', 'kris': kris})


@risk_bp.route('/controls')
@login_required
def risk_controls():
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'ok', 'controls': []})
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        rows = conn.execute("SELECT * FROM controls ORDER BY framework, control_id").fetchall()
    return jsonify({'status': 'ok', 'controls': [dict(r) for r in rows]})


@risk_bp.route('/export')
@login_required
def risk_export():
    fmt = request.args.get('format', 'json')
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'ok', 'data': ''})
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        rows = conn.execute("SELECT * FROM risks ORDER BY residual_score DESC").fetchall()
        risks = [_risk_row_to_dict(r) for r in rows]
    if fmt == 'csv':
        import io, csv
        buf = io.StringIO()
        if risks:
            w = csv.DictWriter(buf, fieldnames=list(risks[0].keys()))
            w.writeheader()
            for r in risks:
                row = {k: (json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in r.items()}
                w.writerow(row)
        return Response(buf.getvalue(), mimetype='text/csv',
                        headers={'Content-Disposition': 'attachment; filename=risk_register.csv'})
    if fmt == 'markdown':
        lines = ['# Risk Register', '', '| ID | Title | Asset | Inherent | Residual | Treatment | Owner | Status |',
                 '|----|-------|-------|----------|----------|-----------|-------|--------|']
        for r in risks:
            lines.append(f"| {r['risk_id']} | {r['title'][:40]} | {r.get('asset_name','')} | "
                         f"{r['inherent_level']} ({r['inherent_score']}) | "
                         f"{r['residual_level']} ({r['residual_score']}) | "
                         f"{r['treatment']} | {r.get('owner','')} | {r['status']} |")
        return Response('\n'.join(lines), mimetype='text/markdown',
                        headers={'Content-Disposition': 'attachment; filename=risk_register.md'})
    return jsonify({'status': 'ok', 'risks': risks})


@risk_bp.route('/auto_populate', methods=['POST'])
@login_required
def risk_auto_populate():
    """Create draft risks from current scan findings (idempotent per scan target)."""
    if not SQLITE_AVAILABLE:
        return jsonify({'status': 'error'}), 500
    with LOCK:
        findings = list(scan_state.get('findings', []))
        target = scan_state.get('target', '')
    if not findings:
        return jsonify({'status': 'ok', 'created': 0, 'skipped': 0, 'message': 'No findings to convert'})
    sev_map = {'critical': (5, 5), 'high': (4, 4), 'medium': (3, 3), 'low': (2, 2), 'info': (1, 1)}
    # Ensure an asset exists for the scan target
    with sqlite3_mod.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3_mod.Row
        asset_row = conn.execute("SELECT * FROM assets WHERE name=?", (target,)).fetchone()
        if not asset_row:
            cur = conn.execute(
                "INSERT INTO assets(name,asset_type,criticality,data_class,environment,notes) VALUES (?,?,?,?,?,?)",
                (target, 'application', 4, 'confidential', 'production',
                 f'Auto-created from scan of {target}')
            )
            asset_id = cur.lastrowid
        else:
            asset_id = asset_row['id']
        created = 0
        skipped = 0
        for f in findings:
            l, i = sev_map.get(f.get('sev', 'medium'), (3, 3))
            # Skip if a risk with the same title+asset already exists
            existing = conn.execute(
                "SELECT id FROM risks WHERE title=? AND asset_id=? AND status='open'",
                (f.get('title', ''), asset_id)
            ).fetchone()
            if existing:
                skipped += 1
                continue
            calc = compute_risk('NIST', l, i, control_eff=0)
            risk_id = _next_risk_id()
            conn.execute("""
                INSERT INTO risks(risk_id,title,description,asset_id,asset_name,threat,vulnerability,
                    methodology,likelihood,impact,inherent_score,inherent_level,
                    control_effectiveness,residual_likelihood,residual_impact,residual_score,residual_level,
                    treatment,treatment_plan,owner,review_date,status,linked_findings,framework_refs)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                risk_id, f.get('title', ''), f.get('details', '') or f.get('sub', ''),
                asset_id, target, f.get('sub', '') or 'Identified during scan',
                f.get('cve', '') or f.get('title', ''),
                'NIST', l, i,
                calc['inherent_score'], calc['inherent_level'],
                0, calc['residual_likelihood'], calc['residual_impact'],
                calc['residual_score'], calc['residual_level'],
                'mitigate', '', '', '', 'open',
                json.dumps([f.get('id', '')]),
                json.dumps([x for x in (f.get('owasp', ''), f.get('mitre', '')) if x])
            ))
            created += 1
    log('info', f'[RISK] Auto-populated {created} risks from {len(findings)} findings (skipped {skipped} duplicates)')
    return jsonify({'status': 'ok', 'created': created, 'skipped': skipped, 'asset_id': asset_id})

