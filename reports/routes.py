"""Export/report routes: JSON, SARIF, CSV, PDF, Markdown."""
from flask import Blueprint, request, jsonify, Response
import json, csv, io, time, re, os
from datetime import datetime
from core.auth import login_required
from core.logger import log
from core.database import DB_PATH
from core.utils import SQLITE_AVAILABLE, sqlite3_mod, _safe_str, _safe_int, _find_tool
from scanner.state import scan_state, LOCK
from reports.pdf import finding_remediation, build_poc_section

try:
    from fpdf import FPDF; FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False; FPDF = None

reports_bp = Blueprint('reports', __name__, url_prefix='/api/export')

@reports_bp.route('/json', methods=['POST'])
@login_required
def export_json():
    with LOCK:
        target = scan_state['target'] or 'unknown'
        data = {
            'meta': {
                'tool': 'INFOSEC Recon Platform',
                'target': target,
                'scan_date': datetime.now().isoformat(),
                'elapsed': scan_state['elapsed'],
                'risk_score': scan_state['risk_score'],
            },
            'stats': dict(scan_state['stats']),
            'findings': list(scan_state['findings']),
            'dns': dict(scan_state['dns_data']),
            'ssl': dict(scan_state['ssl_data']),
            'technologies': dict(scan_state['tech_data']),
            'open_ports': list(scan_state['port_data']),
            'subdomains': list(scan_state['assets']),
            'whois': dict(scan_state['whois_data']),
        }
    resp = Response(
        json.dumps(data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=infosec_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
    )
    return resp



@reports_bp.route('/sarif', methods=['POST'])
@login_required
def export_sarif():
    """Export findings in SARIF 2.1.0 format for GitHub/DevOps integration."""
    with LOCK:
        target = scan_state['target'] or 'unknown'
        findings = list(scan_state['findings'])
        risk_score = scan_state.get('risk_score', 0)

    # SARIF severity mapping
    sev_map = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'none'}

    rules = {}
    results = []
    for f in findings:
        rule_id = f.get('owasp', '') or f.get('mitre', '') or 'GENERIC'
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'name': rule_id,
                'shortDescription': {'text': f.get('title', 'Security finding')},
                'helpUri': f.get('poc_link', ''),
                'properties': {
                    'tags': ['security', f.get('sev', 'info')],
                    'cvss_score': f.get('cvss', ''),
                }
            }
        results.append({
            'ruleId': rule_id,
            'level': sev_map.get(f.get('sev', 'info'), 'warning'),
            'message': {
                'text': f'{f.get("title", "Unknown")}\n\n{f.get("details", "")[:500]}'
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': f.get('asset', target)},
                    'region': {'startLine': 1}
                }
            }],
            'properties': {
                'cvss': f.get('cvss', ''),
                'cve': f.get('cve', ''),
                'exploit': f.get('exploit', ''),
                'confidence': f.get('confidence', 'medium'),
                'verified': f.get('verified', True),
                'context_risk_score': f.get('context_risk_score', 0),
            }
        })

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'INFOSEC Recon Platform',
                    'version': '2.0.0',
                    'informationUri': 'https://github.com/infosec-recon',
                    'rules': list(rules.values())
                }
            },
            'results': results,
            'invocations': [{
                'startTimeUtc': datetime.now().isoformat(),
                'executionSuccessful': True,
                'properties': {
                    'target': target,
                    'risk_score': risk_score,
                }
            }]
        }]
    }

    resp = Response(
        json.dumps(sarif, indent=2),
        mimetype='application/sarif+json',
        headers={'Content-Disposition': f'attachment; filename=infosec_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sarif'}
    )
    return resp



@reports_bp.route('/csv', methods=['POST'])
@login_required
def export_csv():
    target = scan_state['target'] or 'unknown'
    with LOCK:
        findings = list(scan_state['findings'])  # shallow copy
    import io as _io
    buf = _io.StringIO()
    w = csv.writer(buf)
    w.writerow(['Severity', 'Title', 'Asset', 'CVE', 'CVSS', 'Exploit', 'Description', 'Timestamp'])
    for f in findings:
        w.writerow([f.get('sev',''), f.get('title',''), f.get('asset',''),
                     f.get('cve',''), f.get('cvss',''), f.get('exploit',''),
                     f.get('sub',''), f.get('ts','')])
    resp = Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=infosec_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )
    return resp


@reports_bp.route('/report', methods=['GET', 'POST'])
@login_required
def export_report():
    target = scan_state['target'] or 'unknown.com'
    with LOCK:
        state_copy = json.loads(json.dumps(scan_state, default=str))
    # Sort findings by severity (Critical -> Info)
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    state_copy['findings'] = sorted(
        state_copy.get('findings', []),
        key=lambda f: (sev_order.get((f.get('sev') or 'info').lower(), 4), -float(f.get('cvss') or 0) if str(f.get('cvss','')).replace('.','').isdigit() else 0)
    )

    # Build category-separated finding lists
    findings_all = state_copy.get('findings', [])
    cat_confirmed = [f for f in findings_all if f.get('report_category') == 'Confirmed Vulnerabilities']
    cat_likely    = [f for f in findings_all if f.get('report_category') == 'Likely Vulnerabilities']
    cat_potential = [f for f in findings_all if f.get('report_category') == 'Potential Findings']
    cat_hardening = [f for f in findings_all if f.get('report_category') == 'Security Hardening Issues']
    cat_info      = [f for f in findings_all if f.get('report_category') == 'Informational Observations']
    cat_other     = [f for f in findings_all if not f.get('report_category')]

    stats_by_sev = {}
    for f in findings_all:
        s = f.get('sev','info')
        stats_by_sev[s] = stats_by_sev.get(s,0) + 1

    def sev_badge(sev):
        colors = {'critical':'#e31e24','high':'#ea580c','medium':'#ca8a04','low':'#16a34a','info':'#2563eb'}
        c = colors.get(sev,'#71717a')
        return f'<span style="display:inline-block;padding:2px 8px;border-radius:3px;background:{c}20;color:{c};font-size:9px;font-weight:700;text-transform:uppercase;border:1px solid {c}40;">{sev}</span>'

    def conf_badge(cs):
        cs = int(cs or 0)
        if cs >= 90: return f'<span style="color:#16a34a;font-weight:700;font-size:10px;">CONFIRMED ({cs}/100)</span>'
        if cs >= 70: return f'<span style="color:#2563eb;font-weight:700;font-size:10px;">LIKELY ({cs}/100)</span>'
        if cs >= 40: return f'<span style="color:#ca8a04;font-weight:700;font-size:10px;">POTENTIAL ({cs}/100)</span>'
        return f'<span style="color:#71717a;font-weight:700;font-size:10px;">INFORMATIONAL ({cs}/100)</span>'

    def conf_bar(cs):
        cs = int(cs or 0)
        c = '#16a34a' if cs >= 90 else '#2563eb' if cs >= 70 else '#ca8a04' if cs >= 40 else '#71717a'
        return f'<div style="height:4px;background:#f0f0f0;border-radius:2px;width:80px;display:inline-block;vertical-align:middle;margin-left:6px;"><div style="height:100%;width:{cs}%;background:{c};border-radius:2px;"></div></div>'

    def finding_rows(flist):
        if not flist:
            return '<tr><td colspan="7" style="text-align:center;color:#999;padding:20px;font-style:italic;">No findings in this category</td></tr>'
        rows = []
        for f in flist:
            cs = f.get('confidence_score', 55)
            evid = (f.get('validation_evidence') or f.get('details',''))[:200].replace('<','&lt;').replace('>','&gt;')
            repro = (f.get('reproduction_steps','') or '')[:120].replace('<','&lt;').replace('>','&gt;')
            rows.append(f"""
            <tr style="border-bottom:1px solid #e4e4e7;">
              <td style="padding:10px 12px;vertical-align:top;">{sev_badge(f.get('sev','info'))}</td>
              <td style="padding:10px 12px;vertical-align:top;">
                <div style="font-weight:700;font-size:13px;color:#18181b;">{f.get('title','').replace('<','&lt;')}</div>
                <div style="font-size:11px;color:#71717a;margin-top:2px;">{f.get('asset','').replace('<','&lt;')}</div>
                {f'<div style="font-size:10px;color:#a1a1aa;margin-top:2px;">{f.get("cve","").replace("<","&lt;")}</div>' if f.get("cve") else ''}
              </td>
              <td style="padding:10px 12px;vertical-align:top;">{conf_badge(cs)}{conf_bar(cs)}</td>
              <td style="padding:10px 12px;vertical-align:top;font-size:12px;font-weight:700;color:#18181b;">{f.get('cvss','—')}</td>
              <td style="padding:10px 12px;vertical-align:top;font-size:11px;color:#52525b;max-width:160px;">{evid}{'…' if len(f.get('validation_evidence') or f.get('details','')) > 200 else ''}</td>
              <td style="padding:10px 12px;vertical-align:top;font-size:11px;color:#2563eb;font-family:monospace;">{repro}{'…' if len(f.get('reproduction_steps','') or '') > 120 else ''}</td>
              <td style="padding:10px 12px;vertical-align:top;font-size:11px;color:#52525b;">{f.get('owasp','—')}</td>
            </tr>""")
        return ''.join(rows)

    def cat_section(label, color, icon, flist, section_num):
        count = len(flist)
        if count == 0:
            return f'<div style="margin-bottom:8px;padding:12px;background:#f8f9fa;border-left:3px solid #e4e4e7;border-radius:4px;color:#999;font-size:13px;">{icon} <strong>Section {section_num}: {label}</strong> — No findings</div>'
        return f"""
    <div class="section-title" style="color:{color};border-left-color:{color};">{icon} {section_num}. {label} <span style="font-size:14px;font-weight:400;color:{color};opacity:.7;">({count})</span></div>
    <table>
      <thead>
        <tr>
          <th style="width:80px;">Severity</th>
          <th>Finding</th>
          <th style="width:130px;">Confidence</th>
          <th style="width:55px;">CVSS</th>
          <th>Validation Evidence</th>
          <th>Reproduction</th>
          <th style="width:55px;">OWASP</th>
        </tr>
      </thead>
      <tbody>{finding_rows(flist)}</tbody>
    </table>"""

    risk_score = state_copy.get('risk_score', 0)
    risk_color = '#e31e24' if risk_score >= 70 else '#ea580c' if risk_score >= 40 else '#ca8a04' if risk_score >= 20 else '#16a34a'
    risk_label = 'CRITICAL' if risk_score >= 70 else 'HIGH' if risk_score >= 40 else 'MEDIUM' if risk_score >= 20 else 'LOW'
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M UTC')

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Assessment Report — {target}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #fafafa; color: #18181b; line-height: 1.6; }}

    /* Cover page */
    .cover {{ background: linear-gradient(135deg, #0f0f11 0%, #1a1a2e 50%, #0f0f11 100%); color: #fff; padding: 80px 60px; min-height: 320px; position: relative; overflow: hidden; }}
    .cover::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(90deg, #e31e24, #ea580c, #ca8a04); }}
    .cover-badge {{ display: inline-block; padding: 4px 12px; border: 1px solid rgba(255,255,255,.2); border-radius: 20px; font-size: 11px; font-weight: 600; color: rgba(255,255,255,.7); margin-bottom: 24px; letter-spacing: 2px; text-transform: uppercase; }}
    .cover-title {{ font-size: 40px; font-weight: 800; line-height: 1.2; margin-bottom: 12px; }}
    .cover-target {{ font-size: 22px; color: #e31e24; font-weight: 700; margin-bottom: 8px; }}
    .cover-meta {{ font-size: 13px; color: rgba(255,255,255,.5); }}
    .cover-risk {{ position: absolute; right: 60px; top: 50%; transform: translateY(-50%); text-align: center; }}
    .risk-circle {{ width: 110px; height: 110px; border-radius: 50%; background: {risk_color}18; border: 3px solid {risk_color}; display: flex; flex-direction: column; align-items: center; justify-content: center; }}
    .risk-num {{ font-size: 32px; font-weight: 800; color: {risk_color}; }}
    .risk-lbl {{ font-size: 10px; font-weight: 700; color: {risk_color}; letter-spacing: 1px; }}

    /* Page content */
    .page {{ max-width: 1100px; margin: 0 auto; padding: 40px 40px; }}

    /* Executive KPI strip */
    .kpi-strip {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin: 32px 0; }}
    .kpi-card {{ background: #fff; border: 1px solid #e4e4e7; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.05); }}
    .kpi-num {{ font-size: 28px; font-weight: 800; }}
    .kpi-lbl {{ font-size: 10px; font-weight: 700; color: #71717a; text-transform: uppercase; margin-top: 4px; letter-spacing: .5px; }}
    .kpi-sub {{ font-size: 10px; color: #a1a1aa; margin-top: 2px; }}

    /* Confidence distribution chart (CSS bars) */
    .conf-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 20px 0; }}
    .conf-bar-wrap {{ background: #fff; border: 1px solid #e4e4e7; border-radius: 6px; padding: 12px 10px; text-align: center; }}
    .conf-bar-outer {{ height: 60px; background: #f4f4f5; border-radius: 4px; display: flex; align-items: flex-end; margin-bottom: 6px; overflow: hidden; }}
    .conf-bar-inner {{ width: 100%; border-radius: 4px; transition: height .3s; }}
    .conf-bar-label {{ font-size: 10px; font-weight: 700; color: #71717a; }}
    .conf-bar-count {{ font-size: 18px; font-weight: 800; }}

    /* Sections */
    .section-title {{ font-size: 18px; font-weight: 800; border-left: 4px solid #e31e24; padding-left: 14px; margin: 40px 0 16px 0; color: #18181b; text-transform: uppercase; letter-spacing: .5px; }}
    .category-divider {{ margin: 48px 0 0 0; }}

    /* Table */
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; background: #fff; border: 1px solid #e4e4e7; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.04); }}
    th {{ background: #f4f4f5; text-align: left; padding: 10px 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; color: #71717a; border-bottom: 1px solid #e4e4e7; letter-spacing: .5px; }}
    td {{ padding: 10px 12px; font-size: 13px; vertical-align: top; }}
    tr:hover {{ background: #fafafa; }}

    /* Evidence box */
    .evidence-box {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 4px; padding: 8px; font-size: 11px; color: #15803d; font-family: monospace; word-break: break-all; }}

    /* FP rules compliance box */
    .rule-compliance {{ background: #fff; border: 1px solid #e4e4e7; border-radius: 8px; padding: 20px; margin: 24px 0; }}
    .rule-row {{ display: flex; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px solid #f4f4f5; font-size: 12px; }}
    .rule-row:last-child {{ border-bottom: none; }}

    /* Page break for print */
    @media print {{
      .page-break {{ page-break-before: always; }}
      .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    }}
  </style>
</head>
<body>

<!-- ═══ COVER ═══ -->
<div class="cover">
  <div class="cover-badge">Security Assessment Report</div>
  <div class="cover-title">Application Security<br>Risk Assessment</div>
  <div class="cover-target">{target}</div>
  <div class="cover-meta">Generated: {scan_date} &nbsp;|&nbsp; Engine: Prodapt InfoSec Platform &nbsp;|&nbsp; FP Rate Target: &lt;10%</div>
  <div class="cover-risk">
    <div class="risk-circle">
      <div class="risk-num">{risk_score}</div>
      <div class="risk-lbl">{risk_label}</div>
    </div>
    <div style="font-size:10px;color:rgba(255,255,255,.4);margin-top:8px;">RISK SCORE /100</div>
  </div>
</div>

<!-- ═══ PAGE ═══ -->
<div class="page">

  <!-- KPI Strip -->
  <div class="kpi-strip">
    <div class="kpi-card">
      <div class="kpi-num" style="color:#e31e24;">{stats_by_sev.get('critical',0)}</div>
      <div class="kpi-lbl">Critical</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color:#ea580c;">{stats_by_sev.get('high',0)}</div>
      <div class="kpi-lbl">High</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color:#ca8a04;">{stats_by_sev.get('medium',0)}</div>
      <div class="kpi-lbl">Medium</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color:#16a34a;">{stats_by_sev.get('low',0)}</div>
      <div class="kpi-lbl">Low</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-num" style="color:#2563eb;">{len(findings_all)}</div>
      <div class="kpi-lbl">Total</div>
      <div class="kpi-sub">Risk Score: {risk_score}/100</div>
    </div>
  </div>

  <!-- Category distribution (Rule 14) -->
  <div class="section-title" style="margin-top:8px;">Report Breakdown by Evidence Category</div>
  <div class="conf-grid">
    <div class="conf-bar-wrap">
      <div class="conf-bar-count" style="color:#e31e24;">{len(cat_confirmed)}</div>
      <div class="conf-bar-label">Confirmed</div>
      <div style="font-size:9px;color:#a1a1aa;">Score 90–100</div>
    </div>
    <div class="conf-bar-wrap">
      <div class="conf-bar-count" style="color:#ea580c;">{len(cat_likely)}</div>
      <div class="conf-bar-label">Likely</div>
      <div style="font-size:9px;color:#a1a1aa;">Score 70–89</div>
    </div>
    <div class="conf-bar-wrap">
      <div class="conf-bar-count" style="color:#ca8a04;">{len(cat_potential)}</div>
      <div class="conf-bar-label">Potential</div>
      <div style="font-size:9px;color:#a1a1aa;">Score 40–69</div>
    </div>
    <div class="conf-bar-wrap">
      <div class="conf-bar-count" style="color:#2563eb;">{len(cat_hardening)}</div>
      <div class="conf-bar-label">Hardening</div>
      <div style="font-size:9px;color:#a1a1aa;">Config issues</div>
    </div>
    <div class="conf-bar-wrap">
      <div class="conf-bar-count" style="color:#71717a;">{len(cat_info)}</div>
      <div class="conf-bar-label">Info</div>
      <div style="font-size:9px;color:#a1a1aa;">Score 0–39</div>
    </div>
  </div>

  <!-- FP Rules Compliance Summary -->
  <div class="rule-compliance">
    <div style="font-weight:700;font-size:13px;margin-bottom:12px;color:#18181b;">FP Reduction Engine — 15-Rule Compliance</div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rule 3:</strong> Confidence scoring applied — severity capped to evidence tier</span></div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rule 4:</strong> SSRF findings require callback or metadata proof</span></div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rule 5:</strong> XSS findings require execution evidence (Playwright/DOM)</span></div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rules 6–7:</strong> Auth/2FA bypass requires auth-protected baseline + access proof</span></div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rule 8:</strong> Secrets validated with Shannon entropy threshold (≥3.5)</span></div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rule 13:</strong> Risk score uses only Confirmed (100%) + Likely (50%) findings</span></div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rule 14:</strong> {len(cat_confirmed)} Confirmed | {len(cat_likely)} Likely | {len(cat_potential)} Potential | {len(cat_hardening)} Hardening | {len(cat_info)} Info</span></div>
    <div class="rule-row"><span style="color:#16a34a;font-weight:700;">✓</span><span><strong>Rule 15:</strong> Target false positive rate: &lt;10% — uncertain findings reported as observations only</span></div>
  </div>

  <!-- Executive Summary -->
  <div class="section-title">Executive Summary</div>
  <p style="font-size:14px;color:#52525b;line-height:1.8;background:#fff;padding:16px;border-radius:6px;border:1px solid #e4e4e7;">
    This report documents the security posture of <strong>{target}</strong> assessed by the Prodapt InfoSec Platform using the 15-Rule False Positive Reduction Engine.
    The overall risk score is <strong style="color:{risk_color};">{risk_score}/100 ({risk_label})</strong>.
    Out of {len(findings_all)} total findings, <strong>{len(cat_confirmed)} are Confirmed</strong> (full evidence) and
    <strong>{len(cat_likely)} are Likely</strong> (contributing 50% to risk).
    Potential and Informational findings ({len(cat_potential) + len(cat_info)}) are listed for awareness but do <em>not</em> contribute to the risk score.
  </p>

  <!-- SECTION 1: Confirmed Vulnerabilities -->
  <div class="category-divider"></div>
  {cat_section("Confirmed Vulnerabilities", "#e31e24", "🔴", cat_confirmed, 1)}

  <!-- SECTION 2: Likely Vulnerabilities -->
  <div class="category-divider page-break"></div>
  {cat_section("Likely Vulnerabilities", "#ea580c", "🟠", cat_likely, 2)}

  <!-- SECTION 3: Potential Findings -->
  <div class="category-divider page-break"></div>
  {cat_section("Potential Findings", "#ca8a04", "🟡", cat_potential, 3)}

  <!-- SECTION 4: Security Hardening Issues -->
  <div class="category-divider page-break"></div>
  {cat_section("Security Hardening Issues", "#2563eb", "🔵", cat_hardening, 4)}

  <!-- SECTION 5: Informational Observations -->
  <div class="category-divider page-break"></div>
  {cat_section("Informational Observations", "#71717a", "⚪", cat_info, 5)}

  <!-- SECTION 6: Threat Model (STRIDE) -->
  <div class="category-divider page-break"></div>
  <div class="section-title" style="color:#6366f1;border-left-color:#6366f1;">⚡ 6. Design-Level Threat Modeling (STRIDE)</div>
  <table>
    <thead><tr>
      <th>ID</th><th>Category</th><th>Threat Scenario</th><th>Entry Point</th><th>Status</th>
    </tr></thead>
    <tbody>
      {"".join(f'<tr><td>{t["id"]}</td><td><strong>{t["category"]}</strong></td><td>{t["threat"]}</td><td>{t["entry_point"]}</td><td><span style="font-size:10px;font-weight:700;color:{"#16a34a" if t["status"]=="Mitigated" else "#e31e24"};">{t["status"]}</span></td></tr>' for t in (state_copy.get('threat_model') or {}).values() if isinstance(t, dict)) or '<tr><td colspan="5" style="text-align:center;color:#999;">No threat model data</td></tr>'}
    </tbody>
  </table>

  <!-- SECTION 7: Manual Pentest -->
  <div class="section-title" style="color:#6366f1;border-left-color:#6366f1;">🔍 7. Manual Penetration Testing</div>
  <table>
    <thead><tr>
      <th>ID</th><th>Category</th><th>Test Scenario</th><th>Status</th><th>Notes</th>
    </tr></thead>
    <tbody>
      {"".join(f'<tr><td>{m["id"]}</td><td>{m["category"]}</td><td><strong>{m["name"]}</strong></td><td><span style="font-size:10px;font-weight:700;color:{"#16a34a" if m["status"]=="Tested" else "#e31e24" if m["status"]=="Vulnerable" else "#ca8a04"};">{m["status"]}</span></td><td>{m.get("notes") or "—"}</td></tr>' for m in (state_copy.get('manual_pentest') or {}).values() if isinstance(m, dict)) or '<tr><td colspan="5" style="text-align:center;color:#999;">No manual pentest data</td></tr>'}
    </tbody>
  </table>

  <!-- Footer -->
  <div style="margin-top:60px;padding-top:20px;border-top:1px solid #e4e4e7;display:flex;justify-content:space-between;font-size:11px;color:#a1a1aa;">
    <div>Prodapt InfoSec Platform &nbsp;|&nbsp; 15-Rule FP Reduction Engine</div>
    <div>{target} &nbsp;|&nbsp; {scan_date}</div>
    <div>Risk Score: {risk_score}/100 &nbsp;|&nbsp; {len(cat_confirmed)} Confirmed Findings</div>
  </div>

</div>
</body>
</html>"""
    return Response(
        report_html,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename=infosec_lifecycle_report_{target}.html'}
    )


REMEDIATION_TIPS = {
    'critical': 'Immediate remediation required. Patch within 24 hours. Isolate affected asset if exploitation is active.',
    'high': 'Remediate within 1 week. Verify exploitability in your environment and apply available patches.',
    'medium': 'Schedule remediation within 30 days. Apply defense-in-depth controls as interim mitigation.',
    'low': 'Address in next maintenance window. Low exploitation risk but contributes to overall attack surface.',
    'info': 'Informational — no direct exploitation risk. Review and document.',
}

SECURITY_HEADER_REMEDIATIONS = {
    'Strict-Transport-Security': 'Add "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload" to all HTTPS responses.',
    'Content-Security-Policy': 'Add "Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\'" to prevent XSS.',
    'X-Frame-Options': 'Add "X-Frame-Options: DENY" to prevent clickjacking attacks.',
    'X-Content-Type-Options': 'Add "X-Content-Type-Options: nosniff" to prevent MIME-type sniffing.',
    'Referrer-Policy': 'Add "Referrer-Policy: strict-origin-when-cross-origin" to control referrer leakage.',
    'Permissions-Policy': 'Add "Permissions-Policy: geolocation=(), microphone=(), camera=()" to restrict API access.',
}


@reports_bp.route('/pdf', methods=['GET', 'POST'])
@login_required
def export_pdf():
    try:
        target = scan_state['target'] or 'unknown.com'
        with LOCK:
            state_copy = json.loads(json.dumps(scan_state))

        if not FPDF_AVAILABLE:
            return jsonify({'status': 'error', 'message': 'fpdf2 not installed. Run: pip install fpdf2'}), 400

        findings = state_copy.get('findings', [])
        if not findings:
            findings = state_copy.get('scan_state', {}).get('findings', [])
        if not findings:
            for key in state_copy.keys():
                if isinstance(state_copy[key], dict) and 'findings' in state_copy[key]:
                    findings = state_copy[key]['findings']
                    break
        # Sort findings by severity (Critical -> Info)
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings = sorted(
            findings,
            key=lambda f: (sev_order.get((f.get('sev') or 'info').lower(), 4), -float(f.get('cvss') or 0) if str(f.get('cvss','')).replace('.','').isdigit() else 0)
        )
        state_copy['findings'] = findings

        pdf = FPDF()
        sev_colors = {'critical': (227,30,36), 'high': (234,88,12), 'medium': (202,138,4), 'low': (22,163,74), 'info': (37,99,235)}

        def section_header(title, num):
            pdf.add_page()
            # Clean section header with proper alignment
            pdf.set_fill_color(30, 30, 40)
            pdf.rect(0, 0, 210, 18, 'F')
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('Helvetica', 'B', 14)
            pdf.set_y(4)
            pdf.cell(0, 10, safe_text(f'{num}. {title}'), new_x='LMARGIN', new_y='NEXT', align='C')
            pdf.ln(12)

        def safe_text(text):
            """Sanitize text for FPDF latin-1 encoding"""
            if not text:
                return ''
            text = str(text)
            replacements = {
                '\u2014': '-',   # em dash
                '\u2013': '-',   # en dash
                '\u2018': "'",   # left single quote
                '\u2019': "'",   # right single quote
                '\u201c': '"',   # left double quote
                '\u201d': '"',   # right double quote
                '\u2026': '...',  # ellipsis
                '\u2022': '-',   # bullet
                '\u00a0': ' ',   # non-breaking space
                '\u2192': '->',  # right arrow
                '\u2190': '<-',  # left arrow
                '\u2191': '^',   # up arrow
                '\u2193': 'v',   # down arrow
                '\u21d2': '=>',  # double right arrow
                '\u21d0': '<=',  # double left arrow
                '\u2264': '<=',  # less than or equal
                '\u2265': '>=',  # greater than or equal
                '\u2260': '!=',  # not equal
                '\u2248': '~',   # approximately
                '\u00d7': 'x',   # multiplication
                '\u00f7': '/',   # division
                '\u00b0': 'deg', # degree
                '\u00b1': '+/-', # plus-minus
                '\u00ae': '(R)', # registered
                '\u2122': '(TM)',# trademark
                '\u00a9': '(C)', # copyright
                '\u20ac': 'EUR', # euro
                '\u00a3': 'GBP', # pound
                '\u00a5': 'JPY', # yen
                '\u25cf': '*',   # filled circle
                '\u25cb': 'o',   # empty circle
                '\u25a0': '#',   # filled square
                '\u25a1': '[]',  # empty square
                '\u2713': '[v]', # checkmark
                '\u2717': '[x]', # cross mark
                '\u26a0': '[!]', # warning sign
                '\u2b50': '[*]', # star
                '\u00ab': '<<',  # left guillemet
                '\u00bb': '>>',  # right guillemet
                '\u2039': '<',   # single left guillemet
                '\u203a': '>',   # single right guillemet
                '\u2010': '-',   # hyphen
                '\u2011': '-',   # non-breaking hyphen
                '\u2012': '-',   # figure dash
                '\u2015': '--',  # horizontal bar
                '\u00ad': '-',   # soft hyphen
                '\u200b': '',    # zero-width space
                '\u200c': '',    # zero-width non-joiner
                '\u200d': '',    # zero-width joiner
                '\ufeff': '',    # BOM
                '\u2028': '\n',  # line separator
                '\u2029': '\n',  # paragraph separator
            }
            for k, v in replacements.items():
                text = text.replace(k, v)
            # Remove any remaining non-latin1 characters
            return text.encode('latin-1', errors='replace').decode('latin-1')

        def add_text(text, size=9, bold=False, color=(24,24,27), indent=0):
            pdf.set_x(10 + indent)
            pdf.set_text_color(*color)
            pdf.set_font('Helvetica', 'B' if bold else '', size)
            pdf.multi_cell(190 - indent, 5, safe_text(text))
            pdf.ln(1)

        def draw_line(y_pos=None):
            if y_pos is None:
                y_pos = pdf.get_y()
            pdf.set_draw_color(200, 200, 210)
            pdf.set_line_width(0.3)
            pdf.line(10, y_pos, 200, y_pos)

        # ─── COVER PAGE ───
        pdf.add_page()

        # Top accent bar
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 0, 210, 8, 'F')

        # Main title area
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 40, 210, 80, 'F')

        # Title - centered
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 32)
        pdf.set_y(55)
        pdf.cell(0, 15, 'SECURITY ASSESSMENT', new_x='LMARGIN', new_y='NEXT', align='C')

        pdf.set_font('Helvetica', '', 16)
        pdf.cell(0, 10, 'Penetration Testing Report', new_x='LMARGIN', new_y='NEXT', align='C')

        # Decorative line
        pdf.set_draw_color(227, 30, 36)
        pdf.set_line_width(1)
        pdf.line(60, pdf.get_y() + 5, 150, pdf.get_y() + 5)
        pdf.ln(15)

        # Target info box - centered
        pdf.set_fill_color(245, 245, 248)
        pdf.rect(30, pdf.get_y(), 150, 45, 'F')

        info_y = pdf.get_y() + 8
        pdf.set_text_color(60, 60, 70)
        pdf.set_font('Helvetica', '', 11)

        pdf.set_y(info_y)
        pdf.set_x(40)
        pdf.cell(40, 7, 'Target:', new_x='RIGHT')
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(100, 7, safe_text(target), new_x='LMARGIN', new_y='NEXT')

        pdf.set_font('Helvetica', '', 11)
        pdf.set_x(40)
        pdf.cell(40, 7, 'Date:', new_x='RIGHT')
        pdf.cell(100, 7, datetime.now().strftime("%B %d, %Y at %H:%M"), new_x='LMARGIN', new_y='NEXT')

        pdf.set_x(40)
        pdf.cell(40, 7, 'Classification:', new_x='RIGHT')
        pdf.set_text_color(227, 30, 36)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(100, 7, 'CONFIDENTIAL', new_x='LMARGIN', new_y='NEXT')

        pdf.set_y(180)

        # Bottom info
        pdf.set_text_color(120, 120, 130)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(0, 6, 'This document contains sensitive security information.', new_x='LMARGIN', new_y='NEXT', align='C')
        pdf.cell(0, 6, 'Distribution is restricted to authorized personnel only.', new_x='LMARGIN', new_y='NEXT', align='C')

        # Bottom accent bar
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 289, 210, 8, 'F')

        # ─── TABLE OF CONTENTS ───
        pdf.add_page()

        # Header
        pdf.set_fill_color(30, 30, 40)
        pdf.rect(0, 0, 210, 18, 'F')
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_y(4)
        pdf.cell(0, 10, 'TABLE OF CONTENTS', new_x='LMARGIN', new_y='NEXT', align='C')
        pdf.ln(20)

        # TOC items with proper alignment
        toc = [
            ('1', 'Executive Summary', 'Overview and key findings'),
            ('2', 'Risk Score & Analysis', 'Detailed risk breakdown'),
            ('3', 'Vulnerability Findings', 'Complete findings table'),
            ('4', 'Detailed Findings', 'Remediation & PoC for each finding'),
            ('5', 'Security Headers', 'Missing headers analysis'),
            ('6', 'Open Ports', 'Network services discovered'),
            ('7', 'Recommendations', 'Prioritized action items')
        ]

        for num, title, desc in toc:
            pdf.set_fill_color(245, 245, 248)
            pdf.rect(15, pdf.get_y(), 180, 14, 'F')

            pdf.set_text_color(30, 30, 40)
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_x(20)
            pdf.cell(10, 14, num, new_x='RIGHT')

            pdf.set_font('Helvetica', 'B', 11)
            pdf.cell(80, 14, safe_text(title), new_x='RIGHT')

            pdf.set_text_color(120, 120, 130)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(80, 14, safe_text(desc), new_x='LMARGIN', new_y='NEXT')
            pdf.ln(2)

        # ─── SECTION 1: EXECUTIVE SUMMARY ───
        section_header('EXECUTIVE SUMMARY', 1)
        stats = state_copy.get('stats', {})
        score = state_copy.get('risk_score', 0)
        risk_label = 'CRITICAL' if score >= 80 else 'HIGH' if score >= 60 else 'MEDIUM' if score >= 40 else 'LOW'
        total = len(findings)
        critical_cnt = stats.get('critical', 0)
        high_cnt = stats.get('high', 0)
        medium_cnt = stats.get('medium', 0)
        low_cnt = stats.get('low', 0)

        # Calculate scan duration
        scan_start = state_copy.get('scan_start_time', 0)
        scan_end = state_copy.get('scan_end_time', time.time())
        duration = scan_end - scan_start if scan_start else 0
        duration_str = f'{int(duration//60)}m {int(duration%60)}s' if duration > 60 else f'{int(duration)}s'

        # Count tools used
        tools_used = []
        tool_checks = [
            ('nmap', 'Nmap'), ('sqlmap', 'SQLMap'), ('ffuf', 'FFUF'), ('nuclei', 'Nuclei'),
            ('httpx', 'httpx'), ('subfinder', 'Subfinder'), ('amass', 'Amass'),
            ('gau', 'gau'), ('katana', 'Katana'), ('testssl', 'testssl.sh'),
            ('sslyze', 'SSLYZE'), ('wafw00f', 'wafw00f'), ('dalfox', 'Dalfox'),
            ('osv-scanner', 'osv-scanner'), ('gitleaks', 'Gitleaks'),
            ('semgrep', 'Semgrep'), ('crlfuzz', 'crlfuzz'), ('trufflehog', 'TruffleHog'),
        ]
        for tool_key, tool_name in tool_checks:
            if _find_tool(tool_key):
                tools_used.append(tool_name)

        add_text(f'Target: {target}', 11, True)
        add_text(f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 10)
        add_text(f'Scan Duration: {duration_str} | Tools Used: {len(tools_used)}', 10)
        pdf.ln(3)

        add_text('OVERVIEW', 10, True, (227,30,36))
        add_text(f'This report presents the results of a comprehensive automated security assessment '
                 f'performed against {target} using {len(tools_used)} integrated security tools across '
                 f'{len(state_copy.get("modules_run", []))} scan modules. The assessment identified '
                 f'{total} security findings spanning network services, web application security, '
                 f'SSL/TLS configuration, security headers, dependency vulnerabilities, secrets exposure, '
                 f'SAST analysis, and advanced XSS/CRLF injection testing.', 9)
        pdf.ln(2)

        add_text('TOOLS USED IN THIS ASSESSMENT', 10, True, (227,30,36))
        tools_text = ', '.join(tools_used[:10])
        if len(tools_used) > 10:
            tools_text += f', and {len(tools_used)-10} more'
        add_text(tools_text, 9)
        pdf.ln(2)

        add_text('KEY FINDINGS', 10, True, (227,30,36))
        add_text(f'Overall Risk Score: {score}/100 ({risk_label})', 9)
        add_text(f'Total Vulnerabilities: {total}', 9)
        add_text(f'Critical: {critical_cnt} | High: {high_cnt} | Medium: {medium_cnt} | Low: {low_cnt}', 9)
        if critical_cnt > 0:
            add_text(f'URGENT: {critical_cnt} critical vulnerabilities require immediate attention within 24 hours.', 9, True, (227,30,36))
        if high_cnt > 0:
            add_text(f'WARNING: {high_cnt} high-severity vulnerabilities should be remediated within 1 week.', 9, True, (234,88,12))
        pdf.ln(2)

        # Top findings summary
        add_text('TOP VULNERABILITIES', 10, True, (227,30,36))
        top_findings = sorted(findings, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.get('sev', 'info'), 5))[:5]
        for i, tf in enumerate(top_findings):
            sev_tag = tf.get('sev', 'info').upper()
            sev_c = sev_colors.get(tf.get('sev', 'info'), (113,113,122))
            add_text(f'{i+1}. [{sev_tag}] {tf.get("title", "N/A")}', 9, True, sev_c)
            if tf.get('sub'):
                add_text(f'   {tf.get("sub", "")[:120]}', 8)
        pdf.ln(2)

        add_text('BUSINESS IMPACT', 10, True, (227,30,36))
        if risk_label == 'CRITICAL':
            add_text('The target has a CRITICAL risk posture. Immediate action is required to prevent potential data breaches, '
                     'service disruption, or compliance violations. The organization faces significant exposure to cyber threats.', 9)
        elif risk_label == 'HIGH':
            add_text('The target has a HIGH risk posture. Prompt remediation is recommended to reduce the attack surface and '
                     'prevent potential exploitation. The organization should prioritize fixing critical and high severity findings.', 9)
        elif risk_label == 'MEDIUM':
            add_text('The target has a MEDIUM risk posture. While not immediately critical, the identified vulnerabilities '
                     'should be addressed in a timely manner to maintain a strong security posture.', 9)
        else:
            add_text('The target has a LOW risk posture. The identified issues are mostly informational and should be '
                     'addressed during regular maintenance cycles.', 9)

        # ─── SECTION 2: RISK SCORE ───
        section_header('RISK SCORE & ANALYSIS', 2)
        risk_colors = {'CRITICAL': (227,30,36), 'HIGH': (234,88,12), 'MEDIUM': (202,138,4), 'LOW': (22,163,74)}
        rc = risk_colors.get(risk_label, (113,113,122))
        add_text(f'Overall Risk Score: {score}/100 ({risk_label})', 12, True, rc)
        pdf.set_fill_color(*rc)
        pdf.rect(10, pdf.get_y(), score * 1.9, 8, 'F')
        pdf.ln(12)

        add_text('SEVERITY DISTRIBUTION', 10, True, (227,30,36))
        col_x = [10, 58, 106, 154]
        base_y = pdf.get_y()
        for i, (lbl, key, clr) in enumerate([('CRITICAL','critical',(227,30,36)), ('HIGH','high',(234,88,12)), ('MEDIUM','medium',(202,138,4)), ('LOW','low',(22,163,74))]):
            pdf.set_fill_color(*clr)
            pdf.set_xy(col_x[i], base_y)
            pdf.cell(44, 20, '', border=0, fill=True)
            pdf.set_xy(col_x[i], base_y + 3)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('Helvetica', 'B', 18)
            pdf.cell(44, 10, str(stats.get(key, 0)), align='C')
            pdf.set_xy(col_x[i], base_y + 13)
            pdf.set_font('Helvetica', '', 7)
            pdf.cell(44, 5, lbl, align='C')
        pdf.set_y(base_y + 26)

        add_text('RISK FACTOR BREAKDOWN', 10, True, (227,30,36))
        breakdown = state_copy.get('risk_breakdown', [])
        if breakdown:
            # Header row with dark background
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(150, 7, '  Factor', border=0, fill=True)
            pdf.cell(30, 7, 'Points', border=0, align='C', fill=True)
            pdf.ln()
            # Data rows - no borders, alternating colors
            pdf.set_text_color(24, 24, 27)
            pdf.set_font('Helvetica', '', 8)
            for row_idx, b in enumerate(breakdown[:15]):
                if row_idx % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)
                row_y = pdf.get_y()
                pdf.rect(10, row_y, 190, 5, 'F')
                pdf.cell(150, 5, f'  {b["factor"][:85]}', border=0)
                pdf.set_text_color(227, 30, 36)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(30, 5, f"+{b['points']}", border=0, align='C')
                pdf.set_text_color(24, 24, 27)
                pdf.set_font('Helvetica', '', 8)
                pdf.ln()

        # ─── SECTION 3: ASSESSMENT METHODOLOGY ───
        section_header('ASSESSMENT METHODOLOGY', 3)

        add_text('The security assessment was conducted following industry-standard penetration testing methodologies '
                 'aligned with OWASP Testing Guide v4.2, PTES (Penetration Testing Execution Standard), and '
                 'NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment). '
                 'Testing was performed using a combination of automated scanning tools and manual validation '
                 'techniques to identify, verify, and assess the impact of each finding.', 9)
        pdf.ln(3)

        # Pre-Authentication Testing
        add_text('PRE-AUTHENTICATION TESTING', 10, True, (227, 30, 36))
        pdf.ln(1)
        add_text('The assessment began with unauthenticated testing to identify vulnerabilities accessible to '
                 'external attackers without valid credentials. Security testing focused on publicly exposed '
                 'functionality including landing pages, authentication interfaces, password recovery mechanisms, '
                 'registration workflows, API endpoints, static resources, client-side scripts, HTTP headers, '
                 'and application responses.', 9)
        pdf.ln(2)
        pre_auth_items = [
            'Enumeration of publicly accessible endpoints and functionality.',
            'Analysis of application responses for information disclosure (server versions, stack traces, internal paths).',
            'Validation of input handling across all user-controlled parameters (URL, POST body, headers, cookies).',
            'Assessment of authentication-related workflows (login, registration, password reset).',
            'Identification of exposed administrative interfaces and sensitive resources (.env, .git, /admin).',
            'Verification of security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).',
            'Testing for common web vulnerabilities affecting unauthenticated users (SQLi, XSS, SSRF, open redirects).',
            'Assessment of SSL/TLS configuration, certificate validity, and cipher suite strength.',
            'DNS enumeration for subdomain takeover, zone transfer, and wildcard DNS issues.',
            'Cloud storage exposure testing (S3 buckets, Azure Blobs, GCP Storage).',
        ]
        for i, item in enumerate(pre_auth_items, 1):
            if pdf.get_y() > 270:
                pdf.add_page()
            add_text(f'{i}. {item}', 8, indent=4)
        pdf.ln(3)

        # Login Page Security Assessment
        add_text('LOGIN PAGE SECURITY ASSESSMENT', 10, True, (227, 30, 36))
        pdf.ln(1)
        add_text('A dedicated assessment of the authentication mechanism was performed to evaluate the '
                 'effectiveness of access control and credential validation processes.', 9)
        pdf.ln(2)
        login_items = [
            'Reviewing the authentication workflow and request structure (POST parameters, headers, cookies).',
            'Validating credential transmission security (HTTPS enforcement, no credentials in URL parameters).',
            'Testing account lockout and rate-limiting controls (brute force resistance).',
            'Assessing password policy enforcement (minimum length, complexity, breached password check).',
            'Evaluating user enumeration opportunities through application responses (different error messages).',
            'Verifying multi-factor authentication implementation where applicable (TOTP, WebAuthn).',
            'Reviewing session creation and token generation processes (entropy, randomness, predictability).',
            'Testing authentication bypass scenarios (SQLi in login, default credentials, logic flaws).',
            'Validating password reset and account recovery functionality (token expiry, predictability).',
            'Assessment of protection against automated credential attacks (CAPTCHA, rate limiting).',
        ]
        for i, item in enumerate(login_items, 1):
            if pdf.get_y() > 270:
                pdf.add_page()
            add_text(f'{i}. {item}', 8, indent=4)
        pdf.ln(3)

        # Post-Authentication Testing
        if pdf.get_y() > 200:
            pdf.add_page()
        add_text('POST-AUTHENTICATION TESTING', 10, True, (227, 30, 36))
        pdf.ln(1)
        add_text('Following successful authentication, the assessment expanded to authenticated functionality '
                 'to identify weaknesses that could impact authorized users or enable privilege escalation.', 9)
        pdf.ln(2)
        post_auth_items = [
            'Verification of role-based access controls (admin vs. regular user functionality).',
            'Assessment of authorization enforcement across application functions (horizontal/vertical privilege escalation).',
            'Testing for horizontal and vertical privilege escalation opportunities (IDOR, parameter manipulation).',
            'Validation of direct object reference protections (sequential IDs, predictable filenames).',
            'Review of session management and session lifecycle controls (timeout, fixation, invalidation).',
            'Analysis of sensitive data exposure risks (PII in responses, verbose error messages).',
            'Testing authenticated API endpoints for missing authorization checks (BOLA/IDOR).',
            'Assessment of business logic implementation (race conditions, workflow bypass).',
            'Evaluation of administrative functionality access restrictions (admin panels, debug endpoints).',
            'Verification of secure handling of user-generated content and uploaded files.',
        ]
        for i, item in enumerate(post_auth_items, 1):
            if pdf.get_y() > 270:
                pdf.add_page()
            add_text(f'{i}. {item}', 8, indent=4)
        pdf.ln(3)

        # Detailed Validation Procedure
        if pdf.get_y() > 180:
            pdf.add_page()
        add_text('DETAILED VALIDATION PROCEDURE', 10, True, (227, 30, 36))
        pdf.ln(1)
        add_text('Each finding was validated following a structured five-step process to ensure accuracy, '
                 'reproducibility, and reliable impact assessment.', 9)
        pdf.ln(2)

        steps = [
            ('Step 1 - Reconnaissance and Application Mapping',
             'Identify all accessible application components. Enumerate URLs, parameters, APIs, forms, '
             'and user interaction points. Document discovered functionality for targeted testing. '
             'Analyze technology stack, frameworks, and server configuration. Map the attack surface '
             'including hidden endpoints, backup files, and administrative interfaces.'),
            ('Step 2 - Authentication Assessment',
             'Test valid and invalid authentication scenarios. Observe application behavior during failed '
             'login attempts (error messages, timing differences). Validate lockout protections and rate '
             'limiting. Review session token generation and handling. Test for default credentials and '
             'credential stuffing resistance. Assess password reset flow security.'),
            ('Step 3 - Authorization Assessment',
             'Access application features using different privilege levels. Modify identifiers and parameters '
             'within requests to test for IDOR. Attempt unauthorized access to restricted resources. '
             'Validate server-side access control enforcement (not just client-side hiding). '
             'Test for privilege escalation via parameter manipulation.'),
            ('Step 4 - Session Management Review',
             'Analyze authentication tokens and session cookies for Secure, HttpOnly, SameSite flags. '
             'Verify secure attributes and lifecycle management. Test logout functionality and session '
             'invalidation. Assess session timeout enforcement. Test for session fixation vulnerabilities. '
             'Evaluate token entropy and predictability.'),
            ('Step 5 - Impact Validation',
             'Confirm exploitability of identified weaknesses with proof-of-concept demonstrations. '
             'Determine affected users, systems, and business functions. Evaluate confidentiality, integrity, '
             'and availability impact. Document realistic attack scenarios and risk implications. '
             'Assess the business impact including data breach potential, compliance violations, and reputational damage.'),
        ]

        for step_title, step_desc in steps:
            if pdf.get_y() > 230:
                pdf.add_page()
            add_text(step_title, 9, True, (30, 30, 40))
            add_text(step_desc, 8, indent=4)
            pdf.ln(2)

        # Tools and Environment
        if pdf.get_y() > 220:
            pdf.add_page()
        add_text('TOOLS AND ENVIRONMENT', 10, True, (227, 30, 36))
        pdf.ln(1)
        add_text('The following tools were used during the assessment:', 9)
        pdf.ln(1)
        tools = [
            'Nmap - Network port scanning and service detection',
            'sqlmap - Automated SQL injection detection and exploitation',
            'ffuf - Web content and endpoint discovery',
            'nuclei - Template-based vulnerability scanning',
            'httpx - HTTP probing and technology detection',
            'subfinder - Subdomain enumeration',
            'testssl.sh - SSL/TLS configuration analysis',
            'amass - Network mapping of attack surfaces',
            'gau - Fetch known URLs from AlienVault OTX',
            'katana - Next-gen crawling and spidering',
            'sslyze - SSL/TLS configuration analysis',
            'wafw00f - Web Application Firewall fingerprinting',
            'dalfox - Advanced XSS scanning (reflected/stored/DOM)',
            'osv-scanner - Dependency vulnerability scanning (CVE detection)',
            'gitleaks - Secrets detection in code repositories',
            'semgrep - Static Application Security Testing (SAST)',
            'crlfuzz - CRLF injection vulnerability scanning',
            'trufflehog - Deep secrets scanning with entropy analysis',
            'Custom Python scripts - Automated testing and validation',
            'Browser Developer Tools - Client-side analysis and DOM inspection',
        ]
        for tool in tools:
            if pdf.get_y() > 270:
                pdf.add_page()
            add_text(f'  - {tool}', 8, indent=4)

        pdf.ln(3)

        # ─── SECTION 4: FINDINGS OVERVIEW TABLE (borderless with clickable links) ───
        section_header('VULNERABILITY FINDINGS OVERVIEW', 4)
        if findings:
            # Create internal links for each finding
            finding_links = []
            for fi in range(len(findings)):
                link = pdf.add_link()
                finding_links.append(link)

            col_w = [14, 50, 22, 22, 16, 20, 20, 26, 14]
            headers_list = ['Sev', 'Finding', 'CVE', 'Asset', 'CVSS', 'OWASP', 'MITRE', 'Exploit', 'Conf']
            # Header row
            pdf.set_font('Helvetica', 'B', 7)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            for i, h in enumerate(headers_list):
                pdf.cell(col_w[i], 7, h, border=0, align='C', fill=True)
            pdf.ln()
            # Data rows - no borders, alternating row colors
            conf_colors = {'high': (180, 0, 0), 'medium': (180, 130, 0), 'speculative': (40, 80, 160)}
            for row_idx, f in enumerate(findings):
                sev = f.get('sev', 'info')
                c = sev_colors.get(sev, (113,113,122))
                # Alternating row background
                if row_idx % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)
                row_y = pdf.get_y()
                pdf.rect(10, row_y, 190, 6, 'F')
                # Severity with colored dot
                pdf.set_text_color(*c)
                pdf.set_font('Helvetica', 'B', 7)
                pdf.cell(col_w[0], 6, safe_text(sev.upper()[:4]), border=0, align='C')
                # Finding title as clickable link
                pdf.set_text_color(24, 24, 27)
                pdf.set_font('Helvetica', '', 7)
                title_text = safe_text(f.get('title', '')[:40])
                link_idx = row_idx
                if link_idx < len(finding_links):
                    pdf.cell(col_w[1], 6, title_text, border=0, link=finding_links[link_idx])
                else:
                    pdf.cell(col_w[1], 6, title_text, border=0)
                pdf.cell(col_w[2], 6, safe_text((f.get('cve','') or '')[:10]), border=0, align='C')
                asset_text = safe_text(f.get('asset', '')[:16])
                pdf.cell(col_w[3], 6, asset_text, border=0)
                pdf.cell(col_w[4], 6, safe_text(str(f.get('cvss','') or '')), border=0, align='C')
                pdf.set_text_color(59, 130, 246)
                owasp_text = safe_text((f.get('owasp','') or '')[:8])
                pdf.cell(col_w[5], 6, owasp_text, border=0, align='C')
                pdf.set_text_color(139, 92, 246)
                mitre_text = safe_text((f.get('mitre','') or '')[:8])
                pdf.cell(col_w[6], 6, mitre_text, border=0, align='C')
                pdf.set_text_color(24, 24, 27)
                pdf.cell(col_w[7], 6, safe_text((f.get('exploit','') or '')[:12]), border=0, align='C')
                # Confidence badge
                conf = f.get('confidence', 'medium')
                conf_color = conf_colors.get(conf, conf_colors['medium'])
                pdf.set_fill_color(*conf_color)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font('Helvetica', 'B', 7)
                pdf.cell(col_w[8], 6, conf[0].upper(), border=0, fill=True, align='C')
                pdf.set_text_color(24, 24, 27)
                pdf.ln()
        else:
            add_text('No findings discovered during scan.', 10)

        # ─── SECTION 5: DETAILED FINDINGS WITH REMEDIATION & POC ───
        if findings:
            section_header('DETAILED FINDINGS WITH REMEDIATION & POC', 5)
            add_text('Each finding below includes: actual evidence captured during the scan, '
                     'step-by-step reproduction instructions, impact analysis, risk assessment '
                     'with CVSS scoring, and specific remediation guidance.', 9)
            pdf.ln(3)

            sorted_findings = sorted(findings, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.get('sev', 'info'), 5))

            # Pre-create destination links for each finding
            detail_links = []
            for fi in range(len(sorted_findings)):
                detail_links.append(pdf.add_link())

            for idx, f in enumerate(sorted_findings):
                sev = f.get('sev', 'info')
                c = sev_colors.get(sev, (113,113,122))

                # Check if we need a new page
                if pdf.get_y() > 160:
                    pdf.add_page()

                # Set destination for this finding's link (for navigation from overview)
                if idx < len(detail_links):
                    pdf.set_link(detail_links[idx], y=-1, page=-1)

                # ── Finding header: clean text-based, no colored bar ──
                pdf.set_x(14)
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 11)
                pdf.cell(150, 7, safe_text(f'Finding #{idx+1}: {f.get("title", "")}'))
                pdf.set_font('Helvetica', 'B', 10)
                pdf.set_text_color(*c)
                pdf.cell(32, 7, f'[{sev.upper()}]', align='R')
                pdf.ln(8)

                # ── Subtitle / description line ──
                sub_text = f.get('sub', '')
                if sub_text:
                    pdf.set_x(14)
                    pdf.set_font('Helvetica', 'I', 8)
                    pdf.set_text_color(80, 80, 90)
                    pdf.multi_cell(180, 4, safe_text(sub_text[:180]))
                    pdf.ln(2)

                # ── Thin separator line ──
                pdf.set_draw_color(*c)
                pdf.set_line_width(0.5)
                pdf.line(14, pdf.get_y(), 196, pdf.get_y())
                pdf.ln(4)

                # ── Metadata table: 3 rows x 2 cols ──
                cve_val = safe_text(f.get('cve', '') or 'N/A')
                cvss_val = safe_text(str(f.get('cvss', '') or 'N/A'))
                asset_val = safe_text(f.get('asset', '') or 'N/A')
                exploit_val = safe_text(f.get('exploit', '') or 'N/A')
                owasp_val = safe_text(f.get('owasp', '') or 'N/A')
                mitre_val = safe_text(f.get('mitre', '') or 'N/A')

                my = pdf.get_y()
                pdf.set_fill_color(248, 248, 250)
                pdf.rect(14, my, 182, 18, 'F')

                # Row 0
                pdf.set_xy(16, my + 1)
                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(18, 5, 'CVE:')
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(73, 5, cve_val)

                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(20, 5, 'CVSS:')
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(70, 5, cvss_val)
                # CVSS vector footnote
                cvss_vector = f.get('cvss_vector', '')
                if cvss_vector:
                    pdf.set_text_color(120, 120, 130)
                    pdf.set_font('Helvetica', '', 6)
                    pdf.cell(0, 4, f'    Vector: {safe_text(cvss_vector[:80])}', new_x='LMARGIN', new_y='NEXT')
                else:
                    pdf.ln(5)

                # Row 1
                pdf.set_xy(16, my + 7)
                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(18, 5, 'Asset:')
                pdf.set_text_color(30, 30, 40)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(73, 5, asset_val[:45])

                pdf.set_text_color(100, 100, 110)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(20, 5, 'OWASP:')
                pdf.set_text_color(59, 130, 246)
                pdf.set_font('Helvetica', 'B', 8)
                pdf.cell(70, 5, owasp_val)

                pdf.set_y(my + 20)

                # ── Render PoC sections ──
                poc_items = build_poc_section(f)
                # All section headers use a single neutral dark-grey bar (no red/orange
                # highlighting). Section text is rendered in white on the bar.
                section_bar_color = (60, 60, 70)

                for pi in poc_items:
                    text = safe_text(pi)

                    # Detect section headers
                    if text.startswith('=== ') and text.endswith(' ==='):
                        section_name = text.replace('=== ', '').replace(' ===', '').strip()
                        if pdf.get_y() > 262:
                            pdf.add_page()
                        pdf.ln(2)
                        pdf.set_fill_color(*section_bar_color)
                        pdf.rect(14, pdf.get_y(), 182, 5.5, 'F')
                        pdf.set_text_color(255, 255, 255)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_x(16)
                        pdf.cell(178, 5, section_name, align='L')
                        pdf.set_y(pdf.get_y() + 7)
                        continue

                    if not text.strip():
                        continue

                    if pdf.get_y() > 270:
                        pdf.add_page()

                    pdf.set_text_color(40, 40, 50)
                    pdf.set_font('Helvetica', '', 7.5)

                    # HTTP request/response blocks
                    if text.startswith('  GET ') or text.startswith('  POST ') or text.startswith('  PUT ') or text.startswith('  DELETE ') or text.startswith('  curl ') or text.startswith('  $ '):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(30, 30, 40)
                        # Light gray background for code blocks
                        iy = pdf.get_y()
                        pdf.set_fill_color(245, 245, 248)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text)
                    elif text.startswith('  Response:') or text.startswith('  < HTTP/') or text.startswith('  [INFO]') or text.startswith('  [*]'):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(60, 60, 70)
                        iy = pdf.get_y()
                        pdf.set_fill_color(245, 245, 248)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text)
                    elif text.startswith('  Host:') or text.startswith('  User-Agent:') or text.startswith('  Accept:') or text.startswith('  Authorization:') or text.startswith('  Cookie:') or text.startswith('  Set-Cookie:') or text.startswith('  Content-Type:') or text.startswith('  Access-Control'):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(80, 80, 90)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4, text)
                    # Header labels
                    elif text.startswith('  Observation:') or text.startswith('  Observations:'):
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', 'BI', 7.5)
                        pdf.set_text_color(22, 163, 74)
                        pdf.multi_cell(178, 4.5, text.strip())
                    # NOTE: stale "BEFORE LOGIN" / "AFTER LOGIN" / "TESTING STEPS:" style
                    # branches were removed — those headings are no longer generated by
                    # build_poc_section (replaced by REAL EVIDENCE / EXPLOIT STEPS).
                    # Numbered steps
                    elif text.strip() and text.strip()[0].isdigit() and '. ' in text[:5]:
                        pdf.set_x(16)
                        num_part = text.strip().split('. ', 1)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(59, 130, 246)
                        pdf.cell(12, 4.5, num_part[0] + '.')
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(40, 40, 50)
                        if len(num_part) > 1:
                            pdf.multi_cell(164, 4.5, num_part[1])
                        else:
                            pdf.ln(4.5)
                    # Evidence items
                    elif text.strip() and text.strip()[0].isdigit() and '.' in text[:3]:
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(40, 40, 50)
                        pdf.multi_cell(178, 4.5, text.strip())
                    # Lines starting with bullet/dash
                    elif text.startswith('  - ') or text.startswith('    - '):
                        pdf.set_x(20)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(60, 60, 70)
                        pdf.multi_cell(172, 4.5, text.strip())
                    # Impact/risk text
                    elif text.startswith('CRITICAL:') or text.startswith('HIGH:') or text.startswith('MEDIUM:') or text.startswith('LOW:'):
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(227, 30, 36)
                        pdf.multi_cell(178, 4.5, text)
                    elif text.startswith('CVSS '):
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(234, 88, 12)
                        pdf.multi_cell(178, 4.5, text)
                    # Payload lines (indented with Payload or specific attack patterns)
                    elif 'Payload' in text or 'payload' in text:
                        pdf.set_x(16)
                        iy = pdf.get_y()
                        pdf.set_fill_color(255, 250, 240)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(180, 80, 0)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text.strip())
                    # Exploit PoC code
                    elif '<script>' in text or 'fetch(' in text or '.then(' in text:
                        pdf.set_x(16)
                        iy = pdf.get_y()
                        pdf.set_fill_color(255, 245, 245)
                        pdf.rect(16, iy, 176, 4.2, 'F')
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(180, 40, 40)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4.2, text)
                    # Remaining body text (HTTP bodies, etc.)
                    elif text.startswith('  ') and not text.startswith('   '):
                        pdf.set_x(16)
                        pdf.set_font('Courier', '', 7)
                        pdf.set_text_color(80, 80, 90)
                        pdf.set_x(18)
                        pdf.multi_cell(172, 4, text)
                    else:
                        pdf.set_x(16)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(50, 50, 60)
                        pdf.multi_cell(178, 4.5, text)

                pdf.ln(3)

                # ── Remediation Section ──
                if pdf.get_y() > 240:
                    pdf.add_page()

                ry = pdf.get_y()
                pdf.set_fill_color(22, 163, 74)
                pdf.rect(14, ry, 182, 5.5, 'F')
                pdf.set_xy(16, ry + 0.5)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font('Helvetica', 'B', 7.5)
                pdf.cell(178, 5, 'REMEDIATION RECOMMENDATIONS')
                pdf.set_y(ry + 7)

                rem = finding_remediation(f)
                lines = rem.split(' | ')
                for line in lines:
                    if pdf.get_y() > 272:
                        pdf.add_page()
                    text = safe_text(line.strip())
                    if not text:
                        continue
                    pdf.set_x(16)
                    if text.startswith('Step '):
                        parts = text.split(': ', 1)
                        pdf.set_font('Helvetica', 'B', 7.5)
                        pdf.set_text_color(22, 163, 74)
                        step_text = parts[0] + ':' if len(parts) > 1 else parts[0]
                        pdf.cell(20, 4.5, step_text)
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(40, 40, 50)
                        detail = parts[1] if len(parts) > 1 else ''
                        pdf.multi_cell(156, 4.5, detail)
                    else:
                        pdf.set_font('Helvetica', '', 7.5)
                        pdf.set_text_color(60, 60, 70)
                        pdf.multi_cell(178, 4.5, text)
                pdf.ln(5)

                # ── Separator ──
                if pdf.get_y() < 270:
                    pdf.set_draw_color(220, 220, 225)
                    pdf.set_line_width(0.3)
                    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
                    pdf.ln(6)

        # ─── SECTION 6: SECURITY HEADERS ───
        hdrs = state_copy.get('header_data', {})
        missing_hdrs = hdrs.get('missing_security', [])
        if missing_hdrs:
            section_header('SECURITY HEADERS ANALYSIS', 6)
            add_text(f'The following {len(missing_hdrs)} security headers are missing from the target. '
                     'Missing security headers can expose the application to various attacks.', 9)
            pdf.ln(3)

            # Table with proper styling
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.set_x(14)
            pdf.cell(50, 7, 'Header Name', border=0, fill=True, align='C')
            pdf.cell(136, 7, 'Remediation Guidance', border=0, fill=True, align='C')
            pdf.ln()

            # Alternating row colors
            for i, hdr in enumerate(missing_hdrs):
                if pdf.get_y() > 270:
                    pdf.add_page()
                    # Repeat header on new page
                    pdf.set_font('Helvetica', 'B', 8)
                    pdf.set_fill_color(30, 30, 40)
                    pdf.set_text_color(255, 255, 255)
                    pdf.set_x(14)
                    pdf.cell(50, 7, 'Header Name', border=0, fill=True, align='C')
                    pdf.cell(136, 7, 'Remediation Guidance', border=0, fill=True, align='C')
                    pdf.ln()

                rem = SECURITY_HEADER_REMEDIATIONS.get(hdr, 'Implement this security header.')
                # Alternating row background
                if i % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)

                pdf.set_font('Helvetica', 'B', 8)
                pdf.set_text_color(30, 30, 40)
                pdf.set_x(14)
                pdf.cell(50, 6, safe_text(hdr), border=0, fill=True)
                pdf.set_font('Helvetica', '', 8)
                pdf.set_text_color(60, 60, 70)
                pdf.cell(136, 6, safe_text(rem[:100]), border=0, fill=True)
                pdf.ln()

            pdf.ln(5)

        # ─── SECTION 7: TECHNOLOGIES DETECTED ───
        tech_data = state_copy.get('tech_data', {})
        techs = tech_data.get('technologies', [])
        if techs:
            if pdf.get_y() > 200:
                pdf.add_page()
            else:
                pdf.ln(8)

            # Section header with consistent styling
            pdf.set_fill_color(30, 30, 40)
            pdf.rect(0, pdf.get_y(), 210, 14, 'F')
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_y(pdf.get_y() + 3)
            pdf.cell(0, 10, '  TECHNOLOGY STACK', new_x='LMARGIN', new_y='NEXT')
            pdf.ln(8)

            # Table header
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.set_x(14)
            pdf.cell(30, 7, 'Category', border=0, fill=True, align='C')
            pdf.cell(50, 7, 'Technology', border=0, fill=True, align='C')
            pdf.cell(30, 7, 'Version', border=0, fill=True, align='C')
            pdf.cell(30, 7, 'Confidence', border=0, fill=True, align='C')
            pdf.cell(46, 7, 'Status', border=0, fill=True, align='C')
            pdf.ln()

            # Group by category
            categories = {}
            for t in techs:
                cat = t.get('category', 'Other')
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(t)

            row_idx = 0
            for cat, items in sorted(categories.items()):
                for item in items:
                    if pdf.get_y() > 270:
                        pdf.add_page()
                        # Repeat header on new page
                        pdf.set_font('Helvetica', 'B', 8)
                        pdf.set_fill_color(30, 30, 40)
                        pdf.set_text_color(255, 255, 255)
                        pdf.set_x(14)
                        pdf.cell(30, 7, 'Category', border=0, fill=True, align='C')
                        pdf.cell(50, 7, 'Technology', border=0, fill=True, align='C')
                        pdf.cell(30, 7, 'Version', border=0, fill=True, align='C')
                        pdf.cell(30, 7, 'Confidence', border=0, fill=True, align='C')
                        pdf.cell(46, 7, 'Status', border=0, fill=True, align='C')
                        pdf.ln()

                    name = item.get('name', '')
                    ver = item.get('version', 'detected')
                    conf = item.get('confidence', 'medium')

                    # Alternating row background
                    if row_idx % 2 == 0:
                        pdf.set_fill_color(248, 248, 250)
                    else:
                        pdf.set_fill_color(255, 255, 255)

                    pdf.set_font('Helvetica', '', 8)
                    pdf.set_text_color(60, 60, 70)
                    pdf.set_x(14)
                    pdf.cell(30, 6, safe_text(cat), border=0, fill=True)
                    pdf.set_font('Helvetica', 'B', 8)
                    pdf.set_text_color(30, 30, 40)
                    pdf.cell(50, 6, safe_text(name), border=0, fill=True)

                    # Version with status indicator
                    if ver and ver != 'detected':
                        pdf.set_font('Helvetica', 'B', 8)
                        pdf.set_text_color(22, 163, 74)
                        pdf.cell(30, 6, safe_text(ver), border=0, fill=True, align='C')
                    else:
                        pdf.set_font('Helvetica', '', 8)
                        pdf.set_text_color(120, 120, 130)
                        pdf.cell(30, 6, 'Unknown', border=0, fill=True, align='C')

                    # Confidence
                    pdf.set_font('Helvetica', '', 8)
                    pdf.set_text_color(60, 60, 70)
                    pdf.cell(30, 6, safe_text(conf.title()), border=0, fill=True, align='C')

                    # Status badge
                    if ver and ver != 'detected':
                        pdf.set_fill_color(22, 163, 74)
                        pdf.set_text_color(255, 255, 255)
                        pdf.set_font('Helvetica', 'B', 7)
                        pdf.cell(46, 6, 'DETECTED', border=0, fill=True, align='C')
                    else:
                        pdf.set_fill_color(200, 200, 210)
                        pdf.set_text_color(60, 60, 70)
                        pdf.set_font('Helvetica', '', 7)
                        pdf.cell(46, 6, 'PATTERN MATCH', border=0, fill=True, align='C')

                    pdf.ln()
                    row_idx += 1

            pdf.ln(5)

            # Vulnerabilities in technologies
            vulns = tech_data.get('vulnerabilities', [])
            if vulns:
                if pdf.get_y() > 220:
                    pdf.add_page()

                pdf.ln(3)
                pdf.set_x(14)
                pdf.set_text_color(227, 30, 36)
                pdf.set_font('Helvetica', 'B', 10)
                pdf.cell(0, 6, 'VULNERABLE TECHNOLOGIES', new_x='LMARGIN', new_y='NEXT')
                pdf.ln(2)

                # Vulnerability table header
                pdf.set_font('Helvetica', 'B', 8)
                pdf.set_fill_color(227, 30, 36)
                pdf.set_text_color(255, 255, 255)
                pdf.set_x(14)
                pdf.cell(50, 7, 'Technology', border=0, fill=True, align='C')
                pdf.cell(30, 7, 'Version', border=0, fill=True, align='C')
                pdf.cell(30, 7, 'CVE', border=0, fill=True, align='C')
                pdf.cell(76, 7, 'Description', border=0, fill=True, align='C')
                pdf.ln()

                for i, v in enumerate(vulns):
                    if pdf.get_y() > 260:
                        pdf.add_page()

                    # Alternating rows
                    if i % 2 == 0:
                        pdf.set_fill_color(255, 245, 245)
                    else:
                        pdf.set_fill_color(255, 255, 255)

                    pdf.set_font('Helvetica', 'B', 8)
                    pdf.set_text_color(30, 30, 40)
                    pdf.set_x(14)
                    pdf.cell(50, 6, safe_text(v.get('technology', '')), border=0, fill=True)
                    pdf.cell(30, 6, safe_text(v.get('version', '')), border=0, fill=True, align='C')
                    pdf.set_text_color(227, 30, 36)
                    pdf.cell(30, 6, safe_text(v.get('cve', '')), border=0, fill=True, align='C')
                    pdf.set_text_color(60, 60, 70)
                    pdf.set_font('Helvetica', '', 7)
                    pdf.cell(76, 6, safe_text(v.get('description', '')[:70]), border=0, fill=True)
                    pdf.ln()

        # ─── SECTION 8: OPEN PORTS ───
        ports = state_copy.get('port_data', [])
        if ports:
            if pdf.get_y() > 200:
                pdf.add_page()
            else:
                pdf.ln(8)

            # Section header
            pdf.set_fill_color(30, 30, 40)
            pdf.rect(0, pdf.get_y(), 210, 14, 'F')
            pdf.set_text_color(255, 255, 255)
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_y(pdf.get_y() + 3)
            pdf.cell(0, 10, '  6. OPEN PORTS & SERVICES', new_x='LMARGIN', new_y='NEXT')
            pdf.ln(8)

            add_text(f'Total open ports discovered: {len(ports)}', 9)
            pdf.ln(2)

            # Table header with consistent styling
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(30, 30, 40)
            pdf.set_text_color(255, 255, 255)
            pdf.set_x(14)
            pdf.cell(25, 7, 'Port', border=0, fill=True, align='C')
            pdf.cell(35, 7, 'Service', border=0, fill=True, align='C')
            pdf.cell(40, 7, 'IP Address', border=0, fill=True, align='C')
            pdf.cell(87, 7, 'Banner / Version', border=0, fill=True, align='C')
            pdf.ln()

            high_risk_ports = [21, 23, 445, 3306, 3389, 6379, 27017]

            for i, p in enumerate(ports[:30]):
                if pdf.get_y() > 270:
                    pdf.add_page()
                    # Repeat header on new page
                    pdf.set_font('Helvetica', 'B', 8)
                    pdf.set_fill_color(30, 30, 40)
                    pdf.set_text_color(255, 255, 255)
                    pdf.set_x(14)
                    pdf.cell(25, 7, 'Port', border=0, fill=True, align='C')
                    pdf.cell(35, 7, 'Service', border=0, fill=True, align='C')
                    pdf.cell(40, 7, 'IP Address', border=0, fill=True, align='C')
                    pdf.cell(87, 7, 'Banner / Version', border=0, fill=True, align='C')
                    pdf.ln()

                is_high = p.get('port') in high_risk_ports

                # Alternating row background
                if i % 2 == 0:
                    pdf.set_fill_color(248, 248, 250)
                else:
                    pdf.set_fill_color(255, 255, 255)

                pdf.set_x(14)
                if is_high:
                    pdf.set_text_color(200, 30, 30)
                    pdf.set_font('Helvetica', 'B', 8)
                else:
                    pdf.set_text_color(30, 30, 40)
                    pdf.set_font('Helvetica', '', 8)

                pdf.cell(25, 6, safe_text(str(p.get('port', ''))), border=0, fill=True, align='C')
                pdf.cell(35, 6, safe_text((p.get('service','') or '')[:20]), border=0, fill=True, align='C')
                pdf.cell(40, 6, safe_text((p.get('ip','') or '')[:20]), border=0, fill=True, align='C')

                # Banner with risk indicator
                banner = safe_text((p.get('banner','') or '')[:50])
                if is_high:
                    pdf.set_fill_color(255, 235, 235)
                    pdf.cell(87, 6, f'HIGH RISK - {banner}', border=0, fill=True)
                else:
                    pdf.cell(87, 6, banner, border=0, fill=True)
                pdf.ln()

            pdf.ln(5)

        # ─── SECTION 9: RECOMMENDATIONS ───
        section_header('RECOMMENDATIONS SUMMARY', 9)
        add_text('Based on the assessment findings, the following prioritized actions are recommended:', 9)
        pdf.ln(3)

        # Recommendations with clean card-style layout
        def add_recommendation_block(title, color, items, timeframe):
            if pdf.get_y() > 240:
                pdf.add_page()
            # Header with color accent
            pdf.set_fill_color(*color)
            pdf.rect(14, pdf.get_y(), 4, 22, 'F')
            pdf.set_xy(22, pdf.get_y() + 2)
            pdf.set_text_color(30, 30, 40)
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 6, safe_text(title), new_x='LMARGIN', new_y='NEXT')
            pdf.set_x(22)
            pdf.set_text_color(100, 100, 110)
            pdf.set_font('Helvetica', '', 8)
            pdf.cell(0, 5, safe_text(timeframe), new_x='LMARGIN', new_y='NEXT')
            pdf.set_x(22)
            pdf.set_text_color(60, 60, 70)
            pdf.set_font('Helvetica', '', 9)
            for item in items:
                pdf.set_x(22)
                pdf.cell(5, 5, '-', new_x='RIGHT')
                pdf.cell(170, 5, safe_text(item), new_x='LMARGIN', new_y='NEXT')
            pdf.ln(4)

        if critical_cnt > 0:
            add_recommendation_block(
                'IMMEDIATE ACTIONS',
                (227, 30, 36),
                [
                    f'Remediate all {critical_cnt} critical vulnerabilities immediately',
                    'Isolate affected systems if exploitation is active',
                    'Enable enhanced monitoring and logging',
                    'Notify incident response team'
                ],
                'Timeframe: Within 24 hours'
            )

        if high_cnt > 0:
            add_recommendation_block(
                'SHORT TERM ACTIONS',
                (234, 88, 12),
                [
                    f'Address all {high_cnt} high-severity vulnerabilities',
                    'Implement WAF rules for injection-type vulnerabilities',
                    'Review and harden security configurations',
                    'Conduct targeted code review for affected components'
                ],
                'Timeframe: Within 1 week'
            )

        add_recommendation_block(
            'MEDIUM TERM ACTIONS',
            (202, 138, 4),
            [
                'Implement all missing security headers',
                'Review and update SSL/TLS configurations',
                'Address medium and low severity findings',
                'Conduct developer security training'
            ],
            'Timeframe: Within 30 days'
        )

        add_recommendation_block(
            'ONGOING SECURITY PRACTICES',
            (22, 163, 74),
            [
                'Establish regular vulnerability scanning schedule',
                'Implement security monitoring and alerting',
                'Develop and test incident response procedures',
                'Conduct periodic penetration testing'
            ],
            'Timeframe: Continuous'
        )

        # ─── APPENDIX: OPERATOR TIMELINE ───
        if SQLITE_AVAILABLE:
            try:
                with sqlite3_mod.connect(DB_PATH) as conn:
                    conn.row_factory = sqlite3_mod.Row
                    op_rows = conn.execute(
                        'SELECT ts, operator, action_type, target, detail FROM operator_log ORDER BY id DESC LIMIT 100'
                    ).fetchall()
                if op_rows:
                    section_header('APPENDIX: OPERATOR TIMELINE', 10)
                    add_text('Every action during this assessment is logged for accountability and debrief.', 9)
                    pdf.ln(3)
                    op_col_w = [35, 22, 28, 45, 60]
                    op_headers = ['Timestamp', 'Operator', 'Action', 'Target', 'Detail']
                    pdf.set_font('Helvetica', 'B', 7)
                    pdf.set_fill_color(30, 30, 40)
                    pdf.set_text_color(255, 255, 255)
                    for i, h in enumerate(op_headers):
                        pdf.cell(op_col_w[i], 7, h, border=0, align='C', fill=True)
                    pdf.ln()
                    pdf.set_font('Helvetica', '', 6)
                    for ri, row in enumerate(op_rows):
                        if ri % 2 == 0:
                            pdf.set_fill_color(248, 248, 250)
                        else:
                            pdf.set_fill_color(255, 255, 255)
                        pdf.set_text_color(24, 24, 27)
                        pdf.cell(op_col_w[0], 5, safe_text(str(row['ts'] or '')[:19]), border=0, fill=True)
                        pdf.cell(op_col_w[1], 5, safe_text(str(row['operator'] or '')[:10]), border=0, align='C', fill=True)
                        pdf.cell(op_col_w[2], 5, safe_text(str(row['action_type'] or '')[:14]), border=0, align='C', fill=True)
                        pdf.cell(op_col_w[3], 5, safe_text(str(row['target'] or '')[:25]), border=0, fill=True)
                        pdf.cell(op_col_w[4], 5, safe_text(str(row['detail'] or '')[:40]), border=0, fill=True)
                        pdf.ln()
            except Exception:
                pass

        # ─── FOOTER ───
        pdf.set_text_color(160, 160, 160)
        pdf.set_font('Helvetica', '', 7)
        pdf.ln(10)
        pdf.cell(0, 10, f'Security Assessment Report | {datetime.now().strftime("%Y-%m-%d %H:%M")} | CONFIDENTIAL', new_x='LMARGIN', new_y='NEXT', align='C')

        filename = f'infosec_report_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        pdf_bytes = bytes(pdf.output())
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'PDF generation failed: {str(e)}'}), 500



@reports_bp.route('/markdown', methods=['POST'])
@login_required
def export_markdown():
    target = scan_state['target'] or 'unknown.com'
    with LOCK:
        findings = scan_state['findings'][:]
        stats = dict(scan_state['stats'])
        score = scan_state['risk_score']
    # Sort by severity (Critical -> Info)
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings = sorted(
        findings,
        key=lambda f: (sev_order.get((f.get('sev') or 'info').lower(), 4), -float(f.get('cvss') or 0) if str(f.get('cvss','')).replace('.','').isdigit() else 0)
    )
    lines = []
    lines.append(f'# INFOSEC Recon Report — {target}')
    lines.append(f'**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    lines.append(f'**Risk Score:** {score}/100')
    lines.append(f'**Total Findings:** {len(findings)}')
    lines.append('')
    lines.append('## Summary')
    lines.append(f'| Critical | High | Medium | Low | Info |')
    lines.append(f'|----------|------|--------|-----|------|')
    lines.append(f'| {stats.get("critical",0)} | {stats.get("high",0)} | {stats.get("medium",0)} | {stats.get("low",0)} | {stats.get("info",0)} |')
    lines.append('')
    if findings:
        lines.append('## Findings')
        lines.append('| Severity | Title | Asset | CVE | CVSS |')
        lines.append('|----------|-------|-------|-----|------|')
        for f in findings:
            lines.append(f'| {f.get("sev","").upper()} | {f.get("title","")} | {f.get("asset","")} | {f.get("cve","")} | {f.get("cvss","")} |')
    lines.append('')
    lines.append('---')
    lines.append(f'*Generated by Security Assessment Platform*')
    resp = Response('\n'.join(lines), mimetype='text/markdown')
    resp.headers['Content-Disposition'] = f'attachment; filename=infosec_report_{target}.md'
    return resp


