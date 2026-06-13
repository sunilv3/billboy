"""JSON, SARIF, CSV, Markdown export functions."""
import json
import csv
import io
import time
from datetime import datetime
from flask import Blueprint, request, jsonify, Response
from core.auth import login_required
from scanner.state import scan_state, LOCK
from core.utils import _safe_str

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/api/export/json', methods=['POST'])
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


@reports_bp.route('/api/export/sarif', methods=['POST'])
@login_required
def export_sarif():
    """Export findings in SARIF 2.1.0 format for GitHub/DevOps integration."""
    with LOCK:
        target = scan_state['target'] or 'unknown'
        findings = list(scan_state['findings'])

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
                    'risk_score': scan_state.get('risk_score', 0),
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


@reports_bp.route('/api/export/csv', methods=['POST'])
@login_required
def export_csv():
    target = scan_state['target'] or 'unknown'
    with LOCK:
        findings = list(scan_state['findings'])  # shallow copy
    lines = ['Severity,Title,Asset,CVE,CVSS,Exploit,Description,Timestamp']
    for f in findings:
        lines.append(f'"{f.get("sev","")}","{f.get("title","")}","{f.get("asset","")}","{f.get("cve","")}","{f.get("cvss","")}","{f.get("exploit","")}","{f.get("sub","")}","{f.get("ts","")}"')
    resp = Response(
        '\n'.join(lines),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=infosec_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )
    return resp


@reports_bp.route('/api/export/markdown', methods=['POST'])
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
        key=lambda f: (sev_order.get((f.get('sev') or 'info').lower(), 4), -float(f.get('cvss') or 0) if str(f.get('cvss', '')).replace('.', '').isdigit() else 0)
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
    lines.append(f'| {stats.get("critical", 0)} | {stats.get("high", 0)} | {stats.get("medium", 0)} | {stats.get("low", 0)} | {stats.get("info", 0)} |')
    lines.append('')
    if findings:
        lines.append('## Findings')
        lines.append('| Severity | Title | Asset | CVE | CVSS |')
        lines.append('|----------|-------|-------|-----|------|')
        for f in findings:
            lines.append(f'| {f.get("sev", "").upper()} | {f.get("title", "")} | {f.get("asset", "")} | {f.get("cve", "")} | {f.get("cvss", "")} |')
    lines.append('')
    lines.append('---')
    lines.append(f'*Generated by Security Assessment Platform*')
    resp = Response('\n'.join(lines), mimetype='text/markdown')
    resp.headers['Content-Disposition'] = f'attachment; filename=infosec_report_{target}.md'
    return resp
