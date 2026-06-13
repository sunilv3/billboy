"""Full Report Generation — per-finding JSON format, per-chain narrative, CVSS vectors.

Generates reports in the exact format specified by the discovery engine spec.
"""
import time
import json
from datetime import datetime, timezone
from core.logger import log
from scanner.state import scan_state, LOCK

# ── CVSS 3.1 vector builder ────────────────────────────────────────────────────

CVSS_SEVERITY_MAP = {
    'critical': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H'},
    'high':     {'av': 'N', 'ac': 'L', 'pr': 'L', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'N'},
    'medium':   {'av': 'N', 'ac': 'L', 'pr': 'L', 'ui': 'R', 's': 'U', 'c': 'N', 'i': 'N', 'a': 'N'},
    'low':      {'av': 'N', 'ac': 'H', 'pr': 'L', 'ui': 'R', 's': 'U', 'c': 'N', 'i': 'N', 'a': 'L'},
    'info':     {'av': 'N', 'ac': 'H', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'N', 'i': 'N', 'a': 'N'},
}

def _build_cvss_vector(severity, finding_type=''):
    """Build CVSS 3.1 vector string from severity and vulnerability type."""
    base = CVSS_SEVERITY_MAP.get(severity, CVSS_SEVERITY_MAP['info'])
    overrides = {}
    ft = finding_type.lower()
    if 'sqli' in ft or 'sql injection' in ft:
        overrides = {'c': 'H', 'i': 'H', 'a': 'N', 'pr': 'N'}
    elif 'xss' in ft or 'cross-site scripting' in ft:
        overrides = {'c': 'L', 'i': 'L', 'a': 'N'}
    elif 'rce' in ft or 'command injection' in ft or 'cmdi' in ft:
        overrides = {'c': 'H', 'i': 'H', 'a': 'H', 'pr': 'N'}
    elif 'ssrf' in ft:
        overrides = {'c': 'H', 'i': 'L', 'a': 'N'}
    elif 'xxe' in ft:
        overrides = {'c': 'H', 'i': 'L', 'a': 'N'}
    elif 'idor' in ft or 'broken access' in ft:
        overrides = {'c': 'L', 'i': 'H', 'a': 'N', 'pr': 'L'}
    elif 'auth bypass' in ft:
        overrides = {'c': 'H', 'i': 'H', 'a': 'N', 'pr': 'N'}
    elif 'file read' in ft or 'lfi' in ft:
        overrides = {'c': 'H', 'i': 'N', 'a': 'N'}
    elif 'path traversal' in ft:
        overrides = {'c': 'H', 'i': 'N', 'a': 'N'}
    params = {**base, **overrides}
    vector = f'CVSS:3.1/AV:{params["av"]}/AC:{params["ac"]}/PR:{params["pr"]}/UI:{params["ui"]}/S:{params["s"]}/C:{params["c"]}/I:{params["i"]}/A:{params["a"]}'
    return vector

def _cvss_score_from_severity(severity):
    return {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5, 'info': 0.0}.get(severity, 0.0)

# ── Finding ID generator ───────────────────────────────────────────────────────

_finding_counter = 0
def _next_finding_id():
    global _finding_counter
    _finding_counter += 1
    return f'FND-{datetime.now().strftime("%Y")}-{_finding_counter:05d}'

# ── Report generation ──────────────────────────────────────────────────────────

def generate_finding_report(finding):
    """Generate a single finding report in the exact JSON format specified."""
    sev = finding.get('sev', 'info')
    title = finding.get('title', '')
    ft = finding.get('sub', '') or title
    cvss_vector = _build_cvss_vector(sev, ft)
    cvss_score = _cvss_score_from_severity(sev)
    finding_id = finding.get('id', _next_finding_id())
    return {
        'finding_id': finding_id,
        'classification': 'CONFIRMED' if finding.get('verified') else 'POTENTIAL',
        'novelty': 'KNOWN_PATTERN' if finding.get('cve') else 'CANDIDATE_NOVEL',
        'known_reference': finding.get('cve', ''),
        'type': _classify_vuln_type(title),
        'subtype': _classify_subtype(finding),
        'endpoint': finding.get('asset', ''),
        'parameter': _extract_param(finding),
        'severity': sev.upper(),
        'cvss_vector': cvss_vector,
        'cvss_score': cvss_score,
        'description': title,
        'reproduction': {
            'command': finding.get('poc_link', ''),
            'steps': finding.get('exploitation_steps', [])[:5],
        },
        'evidence': {
            'raw_request': finding.get('raw_request', ''),
            'raw_response': (finding.get('raw_response', '') or finding.get('details', ''))[:2000],
            'oob_callback': finding.get('oob_callback'),
            'minimized_poc': finding.get('minimized_poc', ''),
        },
        'confidence': finding.get('confidence_score', 55),
        'reproducible_count': finding.get('reproducible_count', 1),
        'remediation': _generate_remediation(sev, _classify_vuln_type(title), title),
    }

def _classify_vuln_type(title):
    t = title.lower()
    if 'sqli' in t or 'sql injection' in t: return 'sqli'
    if 'xss' in t or 'cross-site scripting' in t: return 'xss'
    if 'ssrf' in t: return 'ssrf'
    if 'command injection' in t or 'cmdi' in t: return 'command_injection'
    if 'xxe' in t or 'xml external' in t: return 'xxe'
    if 'ssti' in t or 'template injection' in t: return 'ssti'
    if 'csrf' in t: return 'csrf'
    if 'idor' in t: return 'idor'
    if 'auth bypass' in t or 'authentication bypass' in t: return 'auth_bypass'
    if 'path traversal' in t or 'lfi' in t or 'file inclusion' in t: return 'path_traversal'
    if 'open redirect' in t: return 'open_redirect'
    if 'race condition' in t: return 'race_condition'
    if 'deserialization' in t: return 'deserialization'
    if 'prototype pollution' in t: return 'prototype_pollution'
    if 'header injection' in t or 'host header' in t: return 'header_injection'
    if 'smuggling' in t: return 'request_smuggling'
    if 'cache poisoning' in t: return 'cache_poisoning'
    if 'clickjacking' in t: return 'clickjacking'
    if 'cors' in t: return 'cors_misconfiguration'
    if 'secret' in t or 'credential' in t or 'leak' in t: return 'secret_exposure'
    if 'info' in t or 'disclosure' in t: return 'info_disclosure'
    return 'other'

def _classify_subtype(finding):
    details = (finding.get('details', '') + ' ' + finding.get('validation_evidence', '')).lower()
    if 'oob' in details or 'callback' in details or 'interactsh' in details: return 'blind_oob'
    if 'error' in details and ('sql' in details or 'syntax' in details): return 'error_based'
    if 'time' in details or 'sleep' in details or 'delay' in details: return 'time_based'
    if 'reflected' in details or finding.get('sev') == 'high': return 'reflected'
    return 'unknown'

def _extract_param(finding):
    details = finding.get('details', '')
    for line in details.split('\n'):
        if 'parameter:' in line.lower():
            return line.split(':', 1)[1].strip()
    return ''

def _generate_remediation(severity, vuln_type, title):
    remediations = {
        'sqli': 'Use parameterized queries/prepared statements. Never concatenate user input into SQL. Implement input validation and WAF rules.',
        'xss': 'Context-output encode all user data. Implement Content-Security-Policy. Use HTTPOnly cookies.',
        'ssrf': 'Validate and allowlist URLs. Block internal/private IP ranges. Use network segmentation.',
        'command_injection': 'Never pass user input to system commands. Use language-native APIs instead of shell commands. Implement input validation.',
        'xxe': 'Disable DTD processing in XML parsers. Use JSON instead of XML where possible.',
        'ssti': 'Avoid rendering user input in templates. Use sandboxed template engines. Allowlist template functions.',
        'auth_bypass': 'Implement proper authentication checks on every endpoint. Use proven auth frameworks.',
        'path_traversal': 'Validate and sanitize file paths. Use chroot/jails. Implement allowlist-based file access.',
        'idor': 'Implement authorization checks for every resource access. Use indirect references (UUIDs).',
        'race_condition': 'Implement proper locking/transactions. Use idempotency keys for state-changing operations.',
        'deserialization': 'Never deserialize untrusted data. Use safe serialization formats (JSON). Implement integrity checks.',
        'info_disclosure': 'Remove debug information from production. Implement custom error pages.',
        'secret_exposure': 'Rotate exposed credentials immediately. Use secret management (Vault, AWS Secrets Manager). Scan code for secrets.',
        'open_redirect': 'Validate redirect targets against an allowlist. Never redirect to user-controlled URLs.',
    }
    base = remediations.get(vuln_type, 'Review and fix the identified security issue according to OWASP guidelines.')
    if severity == 'critical':
        return f'CRITICAL: {base} This must be remediated immediately.'
    return base

# ── Full report builder ────────────────────────────────────────────────────────

def generate_full_report():
    """Generate complete scan report with findings + chains."""
    with LOCK:
        findings = list(scan_state.get('findings', []))
        chains = list(scan_state.get('attack_chains', []))
        target = scan_state.get('target', '')
        stats = dict(scan_state.get('stats', {}))
        score = scan_state.get('risk_score', 0)
    finding_reports = [generate_finding_report(f) for f in findings]
    chain_reports = []
    for chain in chains:
        chain_reports.append({
            'chain_id': chain.get('chain_id', ''),
            'path': chain.get('path', []),
            'hops': chain.get('hops', 0),
            'combined_cvss': chain.get('combined_cvss', 0),
            'narrative': chain.get('narrative', ''),
            'findings_used': chain.get('findings_used', []),
        })
    report = {
        'report_id': f'RPT-{int(time.time())}',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'target': target,
        'summary': {
            'total_findings': len(findings),
            'critical': stats.get('critical', 0),
            'high': stats.get('high', 0),
            'medium': stats.get('medium', 0),
            'low': stats.get('low', 0),
            'info': stats.get('info', 0),
            'risk_score': score,
            'total_chains': len(chains),
        },
        'findings': finding_reports,
        'chains': chain_reports,
    }
    log('ok', f'[REPORT] Generated: {len(finding_reports)} findings, {len(chain_reports)} chains')
    return report
