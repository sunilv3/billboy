"""
Cross-Layer Enterprise Risk Correlation Engine v1.0
Correlates signals across WEB, NETWORK, VM, CLOUD layers.
HIGH risk only when 3+ layers corroborate with coherent attack chain.
"""
import re
import json
import time
from core.logger import log
from scanner.state import scan_state, LOCK


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL DETECTION PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

WEB_SIGNALS = {
    'sql_injection': {
        'patterns': [
            r'union\s+select', r'or\s+1\s*=\s*1', r'--\s*$',
            r"'\s*or\s*'", r'sleep\s*\(\s*\d', r'benchmark\s*\(',
            r'information_schema', r'load_file\s*\(', r'into\s+outfile',
            r'sqli', r'sql\s*inject', r'dbms_lock', r'waitfor\s+delay',
        ],
        'severity': 'high',
        'mitre': ['T1190', 'T1059'],
        'stage': 'INITIAL_ACCESS',
    },
    'xss': {
        'patterns': [
            r'<script', r'javascript:', r'onerror\s*=',
            r'onload\s*=', r'eval\s*\(', r'document\.cookie',
            r'alert\s*\(', r'xss', r'反射型',
        ],
        'severity': 'medium',
        'mitre': ['T1189'],
        'stage': 'INITIAL_ACCESS',
    },
    'path_traversal': {
        'patterns': [
            r'\.\./\.\.', r'\.\.\\', r'/etc/passwd', r'/etc/shadow',
            r'/proc/self', r'c:\\windows', r'win\.ini',
            r'lfi', r'path.*travers', r'file.*inclusion',
        ],
        'severity': 'high',
        'mitre': ['T1083'],
        'stage': 'INITIAL_ACCESS',
    },
    'command_injection': {
        'patterns': [
            r';\s*whoami', r'\|\s*id\b', r'`id`', r'\$\{.*\}',
            r'cmd\.exe', r'/bin/sh', r'/bin/bash',
            r'exec\s*\(', r'system\s*\(', r'passthru',
            r'cmdi', r'command.*inject',
        ],
        'severity': 'critical',
        'mitre': ['T1059'],
        'stage': 'EXECUTION',
    },
    'waf_block': {
        'patterns': [
            r'waf.*block', r'403.*waf', r'blocked.*pattern',
            r'firewall.*block', r'rate.*limit', r'429',
            r'access.*denied.*waf',
        ],
        'severity': 'info',
        'mitre': [],
        'stage': 'UNKNOWN',
    },
    'auth_brute': {
        'patterns': [
            r'failed.*login', r'invalid.*credential',
            r'401.*x\d+', r'brute.*force', r'password.*spray',
            r'auth.*fail.*\d{3,}', r'multiple.*401',
        ],
        'severity': 'medium',
        'mitre': ['T1110'],
        'stage': 'INITIAL_ACCESS',
    },
    'sensitive_file_access': {
        'patterns': [
            r'\.env', r'\.git', r'\.htpasswd', r'wp-config',
            r'web\.config', r'config\.json', r'config\.php',
            r'database.*dump', r'backup\.sql',
        ],
        'severity': 'medium',
        'mitre': ['T1083', 'T1005'],
        'stage': 'RECON',
    },
    'lateral_movement_web': {
        'patterns': [
            r'admin.*panel', r'phpmyadmin', r'adminer',
            r'console', r'shell', r'webshell',
            r'upload.*file', r'file.*upload',
        ],
        'severity': 'medium',
        'mitre': ['T1078'],
        'stage': 'LATERAL_MOVEMENT',
    },
}

NETWORK_SIGNALS = {
    'port_scan': {
        'patterns': [
            r'syn\s+scan', r'port\s+scan', r'nmap',
            r'\d+\s+open\s+ports', r'scanning\s+.*\/\d+',
            r'connect.*scan', r'stealth.*scan',
            r'tcp\s+syn.*\d+\.\d+\.\d+\.\d+',
        ],
        'severity': 'medium',
        'mitre': ['T1046'],
        'stage': 'RECON',
    },
    'lateral_movement': {
        'patterns': [
            r'smb\s+session', r'rpc.*call', r'winrm',
            r'ps\s+remoting', r'ssh.*brute', r'rdp.*brute',
            r'lateral', r'pass.*the.*hash', r'PTH',
            r'445.*open', r'5985.*open', r'3389.*open',
        ],
        'severity': 'high',
        'mitre': ['T1021'],
        'stage': 'LATERAL_MOVEMENT',
    },
    'c2_beacon': {
        'patterns': [
            r'beacon', r'c2\s+server', r'callback',
            r'jitter', r'periodic.*connect', r'4444',
            r'8443.*unusual', r' dns.*tunnel', r'icmp.*tunnel',
            r'outbound.*suspicious', r'encrypted.*c2',
        ],
        'severity': 'critical',
        'mitre': ['T1071', 'T1573'],
        'stage': 'EXFILTRATION',
    },
    'data_exfil': {
        'patterns': [
            r'exfil', r'data.*transfer', r'large.*upload',
            r'outbound.*data', r'dns.*exfil', r'ico.*exfil',
            r'unusual.*volume', r'traffic.*spike',
        ],
        'severity': 'critical',
        'mitre': ['T1041', 'T1048'],
        'stage': 'EXFILTRATION',
    },
    'arp_spoof': {
        'patterns': [
            r'arp.*spoof', r'arp.*poison', r'arp.*attack',
            r'duplicate.*ip', r'mac.*change', r'arp.*table.*anomal',
        ],
        'severity': 'high',
        'mitre': ['T1557'],
        'stage': 'INITIAL_ACCESS',
    },
    'dns_anomaly': {
        'patterns': [
            r'dns.*tunnel', r'dns.*exfil', r'long.*subdomain',
            r'doh.*suspicious', r'dns.*query.*high.*volume',
            r'dga', r'algorithmic.*domain',
        ],
        'severity': 'medium',
        'mitre': ['T1071.004', 'T1568'],
        'stage': 'EXFILTRATION',
    },
}

VM_SIGNALS = {
    'privesc': {
        'patterns': [
            r'privilege\s+escalat', r'privesc', r'sudo\s+su',
            r'whoami\s+/priv', r'SeImpersonate', r'SeDebugPrivilege',
            r'SeAssignPrimaryToken', r'potato.*attack',
            r'exploit.*privesc', r'jwt.*impersonat',
            r'net\s+user.*\/add', r'net\s+localgroup.*admins',
        ],
        'severity': 'critical',
        'mitre': ['T1068', 'T1134'],
        'stage': 'PRIVILEGE_ESCALATION',
    },
    'webshell_process': {
        'patterns': [
            r'cmd\.exe.*w3wp', r'powershell.*w3wp',
            r'cmd\.exe.*apache', r'cmd\.exe.*nginx',
            r'cmd\.exe.*tomcat', r'shell.*java',
            r'w3wp.*cmd\.exe', r'iis.*shell',
            r'process.*spawn.*web.*server',
        ],
        'severity': 'critical',
        'mitre': ['T1505.003'],
        'stage': 'EXECUTION',
    },
    'persistence': {
        'patterns': [
            r'scheduled\s+task', r'crontab.*new',
            r'service.*install', r'registry.*run.*key',
            r'startup.*folder', r'wmi.*event.*subscription',
            r'schtasks.*create', r'reg\s+add.*run',
        ],
        'severity': 'high',
        'mitre': ['T1053', 'T1543'],
        'stage': 'PERSISTENCE',
    },
    'memory_anomaly': {
        'patterns': [
            r'memory.*inject', r'process\s+hollow',
            r'code\s+inject', r'dll.*inject', r'apc.*queue',
            r'process.*doppelgang', r'reflective.*dll',
            r'mimikatz', r'lsass.*access', r'credential.*dump',
        ],
        'severity': 'critical',
        'mitre': ['T1055', 'T1003'],
        'stage': 'EXECUTION',
    },
    'file_system': {
        'patterns': [
            r'system.*file.*chang', r'\\windows\\system32',
            r'/usr/bin.*modify', r'/etc/passwd.*write',
            r'hosts.*file.*modif', r'dns.*config.*chang',
        ],
        'severity': 'high',
        'mitre': ['T1098'],
        'stage': 'PERSISTENCE',
    },
    'recon_process': {
        'patterns': [
            r'whoami', r'ipconfig', r'ifconfig',
            r'net\s+user', r'net\s+group',
            r'systeminfo', r'uname\s+-a',
            r'hostname', r'netstat', r'ps\s+aux',
            r'tasklist', r'ls\s+/etc',
        ],
        'severity': 'low',
        'mitre': ['T1082', 'T1016'],
        'stage': 'RECON',
    },
}

CLOUD_SIGNALS = {
    'iam_abuse': {
        'patterns': [
            r'iam.*CreatePolicy', r'iam.*AttachPolicy',
            r'iam.*CreateUser', r'iam.*CreateAccessKey',
            r'iam.*CreateLoginProfile', r'iam.*UpdateRole',
            r'iam:*\*', r'policy.*Version.*\*',
            r'assume.*role.*unusual', r'iam.*escaltion',
        ],
        'severity': 'critical',
        'mitre': ['T1098'],
        'stage': 'PRIVILEGE_ESCALATION',
    },
    'data_access': {
        'patterns': [
            r'S3.*GetObject', r'S3.*ListBucket',
            r'blob.*download', r'gcs.*get',
            r'data.*bucket.*access', r'sensitive.*bucket',
            r'billing.*data', r'customer.*data',
            r'download.*backup', r'export.*data',
        ],
        'severity': 'high',
        'mitre': ['T1530'],
        'stage': 'EXFILTRATION',
    },
    'resource_creation': {
        'patterns': [
            r'ec2.*RunInstances', r'CreateFunction',
            r'CreateCluster', r'CreatePipeline',
            r'unusual.*region', r'new.*region.*deploy',
            r'resource.*unusual.*location',
        ],
        'severity': 'medium',
        'mitre': ['T1078'],
        'stage': 'PERSISTENCE',
    },
    'credential_leak': {
        'patterns': [
            r'access.*key.*expos', r'secret.*key.*leak',
            r'credential.*dump', r'api.*key.*compromis',
            r'access.*key.*log', r'credentials?.*cloud.*metadata',
        ],
        'severity': 'high',
        'mitre': ['T1552'],
        'stage': 'INITIAL_ACCESS',
    },
    'audit_gap': {
        'patterns': [
            r'cloudtrail.*stop', r'logging.*disable',
            r'audit.*log.*delet', r'guardduty.*disable',
            r'security.*hub.*disable', r'config.*service.*stop',
        ],
        'severity': 'high',
        'mitre': ['T1562'],
        'stage': 'PERSISTENCE',
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_CHAINS = {
    'web_exploit_to_rce': {
        'layers': ['WEB', 'VM'],
        'signals': {'WEB': ['sql_injection', 'command_injection', 'path_traversal'],
                    'VM': ['webshell_process', 'privesc']},
        'name': 'Web Exploit → Remote Code Execution',
    },
    'web_recon_to_lateral': {
        'layers': ['WEB', 'NETWORK'],
        'signals': {'WEB': ['sensitive_file_access', 'lateral_movement_web'],
                    'NETWORK': ['lateral_movement', 'port_scan']},
        'name': 'Web Reconnaissance → Lateral Movement',
    },
    'full_kill_chain': {
        'layers': ['WEB', 'NETWORK', 'VM'],
        'signals': {'WEB': ['sql_injection', 'command_injection', 'path_traversal', 'sensitive_file_access'],
                    'NETWORK': ['lateral_movement', 'port_scan', 'c2_beacon'],
                    'VM': ['webshell_process', 'privesc', 'persistence', 'memory_anomaly']},
        'name': 'Full Kill Chain: Exploit → Execute → Persist → Exfil',
    },
    'cloud_account_takeover': {
        'layers': ['WEB', 'CLOUD'],
        'signals': {'WEB': ['auth_brute', 'sensitive_file_access'],
                    'CLOUD': ['iam_abuse', 'credential_leak', 'data_access']},
        'name': 'Cloud Account Takeover → Data Exfiltration',
    },
    'lateral_to_cloud': {
        'layers': ['NETWORK', 'VM', 'CLOUD'],
        'signals': {'NETWORK': ['lateral_movement'],
                    'VM': ['privesc', 'recon_process'],
                    'CLOUD': ['iam_abuse', 'data_access']},
        'name': 'Lateral Movement → Cloud Data Exfiltration',
    },
    'apt_killchain': {
        'layers': ['WEB', 'NETWORK', 'VM', 'CLOUD'],
        'signals': {'WEB': ['sql_injection', 'xss', 'path_traversal', 'command_injection', 'sensitive_file_access'],
                    'NETWORK': ['port_scan', 'lateral_movement', 'c2_beacon', 'data_exfil'],
                    'VM': ['privesc', 'webshell_process', 'persistence', 'memory_anomaly'],
                    'CLOUD': ['iam_abuse', 'data_access', 'resource_creation', 'audit_gap']},
        'name': 'APT Full-Spectrum Attack',
    },
}


def _extract_signals(text, signal_db):
    """Extract matching signals from text against a signal database."""
    if not text or not text.strip():
        return []

    text_lower = text.lower()
    found = []

    for signal_name, signal_def in signal_db.items():
        for pattern in signal_def['patterns']:
            if re.search(pattern, text_lower):
                found.append({
                    'signal': signal_name,
                    'severity': signal_def['severity'],
                    'mitre': signal_def['mitre'],
                    'stage': signal_def['stage'],
                    'pattern_matched': pattern,
                })
                break  # One match per signal type is enough

    return found


def _identify_attack_chain(layer_signals):
    """Identify which attack chain best matches the observed signals."""
    best_match = None
    best_score = 0

    active_layers = [layer for layer, signals in layer_signals.items() if signals]

    for chain_name, chain_def in ATTACK_CHAINS.items():
        chain_layers = chain_def['layers']

        # Check if we have signals in the required layers
        matching_layers = 0
        for layer in chain_layers:
            if layer in active_layers:
                # Check if we have matching signal types
                required_signals = chain_def['signals'].get(layer, [])
                layer_signal_names = {s['signal'] for s in layer_signals.get(layer, [])}
                if any(rs in layer_signal_names for rs in required_signals):
                    matching_layers += 1

        # Score based on layer coverage
        score = matching_layers / len(chain_layers) if chain_layers else 0

        if score > best_score:
            best_score = score
            best_match = chain_name

    return best_match, best_score


def correlate_telemetry(web_telemetry, network_telemetry, vm_telemetry, cloud_telemetry):
    """
    Main correlation function. Analyzes telemetry from 4 layers and returns
    structured risk assessment.
    """
    start_time = time.time()

    # Extract signals from each layer
    web_signals = _extract_signals(web_telemetry, WEB_SIGNALS)
    network_signals = _extract_signals(network_telemetry, NETWORK_SIGNALS)
    vm_signals = _extract_signals(vm_telemetry, VM_SIGNALS)
    cloud_signals = _extract_signals(cloud_telemetry, CLOUD_SIGNALS)

    layer_signals = {
        'WEB': web_signals,
        'NETWORK': network_signals,
        'VM': vm_signals,
        'CLOUD': cloud_signals,
    }

    # Count layers with signals
    active_layers = [layer for layer, signals in layer_signals.items() if signals]
    layer_count = len(active_layers)

    # Collect all corroborating signals
    all_signals = []
    for layer, signals in layer_signals.items():
        for sig in signals:
            all_signals.append(f"[{layer}] {sig['signal']} (severity: {sig['severity']})")

    # Collect all MITRE techniques
    all_mitre = set()
    for layer_signals_list in layer_signals.values():
        for sig in layer_signals_list:
            all_mitre.update(sig['mitre'])

    # Identify attack stage (use highest severity stage)
    stage_priority = {
        'EXFILTRATION': 7,
        'IMPACT': 7,
        'PRIVILEGE_ESCALATION': 6,
        'LATERAL_MOVEMENT': 5,
        'PERSISTENCE': 4,
        'EXECUTION': 3,
        'INITIAL_ACCESS': 2,
        'RECON': 1,
        'UNKNOWN': 0,
    }
    max_stage = 'UNKNOWN'
    for layer_signals_list in layer_signals.values():
        for sig in layer_signals_list:
            if stage_priority.get(sig['stage'], 0) > stage_priority.get(max_stage, 0):
                max_stage = sig['stage']

    # Identify best attack chain
    chain_name, chain_score = _identify_attack_chain(layer_signals)

    # Calculate confidence based on signal quality and chain coherence
    base_confidence = 0
    if layer_count >= 3:
        base_confidence = 75
    elif layer_count == 2:
        base_confidence = 55
    elif layer_count == 1:
        base_confidence = 30
    else:
        base_confidence = 5

    # Boost confidence for chain match
    chain_boost = chain_score * 20

    # Boost confidence for critical signals
    critical_count = sum(1 for sig in all_signals if 'critical' in sig)
    severity_boost = min(critical_count * 5, 15)

    confidence = min(100, int(base_confidence + chain_boost + severity_boost))

    # Determine risk level based on rules
    false_positive_likelihood = 'HIGH'

    if layer_count >= 3 and confidence >= 75 and chain_score >= 0.5:
        risk_level = 'HIGH'
        false_positive_likelihood = 'LOW'
    elif layer_count >= 2 and confidence >= 55:
        risk_level = 'MEDIUM'
        false_positive_likelihood = 'MEDIUM'
    elif layer_count >= 1 and confidence >= 35:
        risk_level = 'LOW'
        false_positive_likelihood = 'MEDIUM'
    else:
        risk_level = 'INFO'
        false_positive_likelihood = 'HIGH'

    # Build attack pattern name
    if chain_name and chain_score >= 0.3:
        attack_pattern = ATTACK_CHAINS[chain_name]['name']
    elif all_signals:
        # Use the most severe signal as attack pattern
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        top_signal = max(
            [(sig.split('] ')[1].split(' ')[0], sig) for sig in all_signals],
            key=lambda x: severity_order.get(x[0], 0),
            default=('Unknown', '')
        )
        attack_pattern = top_signal[0].replace('_', ' ').title()
    else:
        attack_pattern = 'No attack pattern detected'

    # Build recommended action
    if risk_level == 'HIGH':
        recommended_action = f'IMMEDIATE: Isolate affected systems and initiate incident response for {attack_pattern}'
        isolation_required = True
    elif risk_level == 'MEDIUM':
        recommended_action = f'Investigate {attack_pattern} activity across {layer_count} layers — escalate if confirmed'
        isolation_required = False
    elif risk_level == 'LOW':
        recommended_action = f'Monitor {attack_pattern} signals — add to watchlist for correlation'
        isolation_required = False
    else:
        recommended_action = 'Log and monitor — insufficient signals for actionable alert'
        isolation_required = False

    # Build analyst notes
    if layer_count == 0:
        analyst_notes = 'No telemetry provided. Cannot assess risk.'
    elif layer_count == 1:
        layer_name = active_layers[0]
        sig_count = len(layer_signals[layer_name])
        analyst_notes = (f'Single-layer signal in {layer_name} with {sig_count} indicator(s). '
                        f'Cannot establish cross-layer corroboration. '
                        f'Risk elevated only if additional layers confirm.')
    elif chain_name and chain_score >= 0.3:
        chain_layers = ATTACK_CHAINS[chain_name]['layers']
        analyst_notes = (f'Cross-layer correlation detected across {", ".join(active_layers)}. '
                        f'Attack chain: {ATTACK_CHAINS[chain_name]["name"]}. '
                        f'{layer_count}/{len(chain_layers)} required layers corroborate.')
    else:
        analyst_notes = (f'{layer_count} layers show activity but signals do not form '
                        f'a coherent attack chain. May be unrelated events.')

    elapsed = time.time() - start_time

    result = {
        'risk_level': risk_level,
        'confidence': confidence,
        'attack_pattern': attack_pattern,
        'attack_stage': max_stage,
        'corroborating_signals': all_signals,
        'layers_involved': active_layers,
        'mitre_techniques': sorted(all_mitre),
        'recommended_action': recommended_action,
        'isolation_required': isolation_required,
        'false_positive_likelihood': false_positive_likelihood,
        'analyst_notes': analyst_notes,
        'meta': {
            'chain_detected': chain_name is not None and chain_score >= 0.3,
            'chain_name': chain_name,
            'chain_score': round(chain_score, 2),
            'signal_counts': {layer: len(sigs) for layer, sigs in layer_signals.items()},
            'elapsed_ms': round(elapsed * 1000, 1),
            'timestamp': time.time(),
        },
    }

    log('ok', f'[RISK-ENGINE] Classification: {risk_level} '
             f'(confidence: {confidence}, layers: {layer_count}, '
             f'chain: {chain_name or "none"}, '
             f'signals: {len(all_signals)})')

    return result
