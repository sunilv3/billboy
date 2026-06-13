import threading

LOCK = threading.Lock()

# ──────────────────────────────────────────────────────────────────────────────
# Canonical scan_state schema.
#
# Every key any route/module reads with hard-bracket access (scan_state['x'])
# MUST be initialised here, or that endpoint 500s on a fresh boot before the
# first scan populates it. Grouped by type for clarity.
# ──────────────────────────────────────────────────────────────────────────────

scan_state = {
    # ── Core scan lifecycle ──────────────────────────────────────────────────
    'scanning': False,
    'target': '',
    'scan_type': 'full',
    'scope_id': '',
    'operator': '',
    'scan_start': 0,
    'scan_start_time': None,
    'scan_end_time': None,
    'elapsed': '00:00:00',
    'current_phase': '',
    'current_module': '',

    # ── Findings & scoring ───────────────────────────────────────────────────
    'findings': [],
    'finding_status': {},
    'status_history': [],
    'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
    'risk_score': 0,
    'risk_breakdown': {},

    # ── Progress tracking ────────────────────────────────────────────────────
    'progress': {},
    'logs': [],
    'module_progress': {},
    'modules_run': [],
    'modules_total': 0,
    'modules_done': 0,
    'module_failures': [],
    'type_stats': {
        'web': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
        'code': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
        'network': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
        'vm': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0},
    },

    # ── Discovery / recon (lists) ────────────────────────────────────────────
    'assets': [],
    'dir_data': [],
    'js_endpoints': [],
    'wayback_urls': [],
    'hardening_checks': [],
    'correlation_chains': [],
    'attack_chains': [],
    'container_findings': [],
    'siem_logs': [],
    'schedule_logs': [],
    'batch_targets': [],

    # ── Module result blobs (dicts, assigned wholesale by each module) ───────
    'crawl_data': {},
    'deep_crawl_data': {},
    'discovery_data': {'urls': [], 'forms': [], 'inputs': [], 'api_endpoints': [], 'js_files': [], 'parameters': []},
    'tech_data': {},
    'waf_data': {},
    'waf_fingerprint_data': {},
    'dns_data': {},
    'whois_data': {},
    'emailsec_data': {},
    'enhanced_subdomain_data': {},
    'port_data': {},
    'ssl_data': {},
    'header_data': {},
    'header_adv_data': {},
    'wp_data': {},
    'cloud_data': {},
    'cloud_vm_data': {},
    'k8s_data': {},
    'firewall_data': {},
    'botcheck_data': {},
    'ddos_data': {},
    'apisec_data': {},
    'api_security_data': {},
    'secrets_data': {},
    'darkweb_data': {},
    'github_leak_data': {},
    'gitleaks_data': {},
    'trufflehog_data': {},
    'semgrep_data': {},
    'netsec_data': {},
    'monitoring_data': {},
    'supplychain_data': {},
    'graph_data': {},
    'graphql_data': {},
    'jwt_deep_data': {},
    'lfi_data': {},
    'crlf_data': {},
    'cors_data': {},
    'dalfox_data': {},
    'vulnscan_data': {},
    'nuclei_data': {},
    'osv_data': {},
    'kev_data': {},
    'osint_data': {},
    'oob_data': {},
    'smuggling_data': {},
    'cache_poisoning_data': {},
    'prototype_pollution_data': {},
    'race_condition_deep_data': {},
    'ssrf_deep_data': {},
    'open_redirect_deep_data': {},
    'subdomain_takeover_data': {},
    'takeover_data': {},
    'bizlogic_data': {},
    'auth_bypass_data': {},
    'compliance_data': {},
    'threat_intel': {},
    'threat_model': {},
    'ai_analysis': {},
    'attack_path_report': {},
    'manual_pentest': {},
    'page_type': '',
    'page_type_result': {},

    # ── Proxy ────────────────────────────────────────────────────────────────
    'proxy_har': None,
    'proxy_pid': None,
    'proxy_port': None,

    # ── Routing / options / tooling ──────────────────────────────────────────
    'routing': {'applied': False, 'modules_kept': 0, 'modules_dropped': 0, 'dropped_names': [], 'reason': ''},
    'advanced_options': {},
    'tool_availability': {'available': [], 'missing_required': [], 'missing_optional': []},
    'schedule': {},

    # ── Diff / CI ────────────────────────────────────────────────────────────
    'scan_diff': {},
    'scan_diffs': [],
    'recon_state': {},
    'webhook_api_key': '',

    # ── Discovery Engines ─────────────────────────────────────────────────────
    'engine_mutation': {'findings': [], 'coverage': 0, 'requests': 0},
    'engine_anomaly': {'anomalies': [], 'findings': [], 'requests': 0},
    'engine_logic': {'flows': [], 'findings': [], 'requests': 0},
    'engine_oob': {'findings': [], 'tokens_used': [], 'requests': 0},
    'engine_parser': {'crashes': [], 'timeouts': [], 'findings': [], 'requests': 0},
    'engine_confirmation': {'confirmed': [], 'total': 0},

    # ── Hard Limits & Health ──────────────────────────────────────────────────
    'limits_status': {},
    'health_paused': False,
    'health_error_rate': 0.0,
    'health_status': {},
}

# CI/CD webhook job tracking: {scan_id: {target, status, started_at, completed_at, findings, score}}
SCAN_JOBS = {}
