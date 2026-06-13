"""Full-scan orchestrator: phase management, module scheduling, completion."""
import time, os, threading, hashlib, json, concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE, SQLITE_AVAILABLE, sqlite3_mod, _check_target_for_ssrf, validate_webhook_url
from core.database import DB_PATH
from scanner.validation import fingerprint
from core.logger import log, push_sse
from core.proxy import _start_proxy, _stop_proxy, analyze_proxy_traffic, _PROXY_PORT
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress, op_log
from scanner.verify import verify_findings, build_attack_chains, calculate_risk_score

# Scan profiles and routing
from scanner.constants import SCAN_PROFILES, ADAPTIVE_ROUTING, SCAN_HARD_LIMIT, ATTACK_MODULE_NAMES
from scanner.routing import apply_adaptive_routing, PageTypeDetector, classify_target

# All scan module runners ─────────────────────────────────────────────────
from scanner.modules.web.headers import (
    run_header_module, run_advanced_header_module, run_cors_module,
    run_cors_creds_module, run_firewall_bypass_module, run_bot_detection_module,
    run_ddos_readiness_module, run_waf_fingerprint_module,
    run_static_hardening_checks,
)
from scanner.modules.web.injection import (
    run_sqlmap_module, run_dalfox_module, run_crlf_module, run_nuclei_module,
    run_vulnscan_module, run_directory_module, run_dir_traversal_module,
    run_xss_test_module, run_sqli_test_module, run_cmdi_test_module, run_ssrf_test_module,
)
from scanner.modules.web.auth import (
    run_auth_test_module, run_jwt_test_module, run_jwt_attack_module,
    run_jwt_deep_module, run_oauth_test_module, run_oauth_attack_module,
    run_session_fixation_module, run_credential_stuffing_module, run_2fa_bypass_module,
)
from scanner.modules.web.api import (
    run_api_security_module, run_api_abuse_module,
    run_graphql_test_module, run_graphql_module, run_graphql_deep_module,
    run_websocket_test_module,
)
from scanner.modules.web.advanced import (
    run_ssti_test_module, run_http_smuggle_module, run_cache_poison_module,
    run_file_upload_test_module, run_mass_assignment_module, run_race_condition_module,
    run_idor_test_module, run_business_logic_module, run_csrf_test_module,
    run_clickjack_deep_module, run_host_header_module, run_file_inclusion_module,
    run_open_redirect_module, run_xxe_injection_module, run_xxe_test_module,
    run_deserialization_module, run_proto_pollution_module, run_prototype_pollution_module,
    run_ldap_test_module, run_nosqli_test_module, run_header_inject_module,
    run_smuggling_module, run_cache_poisoning_module, run_lfi_module,
    run_open_redirect_deep_module, run_race_condition_deep_module, run_bizlogic_module,
    run_dns_rebinding_module, run_subdomain_takeover_module, run_ssrf_deep_module,
    run_crypto_miner_module,
)
from scanner.modules.web.pentest import (
    run_enhanced_subdomain_enum, run_deep_endpoint_crawl,
    run_unauth_endpoint_analysis, run_token_secret_hunt,
    run_sqli_deep_test, run_idor_deep_test,
)
from scanner.modules.web.appsec import (
    run_js_secret_module, run_api_surface_module, run_auth_flow_module,
    run_data_exposure_module, run_cloud_config_module, run_payment_key_module,
    run_sensitive_file_module, run_bizlogic_audit_module,
)
from scanner.modules.web.wazuh import (
    run_fim_module, run_rootkit_module,
    run_vuln_detect_module, run_log_analysis_module, run_compliance_check_module,
)
from scanner.modules.web.discovery import (
    run_tech_module, run_correlation_module, run_graph_module,
)
from scanner.modules.network.recon import (
    run_dns_module, run_subdomain_module, run_ssl_module, run_port_module,
    run_web_crawler_module, run_js_module, run_wayback_module,
    run_takeover_verify_module, run_subdomain_enum_module,
)
from scanner.modules.network.vuln import (
    run_whois_module, run_emailsec_module, run_netsec_module, run_kev_module,
    run_darkweb_module, run_oob_module, run_wp_module,
    run_monitoring_module, run_compliance_module,
)
from scanner.modules.code.sast import (
    run_enhanced_secrets_module, run_gitleaks_module, run_trufflehog_module,
    run_semgrep_module, run_bearer_module, run_osv_module,
    run_supplychain_module, run_github_leak_module,
)
from scanner.modules.vm.container import (
    run_cloud_module, run_cloud_vm_module, run_container_security_module,
    run_checkov_module, run_kubernetes_security_module, run_takeover_module,
)
from scanner.tools.wrappers import run_nikto_module, run_arjun_module, run_theharvester_module


class _TechSpecificTests:
    """Stub for tech-specific tests. Returns empty lists — tests are run via individual modules."""
    @staticmethod
    def wordpress_tests(base_url):
        return []
    @staticmethod
    def laravel_tests(base_url):
        return []
    @staticmethod
    def api_tests(base_url):
        return []

TechSpecificTests = _TechSpecificTests()


def run_full_scan(target, scan_type='full'):
    log('info', f'[ORCH] Starting {scan_type} scan for {target}')

    with LOCK:
        scan_state['scan_start_time'] = time.time()
        scan_state['scan_end_time'] = 0
        scan_state['modules_run'] = []

    # ── Load scan profile ──
    profile_name = scan_state.get('profile', 'balanced')
    profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES['balanced'])
    BATCH_SIZE = profile['batch_size']
    jitter_range = profile['jitter']
    passive_only = profile['passive_only']

    # Start mitmdump proxy for traffic capture
    import hashlib as _hl
    scan_id = _hl.md5(f'{target}_{time.time()}'.encode()).hexdigest()[:12]
    har_path = _start_proxy(scan_id)
    if har_path and req_lib is not None and hasattr(req_lib, 'proxies'):
        req_lib.proxies = {
            'http': f'http://127.0.0.1:{_PROXY_PORT}',
            'https': f'http://127.0.0.1:{_PROXY_PORT}',
        }
        ca_cert = os.path.expanduser('~/.mitmproxy/mitmproxy-ca-cert.pem')
        if os.path.exists(ca_cert):
            req_lib.verify = ca_cert

    log('info', f'[ORCH] Profile: {profile_name} — jitter={jitter_range}, batch={BATCH_SIZE}, passive_only={passive_only}')
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PRE-SCAN: PAGE TYPE DETECTION — classify target before any modules run
    # ═══════════════════════════════════════════════════════════════════════════
    pt_result = None
    pt_skip_modules = []
    try:
        log('info', f'[ORCH] Running PageTypeDetector for {target}')
        pt_result = PageTypeDetector.detect(target)
        with LOCK:
            scan_state['page_type_result'] = pt_result
            scan_state['page_type'] = pt_result.get('page_type', 'unknown')
        log('ok', f'[ORCH] Page type: {pt_result["page_type"].upper()} '
                  f'(confidence={pt_result["confidence"]:.0%}, strategy={pt_result["scan_strategy"]})')
        # Collect modules to skip from PageTypeDetector
        pt_skip_modules = pt_result.get('skip_modules', [])
        if pt_skip_modules:
            log('info', f'[ORCH] PageTypeDetector recommends skipping {len(pt_skip_modules)} modules')
        # Run static hardening checks for static targets
        if pt_result.get('page_type') == 'static':
            log('info', f'[ORCH] Static site detected — running dedicated hardening checks')
            try:
                run_static_hardening_checks(target)
            except Exception as e:
                log('warn', f'[ORCH] Static hardening checks failed: {e}')
    except Exception as e:
        log('warn', f'[ORCH] PageTypeDetector failed: {e} — proceeding with full scan')

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1: FAST PASSIVE RECON — all run in parallel
    # DNS, Ports, Tech, WAF fingerprint, Subdomain enum
    # These are independent and produce data Phase 2 needs.
    # ═══════════════════════════════════════════════════════════════════════════
    log('info', f'[ORCH] ═══ PHASE 1: FAST PASSIVE RECON (parallel) ═══')
    phase1_modules = [
        ('DNS', run_dns_module),
        ('Subdomains', run_subdomain_module),
        ('Port Scan', run_port_module),
        ('Tech Detection', run_tech_module),
        ('WAF Fingerprint', run_waf_fingerprint_module),
        ('Subdomain Enum', run_subdomain_enum_module),
        ('Enhanced Subdomain Enum', run_enhanced_subdomain_enum),
    ]
    with LOCK:
        scan_state['current_phase'] = 'Phase 1: Passive Recon'
        scan_state['modules_total'] = len(phase1_modules) + 4  # phase1 + phase2a minimum
        scan_state['modules_done'] = 0
        scan_state['module_progress'] = {}
    
    def _run_phase1(module_func, module_name, tgt):
        with LOCK:
            scan_state['current_module'] = module_name
            scan_state['module_progress'][module_name] = 'running'
        try:
            module_func(tgt)
            with LOCK:
                scan_state.setdefault('modules_run', []).append(module_name)
                scan_state['modules_done'] = scan_state.get('modules_done', 0) + 1
                scan_state['module_progress'][module_name] = 'completed'
            return (module_name, True)
        except Exception as e:
            with LOCK:
                scan_state['modules_done'] = scan_state.get('modules_done', 0) + 1
                scan_state['module_progress'][module_name] = 'failed'
                scan_state['module_failures'].append({
                    'module': module_name, 'reason': str(e),
                    'ts': time.time()
                })
            log('err', f'[ORCH] Phase1 {module_name} failed: {e}')
            return (module_name, False)
    
    # Run Phase 1 concurrently — WAF detection finishes before Phase 2 starts
    pool = ThreadPoolExecutor(max_workers=len(phase1_modules))
    futures = {pool.submit(_run_phase1, func, name, target): name for name, func in phase1_modules}
    done, not_done = concurrent.futures.wait(futures, timeout=300)
    for future in done:
        try:
            name, ok = future.result(timeout=1)
            if ok:
                log('ok', f'[ORCH] Phase1 complete: {name}')
        except Exception:
            pass
    for future in not_done:
        future.cancel()
    pool.shutdown(wait=False, cancel_futures=True)
    
    # Collect Phase 1 results for Phase 2
    with LOCK:
        crawl_data = dict(scan_state.get('crawl_data', {}))
        discovered_urls = [u.get('url', u) if isinstance(u, dict) else u for u in crawl_data.get('urls', [])]
        discovered_forms = list(crawl_data.get('forms', []))
        discovered_inputs = list(crawl_data.get('inputs', []))
        discovered_api_endpoints = list(crawl_data.get('api_endpoints', []))
        discovered_js_files = list(crawl_data.get('js_files', []))
        discovered_parameters = list(crawl_data.get('parameters', []))
        discovered_admin_panels = list(crawl_data.get('admin_panels', []))
        discovered_sensitive_files = list(crawl_data.get('sensitive_files', []))
        tech_data = dict(scan_state.get('tech_data', {}))
        subdomains = list(scan_state.get('sub_data', {}).get('subdomains', []))
        waf_data = dict(scan_state.get('waf_fingerprint_data', {}))
    
    with LOCK:
        scan_state['discovery_data'] = {
            'urls': discovered_urls,
            'forms': discovered_forms,
            'inputs': discovered_inputs,
            'api_endpoints': discovered_api_endpoints,
            'js_files': discovered_js_files,
            'parameters': discovered_parameters,
            'admin_panels': discovered_admin_panels,
            'sensitive_files': discovered_sensitive_files,
            'technologies': tech_data,
            'subdomains': subdomains,
            'waf_detected': waf_data.get('waf', 'None') if waf_data else 'None',
        }
    
    log('ok', f'[ORCH] Phase 1 done: {len(discovered_urls)} URLs, {len(subdomains)} subdomains, WAF={scan_state["discovery_data"]["waf_detected"]}')

    # ── Adaptive routing: classify target after Phase 1 recon ──
    _cls, _conf, _sig = classify_target(
        target=target, tech_data=tech_data, crawl_data=crawl_data,
        waf_data=waf_data, discovery_data=scan_state.get('discovery_data', {}),
    )
    with LOCK:
        scan_state['routing'] = {
            'enabled': ADAPTIVE_ROUTING,
            'classification': _cls,
            'confidence': _conf,
            'signals': {k: (sorted(v) if isinstance(v, set) else v)
                        for k, v in _sig.items()},
            'applied': False,
            'modules_kept': 0,
            'modules_dropped': 0,
            'dropped_names': [],
            'reason': '',
        }
    log('info', f'[ROUTING] classification={_cls} confidence={_conf} '
                f'(forms={_sig["forms"]}, api={_sig["api_endpoints"]}, '
                f'tech={sorted(t for t in _sig["tech_categories"] if t)})')
    try:
        set_progress('routing', 100)
    except Exception:
        pass


    if not scan_state.get('scanning'):
        log('warn', '[ORCH] Scan aborted after Phase 1')
    else:
        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 2: BASELINE ESTABLISHMENT — 30 normal requests per endpoint
        # ═══════════════════════════════════════════════════════════════════════
        log('info', f'[ORCH] ═══ PHASE 2: BASELINE ESTABLISHMENT ═══')
        with LOCK:
            scan_state['current_phase'] = 'Phase 2: Baseline Establishment'
        try:
            from scanner.health import get_health_monitor, reset_health_monitor
            reset_health_monitor()
            health_monitor = get_health_monitor(target)
            baseline_urls = list(scan_state.get('discovery_data', {}).get('urls', []))[:20]
            for url_str in baseline_urls:
                url = url_str if isinstance(url_str, str) else url_str.get('url', str(url_str))
                if not url.startswith('http'):
                    url = f'https://{url}'
                for _ in range(30):
                    try:
                        import time as _t
                        s = _t.time()
                        resp = req_lib.get(url, timeout=10, verify=False)
                        elapsed = (time.time() - s) * 1000
                        is_err = resp.status_code >= 500
                        is_reset = 'connection reset' in str(resp.reason).lower()
                        health_monitor.record_response(resp.status_code, elapsed, is_err, is_reset)
                    except Exception as e:
                        is_reset = 'connection reset' in str(e).lower() or 'broken pipe' in str(e).lower()
                        health_monitor.record_response(503, 0, True, is_reset)
            log('ok', f'[ORCH] Baseline: {len(baseline_urls)} endpoints × 30 samples')
        except Exception as e:
            log('warn', f'[ORCH] Baseline establishment failed: {e}')

        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 3: INFORMED ACTIVE TESTING — uses Phase 1+2 data
        # ═══════════════════════════════════════════════════════════════════════
        log('info', f'[ORCH] ═══ PHASE 3: INFORMED ACTIVE TESTING ═══')
        with LOCK:
            scan_state['current_phase'] = 'Phase 3: Active Testing'
        
        # ── Phase 2A: Discovery modules that need Phase 1 subdomains/URLs ──
        discovery_phase2 = [
            ('SSL/TLS', run_ssl_module),
            ('Web Crawler', run_web_crawler_module),
            ('JS Analysis', run_js_module),
            ('Wayback', run_wayback_module),
        ]
        
        for i in range(0, len(discovery_phase2), BATCH_SIZE):
            if not scan_state.get('scanning'):
                break
            batch = discovery_phase2[i:i+BATCH_SIZE]
            pool = ThreadPoolExecutor(max_workers=BATCH_SIZE)
            futures = {pool.submit(_run_phase1, func, name, target): name for name, func in batch}
            done, not_done = concurrent.futures.wait(futures, timeout=300)
            for future in done:
                try:
                    future.result(timeout=1)
                except Exception:
                    pass
            for future in not_done:
                future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        
        # Re-collect crawl data after Phase 2A
        with LOCK:
            crawl_data = dict(scan_state.get('crawl_data', {}))
            discovered_urls = [u.get('url', u) if isinstance(u, dict) else u for u in crawl_data.get('urls', [])]
            discovered_forms = list(crawl_data.get('forms', []))
            discovered_inputs = list(crawl_data.get('inputs', []))
            discovered_api_endpoints = list(crawl_data.get('api_endpoints', []))
            discovered_js_files = list(crawl_data.get('js_files', []))
            discovered_parameters = list(crawl_data.get('parameters', []))
            scan_state['discovery_data'].update({
                'urls': discovered_urls, 'forms': discovered_forms,
                'inputs': discovered_inputs, 'api_endpoints': discovered_api_endpoints,
                'js_files': discovered_js_files, 'parameters': discovered_parameters,
            })
        
        # ── Phase 2B: Tech-specific + security modules ──
        # Run tech-specific tests using Phase 1 tech detection
        if isinstance(tech_data, dict):
            tech_names = [v.get('name', '') for v in tech_data.values() if isinstance(v, dict)]
        elif isinstance(tech_data, list):
            tech_names = [t.get('name', '') for t in tech_data if isinstance(t, dict)]
        else:
            tech_names = []
        tech_str = ' '.join(tech_names).lower()
        base_url = f'https://{target}'
        
        if 'wordpress' in tech_str:
            try:
                for f in TechSpecificTests.wordpress_tests(base_url):
                    add_finding('medium', f'WordPress: {f["description"]}', asset=f'{base_url}{f["path"]}',
                               details=f'Path: {f["path"]}\nDescription: {f["description"]}')
            except Exception:
                pass
        if 'laravel' in tech_str or 'php' in tech_str:
            try:
                for f in TechSpecificTests.laravel_tests(base_url):
                    add_finding('high', f'Laravel: {f["description"]}', asset=f'{base_url}{f["path"]}',
                               details=f'Path: {f["path"]}\nDescription: {f["description"]}')
            except Exception:
                pass
        if discovered_api_endpoints or 'api' in tech_str or 'graphql' in tech_str:
            try:
                for f in TechSpecificTests.api_tests(base_url):
                    add_finding('medium', f'API: {f["description"]}', asset=f'{base_url}{f["path"]}',
                               details=f'Path: {f["path"]}\nStatus: {f.get("status", "N/A")}')
            except Exception:
                pass
        
        # ── Phase 2C: All security/attack modules (categorized by scan_type) ──
        
        WEB_MODULES = [
            ('HTTP Headers', run_header_module),
            ('Advanced Headers', run_advanced_header_module),
            ('CORS', run_cors_module),
            ('CORS with Credentials', run_cors_creds_module),
            ('Dir Bruteforce', run_directory_module),
            ('SQLMap', run_sqlmap_module),
            ('Nuclei', run_nuclei_module),
            ('Dalfox XSS', run_dalfox_module),
            ('CRLF Injection', run_crlf_module),
            ('Firewall Bypass', run_firewall_bypass_module),
            ('Bot Detection', run_bot_detection_module),
            ('DDoS Readiness', run_ddos_readiness_module),
            ('WAF Fingerprint', run_waf_fingerprint_module),
            ('API Security', run_api_security_module),
            ('WordPress', run_wp_module),
            ('Vuln Scan', run_vulnscan_module),
            ('Nikto Server Scan', run_nikto_module),
            # Skill-based
            ('Dir Traversal', run_dir_traversal_module),
            ('JWT Testing', run_jwt_test_module),
            ('GraphQL Security', run_graphql_test_module),
            ('GraphQL Advanced', run_graphql_module),
            ('XXE Injection', run_xxe_injection_module),
            ('CSRF Testing', run_csrf_test_module),
            # Attacker simulation
            ('Arjun Params', run_arjun_module),
            ('SQLi Manual', run_sqli_test_module),
            ('XSS Manual', run_xss_test_module),
            ('SSRF Manual', run_ssrf_test_module),
            ('Command Injection', run_cmdi_test_module),
            ('Auth Testing', run_auth_test_module),
            ('SSTI', run_ssti_test_module),
            ('HTTP Smuggle', run_http_smuggle_module),
            ('Cache Poisoning', run_cache_poison_module),
            ('File Upload', run_file_upload_test_module),
            ('Mass Assignment', run_mass_assignment_module),
            ('Race Condition', run_race_condition_module),
            ('IDOR', run_idor_test_module),
            ('NoSQL Injection', run_nosqli_test_module),
            ('LDAP Injection', run_ldap_test_module),
            ('Header Injection', run_header_inject_module),
            ('Open Redirect Manual', run_open_redirect_module),
            ('Insecure Deserialization', run_deserialization_module),
            ('Prototype Pollution', run_proto_pollution_module),
            ('Advanced XXE', run_xxe_test_module),
            ('Business Logic', run_business_logic_module),
            ('Session Fixation', run_session_fixation_module),
            ('JWT Advanced', run_jwt_attack_module),
            ('OAuth Testing', run_oauth_test_module),
            ('OAuth Attack', run_oauth_attack_module),
            ('API Abuse', run_api_abuse_module),
            ('WebSocket Testing', run_websocket_test_module),
            ('Host Header Injection', run_host_header_module),
            ('File Inclusion LFI/RFI', run_file_inclusion_module),
            ('Clickjacking Deep', run_clickjack_deep_module),
            ('DNS Rebinding', run_dns_rebinding_module),
            ('Subdomain Takeover Verify', run_takeover_verify_module),
            # Enhanced recon & pentest modules
            ('Enhanced Subdomain Enum', run_enhanced_subdomain_enum),
            ('Deep Endpoint Crawl', run_deep_endpoint_crawl),
            ('Unauth Endpoint Analysis', run_unauth_endpoint_analysis),
            ('Token & Secret Hunt', run_token_secret_hunt),
            ('SQLi Deep Test', run_sqli_deep_test),
            ('IDOR Deep Test', run_idor_deep_test),
            # New pure-Python vulnerability detection modules
            ('Prototype Pollution Deep', run_prototype_pollution_module),
            ('HTTP Smuggling Raw', run_smuggling_module),
            ('Cache Poisoning Deep', run_cache_poisoning_module),
            ('GraphQL Deep', run_graphql_deep_module),
            ('JWT Deep', run_jwt_deep_module),
            ('LFI Path Traversal', run_lfi_module),
            ('Open Redirect Deep', run_open_redirect_deep_module),
            ('Race Condition Deep', run_race_condition_deep_module),
            ('Business Logic Deep', run_bizlogic_module),
            ('Subdomain Takeover Deep', run_subdomain_takeover_module),
            ('SSRF Deep', run_ssrf_deep_module),
            # Application security modules
            ('JS Secret Scanner', run_js_secret_module),
            ('API Surface Mapper', run_api_surface_module),
            ('Auth Flow Analyzer', run_auth_flow_module),
            ('Data Exposure Checker', run_data_exposure_module),
            ('Cloud Config Checker', run_cloud_config_module),
            ('Payment Key Detector', run_payment_key_module),
            ('Sensitive File Scanner', run_sensitive_file_module),
            ('Business Logic Audit', run_bizlogic_audit_module),
            # Wazuh-style security detection
            ('Wazuh FIM', run_fim_module),
            ('Wazuh Rootkit', run_rootkit_module),
            ('Wazuh Vuln Detect', run_vuln_detect_module),
            ('Wazuh Log Analysis', run_log_analysis_module),
            ('Wazuh Compliance', run_compliance_check_module),
        ]

        CODE_MODULES = [
            ('Secrets Scan', run_enhanced_secrets_module),
            ('Gitleaks Secrets', run_gitleaks_module),
            ('TruffleHog Deep', run_trufflehog_module),
            ('Semgrep SAST', run_semgrep_module),
            ('Bearer SAST', run_bearer_module),
            ('OSV Dependencies', run_osv_module),
            ('Supply Chain', run_supplychain_module),
            ('Git Leaks', run_github_leak_module),
            ('Credential Stuffing', run_credential_stuffing_module),
            ('2FA Bypass', run_2fa_bypass_module),
            ('Crypto Miner Detection', run_crypto_miner_module),
            # Wazuh-style security detection
            ('Wazuh FIM', run_fim_module),
            ('Wazuh Rootkit', run_rootkit_module),
            ('Wazuh Vuln Detect', run_vuln_detect_module),
        ]
        
        NETWORK_MODULES = [
            ('WHOIS', run_whois_module),
            ('Email Security', run_emailsec_module),
            ('Net Sec', run_netsec_module),
            ('KEV', run_kev_module),
            ('Dark Web', run_darkweb_module),
            ('Subdomain Enumeration', run_subdomain_enum_module),
            ('OOB Detection', run_oob_module),
            ('theHarvester OSINT', run_theharvester_module),
        ]
        
        VM_MODULES = [
            ('Cloud Storage', run_cloud_module),
            ('Cloud VM Scan', run_cloud_vm_module),
            ('Container Security', run_container_security_module),
            ('Checkov IaC', run_checkov_module),
            ('Kubernetes Security', run_kubernetes_security_module),
            ('Compliance', run_compliance_module),
            ('Monitoring', run_monitoring_module),
            ('Takeover', run_takeover_module),
        ]
        
        # ═══ SELECT MODULES BASED ON SCAN TYPE ═══
        if scan_type == 'web':
            scanning_modules = WEB_MODULES
        elif scan_type == 'code':
            scanning_modules = CODE_MODULES
        elif scan_type == 'network':
            scanning_modules = NETWORK_MODULES
        elif scan_type == 'vm':
            scanning_modules = VM_MODULES
        else:
            # full scan = discovery modules + all categories
            scanning_modules = WEB_MODULES + CODE_MODULES + NETWORK_MODULES + VM_MODULES

        # ── Apply adaptive routing: prune DYNAMIC_ONLY modules for static targets ──
        if ADAPTIVE_ROUTING:
            scanning_modules, routing_meta = apply_adaptive_routing(
                scanning_modules, {
                    'target': target,
                    'tech_data': tech_data,
                    'crawl_data': crawl_data,
                    'waf_data': waf_data,
                    'discovery_data': scan_state.get('discovery_data', {}),
                })
            with LOCK:
                scan_state['routing'].update({
                    'applied': True,
                    'modules_kept': routing_meta['kept'],
                    'modules_dropped': routing_meta['dropped'],
                    'dropped_names': routing_meta.get('dropped_names', []),
                    'reason': routing_meta['reason'],
                })
            if routing_meta['dropped'] > 0:
                log('info', f'[ROUTING] Pruned {routing_meta["dropped"]} modules '
                            f'for {_cls} target: {routing_meta["reason"]}')

        # ── Apply passive_only filter: skip attack modules in stealth mode ──
        if passive_only:
            scanning_modules = [(n, f) for n, f in scanning_modules if n not in ATTACK_MODULE_NAMES]
            log('info', f'[ORCH] Passive-only mode: filtered to {len(scanning_modules)} modules')
        
        # ── Apply skip_modules filter (quick profile) ──
        skip_list = profile.get('skip_modules', [])
        # Also apply advanced skip_modules from UI
        adv_skip = scan_state.get('advanced_options', {}).get('skip_modules', [])
        if adv_skip:
            skip_list = list(set(skip_list + adv_skip))
        # Also apply PageTypeDetector skip_modules
        if pt_skip_modules:
            skip_list = list(set(skip_list + pt_skip_modules))
        if skip_list:
            before = len(scanning_modules)
            scanning_modules = [(n, f) for n, f in scanning_modules if n not in skip_list]
            log('info', f'[ORCH] Skipped {before - len(scanning_modules)} modules: {", ".join(skip_list[:5])}')
        
        # Always include correlation/attack-graph as final step
        scanning_modules += [('Correlation', run_correlation_module), ('Attack Graph', run_graph_module)]
        
        # Track module counts per scan type for UI progress
        with LOCK:
            if scan_type == 'full':
                for t in ['web', 'code', 'network', 'vm']:
                    tm = {'web': WEB_MODULES, 'code': CODE_MODULES, 'network': NETWORK_MODULES, 'vm': VM_MODULES}
                    scan_state['type_stats'][t]['modules_total'] = len(tm.get(t, []))
            else:
                if scan_type not in scan_state['type_stats']:
                    scan_state['type_stats'][scan_type] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0}
                scan_state['type_stats'][scan_type]['modules_total'] = len(scanning_modules) - 2  # minus correlation+graph
        
        log('info', f'[ORCH] Running {len(scanning_modules)} modules for {scan_type} scan')
        with LOCK:
            scan_state['modules_total'] = scan_state.get('modules_done', 0) + len(scanning_modules)
            scan_state['current_phase'] = 'Phase 2C: Security Testing'
            scan_state['modules_run_count'] = 0
        
        for i in range(0, len(scanning_modules), BATCH_SIZE):
            if not scan_state.get('scanning'):
                log('warn', f'[ORCH] Scan aborted by user')
                break
            # Global hard time limit
            elapsed = time.time() - scan_state.get('scan_start_time', time.time())
            if elapsed > SCAN_HARD_LIMIT:
                log('warn', f'[ORCH] Scan hard time limit reached ({SCAN_HARD_LIMIT}s) — stopping')
                break
            batch = scanning_modules[i:i+BATCH_SIZE]
            batch_names = [n for n, _ in batch]
            log('info', f'[ORCH] Running batch {i//BATCH_SIZE + 1}: {", ".join(batch_names)}')
            
            def _run_module(module_func, module_name, tgt):
                with LOCK:
                    scan_state['current_module'] = module_name
                    scan_state['module_progress'][module_name] = 'running'
                try:
                    module_func(tgt)
                    with LOCK:
                        scan_state.setdefault('modules_run', []).append(module_name)
                        # Only increment if not already counted by the timeout handler
                        if scan_state.get('module_progress', {}).get(module_name) != 'timed_out':
                            scan_state['modules_done'] = scan_state.get('modules_done', 0) + 1
                        scan_state['module_progress'][module_name] = 'completed'
                        st = scan_state.get('scan_type', 'full')
                        if st not in scan_state.get('type_stats', {}):
                            scan_state['type_stats'][st] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0, 'modules_done': 0, 'modules_total': 0}
                        scan_state['type_stats'][st]['modules_done'] = scan_state['type_stats'][st].get('modules_done', 0) + 1
                        if st == 'full':
                            for t, tm in [('web', WEB_MODULES), ('code', CODE_MODULES), ('network', NETWORK_MODULES), ('vm', VM_MODULES)]:
                                if any(n == module_name for n, _ in tm):
                                    scan_state['type_stats'][t]['modules_done'] = scan_state['type_stats'][t].get('modules_done', 0) + 1
                                    break
                    return (module_name, True, None)
                except Exception as e:
                    with LOCK:
                        # Only increment if not already counted by the timeout handler
                        if scan_state.get('module_progress', {}).get(module_name) != 'timed_out':
                            scan_state['modules_done'] = scan_state.get('modules_done', 0) + 1
                        scan_state['module_progress'][module_name] = 'failed'
                        scan_state['module_failures'].append({
                            'module': module_name, 'reason': str(e),
                            'ts': time.time()
                        })
                    log('err', f'[ORCH] Module {module_name} failed: {e}')
                    return (module_name, False, str(e))
            
            MODULE_TIMEOUT = scan_state.get('advanced_options', {}).get('timeout', 120)
            pool = ThreadPoolExecutor(max_workers=BATCH_SIZE)
            futures = {pool.submit(_run_module, func, name, target): name for name, func in batch}
            done, not_done = concurrent.futures.wait(futures, timeout=MODULE_TIMEOUT)
            for future in done:
                try:
                    mod_name, success, error = future.result(timeout=1)
                    if success:
                        log('ok', f'[ORCH] Completed: {mod_name}')
                    else:
                        with LOCK:
                            scan_state['module_failures'].append({
                                'module': mod_name, 'reason': error or 'unknown error',
                                'ts': time.time()
                            })
                except Exception:
                    pass
            for future in not_done:
                mod_name = futures[future]
                future.cancel()
                with LOCK:
                    scan_state['modules_done'] = scan_state.get('modules_done', 0) + 1
                    scan_state['module_progress'][mod_name] = 'timed_out'
                    scan_state['module_failures'].append({
                        'module': mod_name, 'reason': f'timed out after {MODULE_TIMEOUT}s',
                        'ts': time.time()
                    })
                log('warn', f'[ORCH] Module {mod_name} timed out after {MODULE_TIMEOUT}s — skipped')
            pool.shutdown(wait=False, cancel_futures=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3: DISCOVERY ENGINES — coverage-guided mutation, anomaly detection,
    # logic flaws, OOB discovery, parser stress testing
    # ═══════════════════════════════════════════════════════════════════════════
    if scan_state.get('scanning') is not False:
        with LOCK:
            scan_state['current_phase'] = 'Phase 3: Discovery Engines'

        try:
            from scanner.engines.mutation import MutationEngine
            from scanner.engines.anomaly import AnomalyEngine
            from scanner.engines.logic import LogicFlawEngine
            from scanner.engines.oob import OOBEngine
            from scanner.engines.parser_stress import ParserStressEngine
            from scanner.limits import ScanLimits
            from scanner.health import get_health_monitor, reset_health_monitor

            # Initialize hard limits
            scan_limits = ScanLimits(scan_id, {
                'max_requests': 10000,
                'max_rate': 10,
                'max_concurrent': 5,
            })

            # Initialize health monitor
            reset_health_monitor()
            health = get_health_monitor(target)

            # Build endpoint list from discovery data
            discovered_urls = list(scan_state.get('discovery_data', {}).get('urls', []))
            discovered_forms = list(scan_state.get('discovery_data', {}).get('forms', []))
            discovered_params = list(scan_state.get('discovery_data', {}).get('parameters', []))

            # Build endpoints for engines: (url, params_dict, content_type)
            mutation_endpoints = []
            anomaly_endpoints = []
            for url in discovered_urls[:30]:  # limit to 30 endpoints
                url_str = url if isinstance(url, str) else url.get('url', str(url))
                if not url_str.startswith('http'):
                    url_str = f'https://{url_str}'
                # Default params
                mutation_endpoints.append((url_str, {}, 'text/html'))
                anomaly_endpoints.append((url_str, 'GET', None))

            # Add form endpoints
            for form in discovered_forms[:20]:
                action = form.get('action', target)
                if not action.startswith('http'):
                    action = f'{target.rstrip("/")}/{action.lstrip("/")}'
                inputs = form.get('inputs', [])
                params = {inp.get('name', ''): inp.get('value', '') for inp in inputs if inp.get('name')}
                content_type = form.get('enctype', 'application/x-www-form-urlencoded')
                mutation_endpoints.append((action, params, content_type))
                anomaly_endpoints.append((action, form.get('method', 'GET').upper(), None))

            log('info', f'[ORCH] Phase 3: Running 5 discovery engines on {len(mutation_endpoints)} endpoints')

            # Engine 1: Coverage-Guided Input Mutation
            with LOCK:
                scan_state['current_module'] = 'Engine 1: Input Mutation'
            try:
                mut_engine = MutationEngine(target, max_mutations_per_param=50, max_requests=3000)
                mut_result = mut_engine.run(mutation_endpoints[:30])
                with LOCK:
                    scan_state['engine_mutation'] = mut_result
                log('ok', f'[ENGINE-1] Mutation: {mut_result["coverage"]} behaviors, '
                         f'{len(mut_result["findings"])} findings')
            except Exception as e:
                log('warn', f'[ENGINE-1] Mutation engine failed: {e}')

            # Engine 2: Anomaly Detection
            with LOCK:
                scan_state['current_module'] = 'Engine 2: Anomaly Detection'
            try:
                anom_engine = AnomalyEngine(target, max_endpoints=20, baseline_samples=30)
                anom_result = anom_engine.run(anomaly_endpoints[:20])
                with LOCK:
                    scan_state['engine_anomaly'] = anom_result
                log('ok', f'[ENGINE-2] Anomaly: {len(anom_result["anomalies"])} anomalies, '
                         f'{len(anom_result["findings"])} findings')
            except Exception as e:
                log('warn', f'[ENGINE-2] Anomaly engine failed: {e}')

            # Engine 3: Logic-Flaw Hunting
            with LOCK:
                scan_state['current_module'] = 'Engine 3: Logic Flaws'
            try:
                logic_engine = LogicFlawEngine(target, max_flow_steps=10)
                logic_result = logic_engine.run(crawl_data)
                with LOCK:
                    scan_state['engine_logic'] = logic_result
                log('ok', f'[ENGINE-3] Logic: {len(logic_result["flows"])} flows, '
                         f'{len(logic_result["findings"])} findings')
            except Exception as e:
                log('warn', f'[ENGINE-3] Logic engine failed: {e}')

            # Engine 4: Blind OOB Discovery
            with LOCK:
                scan_state['current_module'] = 'Engine 4: OOB Discovery'
            try:
                oob_engine = OOBEngine(target, callback_timeout=15, max_injection_points=30)
                oob_result = oob_engine.run(mutation_endpoints[:30])
                with LOCK:
                    scan_state['engine_oob'] = oob_result
                log('ok', f'[ENGINE-4] OOB: {len(oob_result["findings"])} blind vulnerabilities')
            except Exception as e:
                log('warn', f'[ENGINE-4] OOB engine failed: {e}')

            # Engine 5: Parser Stress Testing
            with LOCK:
                scan_state['current_module'] = 'Engine 5: Parser Stress'
            try:
                parser_engine = ParserStressEngine(target, max_requests=500)
                parser_result = parser_engine.run(mutation_endpoints[:20])
                with LOCK:
                    scan_state['engine_parser'] = parser_result
                log('ok', f'[ENGINE-5] Parser: {len(parser_result["crashes"])} crashes, '
                         f'{len(parser_result["timeouts"])} timeouts')
            except Exception as e:
                log('warn', f'[ENGINE-5] Parser stress engine failed: {e}')

            # Store limits status
            with LOCK:
                scan_state['limits_status'] = scan_limits.get_status()
                scan_state['health_status'] = health.get_status()

            log('ok', f'[ORCH] Phase 3 complete: 5 engines finished')

        except ImportError as e:
            log('warn', f'[ORCH] Discovery engines unavailable: {e}')
        except Exception as e:
            log('warn', f'[ORCH] Discovery engines error: {e}')

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8: CHAIN ANALYSIS — build attack graphs, find paths to objectives
    # ═══════════════════════════════════════════════════════════════════════════
    try:
        from scanner.chains import build_attack_chains_full
        with LOCK:
            scan_state['current_phase'] = 'Phase 8: Chain Analysis'
        chain_result = build_attack_chains_full()
        with LOCK:
            scan_state['attack_chains'] = chain_result.get('chains', [])
        if chain_result.get('chains'):
            log('ok', f'[ORCH] Phase 8: {len(chain_result["chains"])} attack chains found')
    except Exception as e:
        log('warn', f'[ORCH] Chain analysis failed: {e}')
    
    # Post-scan processing: wrap in try/except to ensure scanning=False is set
    try:
        # Analyze captured proxy traffic for security issues
        har_path = scan_state.get('proxy_har')
        if har_path:
            try:
                analyze_proxy_traffic(har_path, scan_id)
            except Exception as e:
                log('warn', f'[PROXY-ANALYSIS] Error: {e}')
        _stop_proxy()
        verify_findings()
        build_attack_chains()
        calculate_risk_score()

        # ── Automated Verification Agent ─────────────────────────────
        # Actually confirms findings by attempting exploitation
        # This is what separates a scanner from a pentester
        try:
            from scanner.verification_agent import verify_all_findings
            with LOCK:
                scan_state['current_phase'] = 'Phase 8.5: Verification Agent'
            push_sse('phase', {'phase': 'Verification Agent', 'detail': 'Confirming findings via exploitation'})
            verification_result = verify_all_findings(target, max_workers=3)
            with LOCK:
                scan_state['verification_result'] = verification_result
            # Remove false positives from findings
            if verification_result.get('false_positive', 0) > 0:
                with LOCK:
                    fp_ids = {r['finding_id'] for r in verification_result.get('results', [])
                              if r['status'] == 'FALSE_POSITIVE'}
                    original_count = len(scan_state.get('findings', []))
                    scan_state['findings'] = [f for f in scan_state.get('findings', [])
                                              if f.get('id') not in fp_ids]
                    removed = original_count - len(scan_state['findings'])
                    if removed:
                        log('ok', f'[VERIFY] Removed {removed} false positives via exploitation')
            log('ok', f'[VERIFY] {verification_result.get("confirmed", 0)} confirmed, '
                      f'{verification_result.get("false_positive", 0)} false positive, '
                      f'{verification_result.get("inconclusive", 0)} inconclusive')
        except Exception as e:
            log('warn', f'[VERIFY] Verification agent failed: {e}')

        # ── Cross-Layer Risk Correlation Engine ──────────────────────
        try:
            from scanner.modules.web.risk_engine import correlate_telemetry
            with LOCK:
                findings = list(scan_state.get('findings', []))

            # Build telemetry strings from findings
            web_signals = []
            network_signals = []
            vm_signals = []
            cloud_signals = []

            for f in findings:
                title = f.get('title', '').lower()
                details = f.get('details', '').lower()
                sev = f.get('sev', '').lower()
                module = f.get('module', '').lower()
                combined = f'{title} {details}'

                # Classify finding into layer
                if any(kw in combined for kw in ['sql injection', 'xss', 'ssrf', 'csrf', 'path traversal',
                                                  'file inclusion', 'header injection', 'open redirect',
                                                  'auth bypass', 'idor', 'jwt', 'session fixation',
                                                  'brute force', 'rate limit', 'clickjacking',
                                                  'cors misconfiguration', 'csp', 'hsts']):
                    web_signals.append(f'[{sev.upper()}] {f.get("title", "unknown")} (source: {module})')
                elif any(kw in combined for kw in ['port scan', 'port open', 'nmap', 'syn scan',
                                                    'lateral movement', 'smb', 'rdp', 'ssh',
                                                    'dns', 'subdomain', 'certificate', 'tls', 'ssl',
                                                    'exfiltration', 'c2', 'c2 server', 'backdoor']):
                    network_signals.append(f'[{sev.upper()}] {f.get("title", "unknown")} (source: {module})')
                elif any(kw in combined for kw in ['privilege escalation', 'privesc', 'rootkit',
                                                    'container', 'docker', 'kubernetes', 'k8s',
                                                    'process injection', 'credential dump', 'persistence',
                                                    'kernel', 'suid', 'sudo']):
                    vm_signals.append(f'[{sev.upper()}] {f.get("title", "unknown")} (source: {module})')
                elif any(kw in combined for kw in ['cloud', 's3', 'aws', 'azure', 'gcp',
                                                    'iam', 'metadata', 'ec2', 'lambda',
                                                    'policy', 'bucket', 'storage']):
                    cloud_signals.append(f'[{sev.upper()}] {f.get("title", "unknown")} (source: {module})')
                else:
                    # Default to web for HTTP-related findings
                    if any(kw in combined for kw in ['http', 'server', 'cookie', 'security header',
                                                      'missing header', 'information disclosure',
                                                      'stack trace', 'debug', 'error page',
                                                      'backup', 'config', 'env file', '.git']):
                        web_signals.append(f'[{sev.upper()}] {f.get("title", "unknown")} (source: {module})')

            web_telemetry = '\n'.join(web_signals) if web_signals else ''
            network_telemetry = '\n'.join(network_signals) if network_signals else ''
            vm_telemetry = '\n'.join(vm_signals) if vm_signals else ''
            cloud_telemetry = '\n'.join(cloud_signals) if cloud_signals else ''

            if any([web_telemetry, network_telemetry, vm_telemetry, cloud_telemetry]):
                risk_result = correlate_telemetry(web_telemetry, network_telemetry,
                                                  vm_telemetry, cloud_telemetry)
                with LOCK:
                    scan_state['risk_correlation'] = risk_result
                log('ok', f'[RISK-ENGINE] {risk_result["risk_level"]} '
                          f'(confidence: {risk_result["confidence"]}%, '
                          f'layers: {len(risk_result["layers_involved"])}, '
                          f'chain: {risk_result.get("attack_pattern", "none")})')
                push_sse('risk_engine', {
                    'risk_level': risk_result['risk_level'],
                    'confidence': risk_result['confidence'],
                    'layers': risk_result['layers_involved'],
                    'attack_pattern': risk_result.get('attack_pattern', ''),
                })
            else:
                log('info', '[RISK-ENGINE] Insufficient telemetry for cross-layer correlation')
        except Exception as e:
            log('warn', f'[RISK-ENGINE] Correlation failed: {e}')
    except Exception as e:
        log('warn', f'[ORCH] Post-scan processing error: {e}')
    
    with LOCK:
        scan_state['scan_end_time'] = time.time()
        scan_state['scanning'] = False
        total_findings = len(scan_state.get('findings', []))
        score = scan_state.get('risk_score', 0)
        stats = dict(scan_state.get('stats', {}))
    push_sse('complete', {'target': target, 'total': total_findings, 'score': score})
    log('ok', f'[ORCH] Scan complete — {total_findings} findings, Risk Score: {score}/100')
    op_log('scan_complete', target=target, detail=f'{total_findings} findings, score={score}/100')

    # Persist to DB
    if SQLITE_AVAILABLE:
        try:
            scan_id = hashlib.md5(f'{target}_{time.time()}'.encode()).hexdigest()[:12]
            with sqlite3_mod.connect(DB_PATH) as conn:
                conn.execute('INSERT OR IGNORE INTO scan_history (scan_id, target, status, risk_score, total_findings, stats) VALUES (?,?,?,?,?,?)',
                    (scan_id, target, 'completed', score, total_findings, json.dumps(stats)))
                for f in scan_state.get('findings', []):
                    conn.execute('INSERT INTO findings (scan_id, target, sev, title, sub, asset, cve, cvss, exploit, poc_link, owasp, mitre, details, fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        (scan_id, target, f['sev'], f['title'], f.get('sub',''), f.get('asset',''), f.get('cve',''), f.get('cvss',''), f.get('exploit',''), f.get('poc_link',''), f.get('owasp',''), f.get('mitre',''), f.get('details',''), f.get('fingerprint','')))
        except Exception as e:
            log('warn', f'[DB] Persist error: {e}')

    # Compute findings diff against previous scan for this target
    try:
        diff = compute_scan_diff(target)
        if diff:
            with LOCK:
                scan_state['scan_diff'] = diff
            s = diff['summary']
            log('ok', f'[DIFF] vs previous scan — +{s["new_count"]} new, -{s["resolved_count"]} resolved, '
                      f'{s["persisting_count"]} persisting, risk delta={s["risk_delta"]:+.1f}')
            push_sse('diff', diff)
        else:
            log('info', '[DIFF] First scan for this target — no diff available yet')
    except Exception as e:
        log('warn', f'[DIFF] Error: {e}')

    # Auto-notify configured webhooks
    if SQLITE_AVAILABLE:
        try:
            with sqlite3_mod.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3_mod.Row
                configs = conn.execute('SELECT * FROM webhook_config WHERE enabled=1').fetchall()
            for cfg in configs:
                webhook_url = cfg['webhook_url']
                if webhook_url and validate_webhook_url(webhook_url):
                    try:
                        msg = f'🔍 Scan Complete for {target}: {total_findings} findings, Risk Score: {score}/100'
                        if cfg['channel'] == 'slack':
                            req_lib.post(webhook_url, json={'text': msg}, timeout=8)
                        elif cfg['channel'] == 'discord':
                            req_lib.post(webhook_url, json={'content': msg}, timeout=8)
                        log('ok', f'[NOTIFY] Auto-notification sent to {cfg["channel"]}')
                    except Exception:
                        log('warn', f'[NOTIFY] Failed to send to {cfg["channel"]}')
        except Exception:
            pass

# ─── SCAN DIFF ────────────────────────────────────────────────────────────────


def compute_scan_diff(target):
    """Compare the last two completed scans for a target.

    Returns a dict with keys: new, resolved, persisting, summary, scan_a, scan_b.
    Returns None if fewer than 2 scans exist for this target.
    """
    if not SQLITE_AVAILABLE:
        return None
    try:
        with sqlite3_mod.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3_mod.Row
            scans = conn.execute(
                'SELECT scan_id, created_at, risk_score, total_findings FROM scan_history '
                'WHERE target=? ORDER BY created_at DESC LIMIT 2',
                (target,)
            ).fetchall()
            if len(scans) < 2:
                return None

            latest_id = scans[0]['scan_id']
            prev_id   = scans[1]['scan_id']

            def _get_map(sid):
                rows = conn.execute(
                    'SELECT sev, title, asset, cvss, owasp, mitre, fingerprint FROM findings WHERE scan_id=?',
                    (sid,)
                ).fetchall()
                result = {}
                for r in rows:
                    fp = r['fingerprint'] or fingerprint(r['title'] or '', r['asset'] or '')
                    result[fp] = {
                        'sev': r['sev'], 'title': r['title'],
                        'asset': r['asset'], 'cvss': r['cvss'],
                        'owasp': r['owasp'], 'mitre': r['mitre'],
                        'fingerprint': fp,
                    }
                return result

            latest_map = _get_map(latest_id)
            prev_map   = _get_map(prev_id)

            latest_fps    = set(latest_map)
            prev_fps      = set(prev_map)
            new_fps        = latest_fps - prev_fps
            resolved_fps   = prev_fps - latest_fps
            persisting_fps = latest_fps & prev_fps

            # Severity order for sorting
            _sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            def _sev_sort(lst):
                return sorted(lst, key=lambda x: _sev_order.get(x.get('sev', 'info'), 5))

            diff = {
                'target': target,
                'scan_a': {
                    'scan_id': prev_id,
                    'created_at': scans[1]['created_at'],
                    'total': scans[1]['total_findings'],
                    'risk_score': scans[1]['risk_score'],
                },
                'scan_b': {
                    'scan_id': latest_id,
                    'created_at': scans[0]['created_at'],
                    'total': scans[0]['total_findings'],
                    'risk_score': scans[0]['risk_score'],
                },
                'new':        _sev_sort([latest_map[fp] for fp in new_fps]),
                'resolved':   _sev_sort([prev_map[fp]   for fp in resolved_fps]),
                'persisting': _sev_sort([latest_map[fp] for fp in persisting_fps]),
                'summary': {
                    'new_count':        len(new_fps),
                    'resolved_count':   len(resolved_fps),
                    'persisting_count': len(persisting_fps),
                    'risk_delta': round(
                        (scans[0]['risk_score'] or 0) - (scans[1]['risk_score'] or 0), 1
                    ),
                },
            }
            return diff
    except Exception as e:
        log('warn', f'[DIFF] compute_scan_diff error: {e}')
        return None


