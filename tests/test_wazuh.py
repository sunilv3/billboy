"""Tests for Wazuh-style security detection module."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner.modules.web.wazuh import (
    WEB_SHELL_SIGNATURES, LFI_MARKERS, CVE_SIGNATURES, COMPLIANCE_RULES,
    CRITICAL_FILES, LOG_PATHS, WEB_SHELL_PATHS, LFI_PATHS, LFI_PATH_MARKERS,
    run_fim_module, run_rootkit_module,
    run_vuln_detect_module, run_log_analysis_module, run_compliance_check_module,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Static tests — verify data structures are well-formed
# ═══════════════════════════════════════════════════════════════════════════════

class TestWazuhDataStructures:
    def test_web_shell_signatures_not_empty(self):
        assert len(WEB_SHELL_SIGNATURES) > 0

    def test_web_shell_signatures_have_name(self):
        for pattern, name in WEB_SHELL_SIGNATURES:
            assert isinstance(pattern, str)
            assert isinstance(name, str)
            assert len(name) > 0

    def test_web_shell_signatures_compile(self):
        import re
        for pattern, name in WEB_SHELL_SIGNATURES:
            try:
                re.compile(pattern)
            except re.error:
                pytest.fail(f'Invalid regex in web shell signature: {name} ({pattern})')

    def test_lfi_markers_not_empty(self):
        assert len(LFI_MARKERS) > 0

    def test_lfi_markers_have_marker_name(self):
        for pattern, name in LFI_MARKERS:
            assert isinstance(pattern, str)
            assert isinstance(name, str)
            assert len(name) > 0

    def test_lfi_markers_compile(self):
        import re
        for pattern, name in LFI_MARKERS:
            try:
                re.compile(pattern)
            except re.error:
                pytest.fail(f'Invalid regex in LFI marker: {name} ({pattern})')

    def test_lfi_path_markers_cover_lfi_paths(self):
        for path in LFI_PATHS[:10]:
            if path in LFI_PATH_MARKERS:
                markers = LFI_PATH_MARKERS[path]
                assert len(markers) > 0

    def test_cve_signatures_not_empty(self):
        assert len(CVE_SIGNATURES) > 0

    def test_cve_signatures_have_cves(self):
        for pattern, software, cves in CVE_SIGNATURES:
            assert isinstance(pattern, str)
            assert isinstance(software, str)
            assert isinstance(cves, list)
            assert len(cves) > 0
            for cve_id, cve_name, severity, cve_desc in cves:
                assert cve_id.startswith('CVE-')
                assert severity in ('critical', 'high', 'medium', 'low', 'info')

    def test_compliance_rules_not_empty(self):
        assert len(COMPLIANCE_RULES) > 0
        assert 'PCI-DSS' in COMPLIANCE_RULES
        assert 'HIPAA' in COMPLIANCE_RULES
        assert 'GDPR' in COMPLIANCE_RULES
        assert 'OWASP Top 10' in COMPLIANCE_RULES

    def test_compliance_rules_have_valid_severities(self):
        for framework, rules in COMPLIANCE_RULES.items():
            for rule_id, rule_name, severity, pattern in rules:
                assert severity in ('critical', 'high', 'medium', 'low', 'info')

    def test_critical_files_not_empty(self):
        assert len(CRITICAL_FILES) > 0

    def test_log_paths_not_empty(self):
        assert len(LOG_PATHS) > 0

    def test_web_shell_paths_not_empty(self):
        assert len(WEB_SHELL_PATHS) > 0

    def test_lfi_paths_not_empty(self):
        assert len(LFI_PATHS) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Pattern matching tests — verify signatures detect actual content
# ═══════════════════════════════════════════════════════════════════════════════

class TestWazuhPatternMatching:
    def test_c99_shell_detection(self):
        import re
        content = '<?php $c99 = "c99 shell v1.0"; eval(base64_decode($_POST["cmd"])); ?>'
        found = False
        for pattern, name in WEB_SHELL_SIGNATURES:
            if re.search(pattern, content, re.I):
                if 'c99' in name.lower():
                    found = True
                    break
        assert found, 'Should detect c99 shell'

    def test_r57_shell_detection(self):
        import re
        content = '<?php // r57shell $r57 = "r57"; system($_GET["cmd"]); ?>'
        found = False
        for pattern, name in WEB_SHELL_SIGNATURES:
            if re.search(pattern, content, re.I):
                if 'r57' in name.lower():
                    found = True
                    break
        assert found, 'Should detect r57 shell'

    def test_php_eval_detection(self):
        import re
        content = '<?php eval(base64_decode($_POST["code"])); ?>'
        found = False
        for pattern, name in WEB_SHELL_SIGNATURES:
            if re.search(pattern, content, re.I):
                found = True
                break
        assert found, 'Should detect PHP eval webshell'

    def test_php_system_detection(self):
        import re
        content = '<?php system($_GET["cmd"]); ?>'
        found = False
        for pattern, name in WEB_SHELL_SIGNATURES:
            if re.search(pattern, content, re.I):
                found = True
                break
        assert found, 'Should detect PHP system webshell'

    def test_china_chopper_detection(self):
        import re
        content = '<?php eval($_POST["x"]); ?>'
        found = False
        for pattern, name in WEB_SHELL_SIGNATURES:
            if re.search(pattern, content, re.I):
                found = True
                break
        assert found, 'Should detect China Chopper'

    def test_lfi_passwd_detection(self):
        import re
        content = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'
        found = False
        for pattern, name in LFI_MARKERS:
            if re.search(pattern, content, re.I):
                if 'passwd' in name.lower() or 'root' in name.lower():
                    found = True
                    break
        assert found, 'Should detect /etc/passwd content'

    def test_lfi_proc_environ_detection(self):
        import re
        content = 'PATH=/usr/local/bin:/usr/bin:/bin\nHOME=/root\nUSER=root\nLANG=en_US.UTF-8'
        found = False
        for pattern, name in LFI_MARKERS:
            if re.search(pattern, content, re.I):
                if 'environ' in name.lower():
                    found = True
                    break
        assert found, 'Should detect /proc/self/environ content'

    def test_lfi_ssh_key_detection(self):
        import re
        content = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC test@host'
        found = False
        for pattern, name in LFI_MARKERS:
            if re.search(pattern, content, re.I):
                if 'ssh' in name.lower():
                    found = True
                    break
        assert found, 'Should detect SSH key content'

    def test_log4j_detection(self):
        import re
        content = '<html><body>Apache Log4j 2.17.0</body></html>'
        found = False
        for pattern, software, cves in CVE_SIGNATURES:
            if re.search(pattern, content, re.I):
                if 'log4j' in software.lower():
                    found = True
                    assert len(cves) > 0
                    break
        assert found, 'Should detect Log4j'

    def test_spring_framework_detection(self):
        import re
        content = 'Spring Framework 5.3.20'
        found = False
        for pattern, software, cves in CVE_SIGNATURES:
            if re.search(pattern, content, re.I):
                if 'spring' in software.lower():
                    found = True
                    break
        assert found, 'Should detect Spring Framework'

    def test_jquery_detection(self):
        import re
        content = 'jQuery v3.6.0'
        found = False
        for pattern, software, cves in CVE_SIGNATURES:
            if re.search(pattern, content, re.I):
                if 'jquery' in software.lower():
                    found = True
                    break
        assert found, 'Should detect jQuery'

    def test_debug_mode_detection(self):
        import re
        content = 'DEBUG = True\nALLOWED_HOSTS = ["*"]'
        found = False
        for rule_id, rule_name, severity, pattern in COMPLIANCE_RULES['GDPR']:
            if re.search(pattern, content, re.I):
                found = True
                break
        assert found, 'Should detect debug mode for GDPR'

    def test_default_password_detection(self):
        import re
        content = 'admin = "password"\nDB_PASS = "default"'
        found = False
        for rule_id, rule_name, severity, regex in COMPLIANCE_RULES['PCI-DSS']:
            if re.search(regex, content, re.I):
                if 'default' in rule_name.lower() or 'password' in rule_name.lower():
                    found = True
                    break
        assert found, 'Should detect default password for PCI-DSS'

    def test_sql_injection_pattern_detection(self):
        import re
        content = "SELECT * FROM users WHERE id = '1' UNION SELECT * FROM passwords"
        found = False
        for rule_id, rule_name, severity, regex in COMPLIANCE_RULES['PCI-DSS']:
            if re.search(regex, content, re.I):
                if 'injection' in rule_name.lower():
                    found = True
                    break
        assert found, 'Should detect SQL injection pattern'

    def test_credit_card_detection(self):
        import re
        content = 'Payment: 4111111111111111'
        found = False
        for rule_id, rule_name, severity, regex in COMPLIANCE_RULES['PCI-DSS']:
            if re.search(regex, content, re.I):
                if 'pan' in rule_name.lower() or 'card' in rule_name.lower():
                    found = True
                    break
        assert found, 'Should detect credit card number'

    def test_weak_encryption_detection(self):
        import re
        content = 'SSLv3 enabled, RC4 cipher supported'
        found = False
        for rule_id, rule_name, severity, regex in COMPLIANCE_RULES['PCI-DSS']:
            if re.search(regex, content, re.I):
                if 'encryption' in rule_name.lower() or 'weak' in rule_name.lower():
                    found = True
                    break
        assert found, 'Should detect weak encryption'

    def test_no_false_positive_on_clean_content(self):
        import re
        content = '<html><body>Hello World</body></html>'
        for pattern, name in WEB_SHELL_SIGNATURES:
            assert not re.search(pattern, content, re.I), f'False positive: {name}'
