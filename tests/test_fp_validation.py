"""Tests for the universal false-positive validation gate (_validate_finding)."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.validation import _validate_finding

_validate = _validate_finding

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE
# ══════════════════════════════════════════════════════════════════════════════

class TestInfoPatternRejection:
    """Check 1: info-pattern removal (tool status messages)."""

    def test_scan_completed_rejected(self):
        ok, reason = _validate('info', 'Scan completed for target.com')
        assert not ok
        assert 'info-pattern' in reason

    def test_waf_detected_rejected(self):
        ok, reason = _validate('info', 'WAF Detected: Cloudflare')
        assert not ok
        assert 'info-pattern' in reason

    def test_simulation_mode_rejected(self):
        ok, reason = _validate('info', 'Test finding',
                               details='Running in simulation mode')
        assert not ok

    def test_valid_title_not_rejected(self):
        ok, reason = _validate('high', 'SQL Injection via parameter id',
                               details='Confirmed: error-based SQLi\nPayload: 1 OR 1=1')
        assert ok


class TestHTMLPageRejection:
    """Check 3: HTML error page detection."""

    def test_html_404_page_rejected(self):
        ok, reason = _validate(
            'high', 'SQL Injection via param',
            details='Parameter id is vulnerable',
            response_text='<html><head><title>404</title></head><body>Not Found</body></html>')
        assert not ok
        assert 'HTML' in reason

    def test_html_with_confirmed_not_rejected(self):
        ok, reason = _validate(
            'critical', 'SQL Injection via param',
            details='Confirmed: error-based SQLi\nPayload: 1 OR 1=1',
            response_text='<html><body>error</body></html>')
        assert ok

    def test_json_response_not_rejected(self):
        ok, reason = _validate(
            'critical', 'SSRF via param',
            details='Confirmed: metadata accessible',
            response_text='{"ami-id": "ami-12345"}')
        assert ok

    def test_medium_severity_html_not_rejected(self):
        ok, reason = _validate(
            'medium', 'Missing header',
            details='X-Frame-Options not set',
            response_text='<html></html>')
        assert ok  # Only high/critical rejected for HTML


class TestRedirectRejection:
    """Check 4: Redirect-to-login rejection."""

    def test_302_with_login_rejected(self):
        ok, reason = _validate(
            'critical', 'Open Redirect via param',
            details='Redirects to login page after auth',
            response_status=302)
        assert not ok
        assert 'redirect' in reason.lower()

    def test_302_without_auth_keywords_not_rejected(self):
        ok, reason = _validate(
            'critical', 'Parameter Tampering via redirect',
            details='Parameter redirects to external site https://evil.com',
            response_status=302)
        assert ok


class TestErrorIndicatorRejection:
    """Check 5: Generic error indicators for high/critical findings."""

    def test_multiple_errors_no_evidence_rejected(self):
        ok, reason = _validate(
            'critical', 'SQL Injection via param',
            details='Status: 403 Forbidden\nResponse: Error - access denied - invalid token')
        assert not ok
        assert 'error indicators' in reason

    def test_errors_with_evidence_not_rejected(self):
        ok, reason = _validate(
            'critical', 'SQL Injection via param',
            details='Status: 403 Forbidden\nResponse: Error - access denied\nConfirmed: error-based SQLi')
        assert ok


class TestBaselineSimilarity:
    """Check 6: Baseline content similarity."""

    def test_similar_content_rejected(self):
        ok, reason = _validate(
            'critical', 'SQL Injection via param',
            details='Parameter id triggers SQL error',
            response_text='Hello World. This is a normal page with some content.',
            baseline_text='Hello World. This is a normal page with some content.')
        assert not ok
        assert 'similar' in reason

    def test_different_content_not_rejected(self):
        ok, reason = _validate(
            'critical', 'SQL Injection via param',
            details='Confirmed: error-based SQLi\nPayload: 1 OR 1=1',
            response_text='Hello World. This is a normal page.',
            baseline_text='Goodbye Universe. This is a completely different page with totally other stuff.')
        assert ok

    def test_similar_with_proof_not_rejected(self):
        ok, reason = _validate(
            'high', 'XSS via param',
            details='Payload reflected: <script>alert(1)</script>\nConfirmed: DOM-based XSS',
            response_text='Page content here',
            baseline_text='Page content here')
        assert ok  # Has "reflected" keyword


class TestTypeEvidenceRequirements:
    """Check 7: Type-specific evidence requirements."""

    def test_sqli_without_confirmed_rejected(self):
        ok, reason = _validate(
            'critical', 'SQL Injection via param',
            details='Parameter id seems vulnerable to injection')
        assert not ok
        assert 'sql injection' in reason

    def test_sqli_with_confirmed_not_rejected(self):
        ok, reason = _validate(
            'critical', 'SQL Injection via param',
            details='Confirmed: error-based SQLi via parameter id')
        assert ok

    def test_xss_without_payload_rejected(self):
        ok, reason = _validate(
            'high', 'XSS via param',
            details='Parameter reflects input without sanitization')
        assert not ok
        assert 'xss' in reason

    def test_xss_with_payload_not_rejected(self):
        ok, reason = _validate(
            'high', 'XSS via param',
            details='Payload: <script>alert(1)</script> reflected in response')
        assert ok

    def test_ssrf_with_metadata_not_rejected(self):
        ok, reason = _validate(
            'critical', 'SSRF via param',
            details='Response contains 169.254.169.254 metadata')
        assert ok

    def test_nuclei_not_type_restricted(self):
        ok, reason = _validate(
            'critical', 'Nuclei: CVE-2024-1234 Remote Code Execution',
            details='Template ID: cve-2024-1234\nSeverity: critical')
        assert ok  # nuclei not in _TYPE_EVIDENCE

    def test_auth_bypass_with_admin_content_not_rejected(self):
        ok, reason = _validate(
            'critical', 'Auth bypass via X-Forwarded-For',
            details='Header: X-Forwarded-For: 127.0.0.1\nBypass Response: 200\nAdmin Content: Yes')
        assert ok

    def test_crlf_not_confirmed_rejected(self):
        ok, reason = _validate(
            'high', 'CRLF Injection via param',
            details='Parameter injects CRLF sequences but not confirmed')
        assert not ok

    def test_directory_traversal_without_evidence_rejected(self):
        ok, reason = _validate(
            'critical', 'Directory Traversal via param',
            details='Parameter allows path traversal')
        assert not ok

    def test_directory_traversal_with_evidence_not_rejected(self):
        ok, reason = _validate(
            'critical', 'Directory Traversal via param',
            details='Evidence: file contents read\nConfirmed: /etc/passwd accessible')
        assert ok


class TestSecretPlaceholderRejection:
    """Check 8: Secret/dependency placeholder rejection."""

    def test_example_secret_rejected(self):
        ok, reason = _validate(
            'critical', 'Leaked API Key in config',
            details='Key: example_key_12345 found in config.js')
        assert not ok
        assert 'placeholder' in reason

    def test_real_secret_not_rejected(self):
        ok, reason = _validate(
            'critical', 'Leaked API Key in config',
            details='Key: AKIA1234567890ABCDEF found in config.js\nVerified: true')
        assert ok

    def test_vulnerable_dependency_without_cve_rejected(self):
        ok, reason = _validate(
            'high', 'Vulnerable Dependency: lodash 4.17.19',
            details='Package lodash has known vulnerabilities')
        assert not ok
        assert 'cve-' in reason.lower()

    def test_vulnerable_dependency_with_cve_not_rejected(self):
        ok, reason = _validate(
            'high', 'Vulnerable Dependency: lodash 4.17.19',
            details='CVE-2021-23337: lodash prototype pollution')
        assert ok


class TestConfidenceDowngrade:
    """Check 9: Confidence downgrade for speculative findings."""

    def test_speculative_high_severity_gets_downgraded(self):
        ok, reason = _validate(
            'critical', 'Suspicious parameter behavior detected',
            details='Timing difference detected',
            confidence='speculative')
        assert ok  # Should pass but with downgrade note in details

    def test_speculative_low_severity_not_affected(self):
        ok, reason = _validate(
            'low', 'Information disclosure',
            details='Server version disclosed',
            confidence='speculative')
        assert ok


class TestEdgeCases:
    """Edge cases and combined scenarios."""

    def test_empty_details(self):
        ok, reason = _validate('info', 'Missing header: X-Frame-Options')
        assert ok  # info severity, no type match

    def test_empty_title(self):
        ok, reason = _validate('medium', '', details='Some details')
        assert ok

    def test_no_response_text(self):
        ok, reason = _validate('critical', 'SQL Injection via param',
                               details='Confirmed: error-based SQLi')
        assert ok

    def test_medium_severity_skips_most_checks(self):
        ok, reason = _validate(
            'medium', 'Missing security header: X-Frame-Options',
            details='Header not present',
            response_text='<html><body>normal page</body></html>')
        assert ok  # Medium doesn't trigger HTML rejection

    def test_info_severity_always_passes(self):
        ok, reason = _validate('info', 'Server version disclosed: Apache/2.4.41')
        assert ok


class TestStrengthenedSecretDetection:
    """Rule 8 hardening: known example tokens + low-variety values."""

    def test_aws_example_access_key_rejected(self):
        ok, reason = _validate('high', 'API Key Exposed',
                               details='Value: AKIAIOSFODNN7EXAMPLE', confidence='high')
        assert not ok

    def test_known_hex_token_rejected(self):
        ok, reason = _validate('high', 'Secret Exposed',
                               details='Value: 1234567890abcdef1234567890abcdef', confidence='high')
        assert not ok
        assert 'known' in reason.lower() or 'entropy' in reason.lower()

    def test_all_same_char_value_rejected(self):
        ok, reason = _validate('high', 'Credential Found',
                               details='Value: aaaaaaaaaaaaaaaaaaaa', confidence='high')
        assert not ok
        assert 'variety' in reason.lower()

    def test_real_high_entropy_secret_passes(self):
        ok, reason = _validate('high', 'API Key Exposed',
                               details='Value: x9R2$mK7!pQ4zW1nL8vB3jH5', confidence='high')
        assert ok

    def test_redacted_marker_rejected(self):
        ok, reason = _validate('high', 'Credential Exposed',
                               details='Value: REDACTED_placeholder_value', confidence='high')
        assert not ok
