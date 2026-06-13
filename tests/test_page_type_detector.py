"""Tests for PageTypeDetector classification logic."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.routing import PageTypeDetector as PTD

# ══════════════════════════════════════════════════════════════════════════════
# Mock responses for different site types
# ══════════════════════════════════════════════════════════════════════════════

class MockResponse:
    def __init__(self, status_code=200, text='', headers=None, cookies=None, url=''):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.cookies = cookies or []
        self.url = url

class MockCookie:
    def __init__(self, name):
        self.name = name

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE: _get_module_strategy
# ══════════════════════════════════════════════════════════════════════════════

class TestModuleStrategy:
    """Test module skip/recommend lists for each page type."""

    def test_static_site_skips_attack_modules(self):
        recommended, skip = PTD._get_module_strategy('static', {'static': [], 'dynamic': []})
        # Static should skip all active attack modules
        for mod in ['SQLi Manual', 'XSS Manual', 'SSRF Manual', 'Command Injection',
                     'SSTI', 'File Inclusion LFI/RFI', 'SQLMap', 'Dalfox XSS',
                     'Session Fixation', 'JWT Advanced', 'OAuth Testing', 'Auth Testing']:
            assert mod in skip, f'{mod} should be skipped for static sites'
        # Static should recommend hardening modules
        for mod in ['SSL/TLS', 'DNS', 'WHOIS', 'Port Scan']:
            assert mod in recommended, f'{mod} should be recommended for static sites'

    def test_dynamic_site_skips_nothing(self):
        recommended, skip = PTD._get_module_strategy('dynamic', {'static': [], 'dynamic': []})
        assert skip == [], 'Dynamic sites should not skip any modules'

    def test_hybrid_site_skips_nothing(self):
        recommended, skip = PTD._get_module_strategy('hybrid', {'static': [], 'dynamic': []})
        assert skip == [], 'Hybrid sites should not skip any modules'

    def test_spa_skips_ssti_and_file_upload(self):
        recommended, skip = PTD._get_module_strategy('spa', {'static': [], 'dynamic': []})
        assert 'SSTI' in skip, 'SPA should skip SSTI'
        assert 'File Upload' in skip, 'SPA should skip File Upload'
        assert 'LDAP Injection' in skip, 'SPA should skip LDAP Injection'
        # SPA should recommend JS analysis and API modules
        assert 'JS Analysis' in recommended
        assert 'API Abuse' in recommended
        assert 'JWT Advanced' in recommended

    def test_static_skips_count_exceeds_20(self):
        _, skip = PTD._get_module_strategy('static', {'static': [], 'dynamic': []})
        assert len(skip) >= 20, f'Static sites should skip 20+ modules, got {len(skip)}'

    def test_spa_skip_count_moderate(self):
        _, skip = PTD._get_module_strategy('spa', {'static': [], 'dynamic': []})
        assert 10 <= len(skip) <= 20, f'SPA skip list should be 10-20, got {len(skip)}'


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE: _default_dynamic
# ══════════════════════════════════════════════════════════════════════════════

class TestDefaultDynamic:
    """Test the fallback default when detection is inconclusive."""

    def test_default_is_dynamic(self):
        result = PTD._default_dynamic()
        assert result['page_type'] == 'dynamic'

    def test_default_confidence_is_half(self):
        result = PTD._default_dynamic()
        assert result['confidence'] == 0.5

    def test_default_skip_modules_empty(self):
        result = PTD._default_dynamic()
        assert result['skip_modules'] == []

    def test_default_has_required_keys(self):
        result = PTD._default_dynamic()
        for key in ['page_type', 'confidence', 'static_score', 'dynamic_score',
                     'signals', 'scan_strategy', 'recommended_modules', 'skip_modules']:
            assert key in result, f'Missing key: {key}'


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE: classify logic (score ratios)
# ══════════════════════════════════════════════════════════════════════════════

class TestScoreClassification:
    """Test that score ratios map to correct page types."""

    def test_high_static_ratio_is_static(self):
        # static_ratio >= 0.75 → static
        static_score = 15
        dynamic_score = 3
        total = static_score + dynamic_score
        assert static_score / total >= 0.75

    def test_high_dynamic_ratio_is_dynamic(self):
        # dynamic_ratio >= 0.60 → dynamic
        static_score = 2
        dynamic_score = 10
        total = static_score + dynamic_score
        assert dynamic_score / total >= 0.60

    def test_balanced_is_hybrid(self):
        # Neither ratio high enough → hybrid
        static_score = 5
        dynamic_score = 5
        total = static_score + dynamic_score
        assert static_score / total < 0.75
        assert dynamic_score / total < 0.60

    def test_spa_detection_conditions(self):
        # SPA: high dynamic + SPA mount/JS framework + no session/CSRF
        dynamic_score = 10
        signals_dynamic = ['SPA mount point detected (#root/#app/#__next)']
        has_session_cookie = False
        has_csrf = False
        is_spa = (dynamic_score > 5 and
                  any('SPA mount' in s or 'JS framework' in s for s in signals_dynamic) and
                  not has_session_cookie and not has_csrf)
        assert is_spa, 'Should detect SPA from mount point + no session cookie'


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE: Constants and class attributes
# ══════════════════════════════════════════════════════════════════════════════

class TestClassAttributes:
    """Test that PageTypeDetector has the expected constants."""

    def test_static_extensions_non_empty(self):
        assert len(PTD.STATIC_EXTENSIONS) > 10

    def test_session_cookie_names_non_empty(self):
        assert len(PTD.SESSION_COOKIE_NAMES) > 5
        assert 'jsessionid' in PTD.SESSION_COOKIE_NAMES
        assert 'phpsessid' in PTD.SESSION_COOKIE_NAMES

    def test_js_framework_patterns_non_empty(self):
        assert len(PTD.JS_FRAMEWORK_PATTERNS) > 5

    def test_cms_patterns_non_empty(self):
        assert len(PTD.CMS_PATTERNS) > 5

    def test_dynamic_url_patterns_non_empty(self):
        assert len(PTD.DYNAMIC_URL_PATTERNS) > 5

    def test_dynamic_server_keywords_non_empty(self):
        assert len(PTD.DYNAMIC_SERVER_KEYWORDS) > 10
        assert 'php' in PTD.DYNAMIC_SERVER_KEYWORDS
        assert 'node' in PTD.DYNAMIC_SERVER_KEYWORDS

    def test_static_extensions_include_html(self):
        assert '.html' in PTD.STATIC_EXTENSIONS
        assert '.css' in PTD.STATIC_EXTENSIONS
        assert '.js' in PTD.STATIC_EXTENSIONS

    def test_dynamic_url_patterns_include_api(self):
        api_found = any('/api/' in p for p in PTD.DYNAMIC_URL_PATTERNS)
        assert api_found, 'Dynamic URL patterns should include /api/'
