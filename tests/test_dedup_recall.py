"""Duplicate-positive collapse + param-extraction convergence.

Reproduces the reported bug: several SQLi detectors emit the same underlying
vulnerability with different titles / asset URLs / parameter wording, and the
old fingerprint let them through as separate findings. These tests prove the
duplicates now collapse to one while genuinely distinct findings stay separate.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.validation import fingerprint, _extract_param
import scanner.findings as findings
from scanner.state import scan_state, LOCK


@pytest.fixture(autouse=True)
def _clean_state():
    with LOCK:
        scan_state['findings'] = []
        scan_state['stats'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        scan_state['finding_status'] = {}
        scan_state['scan_type'] = 'web'
    yield
    with LOCK:
        scan_state['findings'] = []


# ── Param extraction converges across detector styles ─────────────────────────

class TestParamExtraction:

    def test_from_parameter_line(self):
        assert _extract_param('Error-based SQL injection', 'https://x.com/p',
                              'Parameter: id (MySQL)') == 'id'

    def test_from_title_via(self):
        assert _extract_param('Error-based SQL injection via uid (MySQL)',
                              'https://x.com/p', '') == 'uid'

    def test_from_asset_query(self):
        assert _extract_param('SQL Injection Confirmed', 'https://x.com/p?id=1', '') == 'id'

    def test_from_details_query(self):
        assert _extract_param('SQLi', 'https://x.com/p',
                              'Exploit: sqlmap -u "https://x.com/p?id=1"') == 'id'

    def test_none_when_absent(self):
        assert _extract_param('Some finding', 'https://x.com/p', 'no param here') == ''


# ── Duplicate collapse ────────────────────────────────────────────────────────

class TestDuplicateCollapse:

    def test_manual_and_sqlmap_collapse_to_one(self):
        # Manual error-based finding names the parameter…
        f1 = findings.add_finding(
            'critical', 'Error-based SQL injection via id (MySQL)',
            asset='https://shop.test/item.php?id=1', confidence='high',
            details='Parameter: id\nConfirmed: error appears with payload')
        # …sqlmap-confirmed finding names no parameter but same endpoint.
        f2 = findings.add_finding(
            'critical', 'SQL Injection Confirmed: https://shop.test/item.php?id=1',
            asset='https://shop.test/item.php?id=1', confidence='high',
            details='Type: SQL Injection (sqlmap confirmed)\nConfirmed: injectable')
        with LOCK:
            sqli = [x for x in scan_state['findings'] if 'sql' in x['title'].lower()]
        assert len(sqli) == 1, f'expected 1 merged SQLi finding, got {len(sqli)}'
        assert f1 is not None and f2 is not None

    def test_distinct_params_stay_separate(self):
        findings.add_finding('critical', 'Error-based SQL injection via id',
                             asset='https://shop.test/item.php?id=1', confidence='high',
                             details='Parameter: id\nConfirmed: error pattern observed')
        findings.add_finding('critical', 'Error-based SQL injection via category',
                             asset='https://shop.test/item.php?category=1', confidence='high',
                             details='Parameter: category\nConfirmed: error pattern observed')
        with LOCK:
            sqli = [x for x in scan_state['findings'] if 'sql' in x['title'].lower()]
        assert len(sqli) == 2, 'distinct parameters must remain distinct findings'

    def test_different_classes_never_merge(self):
        findings.add_finding('critical', 'Error-based SQL injection via id',
                             asset='https://shop.test/p?id=1', confidence='high',
                             details='Parameter: id\nConfirmed: error pattern observed')
        findings.add_finding('high', 'Reflected XSS',
                             asset='https://shop.test/p?id=1', confidence='high',
                             details='Parameter: id\nConfirmed: alert(1) executed\nplaywright executed')
        with LOCK:
            titles = [x['title'].lower() for x in scan_state['findings']]
        assert any('sql' in t for t in titles) and any('xss' in t for t in titles)
