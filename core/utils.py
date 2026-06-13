"""Core utility functions: helpers, external tool detection, subprocess runner."""
import os
import ipaddress
import shutil
import subprocess
import time
import ssl
import socket
from urllib.parse import urlparse

try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    req_lib = None
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    BeautifulSoup = None

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from cvss import CVSS3
    CVSS3_AVAILABLE = True
except ImportError:
    CVSS3_AVAILABLE = False
    CVSS3 = None

try:
    import sqlite3 as sqlite3_mod
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False
    sqlite3_mod = None


def _safe_str(val, default=''):
    if val is None:
        return default
    return val if isinstance(val, str) else str(val)


def _safe_int(val, default=0):
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _find_tool(name):
    """Return the full path to an external tool binary, or None."""
    path = shutil.which(name)
    if path:
        return path
    extra = [
        '/usr/local/bin', '/usr/bin', '/bin',
        os.path.expanduser('~/go/bin'),
        os.path.expanduser('~/.local/bin'),
        '/opt/homebrew/bin',
    ]
    for d in extra:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _run_tool(cmd, timeout=45, input=None):
    """Run an external tool subprocess. Returns (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=input,
            env={**os.environ, 'PYTHONUNBUFFERED': '1'},
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', 'timeout', 1
    except FileNotFoundError:
        return '', f'tool not found: {cmd[0]}', 127
    except Exception as e:
        return '', str(e), 1


# ── SSRF protection ───────────────────────────────────────────────────────

_IMDS_IPS = {'169.254.169.254', 'fd00:ec2::254', '169.254.170.2'}  # AWS / Azure / ECS


def _is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # NAT64 prefix (RFC 6052) — extract embedded IPv4 and check that
    if ip.version == 6 and (ipaddress.ip_network('64:ff9b::/96', strict=False)
                            .overlaps(ipaddress.ip_network(str(ip) + '/128'))):
        embedded_v4 = '.'.join(str(int(ip) >> (8 * (3 - i)) & 0xFF) for i in range(4))
        try:
            return _is_private_ip(embedded_v4)
        except Exception:
            return False
    # 2001:db8::/32 is docs-only, not private
    if ip.version == 6 and ip in ipaddress.ip_network('2001:db8::/32'):
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _check_target_for_ssrf(target, allow_private=None):
    """Returns (error_message_or_None, warning_message_or_None).

    allow_private: tri-state. None → legacy env behaviour (ALLOW_PRIVATE_TARGETS);
    True/False → caller-supplied (e.g. driven by the active scope contract).
    IMDS endpoints are blocked regardless.
    """
    if allow_private is None:
        allow_private = os.environ.get('ALLOW_PRIVATE_TARGETS', '0') == '1'
    try:
        ip = ipaddress.ip_address(target)
        if str(ip) in _IMDS_IPS:
            return f'Scan target {target} is a cloud metadata endpoint and is always blocked', None
        if _is_private_ip(str(ip)) and not allow_private:
            return f'Scan target {ip} is in a private/reserved range. Set ALLOW_PRIVATE_TARGETS=1 to allow.', None
        return None, None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
        for _fam, *_rest, sockaddr in infos:
            ip_str = sockaddr[0]
            if ip_str in _IMDS_IPS:
                return f'Scan target {target} resolves to a cloud metadata endpoint and is blocked', None
            if _is_private_ip(ip_str) and not allow_private:
                return f'Scan target {target} resolves to private/reserved IP {ip_str}. Set ALLOW_PRIVATE_TARGETS=1 to allow.', None
        return None, None
    except Exception as e:
        return f'Could not resolve scan target: {e}', None


def validate_webhook_url(url):
    """Validate a webhook URL: must be http(s) and resolve to a public IP."""
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ('http', 'https'):
        return False
    host = p.hostname or ''
    if not host:
        return False
    if _is_private_ip(host) or host in _IMDS_IPS:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for _fam, *_rest, sockaddr in infos:
        ip_str = sockaddr[0]
        if ip_str in _IMDS_IPS or _is_private_ip(ip_str):
            return False
    return True


def run_nvd_lookup(technology, version=''):
    """Query NVD 2.0 API for CVEs affecting a technology. Returns list of dicts."""
    results = []
    if not technology or not REQUESTS_AVAILABLE:
        return results
    keyword = f'{technology} {version}'.strip() if version else technology
    try:
        from core.logger import log as _log
        r = req_lib.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params={'keywordSearch': keyword, 'resultsPerPage': 10},
            timeout=15, verify=True,
        )
        if r.status_code == 403:
            time.sleep(6)
            r = req_lib.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params={'keywordSearch': keyword, 'resultsPerPage': 10},
                timeout=15, verify=False,
            )
        if r.status_code == 200:
            for item in r.json().get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', '')
                desc = next((d['value'] for d in cve_data.get('descriptions', [])
                             if d.get('language') == 'en'), '')
                cvss_score = 0.0
                for mk in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                    mlist = cve_data.get('metrics', {}).get(mk)
                    if mlist:
                        cvss_score = mlist[0].get('cvssData', {}).get('baseScore', 0.0)
                        break
                if cve_id:
                    results.append({'cve': cve_id, 'cvss': cvss_score, 'desc': desc[:200]})
    except Exception as e:
        try:
            from core.logger import log as _log
            _log('warn', f'[NVD] Lookup failed for {keyword}: {e}')
        except Exception:
            pass
    return results
