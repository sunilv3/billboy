"""Container, cloud, Kubernetes, and IaC security modules."""
import re
import json
import os
import time
import secrets
from datetime import datetime
from core.utils import _find_tool, _run_tool, req_lib, REQUESTS_AVAILABLE
from core.logger import log
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding, set_progress

def run_cloud_module(target):
    log('info', f'[CLOUD] Performing comprehensive cloud asset discovery for {target}')
    cloud_data = {
        'aws_assets': [],
        'azure_assets': [],
        'gcp_assets': [],
        'digital_ocean_assets': [],
        'cloudflare_assets': [],
        'exposed_buckets': [],
        'cloud_services': [],
        'recommendations': [],
        'summary': {}
    }
    sanitized = re.sub(r'[^a-zA-Z0-9]', '', target.split('.')[0])

    if not REQUESTS_AVAILABLE:
        log('warn', '[CLOUD] requests library not available')
        with LOCK:
            scan_state['cloud_data'] = cloud_data
        set_progress('cloud', 100)
        return

    # ── AWS S3 Bucket Discovery ──
    log('info', '[CLOUD] Checking AWS S3 buckets')
    bucket_names = [
        f'{sanitized}', f'{sanitized}-backup', f'{sanitized}-data',
        f'{sanitized}-assets', f'{sanitized}-media', f'{sanitized}-public',
        f'{sanitized}-private', f'{sanitized}-uploads', f'{sanitized}-files',
        f'{sanitized}-static', f'{sanitized}-logs', f'{sanitized}-config',
        f'{sanitized}-staging', f'{sanitized}-prod', f'{sanitized}-dev',
        f'{sanitized}-test', f'{sanitized}-archive', f'{sanitized}-temp',
    ]
    for name in bucket_names:
        if not scan_state.get('scanning'):
            break
        aws_endpoints = [
            f'https://{name}.s3.amazonaws.com',
            f'https://{name}.s3.us-east-1.amazonaws.com',
            f'https://{name}.s3.us-west-2.amazonaws.com',
            f'https://s3.amazonaws.com/{name}',
        ]
        for endpoint in aws_endpoints:
            try:
                r = req_lib.get(endpoint, timeout=5, verify=False)
                if r.status_code in (200, 403):
                    is_public = r.status_code == 200
                    bucket_info = {
                        'bucket': name,
                        'provider': 'AWS S3',
                        'endpoint': endpoint,
                        'public': is_public,
                        'readable': is_public,
                        'status_code': r.status_code
                    }
                    cloud_data['aws_assets'].append(bucket_info)
                    if is_public:
                        cloud_data['exposed_buckets'].append(bucket_info)
                        add_finding('critical', f'Publicly accessible AWS S3 bucket: {name}',
                            sub=f'AWS S3 bucket {name} is publicly accessible',
                            asset=endpoint, cvss='8.5', exploit='PUBLIC', owasp='A01', mitre='T1613',
                            details=f'Bucket URL: {endpoint}\nStatus: {r.status_code}\nContent-Length: {len(r.content)}')
                        log('err', f'[CLOUD] PUBLIC AWS S3: {name}')
                    else:
                        log('warn', f'[CLOUD] AWS S3 EXISTS (restricted): {name}')
                    break
            except Exception:
                pass

    # ── Azure Blob Storage Discovery ──
    log('info', '[CLOUD] Checking Azure Blob Storage')
    azure_names = [f'{sanitized}', f'{sanitized}backup', f'{sanitized}data', f'{sanitized}public', f'{sanitized}logs']
    for name in azure_names:
        if not scan_state.get('scanning'):
            break
        azure_endpoints = [
            f'https://{name}.blob.core.windows.net',
            f'https://{name}.blob.core.windows.net/?comp=list',
        ]
        for endpoint in azure_endpoints:
            try:
                r = req_lib.get(endpoint, timeout=5, verify=False)
                if r.status_code in (200, 403):
                    is_public = r.status_code == 200
                    blob_info = {
                        'container': name,
                        'provider': 'Azure Blob',
                        'endpoint': endpoint,
                        'public': is_public,
                        'status_code': r.status_code
                    }
                    cloud_data['azure_assets'].append(blob_info)
                    if is_public:
                        cloud_data['exposed_buckets'].append(blob_info)
                        add_finding('critical', f'Publicly accessible Azure Blob container: {name}',
                            sub=f'Azure Blob container {name} is publicly accessible',
                            asset=endpoint, cvss='8.5', exploit='PUBLIC', owasp='A01', mitre='T1613')
                        log('err', f'[CLOUD] PUBLIC Azure Blob: {name}')
                    break
            except Exception:
                pass

    # ── Google Cloud Storage Discovery ──
    log('info', '[CLOUD] Checking Google Cloud Storage')
    gcp_names = [f'{sanitized}', f'{sanitized}-backup', f'{sanitized}-data', f'{sanitized}-public']
    for name in gcp_names:
        if not scan_state.get('scanning'):
            break
        gcp_endpoint = f'https://{name}.storage.googleapis.com'
        try:
            r = req_lib.get(gcp_endpoint, timeout=5, verify=False)
            if r.status_code in (200, 403):
                is_public = r.status_code == 200
                gcp_info = {
                    'bucket': name,
                    'provider': 'Google Cloud',
                    'endpoint': gcp_endpoint,
                    'public': is_public,
                    'status_code': r.status_code
                }
                cloud_data['gcp_assets'].append(gcp_info)
                if is_public:
                    cloud_data['exposed_buckets'].append(gcp_info)
                    add_finding('critical', f'Publicly accessible GCP bucket: {name}',
                        sub=f'Google Cloud bucket {name} is publicly accessible',
                        asset=gcp_endpoint, cvss='8.5', exploit='PUBLIC', owasp='A01', mitre='T1613')
                    log('err', f'[CLOUD] PUBLIC GCP: {name}')
        except Exception:
            pass

    # ── DigitalOcean Spaces Discovery ──
    log('info', '[CLOUD] Checking DigitalOcean Spaces')
    do_names = [f'{sanitized}', f'{sanitized}-backup', f'{sanitized}-data']
    for name in do_names:
        if not scan_state.get('scanning'):
            break
        do_endpoint = f'https://{name}.nyc3.digitaloceanspaces.com'
        try:
            r = req_lib.get(do_endpoint, timeout=5, verify=False)
            if r.status_code in (200, 403):
                is_public = r.status_code == 200
                do_info = {
                    'bucket': name,
                    'provider': 'DigitalOcean Spaces',
                    'endpoint': do_endpoint,
                    'public': is_public,
                    'status_code': r.status_code
                }
                cloud_data['digital_ocean_assets'].append(do_info)
                if is_public:
                    cloud_data['exposed_buckets'].append(do_info)
                    add_finding('critical', f'Publicly accessible DigitalOcean Space: {name}',
                        sub=f'DigitalOcean Space {name} is publicly accessible',
                        asset=do_endpoint, cvss='8.5', exploit='PUBLIC', owasp='A01', mitre='T1613')
        except Exception:
            pass

    # ── Cloudflare R2 Discovery ──
    log('info', '[CLOUD] Checking Cloudflare R2')
    r2_names = [f'{sanitized}', f'{sanitized}-backup']
    for name in r2_names:
        if not scan_state.get('scanning'):
            break
        r2_endpoint = f'https://{name}.r2.cloudflarestorage.com'
        try:
            r = req_lib.get(r2_endpoint, timeout=5, verify=False)
            if r.status_code in (200, 403):
                is_public = r.status_code == 200
                r2_info = {
                    'bucket': name,
                    'provider': 'Cloudflare R2',
                    'endpoint': r2_endpoint,
                    'public': is_public,
                    'status_code': r.status_code
                }
                cloud_data['cloudflare_assets'].append(r2_info)
                if is_public:
                    cloud_data['exposed_buckets'].append(r2_info)
                    add_finding('critical', f'Publicly accessible Cloudflare R2 bucket: {name}',
                        sub=f'Cloudflare R2 bucket {name} is publicly accessible',
                        asset=r2_endpoint, cvss='8.5', exploit='PUBLIC', owasp='A01', mitre='T1613')
        except Exception:
            pass

    # ── Cloud Service Detection ──
    log('info', '[CLOUD] Detecting cloud services in use')
    cloud_services = []
    with LOCK:
        techs = list(scan_state.get('tech_data', {}).get('technologies', []))
    cloud_keywords = {
        'aws': ['amazon', 'aws', 'cloudfront', 's3', 'ec2', 'elastic', 'beanstalk'],
        'azure': ['microsoft', 'azure', 'office365', 'microsoft.com'],
        'gcp': ['google', 'gcloud', 'firebase', 'googleapis'],
        'cloudflare': ['cloudflare', 'cf-', 'cf_'],
        'fastly': ['fastly'],
        'akamai': ['akamai'],
    }
    for t in techs:
        name = t.get('name', '').lower()
        for provider, keywords in cloud_keywords.items():
            if any(kw in name for kw in keywords):
                cloud_services.append({
                    'service': name,
                    'provider': provider,
                    'version': t.get('version', ''),
                    'type': 'detected'
                })
    cloud_data['cloud_services'] = cloud_services

    # ── Recommendations ──
    recommendations = []
    if cloud_data['exposed_buckets']:
        recommendations.append({
            'priority': 'critical',
            'action': 'Immediately restrict public access to exposed buckets',
            'detail': f'{len(cloud_data["exposed_buckets"])} publicly accessible buckets found'
        })
    if len(cloud_data['aws_assets']) > 5:
        recommendations.append({
            'priority': 'medium',
            'action': 'Review AWS S3 bucket policies',
            'detail': f'{len(cloud_data["aws_assets"])} S3 buckets discovered'
        })
    cloud_data['recommendations'] = recommendations

    # ── Summary ──
    total_assets = (len(cloud_data['aws_assets']) + len(cloud_data['azure_assets']) +
                   len(cloud_data['gcp_assets']) + len(cloud_data['digital_ocean_assets']) +
                   len(cloud_data['cloudflare_assets']))
    cloud_data['summary'] = {
        'total_cloud_assets': total_assets,
        'aws_buckets': len(cloud_data['aws_assets']),
        'azure_containers': len(cloud_data['azure_assets']),
        'gcp_buckets': len(cloud_data['gcp_assets']),
        'digital_ocean_spaces': len(cloud_data['digital_ocean_assets']),
        'cloudflare_r2_buckets': len(cloud_data['cloudflare_assets']),
        'exposed_buckets': len(cloud_data['exposed_buckets']),
        'cloud_services_detected': len(cloud_data['cloud_services']),
        'overall_risk': 'critical' if cloud_data['exposed_buckets'] else 'medium' if total_assets > 0 else 'low',
        'scan_mode': 'active'
    }

    log('ok', f'[CLOUD] Discovery complete: {total_assets} assets, {len(cloud_data["exposed_buckets"])} exposed')
    with LOCK:
        scan_state['cloud_data'] = cloud_data
    set_progress('cloud', 100)

# ─── SUPPLY CHAIN MODULE ──────────────────────────────────────────────────────
KNWON_VULN_PACKAGES = {
    'lodash': {'cve': 'CVE-2021-23337', 'cvss': '7.4'},
    'axios': {'cve': 'CVE-2023-45857', 'cvss': '7.5'},
    'express': {'cve': 'CVE-2023-3420', 'cvss': '5.3'},
    'django': {'cve': 'CVE-2024-27351', 'cvss': '6.5'},
    'flask': {'cve': 'CVE-2023-30861', 'cvss': '5.3'},
    'nginx': {'cve': 'CVE-2024-24989', 'cvss': '7.5'},
    'apache': {'cve': 'CVE-2023-25690', 'cvss': '6.5'},
    'openssl': {'cve': 'CVE-2023-3817', 'cvss': '5.5'},
        'php': {'cve': 'CVE-2024-2756', 'cvss': '7.5'},
    'mysql': {'cve': 'CVE-2023-21971', 'cvss': '4.9'},
    'redis': {'cve': 'CVE-2023-41056', 'cvss': '6.5'},
    'mongodb': {'cve': 'CVE-2024-1359', 'cvss': '5.3'},
    'tomcat': {'cve': 'CVE-2024-21733', 'cvss': '7.5'},
    'kubernetes': {'cve': 'CVE-2024-3177', 'cvss': '6.5'},
    'docker': {'cve': 'CVE-2024-32473', 'cvss': '4.5'},
}



def run_cloud_vm_module(target):
    """Comprehensive cloud VM vulnerability assessment.
    
    Tests 8 attack vectors for cloud environments:
    1. Cloud provider detection (DNS/HTTP headers/tech fingerprint)
    2. IMDS SSRF testing (test SSRF params that reach metadata endpoints)
    3. Metadata enumeration (extract instance metadata via confirmed SSRF)
    4. Cloud credential detection (AWS keys, GCP SA, Azure tokens in responses)
    5. Cloud service exposure (RDS, ElastiCache, ES, internal services)
    6. Security group analysis (test for overly permissive inbound rules)
    7. Cloud IAM role analysis (test for overly permissive role policies)
    8. Cloud network analysis (VPC/subnet detection, internal host discovery)
    """
    log('info', f'[CLOUD-VM] Starting cloud VM vulnerability assessment for {target}')
    base_url = f'https://{target}'
    cloud_vm_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        cloud_data = dict(scan_state.get('cloud_data', {}))
        ports_data = list(scan_state.get('port_data', []))

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 1: CLOUD PROVIDER DETECTION
    # ═══════════════════════════════════════════════════════════════════════════════
    log('info', '[CLOUD-VM] Vector 1: Detecting cloud provider')
    cloud_provider = None
    provider_evidence = []

    try:
        r = req_lib.get(base_url, timeout=10, verify=False, allow_redirects=True)
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}

        # AWS detection
        aws_headers = ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amzn-requestid',
                       'x-amz-apigw-id', 'x-amz-date', 'x-amz-server-side-encryption',
                       'x-amz-version-id', 'x-amz-rid', 'server']
        for h in aws_headers:
            if h in headers_lower:
                if 'amazon' in headers_lower.get(h, '') or 'aws' in headers_lower.get(h, ''):
                    cloud_provider = 'AWS'
                    provider_evidence.append(f'Header: {h}={r.headers[h][:50]}')

        # Azure detection
        azure_headers = ['x-azure-ref', 'x-ms-request-id', 'x-ms-version',
                        'x-ms-correlation-request-id', 'x-azure-fdid', 'x-azure-ref']
        for h in azure_headers:
            if h in headers_lower:
                cloud_provider = 'Azure'
                provider_evidence.append(f'Header: {h}={r.headers[h][:50]}')

        # GCP detection
        gcp_headers = ['x-goog-generation', 'x-goog-metageneration', 'x-guploader-uploadid',
                       'x-cloud-trace-context', 'server']
        for h in gcp_headers:
            val = headers_lower.get(h, '')
            if 'gws' in val or 'google' in val or 'gcp' in val:
                cloud_provider = 'GCP'
                provider_evidence.append(f'Header: {h}={r.headers[h][:50]}')

        # Cloudflare detection
        if 'cf-ray' in headers_lower or 'cf-cache-status' in headers_lower:
            provider_evidence.append(f'Cloudflare CDN detected: cf-ray={r.headers.get("cf-ray", "")}')

        # Server header analysis
        server = headers_lower.get('server', '')
        if 'amazonaws' in server or 'awselb' in server or 'amazons3' in server:
            cloud_provider = cloud_provider or 'AWS'
            provider_evidence.append(f'Server: {server[:50]}')
        elif 'microsoft-iis' in server and any(k in str(r.headers) for k in ['x-ms-', 'x-azure']):
            cloud_provider = cloud_provider or 'Azure'
            provider_evidence.append(f'Server: {server[:50]}')
        elif 'gws' in server or 'google' in server:
            cloud_provider = cloud_provider or 'GCP'
            provider_evidence.append(f'Server: {server[:50]}')

        # DNS-based detection
        import socket
        try:
            resolved = socket.getaddrinfo(target, None)
            for fam, *_, sockaddr in resolved[:3]:
                ip = sockaddr[0]
                # AWS IP ranges: 52.x.x.x, 54.x.x.x, 3.x.x.x, 18.x.x.x, etc.
                if ip.startswith(('52.', '54.', '3.', '18.', '99.', '13.', '184.', '204.')):
                    cloud_provider = cloud_provider or 'AWS (IP range)'
                    provider_evidence.append(f'Resolved IP {ip} in AWS range')
                # Azure IP ranges: 13.64.x.x, 20.x.x.x, 40.x.x.x, etc.
                elif ip.startswith(('13.64.', '20.', '40.', '52.138.', '104.208.')):
                    cloud_provider = cloud_provider or 'Azure (IP range)'
                    provider_evidence.append(f'Resolved IP {ip} in Azure range')
                # GCP IP ranges: 34.x.x.x, 35.x.x.x, etc.
                elif ip.startswith(('34.', '35.', '130.211.', '146.148.')):
                    cloud_provider = cloud_provider or 'GCP (IP range)'
                    provider_evidence.append(f'Resolved IP {ip} in GCP range')
        except Exception:
            pass

        if cloud_provider:
            log('ok', f'[CLOUD-VM] Cloud provider detected: {cloud_provider}')
        else:
            log('info', '[CLOUD-VM] No cloud provider detected from public response')

    except Exception as e:
        log('warn', f'[CLOUD-VM] Provider detection error: {e}')

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 2: IMDS SSRF TESTING
    # Test SSRF-vulnerable parameters to see if they can reach cloud metadata
    # ═══════════════════════════════════════════════════════════════════════════════
    log('info', '[CLOUD-VM] Vector 2: IMDS SSRF testing')

    # Cloud metadata endpoints (IMDSv1 and IMDSv2)
    metadata_targets = {
        'AWS': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/meta-data/instance-id',
            'http://169.254.169.254/latest/meta-data/instance-type',
            'http://169.254.169.254/latest/meta-data/ami-id',
            'http://169.254.169.254/latest/meta-data/placement/region',
            'http://169.254.169.254/latest/meta-data/network/interfaces/macs/',
        ],
        'Azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
        ],
        'GCP': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/id',
            'http://metadata.google.internal/computeMetadata/v1/instance/zone',
            'http://169.254.169.254/computeMetadata/v1/',
        ],
    }

    # SSRF-vulnerable parameters to test
    ssrf_params = ['url', 'uri', 'link', 'src', 'href', 'dest', 'target',
                   'callback', 'webhook', 'proxy', 'fetch', 'load',
                   'redirect', 'return', 'next', 'continue', 'goto',
                   'document', 'file', 'path', 'img', 'image', 'media']

    ssrf_confirmed = False
    ssrf_param_used = None
    metadata_response = None

    # Use discovered parameters from crawl
    with LOCK:
        discovered_params = disc.get('parameters', [])

    # Also test common SSRF parameters
    all_params = list(set(ssrf_params + discovered_params))

    for param in all_params[:20]:
        if ssrf_confirmed:
            break
        if not scan_state.get('scanning'):
            break

        # Test with AWS metadata (most common)
        test_url = f'{base_url}/?{param}=http://169.254.169.254/latest/meta-data/'
        try:
            r = req_lib.get(test_url, timeout=8, verify=False, allow_redirects=False)
            # Check for AWS metadata response indicators
            aws_indicators = ['ami-id', 'ami-launch-index', 'instance-id',
                             'instance-type', 'local-hostname', 'public-hostname',
                             'security-groups', 'iam/', 'placement/']
            if any(ind in r.text for ind in aws_indicators):
                ssrf_confirmed = True
                ssrf_param_used = param
                metadata_response = r.text
                cloud_vm_findings.append({
                    'type': 'IMDS_SSRF',
                    'provider': 'AWS',
                    'param': param,
                    'severity': 'critical'
                })
                log('err', f'[CLOUD-VM] IMDS SSRF CONFIRMED via param: {param}')

                add_finding(
                    'critical',
                    f'Cloud metadata SSRF via {param} parameter',
                    sub=f'Parameter {param} allows accessing AWS IMDS metadata endpoint',
                    asset=f'{base_url}/?{param}=http://169.254.169.254/latest/meta-data/',
                    cvss='10.0', owasp='A10', mitre='T1552',
                    details=f'SSRF Parameter: {param}\n'
                            f'Metadata Endpoint: http://169.254.169.254/latest/meta-data/\n'
                            f'Evidence: {r.text[:500]}\n'
                            f'Confirmed: AWS instance metadata accessible\n'
                            f'Recommendation: Restrict IMDSv1, enforce IMDSv2 with hop limit')
                break
        except Exception:
            pass

        # Test POST-based SSRF
        try:
            r2 = req_lib.post(base_url, data={param: 'http://169.254.169.254/latest/meta-data/'},
                             timeout=8, verify=False, allow_redirects=False)
            if any(ind in r2.text for ind in aws_indicators):
                ssrf_confirmed = True
                ssrf_param_used = f'POST:{param}'
                metadata_response = r2.text
                cloud_vm_findings.append({
                    'type': 'IMDS_SSRF_POST',
                    'provider': 'AWS',
                    'param': param,
                    'severity': 'critical'
                })
                log('err', f'[CLOUD-VM] IMDS SSRF CONFIRMED via POST param: {param}')

                add_finding(
                    'critical',
                    f'Cloud metadata SSRF via POST {param} parameter',
                    sub=f'POST parameter {param} allows accessing AWS IMDS metadata endpoint',
                    asset=base_url, cvss='10.0', owasp='A10', mitre='T1552',
                    details=f'SSRF Parameter: {param}\nMethod: POST\n'
                            f'Metadata Endpoint: http://169.254.169.254/latest/meta-data/\n'
                            f'Evidence: {r2.text[:500]}\n'
                            f'Confirmed: AWS instance metadata accessible via POST')
                break
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 3: METADATA ENUMERATION (if SSRF confirmed)
    # ═══════════════════════════════════════════════════════════════════════════════
    if ssrf_confirmed and metadata_response:
        log('info', '[CLOUD-VM] Vector 3: Enumerating cloud metadata via confirmed SSRF')
        param = ssrf_param_used.replace('POST:', '')

        metadata_paths = [
            ('instance-id', 'Instance ID'),
            ('instance-type', 'Instance Type'),
            ('ami-id', 'AMI ID'),
            ('hostname', 'Hostname'),
            ('local-hostname', 'Local Hostname'),
            ('public-hostname', 'Public Hostname'),
            ('local-ipv4', 'Private IP'),
            ('public-ipv4', 'Public IP'),
            ('iam/security-credentials/', 'IAM Role List'),
            ('placement/availability-zone', 'Availability Zone'),
            ('placement/region', 'Region'),
            ('network/interfaces/macs/', 'Network Interfaces'),
            ('services/domain', 'Domain'),
            ('services/state', 'Service State'),
        ]

        metadata_enum = {}
        for path, label in metadata_paths:
            if not scan_state.get('scanning'):
                break
            try:
                test_url = f'{base_url}/?{param}=http://169.254.169.254/latest/meta-data/{path}'
                r = req_lib.get(test_url, timeout=5, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.text.strip()) > 0:
                    metadata_enum[label] = r.text.strip()[:200]
                    log('info', f'[CLOUD-VM] Metadata enumerated: {label} = {r.text.strip()[:50]}')
            except Exception:
                pass

        if metadata_enum:
            details_text = '\n'.join([f'{k}: {v}' for k, v in metadata_enum.items()])
            add_finding(
                'critical',
                'Cloud instance metadata fully enumerable via SSRF',
                sub='Complete instance metadata exposed — enables credential theft and lateral movement',
                asset=base_url, cvss='10.0', owasp='A10', mitre='T1552',
                details=f'Enumerated Metadata:\n{details_text}\n'
                        f'Severity: CRITICAL — attacker can steal IAM credentials\n'
                        f'Recommendation: Enforce IMDSv2, set hop limit to 1')

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 4: CLOUD CREDENTIAL DETECTION
    # Scan responses for exposed cloud credentials
    # ═══════════════════════════════════════════════════════════════════════════════
    log('info', '[CLOUD-VM] Vector 4: Scanning for cloud credential exposure')
    import re as re_mod

    # Credential patterns
    credential_patterns = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key["\s:=]+[A-Za-z0-9/+=]{40}',
        'AWS Session Token': r'(?i)aws[_\-]?session[_\-]?token["\s:=]+[A-Za-z0-9/+=]{100,}',
        'GCP Service Account': r'"type"\s*:\s*"service_account"',
        'GCP API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Azure Connection String': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
        'Azure SAS Token': r'(?i)sig=[A-Za-z0-9%/+=]{43,}',
        'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
        'GitLab Token': r'glpat-[A-Za-z0-9\-_]{20,}',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
        'Generic API Key': r'(?i)api[_\-]?key["\s:=]+[A-Za-z0-9\-_]{20,}',
        'Private Key Block': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    }

    # Scan all discovered URLs and JS files for credentials
    scan_urls = []
    with LOCK:
        scan_urls.extend(disc.get('urls', [])[:10])
        scan_urls.extend(disc.get('js_files', [])[:5])
        scan_urls.extend(disc.get('sensitive_files', [])[:5])
    scan_urls.append(base_url)

    for url in scan_urls:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(url, timeout=8, verify=False)
            for cred_type, pattern in credential_patterns.items():
                matches = re_mod.findall(pattern, r.text)
                for match in matches[:2]:
                    # Skip common false positives
                    if match in ('AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7',
                                'your_api_key', 'example', 'test'):
                        continue
                    add_finding(
                        'critical',
                        f'Cloud credential exposed: {cred_type}',
                        sub=f'{cred_type} found in response from {urlparse(url).path}',
                        asset=url, cvss='9.1', owasp='A07', mitre='T1552',
                        details=f'Credential Type: {cred_type}\n'
                                f'Found in: {url}\n'
                                f'Value (redacted): {match[:20]}...{match[-4:]}\n'
                                f'Recommendation: Rotate credential immediately, remove from codebase')
                    cloud_vm_findings.append({'type': 'credential', 'cred_type': cred_type})
                    log('err', f'[CLOUD-VM] Credential found: {cred_type} in {url}')
                    break
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 5: CLOUD SERVICE EXPOSURE
    # Test for exposed internal cloud services
    # ═══════════════════════════════════════════════════════════════════════════════
    log('info', '[CLOUD-VM] Vector 5: Testing cloud service exposure')

    cloud_services_endpoints = [
        # AWS Services
        ('AWS RDS', 'https://{service}.amazonaws.com:3306', 'MySQL'),
        ('AWS RDS PostgreSQL', 'https://{service}.amazonaws.com:5432', 'PostgreSQL'),
        ('AWS ElastiCache', 'https://{service}.cache.amazonaws.com:6379', 'Redis'),
        ('AWS Elasticsearch', 'https://{service}.es.amazonaws.com:443', 'Elasticsearch'),
        ('AWS Lambda', 'https://lambda.{region}.amazonaws.com/2015-03-31/functions/', 'Lambda'),
        ('AWS SQS', 'https://sqs.{region}.amazonaws.com/', 'SQS'),
        ('AWS SNS', 'https://sns.{region}.amazonaws.com/', 'SNS'),
        # Azure Services
        ('Azure SQL', 'https://{service}.database.windows.net:1433', 'MSSQL'),
        ('Azure CosmosDB', 'https://{service}.documents.azure.com:443', 'CosmosDB'),
        ('Azure Redis', 'https://{service}.redis.cache.windows.net:6380', 'Redis'),
        # GCP Services
        ('GCP Cloud SQL', 'https://{service}:3306', 'MySQL'),
        ('GCP Firestore', 'https://firestore.googleapis.com/v1/', 'Firestore'),
    ]

    # Test discovered service names
    sanitized = re.sub(r'[^a-zA-Z0-9]', '', target.split('.')[0])
    service_names = [sanitized, f'{sanitized}-prod', f'{sanitized}-staging', f'{sanitized}-db']

    for service_name in service_names[:3]:
        if not scan_state.get('scanning'):
            break
        for svc_type, endpoint_template, svc_name in cloud_services_endpoints:
            try:
                endpoint = endpoint_template.replace('{service}', service_name).replace('{region}', 'us-east-1')
                r = req_lib.get(endpoint, timeout=5, verify=False)
                if r.status_code in (200, 403, 502):
                    # Verify it's actually the target's service, not just a generic AWS/Azure/GCP endpoint
                    resp_body = r.text.lower()
                    # Check for generic AWS/Azure/GCP error pages (not real service exposure)
                    is_generic_error = any(kw in resp_body for kw in [
                        'access denied', 'authorization failed', 'invalid access key',
                        'missing authentication token', 'null', '{}', '[]',
                        'no route to host', 'connection refused', 'service unavailable',
                    ])
                    # Check for actual service data indicators
                    has_service_data = any(kw in resp_body for kw in [
                        service_name.lower(), 'functionname', 'functionarn',
                        'instanceid', 'endpoint', 'hostname', 'address',
                        'port', 'status', 'configuration',
                    ])
                    if is_generic_error and not has_service_data:
                        log('info', f'[CLOUD-VM] {svc_type} endpoint responded but no actual service data — likely generic cloud API')
                        continue
                    add_finding(
                        'high',
                        f'Cloud service exposed: {svc_type} ({service_name})',
                        sub=f'{svc_type} endpoint accessible at {endpoint}',
                        asset=endpoint, cvss='7.5', owasp='A05', mitre='T1190',
                        details=f'Service: {svc_type}\n'
                                f'Endpoint: {endpoint}\n'
                                f'Response: {r.status_code}\n'
                                f'Response preview: {r.text[:200]}\n'
                                f'Recommendation: Restrict access to private VPC only')
                    cloud_vm_findings.append({'type': 'service_exposure', 'service': svc_type})
                    log('warn', f'[CLOUD-VM] Cloud service exposed: {svc_type}')
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 6: SECURITY GROUP ANALYSIS
    # Test for overly permissive inbound rules by port probing
    # ═══════════════════════════════════════════════════════════════════════════════
    log('info', '[CLOUD-VM] Vector 6: Analyzing security groups')

    # Ports that should NOT be publicly exposed in a well-configured cloud environment
    restricted_ports = {
        22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL',
        6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch',
        1433: 'MSSQL', 21: 'FTP', 23: 'Telnet', 5900: 'VNC',
        11211: 'Memcached', 9300: 'Elasticsearch',
    }

    import socket
    for port, service in restricted_ports.items():
        if not scan_state.get('scanning'):
            break
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                # Port is open — check if it's in the existing port scan data
                already_reported = any(p.get('port') == port for p in ports_data)
                if not already_reported:
                    add_finding(
                        'high',
                        f'Security group allows public access to {service} (port {port})',
                        sub=f'Cloud security group permits inbound {service} from the internet',
                        asset=f'{target}:{port}', cvss='7.5', owasp='A05', mitre='T1190',
                        details=f'Port: {port}\nService: {service}\n'
                                f'Status: Open to the internet\n'
                                f'Recommendation: Restrict security group to specific IP ranges')
                    cloud_vm_findings.append({'type': 'security_group', 'port': port, 'service': service})
                    log('warn', f'[CLOUD-VM] Security group allows {service} on port {port}')
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 7: CLOUD IAM ROLE ANALYSIS
    # If metadata is accessible, test for overly permissive IAM roles
    # ═══════════════════════════════════════════════════════════════════════════════
    if ssrf_confirmed and ssrf_param_used:
        log('info', '[CLOUD-VM] Vector 7: Testing IAM role permissions')
        param = ssrf_param_used.replace('POST:', '')

        try:
            # Get IAM role name
            test_url = f'{base_url}/?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
            r = req_lib.get(test_url, timeout=8, verify=False)
            if r.status_code == 200 and r.text.strip():
                role_name = r.text.strip().split('\n')[0]
                log('info', f'[CLOUD-VM] IAM role found: {role_name}')

                # Get role credentials
                cred_url = f'{base_url}/?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'
                r2 = req_lib.get(cred_url, timeout=8, verify=False)
                if r2.status_code == 200:
                    try:
                        creds = r2.json()
                        if 'AccessKeyId' in creds:
                            add_finding(
                                'critical',
                                f'IAM role credentials exposed: {role_name}',
                                sub=f'IAM role {role_name} credentials accessible via SSRF — '
                                    f'AccessKeyId: {creds["AccessKeyId"][:8]}...',
                                asset=base_url, cvss='10.0', owasp='A07', mitre='T1552',
                                details=f'Role: {role_name}\n'
                                        f'AccessKeyId: {creds.get("AccessKeyId", "")[:8]}...\n'
                                        f'Expiration: {creds.get("Expiration", "unknown")}\n'
                                        f'Recommendation: Reduce IAM role permissions, enforce IMDSv2')
                            cloud_vm_findings.append({
                                'type': 'iam_creds_exposed',
                                'role': role_name,
                                'access_key': creds.get('AccessKeyId', '')[:8]
                            })
                            log('err', f'[CLOUD-VM] IAM credentials exposed for role: {role_name}')
                    except Exception:
                        pass
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════════
    # VECTOR 8: CLOUD NETWORK ANALYSIS
    # Test for VPC/subnet information and internal host discovery
    # ═══════════════════════════════════════════════════════════════════════════════
    log('info', '[CLOUD-VM] Vector 8: Cloud network analysis')

    # Test for internal metadata via X-Forwarded-For bypass
    xff_payloads = [
        '169.254.169.254',
        '127.0.0.1',
        '0.0.0.0',
        '[::1]',
        'localhost',
    ]

    internal_endpoints = [
        '/admin', '/debug', '/internal', '/metrics', '/actuator',
        '/api/internal', '/health', '/status', '/info',
    ]

    for xff in xff_payloads[:2]:
        if not scan_state.get('scanning'):
            break
        for endpoint in internal_endpoints[:3]:
            try:
                test_url = f'{base_url}{endpoint}'
                r = req_lib.get(test_url,
                              headers={'X-Forwarded-For': xff, 'X-Real-IP': xff,
                                      'X-Originating-IP': xff, 'X-Client-IP': xff},
                              timeout=5, verify=False)
                if r.status_code == 200:
                    # Check for signs of internal access
                    internal_indicators = ['admin', 'debug', 'metrics', 'internal',
                                         'actuator', 'env', 'config', 'health']
                    if any(ind in r.text.lower() for ind in internal_indicators):
                        add_finding(
                            'high',
                            f'Internal endpoint accessible via X-Forwarded-For bypass',
                            sub=f'Endpoint {endpoint} accessible with XFF={xff}',
                            asset=test_url, cvss='7.5', owasp='A01', mitre='T1190',
                            details=f'Endpoint: {endpoint}\n'
                                    f'X-Forwarded-For: {xff}\n'
                                    f'Response: {r.status_code}\n'
                                    f'Evidence: Internal content returned\n'
                                    f'Recommendation: Remove trust in client-supplied XFF headers')
                        cloud_vm_findings.append({'type': 'xff_bypass', 'endpoint': endpoint})
                        log('warn', f'[CLOUD-VM] XFF bypass on {endpoint}')
                        break
            except Exception:
                pass

    # ── Summary ──
    total_cloud_vm = len(cloud_vm_findings)
    log('ok', f'[CLOUD-VM] Scan complete — {total_cloud_vm} cloud VM findings')

    with LOCK:
        scan_state.setdefault('cloud_vm_data', {})
        scan_state['cloud_vm_data'] = {
            'provider': cloud_provider,
            'provider_evidence': provider_evidence,
            'ssrf_confirmed': ssrf_confirmed,
            'ssrf_param': ssrf_param_used,
            'findings': cloud_vm_findings,
            'metadata_enum': metadata_enum if ssrf_confirmed else {},
        }
    set_progress('cloud_vm', 100)


# ═══════════════════════════════════════════════════════════════════════════════
# REAL ATTACKER SIMULATION MODULES
# These modules simulate real-world attack patterns that automated tools miss
# ═══════════════════════════════════════════════════════════════════════════════

# ─── SQL INJECTION (MANUAL VERIFICATION) ───────────────────────────────────────


def run_container_security_module(target):
    """Container security assessment — pure Python logic.
    
    Detects:
    1. Docker API exposed on TCP (2375/2376) — unauthenticated access
    2. Container escape via privileged mode detection
    3. Docker registry exposure (v2 API)
    4. Dockerfile/.dockerenv leaked in web root
    5. Container image CVE scanning via trivy (if installed)
    6. Docker Compose file exposure
    7. Container breakout via socket mounting
    """
    log('info', '[CONTAINER] Starting container security assessment')
    base_url = f'https://{target}'
    container_findings = []

    with LOCK:
        disc = scan_state.get('discovery_data', {})
        urls = disc.get('urls', [])
        sensitive = disc.get('sensitive_files', [])

    # ── 1. Docker API exposed on TCP ──
    docker_api_ports = [2375, 2376]
    for port in docker_api_ports:
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(5)
            resolved = _sock.getaddrinfo(target, None)
            ip = resolved[0][4][0] if resolved else target
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                # Try unauthenticated access
                for proto in ('http', 'https'):
                    try:
                        r = req_lib.get(f'{proto}://{ip}:{port}/version', timeout=5, verify=False)
                        if r.status_code == 200 and ('docker' in r.text.lower() or 'version' in r.text.lower()):
                            container_findings.append({
                                'type': 'Docker API Exposed',
                                'severity': 'critical',
                                'detail': f'Docker API accessible on {proto}://{ip}:{port} without authentication',
                                'evidence': r.text[:500],
                            })
                            add_finding(
                                'critical',
                                f'Docker API exposed on port {port}',
                                sub='Unauthenticated Docker daemon access — full container control',
                                asset=f'{proto}://{ip}:{port}', cvss='9.8', owasp='A05', mitre='T1610',
                                details=f'Port: {port}\nProtocol: {proto}\n'
                                        f'Endpoint: /version\n'
                                        f'Response: {r.text[:300]}\n'
                                        f'Impact: Attacker can create privileged containers, mount host filesystem, escape to host\n'
                                        f'Exploit: docker -H {proto}://{ip}:{port} run -v /:/host --rm -it alpine chroot /host')
                            log('ok', f'[CONTAINER] CRITICAL: Docker API exposed on {proto}://{ip}:{port}')
                            break
                    except Exception:
                        pass
        except Exception:
            pass

    # ── 2. Docker Registry v2 API exposure ──
    registry_paths = ['/v2/', '/v2/_catalog', '/v2/_tags']
    for path in registry_paths:
        try:
            r = req_lib.get(f'https://{target}{path}', timeout=5, verify=False, headers={'Accept': 'application/vnd.docker.distribution.manifest.v2+json'})
            if r.status_code == 200:
                is_registry = ('repositories' in r.text or 'schemaVersion' in r.text or 'tags' in r.text)
                if is_registry:
                    container_findings.append({
                        'type': 'Docker Registry Exposed',
                        'severity': 'high',
                        'detail': f'Docker Registry v2 API accessible at {target}{path}',
                        'evidence': r.text[:500],
                    })
                    add_finding(
                        'high',
                        'Docker Registry exposed',
                        sub='Container images accessible without authentication',
                        asset=f'https://{target}{path}', cvss='8.5', owasp='A05', mitre='T1610',
                        details=f'Endpoint: {path}\nResponse: {r.text[:300]}\n'
                                f'Impact: Attacker can pull private container images, extract secrets/credentials baked into images\n'
                                f'Exploit: docker pull {target}/<image_name>')
                    log('ok', f'[CONTAINER] Docker Registry exposed at {target}{path}')
                    break
        except Exception:
            pass

    # ── 3. Dockerfile / .dockerenv / docker-compose leaked ──
    leak_paths = [
        ('/.dockerenv', 'Docker environment file exposed'),
        ('/Dockerfile', 'Dockerfile exposed — reveals build process and secrets'),
        ('/docker-compose.yml', 'Docker Compose file exposed — reveals service architecture'),
        ('/docker-compose.yaml', 'Docker Compose YAML exposed'),
        ('/.dockerignore', 'Docker ignore file exposed'),
        ('/docker-entrypoint.sh', 'Docker entrypoint script exposed'),
    ]
    for path, desc in leak_paths:
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(f'{base_url}{path}', timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10:
                body = r.text.lower()
                # Filter SPA catch-all: if response is SPA HTML shell, skip
                _is_spa = sum(1 for m in [
                    '<div id="root">', '<div id="app">', 'noscript',
                    'bundle.js', 'main.js', 'static/js/',
                ] if m in body) >= 2
                if _is_spa:
                    continue
                # Filter out false positives
                if path == '/.dockerenv' or ('from ' in body and ('copy ' in body or 'run ' in body or 'expose ' in body)):
                    sev = 'high' if 'secret' in body or 'password' in body or 'key' in body or 'token' in body else 'medium'
                    container_findings.append({
                        'type': desc,
                        'severity': sev,
                        'detail': f'{desc} at {base_url}{path}',
                        'evidence': r.text[:500],
                    })
                    add_finding(
                        sev,
                        desc,
                        sub=f'File accessible at {path}',
                        asset=f'{base_url}{path}', cvss='6.5' if sev == 'medium' else '7.5', owasp='A05', mitre='T1610',
                        details=f'Path: {path}\nContent preview:\n{r.text[:500]}\n'
                                f'Impact: Exposes container configuration, secrets, internal architecture')
                    log('ok', f'[CONTAINER] {desc}')
        except Exception:
            pass

    # ── 4. Kubernetes API Server detection ──
    k8s_api_paths = [
        ('/api/v1', 'Core API'),
        ('/apis', 'API Discovery'),
        ('/version', 'Version Info'),
        ('/healthz', 'Health Check'),
        ('/metrics', 'Metrics Endpoint'),
    ]
    k8s_found = False
    for path, desc in k8s_api_paths:
        try:
            r = req_lib.get(f'https://{target}{path}', timeout=5, verify=False)
            if r.status_code in (200, 401, 403):
                body = r.text.lower()
                if any(k in body for k in ['serveraddressbyclientcidrs', 'kind', 'apiversions', 'kubernetes']) or r.status_code == 401:
                    if not k8s_found:
                        container_findings.append({
                            'type': 'Kubernetes API Server Detected',
                            'severity': 'high',
                            'detail': f'Kubernetes API server accessible at {target}',
                            'evidence': r.text[:500],
                        })
                        add_finding(
                            'high',
                            'Kubernetes API Server exposed',
                            sub=f'K8s API accessible — {desc}',
                            asset=f'https://{target}{path}', cvss='8.0', owasp='A05', mitre='T1610',
                            details=f'Endpoint: {path}\nStatus: {r.status_code}\n'
                                    f'Verification: {desc}\n'
                                    f'Response: {r.text[:300]}\n'
                                    f'Impact: Cluster enumeration, pod creation, secret theft, lateral movement\n'
                                    f'Exploit: kubectl --server=https://{target} get pods --all-namespaces')
                        k8s_found = True
                        log('ok', f'[CONTAINER] Kubernetes API server detected at {target}')
        except Exception:
            pass

    # ── 5. Container image CVE scan via trivy (if installed) ──
    trivy_path = _find_tool('trivy')
    if trivy_path:
        # Scan the target itself as a potential container registry
        try:
            stdout, stderr, rc = _run_tool([
                trivy_path, 'image', '--format', 'json', '--severity', 'HIGH,CRITICAL',
                '--timeout', '60s', f'{target}/latest'
            ], timeout=45)
            if rc == 0 and stdout:
                import json as _json
                try:
                    trivy_data = _json.loads(stdout)
                    vulns = trivy_data.get('Results', [{}])[0].get('Vulnerabilities', [])
                    if vulns:
                        critical_vulns = [v for v in vulns if v.get('Severity') == 'CRITICAL']
                        high_vulns = [v for v in vulns if v.get('Severity') == 'HIGH']
                        container_findings.append({
                            'type': 'Container Image CVEs',
                            'severity': 'critical' if critical_vulns else 'high',
                            'detail': f'{len(critical_vulns)} critical, {len(high_vulns)} high CVEs in container image',
                            'evidence': '\n'.join(f'  {v.get("VulnerabilityID")} ({v.get("Severity")}): {v.get("Title","")[:60]}' for v in (critical_vulns + high_vulns)[:10]),
                        })
                        sev = 'critical' if critical_vulns else 'high'
                        add_finding(
                            sev,
                            f'Container image has {len(vulns)} vulnerabilities',
                            sub=f'{len(critical_vulns)} critical, {len(high_vulns)} high CVEs',
                            asset=f'{target}/latest', cvss='9.0' if critical_vulns else '7.5',
                            details=f'Total: {len(vulns)} vulns\n'
                                    + '\n'.join(f'{v.get("VulnerabilityID")} [{v.get("Severity")}]: {v.get("Title","")[:80]}' for v in (critical_vulns + high_vulns)[:15]))
                        log('ok', f'[CONTAINER] Trivy found {len(vulns)} CVEs in {target}/latest')
                except Exception:
                    pass
        except Exception:
            pass

    # ── 6. Check for common container escape indicators in web content ──
    try:
        r = req_lib.get(base_url, timeout=8, verify=False)
        body_lower = r.text.lower()
        escape_indicators = [
            ('/proc/self/cgroup', 'Container cgroup filesystem exposed'),
            ('/proc/1/environ', 'Container init process environment exposed'),
            ('/.dockerenv', 'Docker environment accessible via web'),
            ('/run/secrets/', 'Container secrets directory accessible'),
        ]
        for indicator, desc in escape_indicators:
            if indicator in body_lower:
                container_findings.append({
                    'type': 'Container Escape Indicator',
                    'severity': 'critical',
                    'detail': desc,
                    'evidence': f'Found "{indicator}" in response body',
                })
                add_finding(
                    'critical', desc,
                    sub=f'Indicator found: {indicator}',
                    asset=base_url, cvss='9.5', owasp='A01', mitre='T1611',
                    details=f'Indicator: {indicator}\n'
                            f'Impact: Container breakout — attacker can access host filesystem\n'
                            f'Exploit: cat /proc/1/environ | xargs -0 -n1')
                log('ok', f'[CONTAINER] {desc}')
    except Exception:
        pass

    # ── 7. Grype container CVE scanner with exploitability prioritization ──
    grype_path = _find_tool('grype')
    if not grype_path:
        # Python fallback: query OSV API for container image CVEs
        log('info', '[CONTAINER-GRYPE] Binary not found — using OSV API Python fallback')
        try:
            if REQUESTS_AVAILABLE:
                # Query Docker Hub for image metadata, then OSV for CVEs
                image_name = target.split('/')[0] if '/' in target else 'library/' + target
                osv_url = 'https://api.osv.dev/v1/query'
                osv_payload = {'package': {'name': image_name, 'ecosystem': 'Docker'}}
                try:
                    r_osv = req_lib.post(osv_url, json=osv_payload, timeout=10)
                    if r_osv.status_code == 200:
                        osv_data = r_osv.json()
                        vulns = osv_data.get('vulns', [])
                        if vulns:
                            crit = [v for v in vulns if any(s.get('type') == 'CVSS_V3' and s.get('score', 0) >= 9.0
                                                             for s in v.get('severity', []))]
                            high = [v for v in vulns if any(s.get('type') == 'CVSS_V3' and 7.0 <= s.get('score', 0) < 9.0
                                                            for s in v.get('severity', []))]
                            if vulns:
                                add_finding(
                                    'high' if not crit else 'critical',
                                    f'Grype-Python: {len(vulns)} CVEs found for container image {image_name}',
                                    sub=f'{len(crit)} critical, {len(high)} high via OSV API',
                                    asset=target,
                                    cvss='8.0' if not crit else '9.5',
                                    details='\n'.join(
                                        f'{v.get("id","?")} — {v.get("summary","")[:80]}'
                                        for v in (crit + high)[:15]
                                    ) + f'\n\nRemediation: Update base image and dependencies to patched versions')
                                log('ok', f'[GRYPE-PY] {len(vulns)} CVEs found via OSV API')
                except Exception as e:
                    log('warn', f'[GRYPE-PY] OSV API query failed: {e}')
        except Exception as e:
            log('warn', f'[GRYPE-PY] Python fallback error: {e}')
    if grype_path:
        log('info', '[CONTAINER] Running grype with exploitability scoring')
        stdout, stderr, rc = _run_tool([
            grype_path, f'{target}/latest', '-o', 'json',
        ], timeout=45)
        if rc == 0 and stdout:
            try:
                import json as _json
                grype_data = _json.loads(stdout)
                matches = grype_data.get('matches', [])
                if matches:
                    # ── Exploitability scoring: prioritize vulns with known exploits ──
                    HIGH_EXPLOIT = []  # Vulns with known public exploits
                    MEDIUM_EXPLOIT = []  # Vulns with high CVSS but no known exploit
                    LOW_EXPLOIT = []  # Vulns with low CVSS

                    for m in matches:
                        v = m.get('vulnerability', {})
                        artifact = m.get('artifact', {})
                        vuln_id = v.get('id', '?')
                        severity = v.get('severity', 'Unknown')
                        cvss_score = v.get('cvss', [{}])
                        if isinstance(cvss_score, list) and cvss_score:
                            cvss_score = cvss_score[0].get('metrics', {}).get('baseScore', 0)
                        else:
                            cvss_score = 0
                        fixed_version = v.get('fixedInVersion', '')
                        installed_version = artifact.get('version', '')
                        artifact_name = artifact.get('name', '?')
                        vuln_description = v.get('description', '')[:100]

                        # Determine exploitability
                        has_exploit = False
                        # Check for known exploitation indicators
                        exploit_indicators = ['exploit', 'in the wild', 'active exploitation',
                                            'poc', 'proof of concept', 'rce', 'remote code execution']
                        if any(x in vuln_description.lower() for x in exploit_indicators):
                            has_exploit = True
                        # High CVSS + no fix available = more exploitable
                        if cvss_score >= 9.0 and not fixed_version:
                            has_exploit = True

                        entry = {
                            'id': vuln_id, 'severity': severity, 'cvss': cvss_score,
                            'package': artifact_name, 'installed': installed_version,
                            'fixed': fixed_version, 'description': vuln_description,
                            'has_exploit': has_exploit,
                        }
                        if has_exploit:
                            HIGH_EXPLOIT.append(entry)
                        elif cvss_score >= 7.0:
                            MEDIUM_EXPLOIT.append(entry)
                        else:
                            LOW_EXPLOIT.append(entry)

                    # ── Generate prioritized findings ──
                    if HIGH_EXPLOIT:
                        critical_count = sum(1 for e in HIGH_EXPLOIT if e['severity'] == 'Critical')
                        high_count = sum(1 for e in HIGH_EXPLOIT if e['severity'] == 'High')
                        vuln_lines = []
                        for e in HIGH_EXPLOIT[:15]:
                            fix_info = f' → {e["fixed"]}' if e['fixed'] else ' [NO FIX]'
                            vuln_lines.append(
                                f'{e["id"]} [{e["severity"]}] CVSS {e["cvss"]}: '
                                f'{e["package"]} {e["installed"]}{fix_info}\n'
                                f'  {e["description"][:80]}'
                            )
                        add_finding(
                            'critical',
                            f'Grype: {len(HIGH_EXPLOIT)} exploitable container vulnerabilities',
                            sub=f'{critical_count} Critical + {high_count} High — known exploits or no fix available',
                            asset=f'{target}/latest',
                            cvss='9.5',
                            details=(
                                f'EXPLOITABLE VULNERABILITIES (prioritized):\n\n'
                                + '\n'.join(vuln_lines)
                                + f'\n\nImpact: These vulns have known exploits or no available fix — immediate risk\n'
                                f'Remediation: Update affected packages or rebuild container with patched base image'
                            ))
                        log('ok', f'[CONTAINER-GRYPE] {len(HIGH_EXPLOIT)} EXPLOITABLE vulns ({critical_count} critical)')

                    if MEDIUM_EXPLOIT:
                        vuln_lines = []
                        for e in MEDIUM_EXPLOIT[:10]:
                            fix_info = f' → {e["fixed"]}' if e['fixed'] else ' [NO FIX]'
                            vuln_lines.append(
                                f'{e["id"]} [{e["severity"]}] CVSS {e["cvss"]}: '
                                f'{e["package"]} {e["installed"]}{fix_info}'
                            )
                        add_finding(
                            'high',
                            f'Grype: {len(MEDIUM_EXPLOIT)} high-severity container vulnerabilities',
                            sub=f'High CVSS scores — exploit code may exist',
                            asset=f'{target}/latest',
                            cvss='7.5',
                            details=(
                                f'HIGH SEVERITY VULNERABILITIES:\n\n'
                                + '\n'.join(vuln_lines)
                                + f'\n\nImpact: Known vulnerabilities with potential for exploitation\n'
                                f'Remediation: Update affected packages when patches available'
                            ))
                        log('ok', f'[CONTAINER-GRYPE] {len(MEDIUM_EXPLOIT)} high-severity vulns')

                    total_exploitable = len(HIGH_EXPLOIT) + len(MEDIUM_EXPLOIT) + len(LOW_EXPLOIT)
                    log('ok', f'[CONTAINER-GRYPE] Total: {total_exploitable} vulns — '
                        f'{len(HIGH_EXPLOIT)} exploitable, {len(MEDIUM_EXPLOIT)} high, {len(LOW_EXPLOIT)} low')
            except Exception as e:
                log('warn', f'[CONTAINER-GRYPE] Parse error: {e}')

    log('ok', f'[CONTAINER] Scan complete — {len(container_findings)} findings')
    set_progress('container', 100)



def run_checkov_module(target):
    """Checkov IaC scanner with REAL false positive suppression and severity correlation.
    
    Detection improvements over naive checkov wrapper:
    1. Known false-positive check IDs suppressed (checks that commonly FP on cloud environments)
    2. Severity upgraded when cross-referenced with other findings (e.g., if Docker API exposed,
       Dockerfile misconfigs become confirmed-exploitable, not theoretical)
    3. Resource context analysis — misconfigs on internet-facing resources are Critical, 
       internal-only resources are Medium
    4. Guidance links included for remediation
    5. NDJSON and JSON output formats both handled
    """
    log('info', '[CHECKOV] Starting IaC security scan with FP suppression')
    checkov_path = _find_tool('checkov')
    if not checkov_path:
        log('warn', '[CHECKOV] checkov not found — skipping IaC scan')
        set_progress('checkov', 100)
        return

    # ── Known false-positive check IDs (checkov commonly flags these incorrectly) ──
    KNOWN_FP_CHECKS = {
        'CKV_AWS_2',    # API Gateway access logging — not always applicable
        'CKV_AWS_18',   # Access logging — Lambda functions don't need it
        'CKV_AWS_50',   # X-Ray tracing — not required for all workloads
        'CKV_AWS_111',  # IAM policy wildcard — necessary for some service roles
        'CKV_AWS_115',  # Lambda function IAM — execution role permissions
        'CKV_GCP_2',    # GCP project-wide SSH key — legitimate for some setups
        'CKV_K8S_13',   # Read-only root filesystem — not all containers need it
        'CKV_DOCKER_3', # Pinned tag — 'latest' is fine for dev environments
        'CKV_AZURE_2',  # Unmanaged disk encryption — not all disks contain sensitive data
    }

    # ── Cross-reference with existing findings for severity upgrade ──
    with LOCK:
        existing_findings = {f.get('title', ''): f for f in scan_state.get('findings', [])}
    docker_api_exposed = any('Docker API' in t or '2375' in t or '2376' in t for t in existing_findings)
    k8s_exposed = any('Kubernetes' in t or 'k8s' in t.lower() for t in existing_findings)

    # Determine scan directory
    import tempfile, shutil
    scan_dir = None
    cloned = False
    repo_url = scan_state.get('repo_url', '')
    if repo_url and ('github.com' in repo_url or 'gitlab.com' in repo_url):
        try:
            scan_dir = tempfile.mkdtemp(prefix='checkov_scan_')
            _run_tool(['git', 'clone', '--depth', '1', repo_url, scan_dir], timeout=30)
            cloned = True
            log('info', f'[CHECKOV] Cloned repo: {repo_url}')
        except Exception:
            scan_dir = None

    if not scan_dir:
        scan_dir = os.getcwd()

    try:
        stdout, stderr, rc = _run_tool([
            checkov_path, '-d', scan_dir,
            '--output', 'json',
            '--quiet',
            '--compact',
        ], timeout=45)
        set_progress('checkov', 80)

        if not stdout:
            log('warn', '[CHECKOV] No output')
            set_progress('checkov', 100)
            return

        import json as _json
        try:
            data = _json.loads(stdout)
        except Exception:
            data = {'results': {'passed_checks': [], 'failed_checks': []}}
            for line in stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                    if 'check_type' in obj and obj.get('result') == 'FAILED':
                        data['results']['failed_checks'].append(obj)
                except Exception:
                    pass

        failed = data.get('results', {}).get('failed_checks', [])
        total_before = len(failed)

        # ── Filter known false positives ──
        failed = [c for c in failed if c.get('check_id', '') not in KNOWN_FP_CHECKS]
        fp_suppressed = total_before - len(failed)
        if fp_suppressed:
            log('info', f'[CHECKOV] Suppressed {fp_suppressed} known false positives')

        # ── Severity mapping with resource context ──
        CRITICAL_CHECKS = {
            'CKV_AWS_16', 'CKV_AWS_124', 'CKV_AWS_125',  # IAM/policy issues
            'CKV_AWS_18', 'CKV_AWS_19', 'CKV_AWS_20',     # S3/public exposure
            'CKV_AWS_13', 'CKV_AWS_23', 'CKV_AWS_24',     # RDS/public exposure
            'CKV_AWS_68', 'CKV_AWS_69',                     # CloudFormation security
            'CKV_K8S_1', 'CKV_K8S_2', 'CKV_K8S_14',       # K8s RBAC/pod security
            'CKV_DOCKER_2', 'CKV_DOCKER_3',                 # Docker security
            'CKV_AZURE_1', 'CKV_AZURE_3',                   # Azure security
            'CKV_GCP_1', 'CKV_GCP_6',                       # GCP security
        }
        MEDIUM_CHECKS = {
            'CKV_AWS_21', 'CKV_AWS_22', 'CKV_AWS_25', 'CKV_AWS_26',
            'CKV_K8S_3', 'CKV_K8S_4', 'CKV_K8S_5',
        }

        suppressed = []
        for check in failed:
            check_id = check.get('check_id', 'N/A')
            check_name = check.get('check', {}).get('name', check.get('check_name', 'Unknown'))
            resource = check.get('check', {}).get('resource', check.get('resource', ''))
            file_path = check.get('check', {}).get('file_path', check.get('file_path', ''))
            guideline = check.get('check', {}).get('guideline', '')

            # ── Determine severity with context ──
            if check_id in CRITICAL_CHECKS:
                sev = 'critical'
            elif check_id in MEDIUM_CHECKS:
                sev = 'medium'
            else:
                sev = 'high'

            # ── Severity upgrade: if Docker API exposed, Dockerfile misconfigs are confirmed-exploitable ──
            resource_lower = resource.lower() if resource else ''
            file_lower = file_path.lower() if file_path else ''
            is_docker_related = ('docker' in resource_lower or 'docker' in file_lower or
                                'CKV_DOCKER' in check_id)
            is_k8s_related = ('kubernetes' in resource_lower or 'k8s' in resource_lower or
                             'CKV_K8S' in check_id)

            if is_docker_related and docker_api_exposed:
                sev = 'critical'
                check_name += ' [CONFIRMED: Docker API exposed — exploitable now]'
            elif is_k8s_related and k8s_exposed:
                sev = 'critical'
                check_name += ' [CONFIRMED: K8s API exposed — exploitable now]'

            # ── Context-aware severity ──
            # Internet-facing resources are always more severe
            internet_facing = any(x in resource_lower for x in [
                'public', 'alb', 'elb', 'cloudfront', 's3', 'azureblob',
                'gcs', 'internet', 'external', '0.0.0.0'
            ])
            if internet_facing and sev != 'critical':
                sev = 'critical' if sev == 'high' else 'high'

            # ── Build detailed evidence ──
            details_text = (
                f'Check: {check_id}\n'
                f'Rule: {check_name}\n'
                f'Resource: {resource}\n'
                f'File: {file_path}\n'
            )
            if guideline:
                details_text += f'Guideline: {guideline}\n'
            if docker_api_exposed and is_docker_related:
                details_text += (
                    f'\n⚠ CROSS-REFERENCED: Docker API (TCP 2375/2376) was found exposed on this target.\n'
                    f'This Dockerfile misconfiguration is now CONFIRMED EXPLOITABLE, not theoretical.\n'
                )
            details_text += (
                f'\nImpact: IaC misconfig — '
                + ('CRITICAL: internet-facing resource with security misconfiguration' if sev == 'critical'
                   else 'high: security control missing or misconfigured' if sev == 'high'
                   else 'medium: security best practice violated')
                + f'\nRemediation: Fix {resource} per {check_id} guidance'
            )

            add_finding(
                sev,
                f'{check_id}: {check_name}',
                sub=f'IaC misconfig in {resource}' if resource else 'IaC misconfig',
                asset=resource or file_path or target,
                cvss='8.5' if sev == 'critical' else '6.0' if sev == 'high' else '4.0',
                owasp='A05',
                mitre='T1190',
                details=details_text
            )
            log('ok', f'[CHECKOV] {sev.upper()}: {check_id} — {check_name[:80]}')

        if fp_suppressed:
            log('info', f'[CHECKOV] Total: {len(failed)} real findings (suppressed {fp_suppressed} FPs from {total_before})')
        else:
            log('info', f'[CHECKOV] Total: {len(failed)} findings')

    except Exception as e:
        log('warn', f'[CHECKOV] Error: {e}')
    finally:
        if cloned and scan_dir and os.path.isdir(scan_dir):
            try:
                shutil.rmtree(scan_dir, ignore_errors=True)
            except Exception:
                pass
    set_progress('checkov', 100)

# ─── KUBERNETES SECURITY ───────────────────────────────────────────────────────


def run_kubernetes_security_module(target):
    """Kubernetes cluster security assessment — pure Python logic.
    
    Detects:
    1. Exposed K8s API server with anonymous auth
    2. Dashboard/monitoring endpoints
    3. etcd data store exposure
    4. kubelet API exposure
    5. RBAC misconfigurations via API probing
    6. Secret exposure via API
    7. Pod security policy checks
    8. Service mesh detection (Istio/Linkerd)
    """
    log('info', '[K8S] Starting Kubernetes security assessment')
    k8s_findings = []

    # ── 1. Kubernetes API Server probing ──
    k8s_endpoints = {
        '/api/v1': 'Core API — namespace/pod/service listing',
        '/apis/apps/v1': 'Apps API — deployment/replicaSet',
        '/apis/batch/v1': 'Batch API — jobs/cronjobs',
        '/apis/networking.k8s.io/v1': 'Networking — ingress/networkpolicy',
        '/version': 'Cluster version info',
        '/healthz': 'Health endpoint',
        '/readyz': 'Readiness endpoint',
        '/metrics': 'Prometheus metrics',
        '/api/v1/namespaces': 'Namespace listing',
        '/api/v1/pods': 'Pod listing across namespaces',
        '/api/v1/secrets': 'Secret listing — HIGH RISK',
        '/api/v1/configmaps': 'ConfigMap listing',
        '/api/v1/namespaces/default/pods': 'Default namespace pods',
    }

    api_found = False
    for path, desc in k8s_endpoints.items():
        if not scan_state.get('scanning'):
            break
        try:
            r = req_lib.get(f'https://{target}{path}', timeout=5, verify=False)
            if r.status_code == 200:
                body = r.text.lower()
                if 'kind' in body and ('list' in body or 'status' in body or 'items' in body):
                    if not api_found:
                        api_found = True
                        log('ok', f'[K8S] Kubernetes API confirmed at {target}')

                    # Check for anonymous access
                    if path == '/api/v1/pods' and '"items"' in r.text:
                        k8s_findings.append({
                            'type': 'K8s Anonymous Pod Listing',
                            'severity': 'critical',
                            'detail': 'Anonymous access to pod listing enabled',
                            'evidence': r.text[:500],
                        })
                        add_finding(
                            'critical',
                            'Kubernetes anonymous pod listing',
                            sub='API server allows unauthenticated pod enumeration',
                            asset=f'https://{target}{path}', cvss='9.0', owasp='A01', mitre='T1613',
                            details=f'Endpoint: {path}\nStatus: {r.status_code}\n'
                                    f'Impact: Attacker can enumerate all pods, find sensitive workloads, extract env vars\n'
                                    f'Exploit: kubectl --server=https://{target} get pods --all-namespaces -o yaml')

                    # Secrets exposure — highest severity
                    if path == '/api/v1/secrets' and '"items"' in r.text:
                        k8s_findings.append({
                            'type': 'K8s Secrets Exposed',
                            'severity': 'critical',
                            'detail': 'Kubernetes secrets accessible without authentication',
                            'evidence': r.text[:500],
                        })
                        add_finding(
                            'critical',
                            'Kubernetes Secrets exposed via API',
                            sub='Database credentials, API keys, certificates accessible',
                            asset=f'https://{target}{path}', cvss='9.8', owasp='A01', mitre='T1552',
                            details=f'Endpoint: {path}\nStatus: {r.status_code}\n'
                                    f'Impact: Full credential theft — database passwords, TLS certs, API tokens\n'
                                    f'Exploit: kubectl --server=https://{target} get secrets --all-namespaces -o json')

                    # Metrics endpoint
                    if path == '/metrics' and ('http_requests' in r.text or 'go_' in r.text):
                        k8s_findings.append({
                            'type': 'K8s Metrics Exposed',
                            'severity': 'medium',
                            'detail': 'Prometheus metrics endpoint publicly accessible',
                            'evidence': r.text[:500],
                        })
                        add_finding(
                            'medium',
                            'Kubernetes metrics endpoint exposed',
                            sub='Internal cluster metrics visible',
                            asset=f'https://{target}{path}', cvss='5.3', owasp='A05', mitre='T1046',
                            details=f'Endpoint: {path}\nImpact: Reveals cluster internals — request rates, error rates, resource usage')
        except Exception:
            pass

    # ── 2. Kubernetes Dashboard detection ──
    dashboard_paths = [
        '/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/',
        '/api/v1/namespaces/kube-system/services/kubernetes-dashboard:/proxy/',
        '/dashboard/',
        '/api/v1/namespaces/kubernetes-dashboard/services/http:kubernetes-dashboard:/proxy/',
    ]
    for path in dashboard_paths:
        try:
            r = req_lib.get(f'https://{target}{path}', timeout=5, verify=False, allow_redirects=True)
            if r.status_code in (200, 302, 403):
                body = r.text.lower()
                if 'kubernetes' in body and ('dashboard' in body or 'login' in body or 'token' in body):
                    k8s_findings.append({
                        'type': 'K8s Dashboard Exposed',
                        'severity': 'high',
                        'detail': f'Kubernetes Dashboard accessible',
                        'evidence': r.text[:500],
                    })
                    add_finding(
                        'high',
                        'Kubernetes Dashboard exposed',
                        sub='Web UI for cluster management is publicly accessible',
                        asset=f'https://{target}{path}', cvss='7.5', owasp='A05', mitre='T1610',
                        details=f'Path: {path}\nStatus: {r.status_code}\n'
                                f'Impact: Full cluster management via web UI — pod exec, secret access, RBAC bypass\n'
                                f'Mitigation: Restrict dashboard to internal network or use authentication proxy')
                    log('ok', f'[K8S] Kubernetes Dashboard exposed')
                    break
        except Exception:
            pass

    # ── 3. etcd data store exposure ──
    etcd_paths = ['/version', '/v2/keys/', '/v2/keys/?recursive=true', '/v3/kv/range']
    for path in etcd_paths:
        try:
            r = req_lib.get(f'https://{target}{path}', timeout=5, verify=False)
            if r.status_code == 200:
                body = r.text.lower()
                if 'etcdserver' in body or 'key' in body or '"node"' in body or '"kvs"' in body:
                    k8s_findings.append({
                        'type': 'etcd Exposed',
                        'severity': 'critical',
                        'detail': f'etcd key-value store accessible at {path}',
                        'evidence': r.text[:500],
                    })
                    add_finding(
                        'critical',
                        'etcd data store exposed',
                        sub=f'Cluster state store accessible — contains all secrets and configs',
                        asset=f'https://{target}{path}', cvss='9.5', owasp='A01', mitre='T1552',
                        details=f'Endpoint: {path}\nStatus: {r.status_code}\n'
                                f'Impact: Full cluster state dump — secrets, tokens, configs, service accounts\n'
                                f'Exploit: ETCDCTL_API=3 etcdctl --endpoints=https://{target} get / --prefix --keys-only')
                    log('ok', f'[K8S] etcd exposed at {path}')
                    break
        except Exception:
            pass

    # ── 4. Kubelet API detection ──
    kubelet_paths = [
        '/pods', '/stats/summary', '/metrics', '/run/{ns}/{pod}/{container}',
        '/exec/{ns}/{pod}/{container}', '/portForward/{ns}/{pod}', '/logs/{ns}/{pod}/{container}',
    ]
    for path in kubelet_paths[:4]:
        try:
            r = req_lib.get(f'https://{target}:10250{path}', timeout=5, verify=False)
            if r.status_code == 200:
                body = r.text.lower()
                if 'items' in body or 'pod' in body or 'cpu' in body or 'go_' in body:
                    k8s_findings.append({
                        'type': 'Kubelet API Exposed',
                        'severity': 'critical',
                        'detail': f'Kubelet API accessible on port 10250',
                        'evidence': r.text[:500],
                    })
                    add_finding(
                        'critical',
                        'Kubelet API exposed on port 10250',
                        sub='Node-level API allows pod exec, log access, port forwarding',
                        asset=f'https://{target}:10250{path}', cvss='9.0', owasp='A01', mitre='T1610',
                        details=f'Endpoint: {path}\nStatus: {r.status_code}\n'
                                f'Impact: Execute commands in any pod, read logs, forward ports — full node compromise\n'
                                f'Exploit: kubectl --server=https://{target}:10250 exec -it <pod> -- /bin/sh')
                    log('ok', f'[K8S] Kubelet API exposed on port 10250')
                    break
        except Exception:
            pass

    # ── 5. RBAC / Service Account detection ──
    try:
        r = req_lib.get(f'https://{target}/api/v1/namespaces/default/serviceaccounts', timeout=5, verify=False)
        if r.status_code == 200 and '"items"' in r.text:
            import json as _json
            try:
                sa_data = _json.loads(r.text)
                sa_list = sa_data.get('items', [])
                k8s_findings.append({
                    'type': 'Service Account Enumeration',
                    'severity': 'medium',
                    'detail': f'{len(sa_list)} service accounts in default namespace',
                    'evidence': '\n'.join(sa.get('metadata', {}).get('name', '?') for sa in sa_list[:10]),
                })
                add_finding(
                    'medium',
                    'Kubernetes service accounts enumerable',
                    sub=f'{len(sa_list)} service accounts in default namespace',
                    asset=f'https://{target}/api/v1/namespaces/default/serviceaccounts', cvss='5.3',
                    details=f'Service accounts found:\n' + '\n'.join(f'  - {sa.get("metadata",{}).get("name","?")}' for sa in sa_list[:15]))
            except Exception:
                pass
    except Exception:
        pass

    # ── 6. Service mesh detection (Istio/Linkerd) ──
    try:
        r = req_lib.get(f'https://{target}/api/v1/namespaces/istio-system', timeout=5, verify=False)
        if r.status_code == 200:
            body = r.text.lower()
            if 'istio' in body:
                k8s_findings.append({
                    'type': 'Istio Service Mesh Detected',
                    'severity': 'info',
                    'detail': 'Istio service mesh running',
                    'evidence': r.text[:300],
                })
                add_finding('info', 'Istio service mesh detected', asset=target,
                           details='Istio namespace found. Check for mTLS, sidecar injection, authorization policies.')
    except Exception:
        pass

    try:
        r = req_lib.get(f'https://{target}:9995/version', timeout=3, verify=False)
        if r.status_code == 200 and 'linkerd' in r.text.lower():
            k8s_findings.append({
                'type': 'Linkerd Service Mesh Detected',
                'severity': 'info',
                'detail': 'Linkerd service mesh running',
                'evidence': r.text[:300],
            })
            add_finding('info', 'Linkerd service mesh detected', asset=target,
                       details='Linkerd detected. Check for mTLS and authorization policy enforcement.')
    except Exception:
        pass

    # ── 7. Container escape via K8s API — create privileged pod ──
    try:
        # Check if we can list clusterroles with cluster-admin binding
        r = req_lib.get(f'https://{target}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings', timeout=5, verify=False)
        if r.status_code == 200 and '"items"' in r.text:
            import json as _json
            try:
                rb_data = _json.loads(r.text)
                for binding in rb_data.get('items', []):
                    role_ref = binding.get('roleRef', {})
                    if role_ref.get('name') == 'cluster-admin':
                        subject = binding.get('subjects', [{}])[0]
                        k8s_findings.append({
                            'type': 'Cluster Admin Binding',
                            'severity': 'high',
                            'detail': f'cluster-admin bound to: {subject.get("name", "unknown")}',
                            'evidence': str(binding)[:500],
                        })
                        add_finding(
                            'high',
                            f'cluster-admin RBAC binding: {subject.get("name", "unknown")}',
                            sub='Overly permissive RBAC configuration',
                            asset=target, cvss='7.0',
                            details=f'Subject: {subject.get("name")}\nKind: {subject.get("kind")}\n'
                                    f'Mitigation: Apply least-privilege RBAC — use ClusterRole with specific verbs/resources')
                        break
            except Exception:
                pass
    except Exception:
        pass

    log('ok', f'[K8S] Scan complete — {len(k8s_findings)} findings')
    set_progress('kubernetes', 100)


# ─── ATTACK CHAIN DETECTION ───────────────────────────────────────────────────
# Chains link related findings into multi-step exploitation paths

ATTACK_CHAINS = [
    # (keywords_all_must_match, chain_name, severity)
    (['cors', 'xss'],                    'Session theft via CORS + XSS',                'critical'),
    (['sqli', 'auth'],                   'Auth bypass via SQLi + weak credentials',      'critical'),
    (['sqli', 'secret'],                 'Data dump via SQLi + leaked credentials',      'critical'),
    (['ssrf', 'cloud'],                  'Cloud metadata takeover via SSRF',            'critical'),
    (['ssrf', 'secret'],                 'Internal secrets exfil via SSRF',             'high'),
    (['lfi', 'secret'],                  'Credential theft via LFI',                    'high'),
    (['lfi', 'auth'],                    'Auth bypass via LFI + credential file read',  'critical'),
    (['xss', 'session'],                 'Session hijack via stored XSS',               'critical'),
    (['xss', 'redirect'],               'Phishing chain via XSS + open redirect',      'high'),
    (['upload', 'auth'],                 'Server compromise via file upload + auth',    'critical'),
    (['upload', 'cmdi'],                 'Remote code execution via upload',            'critical'),
    (['deser', 'auth'],                  'RCE via insecure deserialization',            'critical'),
    (['ssti', 'auth'],                   'RCE via template injection',                  'critical'),
    (['jwt', 'auth'],                    'Full auth bypass via JWT weakness',           'critical'),
    (['secret', 'cloud'],                'Cloud account compromise via leaked creds',   'critical'),
    (['idor', 'auth'],                   'Privilege escalation via IDOR',              'high'),
    (['cors', 'auth'],                   'Cross-origin credential theft',              'high'),
    (['smuggle', 'auth'],                'Request smuggling → auth bypass',            'critical'),
    (['cache', 'secret'],                'Credential leakage via cache poisoning',     'high'),
    (['container', 'secret'],            'Container escape via leaked credentials',    'critical'),
    (['container', 'cloud'],             'Cloud host compromise via container breakout','critical'),
    (['nosql', 'auth'],                  'NoSQL auth bypass + data exfil',             'high'),
    (['ldap', 'auth'],                   'LDAP auth bypass',                           'critical'),
    (['proto', 'xss'],                   'XSS via prototype pollution',                'high'),
    (['header', 'redirect'],             'Open redirect via header injection',         'high'),
    (['race', 'upload'],                 'Privilege escalation via race condition',    'high'),
    (['supplychain', 'secret'],          'Supply chain credential exposure',           'high'),
    (['port', 'auth'],                   'Brute force via exposed service',            'medium'),
    (['ssl', 'secret'],                  'Credential interception via weak TLS',       'high'),
    (['graphql', 'auth'],                'GraphQL auth bypass + data leak',            'high'),
    (['websocket', 'auth'],              'WebSocket auth bypass',                      'high'),
]




def run_takeover_module(target):
    log('info', f'[TAKEOVER] Checking for subdomain takeover vulnerabilities')
    takeover_data = []
    with LOCK:
        assets = list(scan_state.get('assets', []))
    for asset in assets:
        fqdn = asset.get('fqdn', '')
        if not fqdn:
            continue
        try:
            cname = ''
            if DNS_AVAILABLE:
                try:
                    answers = dns.resolver.resolve(fqdn, 'CNAME', lifetime=4)
                    cname = str(answers[0].target).rstrip('.')
                except Exception:
                    pass
            if cname:
                for domain, service in TAKEOVER_SERVICES.items():
                    if domain in cname.lower():
                        takeover_data.append({'subdomain': fqdn, 'service': service, 'cname': cname})
                        add_finding('high', f'Potential subdomain takeover: {fqdn}',
                            sub=f'{fqdn} has CNAME to {cname} pointing to {service}',
                            asset=fqdn, cvss='7.5', exploit='PUBLIC', owasp='A05', mitre='T1584')
                        log('warn', f'[TAKEOVER] {fqdn} -> {cname} (potential {service} takeover)')
                        break
        except Exception:
            pass
    log('ok', f'[TAKEOVER] Checked {len(assets)} assets — {len(takeover_data)} potential takeovers')
    with LOCK:
        scan_state['takeover_data'] = takeover_data
    set_progress('takeover', 100)

# ─── COMPLIANCE MODULE ─────────────────────────────────────────────────────────

def run_compliance_module(target):
    log('info', f'[COMPLIANCE] Performing comprehensive compliance audit for {target}')
    compliance = {}

    with LOCK:
        missing_hdrs = list(scan_state.get('header_data', {}).get('missing_security', []))
        findings = list(scan_state.get('findings', []))
        ports = list(scan_state.get('port_data', []))
        ssl_data = dict(scan_state.get('ssl_data', {}))
        techs = list(scan_state.get('tech_data', {}).get('technologies', []))
        assets = list(scan_state.get('assets', []))

    # ── OWASP Top 10 2021 Compliance ──
    log('info', '[COMPLIANCE] Checking OWASP Top 10 2021')
    owasp_checks = [
        {'id': 'A01', 'requirement': 'Broken Access Control', 'checks': [
            any('idor' in f.get('title', '').lower() for f in findings),
            any('access control' in f.get('title', '').lower() for f in findings),
            any('privilege' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A02', 'requirement': 'Cryptographic Failures', 'checks': [
            'Strict-Transport-Security' in missing_hdrs,
            ssl_data.get('protocol', '') in ('SSLv3', 'TLSv1', 'TLSv1.1'),
            any('weak cipher' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A03', 'requirement': 'Injection', 'checks': [
            any('sql injection' in f.get('title', '').lower() for f in findings),
            any('xss' in f.get('title', '').lower() for f in findings),
            any('command injection' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A04', 'requirement': 'Insecure Design', 'checks': [
            any('insecure design' in f.get('title', '').lower() for f in findings),
            len(findings) > 10,
        ]},
        {'id': 'A05', 'requirement': 'Security Misconfiguration', 'checks': [
            len(missing_hdrs) > 3,
            any('misconfiguration' in f.get('title', '').lower() for f in findings),
            any(p.get('port') in (23, 3389, 445, 3306, 6379) for p in ports),
        ]},
        {'id': 'A06', 'requirement': 'Vulnerable and Outdated Components', 'checks': [
            any('vulnerable' in f.get('title', '').lower() for f in findings),
            any('outdated' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A07', 'requirement': 'Identification and Authentication Failures', 'checks': [
            any('authentication' in f.get('title', '').lower() for f in findings),
            any('brute force' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A08', 'requirement': 'Software and Data Integrity Failures', 'checks': [
            any('integrity' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A09', 'requirement': 'Security Logging and Monitoring Failures', 'checks': [
            any('logging' in f.get('title', '').lower() for f in findings),
        ]},
        {'id': 'A10', 'requirement': 'Server-Side Request Forgery', 'checks': [
            any('ssrf' in f.get('title', '').lower() for f in findings),
        ]},
    ]
    owasp_pass = 0
    owasp_fail = 0
    owasp_failing = []
    for check in owasp_checks:
        fails = any(check['checks'])
        if fails:
            owasp_fail += 1
            owasp_failing.append({'id': check['id'], 'requirement': check['requirement']})
        else:
            owasp_pass += 1
    compliance['OWASP Top 10 2021'] = {
        'status': 'PASS' if owasp_fail == 0 else 'FAIL',
        'score': f'{owasp_pass}/10',
        'failing_requirements': owasp_failing,
        'checks_performed': 10,
        'checks_passed': owasp_pass
    }

    # ── CIS Benchmarks Compliance ──
    log('info', '[COMPLIANCE] Checking CIS Benchmarks')
    cis_checks = [
        {'id': 'CIS-1.1', 'requirement': 'Ensure HTTPS is enabled', 'passed': 'Strict-Transport-Security' not in missing_hdrs},
        {'id': 'CIS-1.2', 'requirement': 'Ensure HSTS header is present', 'passed': 'Strict-Transport-Security' not in missing_hdrs},
        {'id': 'CIS-1.3', 'requirement': 'Ensure CSP header is present', 'passed': 'Content-Security-Policy' not in missing_hdrs},
        {'id': 'CIS-1.4', 'requirement': 'Ensure X-Frame-Options is set', 'passed': 'X-Frame-Options' not in missing_hdrs},
        {'id': 'CIS-1.5', 'requirement': 'Ensure X-Content-Type-Options is set', 'passed': 'X-Content-Type-Options' not in missing_hdrs},
        {'id': 'CIS-1.6', 'requirement': 'Ensure Referrer-Policy is set', 'passed': 'Referrer-Policy' not in missing_hdrs},
        {'id': 'CIS-1.7', 'requirement': 'Ensure Permissions-Policy is set', 'passed': 'Permissions-Policy' not in missing_hdrs},
        {'id': 'CIS-2.1', 'requirement': 'Ensure SSL/TLS is properly configured', 'passed': ssl_data.get('protocol', '') not in ('SSLv3', 'TLSv1', 'TLSv1.1')},
        {'id': 'CIS-2.2', 'requirement': 'Ensure strong cipher suites', 'passed': not any(weak in ssl_data.get('cipher', '').lower() for weak in ['rc4', 'des', '3des', 'null'])},
        {'id': 'CIS-3.1', 'requirement': 'Ensure no critical ports are exposed', 'passed': not any(p.get('port') in (23, 3389, 445) for p in ports)},
        {'id': 'CIS-3.2', 'requirement': 'Ensure database ports are restricted', 'passed': not any(p.get('port') in (3306, 5432, 1433, 27017) for p in ports)},
        {'id': 'CIS-4.1', 'requirement': 'Ensure admin panels are not exposed', 'passed': not any('admin' in f.get('title', '').lower() for f in findings)},
    ]
    cis_pass = sum(1 for c in cis_checks if c['passed'])
    cis_fail = sum(1 for c in cis_checks if not c['passed'])
    compliance['CIS Benchmarks'] = {
        'status': 'PASS' if cis_fail == 0 else 'FAIL',
        'score': f'{cis_pass}/{len(cis_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in cis_checks if not c['passed']],
        'checks_performed': len(cis_checks),
        'checks_passed': cis_pass
    }

    # ── PCI-DSS v4.0 Compliance ──
    log('info', '[COMPLIANCE] Checking PCI-DSS v4.0')
    pci_checks = [
        {'id': 'PCI-1', 'requirement': 'Encrypt cardholder data in transit (TLS 1.2+)', 'passed': ssl_data.get('protocol', '') not in ('SSLv3', 'TLSv1', 'TLSv1.1')},
        {'id': 'PCI-2', 'requirement': 'Use strong cryptography', 'passed': not any(weak in ssl_data.get('cipher', '').lower() for weak in ['rc4', 'des', '3des', 'null', 'export'])},
        {'id': 'PCI-3', 'requirement': 'Implement strong access control', 'passed': not any('access control' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-4', 'requirement': 'Regular security testing', 'passed': len(findings) < 5},
        {'id': 'PCI-5', 'requirement': 'Maintain secure systems', 'passed': len(missing_hdrs) < 3},
        {'id': 'PCI-6', 'requirement': 'Protect sensitive data', 'passed': not any('sensitive' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-7', 'requirement': 'Restrict access by business need-to-know', 'passed': not any('idor' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-8', 'requirement': 'Identify users and authenticate access', 'passed': not any('authentication' in f.get('title', '').lower() for f in findings)},
        {'id': 'PCI-9', 'requirement': 'Restrict physical access', 'passed': True},
        {'id': 'PCI-10', 'requirement': 'Log and monitor all access', 'passed': not any('logging' in f.get('title', '').lower() for f in findings)},
    ]
    pci_pass = sum(1 for c in pci_checks if c['passed'])
    pci_fail = sum(1 for c in pci_checks if not c['passed'])
    compliance['PCI-DSS v4.0'] = {
        'status': 'PASS' if pci_fail == 0 else 'FAIL',
        'score': f'{pci_pass}/{len(pci_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in pci_checks if not c['passed']],
        'checks_performed': len(pci_checks),
        'checks_passed': pci_pass
    }

    # ── HIPAA Compliance ──
    log('info', '[COMPLIANCE] Checking HIPAA Security Rule')
    hipaa_checks = [
        {'id': 'HIPAA-1', 'requirement': 'Encrypt ePHI in transit (TLS)', 'passed': ssl_data.get('protocol', '') not in ('SSLv3', 'TLSv1', 'TLSv1.1')},
        {'id': 'HIPAA-2', 'requirement': 'Implement access controls', 'passed': not any('access control' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-3', 'requirement': 'Audit controls for access', 'passed': not any('logging' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-4', 'requirement': 'Integrity controls', 'passed': not any('integrity' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-5', 'requirement': 'Transmission security', 'passed': 'Strict-Transport-Security' not in missing_hdrs},
        {'id': 'HIPAA-6', 'requirement': 'Person or entity authentication', 'passed': not any('authentication' in f.get('title', '').lower() for f in findings)},
        {'id': 'HIPAA-7', 'requirement': 'Automatic logoff', 'passed': True},
        {'id': 'HIPAA-8', 'requirement': 'Emergency access procedure', 'passed': True},
    ]
    hipaa_pass = sum(1 for c in hipaa_checks if c['passed'])
    hipaa_fail = sum(1 for c in hipaa_checks if not c['passed'])
    compliance['HIPAA'] = {
        'status': 'PASS' if hipaa_fail == 0 else 'FAIL',
        'score': f'{hipaa_pass}/{len(hipaa_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in hipaa_checks if not c['passed']],
        'checks_performed': len(hipaa_checks),
        'checks_passed': hipaa_pass
    }

    # ── NIST CSF Compliance ──
    log('info', '[COMPLIANCE] Checking NIST Cybersecurity Framework')
    nist_checks = [
        {'id': 'NIST-IDENTIFY', 'requirement': 'Asset Management', 'passed': len(assets) > 0},
        {'id': 'NIST-PROTECT', 'requirement': 'Access Control', 'passed': not any('idor' in f.get('title', '').lower() for f in findings)},
        {'id': 'NIST-PROTECT', 'requirement': 'Data Security', 'passed': not any('sensitive' in f.get('title', '').lower() for f in findings)},
        {'id': 'NIST-DETECT', 'requirement': 'Detection Processes', 'passed': not any('logging' in f.get('title', '').lower() for f in findings)},
        {'id': 'NIST-RESPOND', 'requirement': 'Response Planning', 'passed': True},
        {'id': 'NIST-RECOVER', 'requirement': 'Recovery Planning', 'passed': True},
    ]
    nist_pass = sum(1 for c in nist_checks if c['passed'])
    nist_fail = sum(1 for c in nist_checks if not c['passed'])
    compliance['NIST CSF'] = {
        'status': 'PASS' if nist_fail == 0 else 'FAIL',
        'score': f'{nist_pass}/{len(nist_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in nist_checks if not c['passed']],
        'checks_performed': len(nist_checks),
        'checks_passed': nist_pass
    }

    # ── SOC 2 Compliance ──
    log('info', '[COMPLIANCE] Checking SOC 2 Trust Service Criteria')
    soc2_checks = [
        {'id': 'SOC2-CC6.1', 'requirement': 'Logical access controls', 'passed': not any('access control' in f.get('title', '').lower() for f in findings)},
        {'id': 'SOC2-CC6.6', 'requirement': 'System boundaries', 'passed': len(ports) < 15},
        {'id': 'SOC2-CC7.1', 'requirement': 'Vulnerability management', 'passed': len(findings) < 5},
        {'id': 'SOC2-CC8.1', 'requirement': 'Change management', 'passed': True},
        {'id': 'SOC2-A1.1', 'requirement': 'Capacity management', 'passed': True},
    ]
    soc2_pass = sum(1 for c in soc2_checks if c['passed'])
    soc2_fail = sum(1 for c in soc2_checks if not c['passed'])
    compliance['SOC 2'] = {
        'status': 'PASS' if soc2_fail == 0 else 'FAIL',
        'score': f'{soc2_pass}/{len(soc2_checks)}',
        'failing_requirements': [{'id': c['id'], 'requirement': c['requirement']} for c in soc2_checks if not c['passed']],
        'checks_performed': len(soc2_checks),
        'checks_passed': soc2_pass
    }

    # ── Summary ──
    total_checks = sum(c.get('checks_performed', 0) for c in compliance.values())
    total_passed = sum(c.get('checks_passed', 0) for c in compliance.values())
    overall_score = round(total_passed / total_checks * 100, 1) if total_checks > 0 else 0
    frameworks_failed = sum(1 for c in compliance.values() if c.get('status') == 'FAIL')

    compliance['_summary'] = {
        'total_frameworks': len([k for k in compliance.keys() if not k.startswith('_')]),
        'frameworks_passed': len([k for k in compliance.keys() if not k.startswith('_')]) - frameworks_failed,
        'frameworks_failed': frameworks_failed,
        'total_checks': total_checks,
        'total_passed': total_passed,
        'overall_score': overall_score,
        'scan_mode': 'active'
    }

    if frameworks_failed > 0:
        add_finding('info', f'Compliance gaps detected: {frameworks_failed} frameworks failing',
            sub=f'{total_checks - total_passed} of {total_checks} compliance checks failed across {frameworks_failed} frameworks',
            asset=target, cvss='4.0', owasp='A05', mitre='T1592',
            details=f'Failed frameworks: {", ".join([k for k, v in compliance.items() if not k.startswith("_") and v.get("status") == "FAIL"])}')

    log('ok', f'[COMPLIANCE] Audit complete: {total_passed}/{total_checks} checks passed ({overall_score}%)')
    with LOCK:
        scan_state['compliance_data'] = compliance
    set_progress('compliance', 100)

# ─── MONITORING MODULE ─────────────────────────────────────────────────────────

def run_monitoring_module(target):
    log('info', f'[MONITORING] Performing comprehensive monitoring analysis for {target}')
    monitoring = {
        'cert_expiry': {},
        'dns_changes': [],
        'ssl_configuration': {},
        'availability_checks': [],
        'security_headers_monitoring': {},
        'port_monitoring': [],
        'recommendations': [],
        'summary': {}
    }

    with LOCK:
        ssl_data = dict(scan_state.get('ssl_data', {}))
        assets = list(scan_state.get('assets', []))
        ports = list(scan_state.get('port_data', []))
        header_data = dict(scan_state.get('header_data', {}))
        dns_data = dict(scan_state.get('dns_data', {}))

    # ── Certificate Expiry Monitoring ──
    log('info', '[MONITORING] Analyzing certificate expiry status')
    cert_expiry = {
        'days_left': ssl_data.get('days_until_expiry', 999),
        'expires': ssl_data.get('not_after', 'N/A'),
        'issuer': ssl_data.get('issuer', 'N/A'),
        'subject': ssl_data.get('subject', 'N/A'),
        'status': 'healthy',
        'alert_level': 'info'
    }
    if cert_expiry['days_left'] < 7:
        cert_expiry['status'] = 'critical'
        cert_expiry['alert_level'] = 'critical'
        add_finding('critical', f'SSL certificate expires in {cert_expiry["days_left"]} days',
            sub=f'Certificate for {target} expires on {cert_expiry["expires"]}',
            asset=target, cvss='7.0', owasp='A07', mitre='T1587',
            details=f'Certificate issuer: {cert_expiry["issuer"]}')
    elif cert_expiry['days_left'] < 30:
        cert_expiry['status'] = 'warning'
        cert_expiry['alert_level'] = 'medium'
        add_finding('medium', f'SSL certificate expires in {cert_expiry["days_left"]} days',
            sub=f'Certificate for {target} expires on {cert_expiry["expires"]}',
            asset=target, cvss='4.0', owasp='A05', mitre='T1587')
    elif cert_expiry['days_left'] < 90:
        cert_expiry['status'] = 'attention'
        cert_expiry['alert_level'] = 'low'
    monitoring['cert_expiry'] = cert_expiry

    # ── DNS Change Monitoring ──
    log('info', '[MONITORING] Setting up DNS change monitoring')
    dns_changes = []
    if dns_data:
        a_records = dns_data.get('a_records', [])
        mx_records = dns_data.get('mx_records', [])
        ns_records = dns_data.get('ns_records', [])

        for record in a_records:
            dns_changes.append({
                'type': 'A',
                'value': record,
                'monitoring_status': 'active',
                'last_checked': datetime.now().isoformat()
            })
        for record in mx_records:
            dns_changes.append({
                'type': 'MX',
                'value': str(record),
                'monitoring_status': 'active',
                'last_checked': datetime.now().isoformat()
            })
        for record in ns_records:
            dns_changes.append({
                'type': 'NS',
                'value': record,
                'monitoring_status': 'active',
                'last_checked': datetime.now().isoformat()
            })
    monitoring['dns_changes'] = dns_changes

    # ── SSL Configuration Monitoring ──
    log('info', '[MONITORING] Analyzing SSL configuration')
    ssl_config = {
        'protocol': ssl_data.get('protocol', 'N/A'),
        'cipher': ssl_data.get('cipher', 'N/A'),
        'key_size': ssl_data.get('key_size', 'N/A'),
        'hsts_enabled': 'Strict-Transport-Security' not in header_data.get('missing_security', []),
        'ocsp_stapling': ssl_data.get('ocsp_stapling', False),
        'status': 'healthy',
        'issues': []
    }
    if ssl_config['protocol'] in ('SSLv3', 'TLSv1', 'TLSv1.1'):
        ssl_config['status'] = 'critical'
        ssl_config['issues'].append(f'Weak protocol: {ssl_config["protocol"]}')
    if any(weak in ssl_config['cipher'].lower() for weak in ['rc4', 'des', '3des', 'null']):
        ssl_config['status'] = 'critical'
        ssl_config['issues'].append(f'Weak cipher: {ssl_config["cipher"]}')
    if not ssl_config['hsts_enabled']:
        ssl_config['issues'].append('HSTS not enabled')
    monitoring['ssl_configuration'] = ssl_config

    # ── Availability Checks ──
    log('info', '[MONITORING] Performing availability checks')
    availability_checks = []
    check_urls = [
        f'https://{target}',
        f'http://{target}',
        f'https://www.{target}',
    ]
    for url in check_urls:
        try:
            start_time = time.time()
            r = req_lib.get(url, timeout=10, verify=False, allow_redirects=True)
            elapsed = round((time.time() - start_time) * 1000, 2)
            availability_checks.append({
                'url': url,
                'status_code': r.status_code,
                'response_time_ms': elapsed,
                'status': 'up' if r.status_code < 400 else 'degraded',
                'redirects': len(r.history),
                'final_url': r.url,
                'headers': dict(r.headers),
                'ssl_verify': r.verify
            })
        except Exception as e:
            availability_checks.append({
                'url': url,
                'status_code': 0,
                'response_time_ms': 0,
                'status': 'down',
                'error': str(e)[:100]
            })
    monitoring['availability_checks'] = availability_checks

    # ── Security Headers Monitoring ──
    log('info', '[MONITORING] Analyzing security headers status')
    missing_hdrs = header_data.get('missing_security', [])
    present_hdrs = header_data.get('present', [])
    headers_monitoring = {
        'missing_headers': missing_hdrs,
        'present_headers': present_hdrs,
        'total_expected': 12,
        'total_present': len(present_hdrs),
        'compliance_score': round(len(present_hdrs) / 12 * 100, 1),
        'critical_missing': [],
        'status': 'healthy'
    }
    critical_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
    for hdr in critical_headers:
        if hdr in missing_hdrs:
            headers_monitoring['critical_missing'].append(hdr)
    if headers_monitoring['critical_missing']:
        headers_monitoring['status'] = 'warning'
    monitoring['security_headers_monitoring'] = headers_monitoring

    # ── Port Monitoring ──
    log('info', '[MONITORING] Setting up port monitoring')
    port_monitoring = []
    for p in ports[:20]:
        port_monitoring.append({
            'port': p.get('port', 0),
            'service': p.get('service', 'unknown'),
            'status': 'open',
            'monitoring_status': 'active',
            'last_checked': datetime.now().isoformat()
        })
    monitoring['port_monitoring'] = port_monitoring

    # ── Recommendations ──
    recommendations = []
    if cert_expiry['days_left'] < 30:
        recommendations.append({
            'priority': 'high',
            'action': 'Renew SSL certificate immediately',
            'detail': f'Certificate expires in {cert_expiry["days_left"]} days'
        })
    if ssl_config['issues']:
        recommendations.append({
            'priority': 'high',
            'action': 'Fix SSL configuration issues',
            'detail': '; '.join(ssl_config['issues'])
        })
    if missing_hdrs:
        recommendations.append({
            'priority': 'medium',
            'action': 'Add missing security headers',
            'detail': f'Missing: {", ".join(missing_hdrs[:5])}'
        })
    if any(c.get('status') == 'down' for c in availability_checks):
        recommendations.append({
            'priority': 'critical',
            'action': 'Investigate availability issues',
            'detail': 'Some endpoints are not responding'
        })
    monitoring['recommendations'] = recommendations

    # ── Summary ──
    monitoring['summary'] = {
        'cert_status': cert_expiry['status'],
        'cert_days_left': cert_expiry['days_left'],
        'dns_records_monitored': len(dns_changes),
        'ssl_config_status': ssl_config['status'],
        'availability_up': sum(1 for c in availability_checks if c.get('status') == 'up'),
        'availability_total': len(availability_checks),
        'headers_compliance_score': headers_monitoring['compliance_score'],
        'ports_monitored': len(port_monitoring),
        'total_recommendations': len(recommendations),
        'scan_mode': 'active'
    }

    log('ok', f'[MONITORING] Analysis complete: cert {cert_expiry["status"]}, {len(recommendations)} recommendations')
    with LOCK:
        scan_state['monitoring_data'] = monitoring
    set_progress('monitoring', 100)

# ─── CLOUD STORAGE MODULE ──────────────────────────────────────────────────────
