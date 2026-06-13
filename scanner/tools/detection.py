"""Tool availability detection and Python fallback registry."""
from core.utils import _find_tool
from core.logger import log
from scanner.state import scan_state, LOCK

# Tools that have pure-Python fallback implementations (no binary required)
PYTHON_FALLBACK_TOOLS = {
    'tplmap', 'searchsploit', 'ssrfmap', 'theHarvester', 'wpscan',
    'feroxbuster', 'nikto', 'rustscan', 'jwt_tool', 'bearer', 'grype',
}

REQUIRED_TOOLS = {
    'nmap': 'apt install nmap',
    'sqlmap': 'pip install sqlmap',
    'nuclei': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    'ffuf': 'go install github.com/ffuf/ffuf/v2@latest',
    'httpx': 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'subfinder': 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'dalfox': 'go install github.com/hahwul/dalfox/v2@latest',
    'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
    'katana': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
    'osv-scanner': 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest',
    'gitleaks': 'go install github.com/gitleaks/gitleaks@latest',
    'semgrep': 'pip install semgrep',
    'trivy': 'apt install trivy OR curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh',
    'checkov': 'pip install checkov',
    'wafw00f': 'pip install wafw00f',
    'testssl.sh': 'git clone https://github.com/drwetter/testssl.sh.git && ln -s testssl.sh/testssl.sh /usr/local/bin/testssl.sh',
}

OPTIONAL_TOOLS = {
    'arjun': 'pip install arjun',
    'naabu': 'go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
    'commix': 'pip install commix',
    'tplmap': 'git clone https://github.com/epinna/tplmap.git',
    'puredns': 'go install github.com/d3mondev/puredns/v2@latest',
    'searchsploit': 'apt install exploitdb',
    'gospider': 'go install github.com/jaeles-project/gospider@latest',
    'ssrfmap': 'git clone https://github.com/swisskyrepo/SSRFmap.git',
    'theHarvester': 'pip install theHarvester',
    'wpscan': 'gem install wpscan',
    'feroxbuster': 'apt install feroxbuster',
    'nikto': 'apt install nikto',
    'rustscan': 'cargo install rustscan OR apt install rustscan',
    'dnsx': 'go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
    'hakrawler': 'go install github.com/hakluke/hakrawler@latest',
    'crlfuzz': 'go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest',
    'jwt_tool': 'git clone https://github.com/ticarpi/jwt_tool.git',
    'amass': 'go install github.com/owasp-amass/amass/v4/...@master',
    'mitmproxy': 'pip install mitmproxy',
    'playwright': 'pip install playwright && playwright install chromium',
    'bearer': 'npm install -g @bearer/bearer',
    'grype': 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin',
    # HexStrike tools (pre-installed on Kali Linux)
    'masscan': 'apt install masscan',
    'fierce': 'apt install fierce',
    'dnsenum': 'apt install dnsenum',
    'autorecon': 'pip install autorecon',
    'arp-scan': 'apt install arp-scan',
    'nbtscan': 'apt install nbtscan',
    'enum4linux': 'apt install enum4linux',
    'enum4linux-ng': 'pip install enum4linux-ng',
    'smbmap': 'pip install smbmap',
    'responder': 'apt install responder',
    'netexec': 'pip install netexec',
    'rpcclient': 'apt install rpcclient',
    'gobuster': 'apt install gobuster',
    'dirsearch': 'pip install dirsearch',
    'dirb': 'apt install dirb',
    'whatweb': 'apt install whatweb',
    'wfuzz': 'apt install wfuzz',
    'jaeles': 'go install github.com/jaeles-project/jaeles@latest',
    'x8': 'go install github.com/Sh1ne0x8/x8@latest',
    'sslyze': 'pip install sslyze',
    'sslscan': 'apt install sslscan',
    'hydra': 'apt install hydra',
    'john': 'apt install john',
    'hashcat': 'apt install hashcat',
    'medusa': 'apt install medusa',
    'evil-winrm': 'gem install evil-winrm',
    'hashid': 'pip install hashid',
    'checksec': 'apt install checksec',
    'binwalk': 'apt install binwalk',
    'r2': 'apt install radare2',
    'radare2': 'apt install radare2',
    'volatility3': 'pip install volatility3',
    'foremost': 'apt install foremost',
    'steghide': 'apt install steghide',
    'exiftool': 'apt install libimage-exiftool-perl',
    'zsteg': 'gem install zsteg',
    'prowler': 'pip install prowler',
    'scout': 'pip install scout-suite',
    'kube-hunter': 'pip install kube-hunter',
    'kube-bench': 'apt install kube-bench',
    'docker-bench-security': 'apt install docker-bench-security',
    'falco': 'apt install falco',
    'bulk_extractor': 'apt install bulk-extractor',
    'scalpel': 'apt install scalpel',
    'sherlock': 'pip install sherlock-project',
    'recon-ng': 'apt install recon-ng',
    'spiderfoot': 'apt install spiderfoot',
    'shodan': 'pip install shodan',
    'censys': 'pip install censys',
}


def check_tool_availability():
    """Check all tools at startup and log status."""
    available = []
    missing_required = []
    missing_optional = []
    for name, install_cmd in REQUIRED_TOOLS.items():
        path = _find_tool(name)
        if path:
            available.append(name)
        else:
            missing_required.append((name, install_cmd))
    for name, install_cmd in OPTIONAL_TOOLS.items():
        path = _find_tool(name)
        # Special case: theHarvester binary name varies
        if not path and name == 'theHarvester':
            path = _find_tool('theharvester')
        if path:
            available.append(name)
        elif name in PYTHON_FALLBACK_TOOLS:
            available.append(f'{name} (python)')
        else:
            missing_optional.append((name, install_cmd))
    total = len(available) + len(missing_required) + len(missing_optional)
    log('info', f'[TOOLS] {len(available)}/{total} tools available')
    if missing_required:
        log('warn', f'[TOOLS] Missing {len(missing_required)} required: {", ".join(n for n, _ in missing_required[:5])}')
    if missing_optional:
        log('warn', f'[TOOLS] Missing {len(missing_optional)} optional: {", ".join(n for n, _ in missing_optional[:5])}')
    # Store in scan_state for UI
    with LOCK:
        scan_state['tool_availability'] = {
            'available': available,
            'missing_required': [(n, c) for n, c in missing_required],
            'missing_optional': [(n, c) for n, c in missing_optional],
        }
    return available, missing_required, missing_optional
