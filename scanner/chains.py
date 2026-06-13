"""Vulnerability Chain Mapping — graph building, BFS path search, loot extraction, chain reporting.

Builds attack graphs from confirmed findings, finds paths to high-value objectives,
and generates step-by-step chain reports.
"""
import time
import json
from collections import defaultdict, deque
from core.logger import log
from core.utils import SQLITE_AVAILABLE, sqlite3_mod
from core.database import DB_PATH
from scanner.state import scan_state, LOCK

# ── Node / Edge types ──────────────────────────────────────────────────────────

NODE_STATES = {
    'unauth': {'label': 'Unauthenticated', 'level': 0},
    'auth': {'label': 'Authenticated', 'level': 1},
    'admin': {'label': 'Admin Access', 'level': 2},
    'internal': {'label': 'Internal Network', 'level': 3},
    'rce': {'label': 'Remote Code Execution', 'level': 4},
    'data_exfil': {'label': 'Data Exfiltration', 'level': 5},
}

SEVERITY_WEIGHT = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}

# ── Finding → state transition mapping ─────────────────────────────────────────

def _finding_enables_state(finding):
    """Determine what state transition a finding enables."""
    title = (finding.get('title', '') + ' ' + finding.get('details', '')).lower()
    sev = finding.get('sev', 'info')
    transitions = []
    if any(kw in title for kw in ['auth bypass', 'authentication bypass', 'credential', 'default password', 'brute force']):
        transitions.append(('unauth', 'auth', 'credential_theft'))
    if any(kw in title for kw in ['xss', 'cross-site scripting', 'session fixation', 'session hijack']):
        transitions.append(('auth', 'auth', 'session_hijack'))
    if any(kw in title for kw in ['sqli', 'sql injection', 'database']):
        transitions.append(('auth', 'internal', 'database_access'))
    if any(kw in title for kw in ['command injection', 'cmdi', 'rce', 'code execution', 'ssti', 'deserialization']):
        transitions.append(('unauth', 'rce', 'command_execution'))
        transitions.append(('auth', 'rce', 'command_execution'))
    if any(kw in title for kw in ['ssrf', 'server-side request forgery']):
        transitions.append(('unauth', 'internal', 'ssrf'))
        transitions.append(('auth', 'internal', 'ssrf'))
    if any(kw in title for kw in ['privilege escalation', 'idor', 'broken access', 'vertical']):
        transitions.append(('auth', 'admin', 'privilege_escalation'))
    if any(kw in title for kw in ['admin', 'dashboard', 'panel']):
        transitions.append(('auth', 'admin', 'admin_access'))
    if any(kw in title for kw in ['file read', 'lfi', 'path traversal', 'file inclusion']):
        transitions.append(('auth', 'internal', 'file_access'))
    if any(kw in title for kw in ['data leak', 'exfiltration', 'pii', 'sensitive data']):
        transitions.append(('internal', 'data_exfil', 'data_theft'))
    if not transitions:
        transitions.append(('unauth', 'unauth', 'info_gather'))
    return transitions

# ── Graph building ─────────────────────────────────────────────────────────────

class AttackGraph:
    """Graph of achievable states from confirmed findings."""

    def __init__(self):
        self.nodes = {}  # state_id → {label, level, findings}
        self.edges = []  # [{from, to, type, finding, evidence}]
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)
        transitions = _finding_enables_state(finding)
        for from_state, to_state, edge_type in transitions:
            if from_state not in self.nodes:
                self.nodes[from_state] = NODE_STATES.get(from_state, {'label': from_state, 'level': 0})
            if to_state not in self.nodes:
                self.nodes[to_state] = NODE_STATES.get(to_state, {'label': to_state, 'level': 0})
            self.edges.append({
                'from': from_state, 'to': to_state, 'type': edge_type,
                'finding': finding.get('title', ''),
                'severity': finding.get('sev', 'info'),
                'evidence': finding.get('details', '')[:500],
            })

    def find_paths(self, start='unauth', goals=None):
        """BFS to find all paths from start to goal states."""
        if goals is None:
            goals = ['rce', 'data_exfil', 'admin']
        adj = defaultdict(list)
        for e in self.edges:
            adj[e['from']].append(e)
        paths = []
        queue = deque([(start, [])])
        visited = set()
        while queue:
            state, path = queue.popleft()
            if state in goals:
                paths.append(path)
                continue
            if state in visited:
                continue
            visited.add(state)
            for edge in adj.get(state, []):
                if edge['to'] not in [p['to'] for p in path]:
                    queue.append((edge['to'], path + [edge]))
        return paths

    def to_dict(self):
        return {
            'nodes': self.nodes,
            'edges': self.edges,
            'paths': self.find_paths(),
        }

# ── Chain reporting ────────────────────────────────────────────────────────────

def build_attack_chains_full():
    """Build vulnerability chains from current scan findings."""
    with LOCK:
        findings = list(scan_state.get('findings', []))
    if not findings:
        return {'chains': [], 'graph': {}, 'total_paths': 0}
    graph = AttackGraph()
    for f in findings:
        if f.get('sev') in ('critical', 'high', 'medium'):
            graph.add_finding(f)
    paths = graph.find_paths()
    chains = []
    for i, path in enumerate(paths):
        if not path: continue
        chain = {
            'chain_id': f'CHAIN-{int(time.time())}-{i:04d}',
            'path': [],
            'hops': len(path),
            'findings_used': [],
            'combined_cvss': 0,
            'narrative': '',
        }
        cvss_sum = 0
        for edge in path:
            chain['path'].append(f'{edge["from"]} → {edge["type"]} → {edge["to"]}')
            chain['findings_used'].append(edge['finding'])
            cvss_sum += SEVERITY_WEIGHT.get(edge['severity'], 1)
        chain['combined_cvss'] = min(10.0, round(cvss_sum / len(path), 1))
        narrative_parts = [f'## Attack Chain: {chain["chain_id"]}\n']
        narrative_parts.append(f'**Hops:** {chain["hops"]} | **Combined CVSS:** {chain["combined_cvss"]}\n')
        for j, edge in enumerate(path):
            narrative_parts.append(f'### Step {j+1}: {edge["type"].replace("_"," ").title()}')
            narrative_parts.append(f'**From:** {edge["from"]} → **To:** {edge["to"]}')
            narrative_parts.append(f'**Finding:** {edge["finding"]}')
            narrative_parts.append(f'**Severity:** {edge["severity"]}')
            narrative_parts.append(f'**Evidence:** {edge["evidence"][:200]}\n')
        chain['narrative'] = '\n'.join(narrative_parts)
        chains.append(chain)
    graph_dict = graph.to_dict()
    with LOCK:
        scan_state['attack_chains'] = chains
    log('ok', f'[CHAINS] Built {len(chains)} attack chains from {len(findings)} findings')
    return {'chains': chains, 'graph': graph_dict, 'total_paths': len(paths)}
