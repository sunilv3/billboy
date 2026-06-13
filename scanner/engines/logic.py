"""ENGINE 3: State-Aware Logic-Flaw Hunting (FULL).

Discovers multi-step flows and tests:
- Step skipping, step repetition, step reversal
- Race conditions (5 concurrent), replay attacks
- Parameter tampering (negative, boundary, cross-step injection)
"""
import time
import re
import threading
import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from core.logger import log
from core.utils import req_lib, REQUESTS_AVAILABLE
from scanner.state import scan_state, LOCK
from scanner.findings import add_finding

def _discover_flows(target, crawl_data):
    flows = []
    forms = crawl_data.get('forms', [])
    urls = crawl_data.get('urls', [])
    action_groups = {}
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        if action:
            action_groups.setdefault(action, []).append({'method': method, 'inputs': inputs})
    login_flow, register_flow, checkout_flow, password_flow = [], [], [], []
    for url_str in urls:
        url_lower = url_str.lower() if isinstance(url_str, str) else ''
        if any(kw in url_lower for kw in ['login', 'signin', 'auth']):
            login_flow.append(url_str)
        elif any(kw in url_lower for kw in ['register', 'signup', 'create']):
            register_flow.append(url_str)
        elif any(kw in url_lower for kw in ['checkout', 'payment', 'cart']):
            checkout_flow.append(url_str)
        elif any(kw in url_lower for kw in ['password', 'reset', 'forgot', 'change']):
            password_flow.append(url_str)
    if login_flow: flows.append({'name': 'Login Flow', 'steps': login_flow[:5], 'type': 'authentication'})
    if register_flow: flows.append({'name': 'Registration Flow', 'steps': register_flow[:5], 'type': 'registration'})
    if checkout_flow: flows.append({'name': 'Checkout Flow', 'steps': checkout_flow[:5], 'type': 'transaction'})
    if password_flow: flows.append({'name': 'Password Reset Flow', 'steps': password_flow[:5], 'type': 'password_reset'})
    if action_groups and not flows:
        sorted_actions = sorted(action_groups.keys())
        flows.append({'name': 'Generic Form Flow', 'steps': sorted_actions[:10], 'type': 'generic'})
    return flows

def _test_step_skipping(engine, flow, session):
    findings = []
    steps = flow.get('steps', [])
    if len(steps) < 2: return findings
    for i, step_url in enumerate(steps[1:], 1):
        try:
            resp = session.get(step_url, timeout=10, verify=False)
            if resp.status_code == 200 and i > 1:
                body = resp.text[:2000] if resp.text else ''
                if not any(kw in body.lower() for kw in ['login', 'sign in', 'unauthorized', 'forbidden']):
                    findings.append({'type': 'step_skipping', 'flow': flow['name'], 'step_index': i,
                                    'url': step_url, 'status': resp.status_code,
                                    'evidence': f'Step {i} ({step_url}) accessible without completing steps 0-{i-1}'})
        except Exception:
            pass
    return findings

def _test_step_repetition(engine, flow, session):
    findings = []
    for step_url in flow.get('steps', []):
        try:
            responses = []
            for _ in range(5):
                resp = session.get(step_url, timeout=10, verify=False)
                responses.append(resp.status_code)
                time.sleep(0.1)
            success_count = sum(1 for s in responses if s < 400)
            if success_count >= 4:
                findings.append({'type': 'step_repetition', 'flow': flow['name'], 'url': step_url,
                                'repeat_count': 5, 'success_count': success_count,
                                'evidence': f'Endpoint succeeded {success_count}/5 times — possible idempotency violation'})
        except Exception:
            pass
    return findings

def _test_step_reversal(engine, flow, session):
    """Test if going back to a previous step after completing a later step causes issues."""
    findings = []
    steps = flow.get('steps', [])
    if len(steps) < 3: return findings
    try:
        # Complete the flow normally
        for step_url in steps:
            session.get(step_url, timeout=10, verify=False)
            time.sleep(0.1)
        # Now go back to step 1
        resp_back = session.get(steps[0], timeout=10, verify=False)
        # Then try to proceed to the last step directly
        resp_last = session.get(steps[-1], timeout=10, verify=False)
        if resp_back.status_code == 200 and resp_last.status_code == 200:
            body_back = (resp_back.text or '')[:2000]
            body_last = (resp_last.text or '')[:2000]
            # If both succeed and have different content, state may not be properly enforced
            if len(set([body_back[:500], body_last[:500]])) > 1:
                findings.append({'type': 'step_reversal', 'flow': flow['name'],
                                'url': steps[0], 'evidence':
                                f'Step reversal: returned to step 0 after completing flow, '
                                f'state may not be properly enforced'})
    except Exception:
        pass
    return findings

def _test_parameter_tampering(engine, flow, session):
    findings = []
    tamper_payloads = {
        'price': ['-1', '0', '999999999', '-0.01'],
        'quantity': ['-1', '0', '2147483647', '-999'],
        'discount': ['100', '999', '-50'],
        'user_id': ['1', '0', '999999', '../admin'],
        'admin': ['true', '1', 'yes'],
        'role': ['admin', 'root', 'superuser'],
    }
    for step_url in flow.get('steps', []):
        parsed = urlparse(step_url)
        params = parse_qs(parsed.query)
        for param_name in params:
            for tamper_key, payloads in tamper_payloads.items():
                if tamper_key in param_name.lower():
                    for payload in payloads:
                        try:
                            tampered_params = {k: v[0] for k, v in params.items()}
                            tampered_params[param_name] = payload
                            tampered_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(tampered_params)}'
                            resp = session.get(tampered_url, timeout=10, verify=False)
                            if resp.status_code == 200:
                                body = (resp.text or '')[:2000].lower()
                                if any(kw in body for kw in ['success', 'confirmed', 'complete', 'thank']):
                                    findings.append({'type': 'parameter_tampering', 'flow': flow['name'],
                                                    'url': step_url, 'param': param_name, 'payload': payload,
                                                    'evidence': f'Parameter {param_name} accepted value {payload!r} and returned success'})
                                    break
                        except Exception:
                            pass
    return findings

def _test_cross_step_injection(engine, flow, session):
    """Inject a value in step 1, check if it reflects/exploits in step 3."""
    findings = []
    steps = flow.get('steps', [])
    if len(steps) < 3: return findings
    injection_payloads = ['<script>alert(1)</script>', "' OR '1'='1", '../../../../etc/passwd', '; id']
    for payload in injection_payloads:
        try:
            # Inject in step 1
            resp1 = session.get(steps[0], params={'inject': payload}, timeout=10, verify=False)
            # Check reflection in step 3
            resp3 = session.get(steps[-1], timeout=10, verify=False)
            if resp3.status_code == 200:
                body3 = (resp3.text or '')[:5000]
                if payload in body3:
                    findings.append({'type': 'cross_step_injection', 'flow': flow['name'],
                                    'url': steps[-1], 'payload': payload,
                                    'evidence': f'Payload injected in step 0 reflected in step {len(steps)-1}'})
                    break
        except Exception:
            pass
    return findings

def _test_race_conditions(engine, flow, session):
    findings = []
    for step_url in flow.get('steps', []):
        try:
            results = []
            barrier = threading.Barrier(5)
            def _send():
                try:
                    barrier.wait(timeout=5)
                    resp = session.get(step_url, timeout=10, verify=False)
                    results.append({'status': resp.status_code, 'length': len(resp.text or '')})
                except Exception:
                    pass
            threads = [threading.Thread(target=_send) for _ in range(5)]
            for t in threads: t.start()
            for t in threads: t.join(timeout=15)
            if len(results) >= 4:
                statuses = [r['status'] for r in results]
                if len(set(statuses)) > 1 and 200 in statuses:
                    findings.append({'type': 'race_condition', 'flow': flow['name'], 'url': step_url,
                                    'concurrent_requests': len(results), 'statuses': statuses,
                                    'evidence': f'{len(results)} concurrent requests produced mixed statuses {statuses}'})
                lengths = [r['length'] for r in results]
                if len(lengths) >= 4 and max(lengths) - min(lengths) > 5000:
                    findings.append({'type': 'race_condition', 'flow': flow['name'], 'url': step_url,
                                    'evidence': f'Response lengths vary by {max(lengths)-min(lengths)} bytes'})
        except Exception:
            pass
    return findings

def _test_replay_attacks(engine, flow, session):
    findings = []
    for step_url in flow.get('steps', []):
        try:
            responses = []
            for _ in range(10):
                resp = session.get(step_url, timeout=10, verify=False)
                responses.append({'status': resp.status_code, 'length': len(resp.text or '')})
                time.sleep(0.05)
            success_count = sum(1 for r in responses if r['status'] < 400)
            if success_count >= 8:
                lengths = [r['length'] for r in responses]
                if len(set(lengths)) > 3:
                    findings.append({'type': 'replay_attack', 'flow': flow['name'], 'url': step_url,
                                    'replay_count': 10, 'success_count': success_count,
                                    'evidence': f'Accepted {success_count}/10 replays with varying response lengths'})
        except Exception:
            pass
    return findings

class LogicFlawEngine:
    """State-aware logic-flaw hunting engine (FULL)."""

    def __init__(self, target, max_flow_steps=10):
        self.target = target
        self.max_flow_steps = max_flow_steps
        self.flows = []
        self.findings = []
        self.request_count = 0

    def run(self, crawl_data):
        log('info', f'[LOGIC] Starting logic-flaw hunting for {self.target}')
        self.flows = _discover_flows(self.target, crawl_data)
        if not self.flows:
            return {'flows': [], 'findings': [], 'requests': 0}
        session = req_lib.Session() if REQUESTS_AVAILABLE and req_lib else None
        if not session:
            return {'flows': self.flows, 'findings': [], 'requests': 0}
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        for flow in self.flows:
            flow['steps'] = flow['steps'][:self.max_flow_steps]
            test_funcs = [
                ('step_skipping', _test_step_skipping),
                ('step_repetition', _test_step_repetition),
                ('step_reversal', _test_step_reversal),
                ('parameter_tampering', _test_parameter_tampering),
                ('cross_step_injection', _test_cross_step_injection),
                ('race_conditions', _test_race_conditions),
                ('replay_attacks', _test_replay_attacks),
            ]
            for test_name, test_func in test_funcs:
                try:
                    new_findings = test_func(self, flow, session)
                    self.findings.extend(new_findings)
                    for f in new_findings:
                        try:
                            sev = 'high' if f['type'] in ('race_condition', 'parameter_tampering', 'cross_step_injection') else 'medium'
                            add_finding(sev=sev, title=f'{f["type"].replace("_"," ").title()} in {flow["name"]}',
                                       sub=f'Logic engine — {test_name}', asset=f.get('url', ''),
                                       details=f'Evidence: {f["evidence"]}\nFlow: {flow["name"]}', confidence='medium')
                        except Exception:
                            pass
                except Exception:
                    pass
        log('ok', f'[LOGIC] Complete: {len(self.flows)} flows, {len(self.findings)} findings')
        return {'flows': self.flows, 'findings': self.findings, 'requests': self.request_count}
