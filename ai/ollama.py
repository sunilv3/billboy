"""Ollama LLM integration for AI-assisted vulnerability analysis — enhanced."""
import json
import time
import os
from core.utils import req_lib, REQUESTS_AVAILABLE
from core.logger import log

OLLAMA_BASE = os.environ.get('OLLAMA_BASE_URL', 'http://127.0.0.1:11434')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'dolphin3:8b')

# Model fallback order — try these if primary model unavailable
MODEL_FALLBACKS = [
    'dolphin3:8b',
    'llama3.2:3b',
    'mistral:7b',
    'codellama:7b',
    'phi3:3.8b',
]


def _ollama_generate(prompt, system='', timeout=120, retries=2):
    """Call Ollama API with retries and fallback. Returns response text or None."""
    system = system or 'You are a senior penetration tester and vulnerability analyst. Analyze security findings with precision. Be concise and direct. Respond in valid JSON only.'

    for attempt in range(retries + 1):
        try:
            payload = {
                'model': OLLAMA_MODEL,
                'messages': [
                    {'role': 'system', 'content': system},
                    {'role': 'user', 'content': prompt},
                ],
                'stream': False,
                'options': {
                    'temperature': 0.2,  # Lower = more deterministic
                    'num_predict': 4096,
                    'top_p': 0.9,
                    'repeat_penalty': 1.1,
                },
            }
            r = req_lib.post(f'{OLLAMA_BASE}/api/chat', json=payload, timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                content = data.get('message', {}).get('content', '')
                if content:
                    return content
            elif r.status_code == 503:
                # Model loading — wait and retry
                log('warn', f'[AI] Model loading, retrying in 5s... (attempt {attempt+1})')
                time.sleep(5)
                continue
        except Exception as e:
            if attempt < retries:
                log('warn', f'[AI] Ollama call failed (attempt {attempt+1}): {e}')
                time.sleep(2)
            else:
                log('warn', f'[AI] Ollama call failed after {retries+1} attempts: {e}')
    return None


def _ollama_available():
    """Check if Ollama is reachable and the model is available."""
    try:
        r = req_lib.get(f'{OLLAMA_BASE}/api/tags', timeout=5)
        if r.status_code == 200:
            models = [m.get('name', '') for m in r.json().get('models', [])]
            # Check if primary model is available
            if any(OLLAMA_MODEL in m for m in models):
                return True
            # Check fallbacks
            for fallback in MODEL_FALLBACKS:
                if any(fallback in m for m in models):
                    global OLLAMA_MODEL
                    OLLAMA_MODEL = fallback
                    log('info', f'[AI] Using fallback model: {fallback}')
                    return True
    except Exception:
        pass
    return False


def _ollama_list_models():
    """List all available Ollama models."""
    try:
        r = req_lib.get(f'{OLLAMA_BASE}/api/tags', timeout=5)
        if r.status_code == 200:
            return [m.get('name', '') for m in r.json().get('models', [])]
    except Exception:
        pass
    return []


def _ollama_pull_model(model=None):
    """Pull a model from Ollama registry."""
    model = model or OLLAMA_MODEL
    try:
        r = req_lib.post(f'{OLLAMA_BASE}/api/pull', json={'name': model}, timeout=300)
        return r.status_code == 200
    except Exception:
        return False
