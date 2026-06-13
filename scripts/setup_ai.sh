#!/bin/bash
# ─── AI Analysis Setup (Ollama + Dolphin 3:8B) ─────────────────────────────
# This sets up the local AI engine for post-scan analysis.
# Requirements: 8GB+ RAM or 4GB+ VRAM GPU
# ─────────────────────────────────────────────────────────────────────────────

set -e

OLLAMA_MODEL="${OLLAMA_MODEL:-dolphin3:8b}"
OLLAMA_BIN="$HOME/.local/bin/ollama"

echo "═══════════════════════════════════════════════════════════════"
echo "  AI Post-Scan Analysis Setup"
echo "  Model: $OLLAMA_MODEL"
echo "═══════════════════════════════════════════════════════════════"

# ── Step 1: Install Ollama ──
if command -v ollama &>/dev/null || [ -x "$OLLAMA_BIN" ]; then
    echo "[OK] Ollama already installed: $(ollama --version 2>/dev/null || $OLLAMA_BIN --version 2>/dev/null)"
else
    echo "[..] Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo "[OK] Ollama installed"
fi

# ── Step 2: Start Ollama server ──
if curl -s http://127.0.0.1:11434/api/tags &>/dev/null; then
    echo "[OK] Ollama server already running"
else
    echo "[..] Starting Ollama server..."
    ollama serve &>/dev/null &
    sleep 3
    if curl -s http://127.0.0.1:11434/api/tags &>/dev/null; then
        echo "[OK] Ollama server started"
    else
        echo "[!!] Failed to start Ollama. Try: ollama serve"
        exit 1
    fi
fi

# ── Step 3: Pull model ──
echo "[..] Pulling $OLLAMA_MODEL (this may take a few minutes)..."
ollama pull "$OLLAMA_MODEL"
echo "[OK] Model $OLLAMA_MODEL ready"

# ── Step 4: Verify ──
echo ""
echo "[..] Verifying setup..."
MODELS=$(ollama list 2>/dev/null | grep "$OLLAMA_MODEL")
if [ -n "$MODELS" ]; then
    echo "[OK] Everything ready!"
    echo ""
    echo "  Model:  $OLLAMA_MODEL"
    echo "  Server: http://127.0.0.1:11434"
    echo "  Usage:  Run a scan → Click 'AI Analysis' in Findings tab"
    echo ""
    echo "  Environment variables (optional):"
    echo "    OLLAMA_BASE_URL=http://127.0.0.1:11434"
    echo "    OLLAMA_MODEL=$OLLAMA_MODEL"
else
    echo "[!!] Model not found. Try: ollama pull $OLLAMA_MODEL"
    exit 1
fi
