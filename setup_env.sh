#!/bin/bash
# FMAttack setup: clone opencis-core and install dependencies
set -e

REPO_DIR="$(dirname "$0")/opencis-core"

echo "[*] Cloning opencis-core..."
if [ ! -d "$REPO_DIR" ]; then
    git clone --depth=1 https://github.com/opencis/opencis-core.git "$REPO_DIR"
else
    echo "    Already cloned, skipping."
fi

echo "[*] Installing Python dependencies..."
pip install --break-system-packages \
    "python-socketio[asyncio_client]>=5.10.0" \
    "aiohttp>=3.8.6" \
    "websockets>=12.0" \
    "pyyaml>=6.0.1" \
    "click>=8.1.7" \
    "humanfriendly>=10.0" \
    "sortedcontainers>=2.4.0" \
    "readerwriterlock>=1.0.9" \
    "dill>=0.3.7" \
    "jsonrpcserver>=5.0.9" \
    "jsonrpcclient>=4.0.3" \
    "psutil>=5.9.0" \
    2>/dev/null

# Install opencis itself
cd "$REPO_DIR"
pip install --break-system-packages -e . --no-deps 2>/dev/null || \
pip install --break-system-packages . --no-deps 2>/dev/null || true

echo "[*] Setup complete."
echo "    Run experiments with: python run_experiments.py"
