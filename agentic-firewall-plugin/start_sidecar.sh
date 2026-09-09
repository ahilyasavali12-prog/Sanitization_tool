#!/usr/bin/env bash
# Start the firewall sidecar in the background and verify it.
cd "$(dirname "$0")"
if curl -s --max-time 2 http://127.0.0.1:8100/health > /dev/null 2>&1; then
    echo "✅ Sidecar already running."
    exit 0
fi
nohup python3 scripts/sidecar.py > data/sidecar.log 2>&1 &
echo "⏳ Starting sidecar (models loading ~10-30s)..."
for i in $(seq 1 30); do
    if curl -s --max-time 2 http://127.0.0.1:8100/health > /dev/null 2>&1; then
        echo "✅ Sidecar ready on http://127.0.0.1:8100"
        exit 0
    fi
    sleep 1
done
echo "❌ Sidecar failed to start — check data/sidecar.log"
exit 1