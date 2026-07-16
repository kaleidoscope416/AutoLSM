#!/usr/bin/env bash
# Non-interactive demo runner with full output capture
# Usage: bash demo-auto.sh

set -uo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="/root/demo-output/run_${TIMESTAMP}"
mkdir -p "$OUTDIR"

echo "[$(date)] Starting AutoLSM demo..."
echo "[$(date)] Output directory: $OUTDIR"

cd /root/AutoLSM

# Clean up from previous runs
pkill -9 autolsm 2>/dev/null || true
pkill -9 semodule 2>/dev/null || true
rm -f /var/lib/selinux/targeted/semanage.trans.LOCK /var/lib/selinux/targeted/semanage.read.LOCK 2>/dev/null || true
rm -rf /tmp/autolsm /tmp/autolsm-demo.log
mkdir -p /tmp/autolsm

# Start auditd
systemctl start auditd 2>/dev/null || true

# Run demo with yes to auto-answer prompts
# Capture ALL output (both script and daemon) via script command
echo "[$(date)] Running demo.sh..."
yes "" | stdbuf -oL bash scripts/demo.sh 2>&1 | tee "$OUTDIR/demo-full.log"
EXIT_CODE=${PIPESTATUS[0]}

echo ""
echo "[$(date)] Demo script exited with code: $EXIT_CODE"

# Copy daemon log (more detailed)
if [ -f /tmp/autolsm-demo.log ]; then
    cp /tmp/autolsm-demo.log "$OUTDIR/daemon.log"
fi

# Copy CIL files if any remain
if ls /tmp/autolsm/*.cil 2>/dev/null; then
    cp /tmp/autolsm/*.cil "$OUTDIR/" 2>/dev/null || true
fi

# List installed modules
echo "[$(date)] Collecting installed modules..."
timeout 5 semodule -l 2>/dev/null | grep autolsm > "$OUTDIR/installed-modules.txt" || true

echo ""
echo "============================================"
echo "  Results saved to: $OUTDIR"
echo "  Files:"
ls -la "$OUTDIR/"
echo "============================================"
