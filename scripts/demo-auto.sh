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

# ── Pre-cleanup ──
pkill -9 autolsm 2>/dev/null || true
pkill -9 semodule 2>/dev/null || true
rm -f /var/lib/selinux/targeted/semanage.trans.LOCK 2>/dev/null || true
rm -f /var/lib/selinux/targeted/semanage.read.LOCK 2>/dev/null || true
rm -rf /tmp/autolsm /tmp/autolsm-demo.log
mkdir -p /tmp/autolsm
systemctl start auditd 2>/dev/null || true

# ── Run demo with yes to auto-answer prompts ──
# Capture ALL output (script + daemon)
echo "[$(date)] Running demo.sh..."
yes "" | stdbuf -oL bash scripts/demo.sh 2>&1 | tee "$OUTDIR/demo-full.log"
DEMO_EXIT=${PIPESTATUS[0]}
echo "[$(date)] Demo script exited with code: $DEMO_EXIT"

# ── Post-run: kill daemon ──
sleep 2
DAEMON_PIDS=$(pgrep -f 'autolsm --target-cgroups' 2>/dev/null || true)
if [ -n "$DAEMON_PIDS" ]; then
    echo "[$(date)] Killing daemon PIDs: $DAEMON_PIDS"
    kill $DAEMON_PIDS 2>/dev/null || true
    sleep 1
    pkill -9 -f 'autolsm --target-cgroups' 2>/dev/null || true
fi

# ── Save artifacts ──
if [ -f /tmp/autolsm-demo.log ]; then
    cp /tmp/autolsm-demo.log "$OUTDIR/daemon.log"
fi

if ls /tmp/autolsm/*.cil 2>/dev/null; then
    cp /tmp/autolsm/*.cil "$OUTDIR/" 2>/dev/null || true
fi

# Save installed modules
timeout 5 semodule -l 2>/dev/null | grep autolsm > "$OUTDIR/installed-modules.txt" 2>/dev/null || true

# Save environment info
{
    echo "=== Environment ==="
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "LSM: $(cat /sys/kernel/security/lsm 2>/dev/null)"
    echo "SELinux: $(getenforce 2>/dev/null || echo N/A)"
    echo "BTF: $([ -f /sys/kernel/btf/vmlinux ] && echo YES || echo NO)"
    echo ""
    echo "=== Build Info ==="
    cd /root/AutoLSM
    echo "Commit: $(git rev-parse HEAD)"
    echo "Message: $(git log --oneline -1)"
} > "$OUTDIR/environment.txt"

echo ""
echo "============================================"
echo "  Demo completed!"
echo "  Results saved to: $OUTDIR"
echo "  Files:"
ls -la "$OUTDIR/"
echo "============================================"
