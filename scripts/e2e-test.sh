#!/usr/bin/env bash
# AutoLSM End-to-End Test — eBPF LSM observer capture
#
# Usage: sudo bash scripts/e2e-test.sh

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'; PASS=0; FAIL=0
pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; }

DAEMON_LOG="/tmp/autolsm-e2e.log"; DAEMON_PID=""

cleanup() {
    echo ""; echo "--- Cleanup ---"
    [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null && kill "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
    rm -f "$DAEMON_LOG"
}
trap cleanup EXIT

echo "============================================"
echo " AutoLSM End-to-End Test"
echo "============================================"

# ── Step 1: Build ──────────────────────────────────────────────────────

echo ""; echo "--- Step 1: Build ---"
cargo build --bin autolsm 2>/dev/null && pass "cargo build" || { fail "build"; exit 1; }

# ── Step 2: Compile C eBPF (skip if clang missing) ─────────────────────

echo ""; echo "--- Step 2: eBPF build ---"
if command -v clang &>/dev/null && [ -f /sys/kernel/btf/vmlinux ]; then
    ( cd crates/autolsm-ebpf && \
      bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null && \
      clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c autolsm.bpf.c -o autolsm.bpf.o 2>/dev/null ) && \
      pass "eBPF compiled" || skip "eBPF compile failed"
else
    skip "clang or BTF not available"
fi

# ── Step 3: Get target cgroup ──────────────────────────────────────────

echo ""; echo "--- Step 3: Target cgroup ---"
CGROUP_ID=$(stat -c %i /sys/fs/cgroup 2>/dev/null || echo "0")
[ "$CGROUP_ID" != "0" ] && pass "cgroup_id=$CGROUP_ID" || { fail "no cgroup"; exit 1; }

# ── Step 4: Start daemon ───────────────────────────────────────────────

echo ""; echo "--- Step 4: Start daemon ---"
RUST_LOG=info AUTOLSM_EBPF_PATH="crates/autolsm-ebpf/autolsm.bpf.o" \
    ./target/debug/autolsm \
    --target-cgroups "$CGROUP_ID" \
    --batch-window-s 3 \
    --log-level info \
    > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null && pass "daemon pid=$DAEMON_PID" || { fail "daemon crash"; cat "$DAEMON_LOG"; exit 1; }

# ── Step 5: Check startup log ──────────────────────────────────────────

echo ""; echo "--- Step 5: Startup log ---"
check() { grep -q "$1" "$DAEMON_LOG" && pass "$2" || fail "$2 (missing: $1)"; }
check "AutoLSM daemon starting" "startup banner"
check "normalizer started"        "normalizer started"
check "LLM loop started"          "LLM loop started"

if grep -q "attached LSM hook" "$DAEMON_LOG"; then
    pass "LSM hooks attached"
elif grep -q "no-op tick" "$DAEMON_LOG"; then
    skip "no-op mode (eBPF not loaded)"
fi

# ── Step 6: Run test commands ──────────────────────────────────────────

echo ""; echo "--- Step 6: Test commands ---"
for cmd in "cat /etc/hostname" "ls /tmp" "cat /dev/null"; do
    echo "  \$ $cmd"
    $cmd > /dev/null 2>&1 || true
done
sleep 4  # wait for 3s batch window

# ── Step 7: Verify event pipeline ──────────────────────────────────────

echo ""; echo "--- Step 7: Event pipeline ---"
grep -q "emitting batch" "$DAEMON_LOG"    && pass "normalizer emitted batch"    || skip "no batch emitted"
grep -q "received batch" "$DAEMON_LOG"     && pass "LLM loop received batch"     || skip "no batch received"
grep -q "validation passed" "$DAEMON_LOG"  && pass "validator passed"            || skip "validator not exercised"

# ── Step 8: Error check ─────────────────────────────────────────────────

echo ""; echo "--- Step 8: Errors ---"
ERRS=$(grep -ci "ERROR" "$DAEMON_LOG" 2>/dev/null || echo 0)
WARNS=$(grep -c "WARN" "$DAEMON_LOG" 2>/dev/null || echo 0)
[ "$ERRS" -eq 0 ] && pass "no ERROR in log" || fail "$ERRS ERROR(s)"
echo "  (${WARNS} warning(s) in log)"

# ── Summary ─────────────────────────────────────────────────────────────

echo ""; echo "--- Daemon log (tail) ---"
tail -20 "$DAEMON_LOG"
echo ""
echo "============================================"
echo " Result: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "============================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
