#!/usr/bin/env bash
# AutoLSM pre-requisite checker for OpenCloudOS / RHEL / CentOS
#
# Run: bash scripts/check-prereqs.sh
#
# Checks:
#   1. Kernel version >= 5.7 (BPF LSM)
#   2. BTF availability
#   3. SELinux status
#   4. BPF LSM in enabled LSM list
#   5. Required tools (semodule, matchpathcon, auditd)
#   6. Rust toolchain (nightly + bpf target)
#   7. cgroup v2 availability

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
WARN=0
FAIL=0

check() {
    local desc="$1"
    local result="$2"
    if [ "$result" = "pass" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        PASS=$((PASS + 1))
    elif [ "$result" = "warn" ]; then
        echo -e "  ${YELLOW}[WARN]${NC} $desc"
        WARN=$((WARN + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "============================================"
echo " AutoLSM Prerequisite Check"
echo " Target: OpenCloudOS / RHEL / CentOS"
echo "============================================"
echo ""

# ── 1. Kernel version ────────────────────────────────────────────────

echo "--- Kernel ---"
KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
echo "  Detected: $KVER"

if [ "$KMAJOR" -gt 5 ] || ([ "$KMAJOR" -eq 5 ] && [ "$KMINOR" -ge 7 ]); then
    check "Kernel >= 5.7 (BPF LSM support)" "pass"
else
    check "Kernel >= 5.7 (BPF LSM support) — got ${KMAJOR}.${KMINOR}" "fail"
fi

# ── 2. BTF ────────────────────────────────────────────────────────────

echo ""
echo "--- BTF (BPF Type Format) ---"

if [ -f /sys/kernel/btf/vmlinux ]; then
    BTF_SIZE=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo "0")
    check "BTF vmlinux available (${BTF_SIZE} bytes)" "pass"
else
    check "BTF vmlinux not found at /sys/kernel/btf/vmlinux" "fail"
fi

# ── 3. SELinux ────────────────────────────────────────────────────────

echo ""
echo "--- SELinux ---"

if [ -f /sys/fs/selinux/enforce ]; then
    ENFORCE=$(cat /sys/fs/selinux/enforce)
    check "SELinux enabled (enforce=${ENFORCE})" "pass"
else
    check "SELinux not available (/sys/fs/selinux not found)" "fail"
fi

LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "unknown")
echo "  Active LSMs: $LSM_LIST"
if echo "$LSM_LIST" | grep -q "selinux"; then
    check "selinux in active LSMs" "pass"
else
    check "selinux NOT in active LSMs: $LSM_LIST" "fail"
fi

if echo "$LSM_LIST" | grep -q "bpf"; then
    check "bpf in active LSMs (BPF LSM hooks available)" "pass"
else
    check "bpf NOT in active LSMs — add 'lsm=selinux,bpf' to GRUB_CMDLINE_LINUX" "warn"
fi

# ── 4. Required tools ─────────────────────────────────────────────────

echo ""
echo "--- Required Tools ---"

for tool in semodule matchpathcon ausearch; do
    if command -v "$tool" &>/dev/null; then
        check "$tool found at $(which $tool)" "pass"
    else
        check "$tool NOT found — install policycoreutils / audit" "fail"
    fi
done

if [ -f /var/log/audit/audit.log ]; then
    check "audit.log exists at /var/log/audit/audit.log" "pass"
else
    check "audit.log not found — auditd may not be running" "warn"
fi

# ── 5. Rust toolchain ─────────────────────────────────────────────────

echo ""
echo "--- Rust Toolchain ---"

if command -v rustup &>/dev/null; then
    check "rustup found" "pass"
    
    TOOLCHAIN=$(rustup show active-toolchain 2>/dev/null || echo "none")
    echo "  Active toolchain: $TOOLCHAIN"
    
    if echo "$TOOLCHAIN" | grep -q "nightly"; then
        check "nightly toolchain active" "pass"
    else
        check "nightly toolchain NOT active — run: rustup default nightly" "warn"
    fi
    
    if rustup target list --installed 2>/dev/null | grep -q "bpfel-unknown-none"; then
        check "bpfel-unknown-none target installed" "pass"
    else
        check "bpfel-unknown-none target NOT installed — run: rustup target add bpfel-unknown-none" "warn"
    fi
    
    if rustup component list --installed 2>/dev/null | grep -q "rust-src"; then
        check "rust-src component installed" "pass"
    else
        check "rust-src component NOT installed — run: rustup component add rust-src" "warn"
    fi
else
    check "rustup not found — install Rust from https://rustup.rs" "warn"
fi

# ── 6. cgroup v2 ──────────────────────────────────────────────────────

echo ""
echo "--- cgroup ---"

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    check "cgroup v2 available (/sys/fs/cgroup/cgroup.controllers)" "pass"
else
    check "cgroup v2 NOT detected — BPF cgroup helpers require v2" "warn"
fi

# ── 7. BPF filesystem ─────────────────────────────────────────────────

echo ""
echo "--- BPF Filesystem ---"

if mount | grep -q "bpf on /sys/fs/bpf"; then
    check "/sys/fs/bpf mounted" "pass"
else
    check "/sys/fs/bpf NOT mounted — run: mount -t bpf bpf /sys/fs/bpf" "warn"
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " Summary: ${GREEN}${PASS} passed${NC}, ${YELLOW}${WARN} warnings${NC}, ${RED}${FAIL} failed${NC}"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo -e "${RED}Some prerequisites are not met. Fix FAIL items before running AutoLSM.${NC}"
    exit 1
fi

if [ "$WARN" -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}Warnings may prevent some features (BPF LSM hooks, cgroup filtering).${NC}"
    echo -e "${YELLOW}AutoLSM can still run in no-op mode without eBPF.${NC}"
fi

echo ""
echo "To run AutoLSM tests:"
echo "  cargo test"
echo ""
echo "To run AutoLSM daemon:"
echo "  cargo run -- --target-cgroups 1234,5678 --llm-endpoint http://localhost:11434/v1"
echo ""

exit 0
