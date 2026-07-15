#!/usr/bin/env bash
# AutoLSM 汇报演示脚本
# 使用: bash demo.sh
# 全程约 60 秒，展示完整的 采集→归一化→策略生成→校验→下发 闭环

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
BOLD='\033[1m'

stage() { echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $*${NC}"; echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${NC}"; }
info() { echo -e "  ${GREEN}→${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }

cd /root/AutoLSM
export RUSTC_BOOTSTRAP=1
MY_CGID=$(stat -c %i /sys/fs/cgroup$(cat /proc/self/cgroup | head -1 | cut -d: -f3))
rm -f /tmp/autolsm/*.cil /tmp/autolsm-demo.log
mkdir -p /tmp/autolsm

# ════════════════════════════════════════════════════════════════════════
stage "Stage 1: 环境就绪"
# ════════════════════════════════════════════════════════════════════════

info "SELinux 模式: $(getenforce) (enforcing=拦截 permissive=仅记录)"
info "内核 LSM:    $(cat /sys/kernel/security/lsm)"
info "BTF 可用:    $(ls /sys/kernel/btf/vmlinux >/dev/null && echo YES || echo NO)"
info "Cgroup ID:   $MY_CGID"
read -p "  按 Enter 开始..."

# ════════════════════════════════════════════════════════════════════════
stage "Stage 2: 编译 C eBPF 程序"
# ════════════════════════════════════════════════════════════════════════

cd crates/autolsm-ebpf
info "生成 vmlinux.h (从内核 BTF)..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null
info "编译 autolsm.bpf.c → autolsm.bpf.o"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c autolsm.bpf.c -o autolsm.bpf.o 2>&1
SIZE=$(ls -lh autolsm.bpf.o | awk '{print $5}')
info "eBPF ELF: ${SIZE}"
info "5 个 LSM hook: file_open, file_permission, socket_bind, socket_connect, task_setrlimit"
cd /root/AutoLSM
read -p "  按 Enter 加载 eBPF 到内核..."

# ════════════════════════════════════════════════════════════════════════
stage "Stage 3: 启动 daemon，eBPF 开始采集"
# ════════════════════════════════════════════════════════════════════════

info "启动 autolsm daemon (2秒批处理窗口, demo模式)..."
RUSTC_BOOTSTRAP=1 cargo run --bin autolsm -- \
    --target-cgroups $MY_CGID \
    --batch-window-s 2 \
    --tmp-dir /tmp/autolsm \
    --demo-mode \
    --log-level info \
    2>&1 | tee /tmp/autolsm-demo.log &
DAEMON_PID=$!
sleep 6

info "检查 eBPF hook attach 状态:"
grep "attached LSM hook" /tmp/autolsm-demo.log | while read line; do
    echo -e "    ${GREEN}✓${NC} $line"
done

grep "collector running" /tmp/autolsm-demo.log >/dev/null && \
    info "Collector 运行中 — RingBuf 等待事件" || warn "Collector 未启动"

read -p "  按 Enter 触发行为采集..."

# ════════════════════════════════════════════════════════════════════════
stage "Stage 4: 触发测试行为 → 观察采集和策略生成"
# ════════════════════════════════════════════════════════════════════════

info "执行测试命令: cat /etc/hostname (15次), ls /tmp (15次), cat /etc/os-release (10次)"
for i in $(seq 15); do cat /etc/hostname >/dev/null 2>&1; done
for i in $(seq 15); do ls /tmp >/dev/null 2>&1; done  
for i in $(seq 10); do cat /etc/os-release >/dev/null 2>&1; done

sleep 5

echo ""
info "=== 采集结果 ==="
grep "emitting batch" /tmp/autolsm-demo.log | while read line; do
    echo -e "    ${GREEN}📊${NC} $line"
done

echo ""
info "=== 策略生成 ==="
grep "LLM response" /tmp/autolsm-demo.log | while read line; do
    echo -e "    ${GREEN}🧠${NC} $line"
done

echo ""
info "=== 校验结果 ==="
grep "validation" /tmp/autolsm-demo.log | while read line; do
    if echo "$line" | grep -q "passed"; then
        echo -e "    ${GREEN}✓${NC} $line"
    else
        echo -e "    ${RED}✗${NC} $line"
    fi
done

# ════════════════════════════════════════════════════════════════════════
stage "Stage 5: 策略下发与验证"
# ════════════════════════════════════════════════════════════════════════

echo ""
info "生成的 CIL 策略文件:"
cat /tmp/autolsm/*.cil 2>/dev/null | head -8 | while read line; do
    echo -e "    ${CYAN}${line}${NC}"
done

echo ""
info "SELinux 模块列表 (autolsm_*):"
semodule -l 2>/dev/null | grep autolsm | while read mod; do
    echo -e "    ${GREEN}✓${NC} 已安装: $mod"
done

COUNT=$(semodule -l 2>/dev/null | grep -c autolsm || echo 0)
if [ "$COUNT" -gt 0 ]; then
    info "策略已下发到 SELinux 内核 — ${COUNT} 个模块"
else
    warn "策略未安装: 检查 semodule 权限和 SELinux 类型名"
fi

# ════════════════════════════════════════════════════════════════════════
stage "演示完成"
# ════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}数据流回顾:${NC}"
echo "  eBPF hooks ──→ RingBuf ──→ Collector ──→ Normalizer ──→ LLM ──→ Validator ──→ semodule"
echo "   (内核)       (共享内存)   (用户态)     (去重批处理)   (规则生成)  (安全检查)    (策略安装)"
echo ""

# 清理
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true

echo "日志保存: /tmp/autolsm-demo.log"
echo "CIL文件:  /tmp/autolsm/*.cil"
