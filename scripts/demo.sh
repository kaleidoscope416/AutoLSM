#!/usr/bin/env bash
# AutoLSM 汇报演示脚本 — 支持 LLM 语义分析
# 使用: bash demo.sh
# LLM 模式: bash demo.sh openai
# 全程约 60 秒，展示完整的 采集→归一化→LLM分析→策略生成→校验→下发 闭环

set -euo pipefail

# ════════════════════════════════════════════════════════════════════════
# LLM 配置 — 填写你的 API 信息
# ════════════════════════════════════════════════════════════════════════
LLM_ENDPOINT="${AUTOLSM_LLM_ENDPOINT:-}"      # OpenAI-compatible 地址，如 https://api.openai.com/v1 或 http://localhost:11434/v1
LLM_MODEL="${AUTOLSM_LLM_MODEL:-gpt-4o}"       # 模型名
LLM_KEY="${AUTOLSM_LLM_KEY:-}"                 # API key（不填 = 用 SimplePolicyGenerator 演示）
# ════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

stage() { echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $*${NC}"; echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${NC}"; }
info() { echo -e "  ${GREEN}→${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }

cd /root/AutoLSM
export RUSTC_BOOTSTRAP=1
MY_CGID=$(stat -c %i /sys/fs/cgroup$(cat /proc/self/cgroup | head -1 | cut -d: -f3))
rm -f /tmp/autolsm/*.cil /tmp/autolsm-demo.log
mkdir -p /tmp/autolsm

# 构建 LLM 参数
LLM_FLAGS=""
USE_LLM=false
if [ -n "$LLM_KEY" ] && [ -n "$LLM_ENDPOINT" ]; then
    USE_LLM=true
    LLM_FLAGS="--llm-endpoint $LLM_ENDPOINT --llm-model $LLM_MODEL --llm-key $LLM_KEY"
fi

# ════════════════════════════════════════════════════════════════════════
stage "Stage 1: 环境就绪"
# ════════════════════════════════════════════════════════════════════════

info "SELinux 模式: $(getenforce 2>/dev/null || echo 'N/A')"
info "内核 LSM:    $(cat /sys/kernel/security/lsm 2>/dev/null)"
info "BTF 可用:    $(ls /sys/kernel/btf/vmlinux >/dev/null 2>&1 && echo YES || echo NO)"
info "Cgroup ID:   $MY_CGID"

if $USE_LLM; then
    info "策略生成器:  ${BOLD}OpenAI LLM${NC}  →  $LLM_MODEL @ $LLM_ENDPOINT"
else
    info "策略生成器:  ${BOLD}SimplePolicyGenerator${NC} (演示用确定性转换器 — 未配置 LLM)"
    info "  → 要使用 LLM: export AUTOLSM_LLM_KEY=sk-xxx AUTOLSM_LLM_ENDPOINT=https://..."
    info "  → 或:       bash demo.sh openai"
fi
read -p "  按 Enter 开始..."

# ════════════════════════════════════════════════════════════════════════
stage "Stage 2: 编译 C eBPF 程序"
# ════════════════════════════════════════════════════════════════════════

cd crates/autolsm-ebpf
info "生成 vmlinux.h (从内核 BTF)..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null
info "编译 autolsm.bpf.c → autolsm.bpf.o (5 个 LSM hooks)"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c autolsm.bpf.c -o autolsm.bpf.o 2>&1
SIZE=$(ls -lh autolsm.bpf.o | awk '{print $5}')
info "eBPF ELF: ${SIZE}  — 观测 hook: file_open, file_permission, socket_bind, socket_connect, task_setrlimit"
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
    $LLM_FLAGS \
    2>&1 | tee /tmp/autolsm-demo.log &
DAEMON_PID=$!
sleep 6

info "eBPF hook attach 状态:"
grep "attached LSM hook" /tmp/autolsm-demo.log | while read line; do
    echo -e "    ${GREEN}✓${NC} $line"
done
grep "collector running" /tmp/autolsm-demo.log >/dev/null 2>&1 && \
    info "Collector 运行中 — RingBuf 等待事件" || warn "Collector 未启动"

read -p "  按 Enter 触发行为采集..."

# ════════════════════════════════════════════════════════════════════════
stage "Stage 4: 触发测试行为 → 观察采集和 LLM 策略生成"
# ════════════════════════════════════════════════════════════════════════

info "执行测试命令: cat /etc/hostname ×15, ls /tmp ×15, cat /etc/os-release ×10"
for i in $(seq 15); do cat /etc/hostname >/dev/null 2>&1; done
for i in $(seq 15); do ls /tmp >/dev/null 2>&1; done
for i in $(seq 10); do cat /etc/os-release >/dev/null 2>&1; done

sleep 5

echo ""
info "=== eBPF 采集 (每 2s 一批) ==="
grep "emitting batch" /tmp/autolsm-demo.log | while read line; do
    echo -e "    ${GREEN}📊${NC} $line"
done

echo ""
if $USE_LLM; then
    info "=== LLM 语义分析 ==="
    echo -e "    ${CYAN}向 LLM ($LLM_MODEL) 发送结构化事件集:${NC}"
    echo -e "    ${CYAN}  - 包含 scontext/tcontext/tclass/perm/count${NC}"
    echo -e "    ${CYAN}  - LLM 做语义判断: 区分 '正常业务' vs '可疑行为'${NC}"
    echo -e "    ${CYAN}  - 输出: allow_rules + alerts + confidence${NC}"
else
    info "=== 策略生成 (SimplePolicyGenerator) ==="
    echo -e "    ${YELLOW}  演示用确定性转换: 观测到的访问 → allow 规则${NC}"
    echo -e "    ${YELLOW}  LLM 会做语义判断: 同样读 /etc, hostname=正常 shadow=攻击${NC}"
fi
grep "LLM response" /tmp/autolsm-demo.log | while read line; do
    echo -e "    ${GREEN}🧠${NC} $line"
done

echo ""
info "=== 校验结果 (Validator 7 项检查) ==="
grep "validation" /tmp/autolsm-demo.log | while read line; do
    if echo "$line" | grep -q "passed"; then
        echo -e "    ${GREEN}✓${NC} $line"
    elif echo "$line" | grep -q "failed"; then
        echo -e "    ${RED}✗${NC} $line"
    fi
done

# ════════════════════════════════════════════════════════════════════════
stage "Stage 5: 策略下发 → SELinux 内核"
# ════════════════════════════════════════════════════════════════════════

echo ""
info "生成的 CIL 策略文件 (JSON → CIL 确定性转换):"
cat /tmp/autolsm/*.cil 2>/dev/null | head -8 | while read line; do
    echo -e "    ${CYAN}${line}${NC}"
done

echo ""
info "SELinux 已安装模块 (autolsm_*):"
INSTALLED=$(semodule -l 2>/dev/null | grep autolsm || echo "")
if [ -n "$INSTALLED" ]; then
    echo "$INSTALLED" | while read mod; do
        echo -e "    ${GREEN}✓${NC} 已安装: $mod"
    done
    COUNT=$(echo "$INSTALLED" | wc -l)
    info "策略已下发到 SELinux 内核 — ${COUNT} 个模块"
else
    warn "策略未安装: 检查 semodule 权限和 SELinux 类型名"
fi

# ════════════════════════════════════════════════════════════════════════
stage "演示完成 — 数据流回顾"
# ════════════════════════════════════════════════════════════════════════

echo ""
echo -e "  ${BOLD}eBPF hooks${NC} ──→ ${BOLD}RingBuf${NC} ──→ ${BOLD}Collector${NC} ──→ ${BOLD}Normalizer${NC} ──→ ${BOLD}LLM${NC} ──→ ${BOLD}Validator${NC} ──→ ${BOLD}semodule${NC}"
echo "   (内核)       (共享内存)   (用户态)     (去重批处理)   (语义分析)  (安全检查)    (策略安装)"
echo ""

if $USE_LLM; then
    echo -e "  ${GREEN}本次使用 LLM:${NC} $LLM_MODEL @ $LLM_ENDPOINT"
    echo -e "  LLM 的增量价值: 区分 '正常业务需要' vs '可疑攻击行为'"
    echo -e "  → audit2allow 会无差别放行所有拒绝, LLM 能做语义判断"
else
    echo -e "  ${YELLOW}本次使用确定性策略生成器 (未配置 LLM API)${NC}"
    echo -e "  要切换 LLM: 在脚本顶部填写 LLM_ENDPOINT / LLM_MODEL / LLM_KEY"
fi

echo ""
echo "  日志: /tmp/autolsm-demo.log"
echo "  CIL:  /tmp/autolsm/*.cil"

# 清理
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
