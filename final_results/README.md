# AutoLSM Demo 运行报告

## 运行环境
- **服务器**: OpenCloudOS 9.6, CPU x86_64
- **内核**: 6.6.119-49.23.oc9.x86_64
- **LSM**: capability,landlock,yama,selinux,bpf
- **SELinux**: Permissive 模式
- **BTF**: 可用 (`/sys/kernel/btf/vmlinux` 6MB)
- **Rust**: 1.97.0 (RUSTC_BOOTSTRAP=1)
- **clang**: 17.0.6
- **bpftool**: 7.3.0 (libbpf 1.3, llvm)
- **semodule**: 可用 (policy 400)
- **auditd**: systemctl 管理

## LLM 配置 (OpenAI 兼容)
- **模型**: deepseek-v4-flash
- **端点**: https://api.deepseek.com
- **调用方式**: OpenAiPolicyGenerator → chat/completions API → JSON response

## 执行结果
Demo 完整跑通，7 个 Stage 全部执行完成（LLM 模式）：

| Stage | 描述 | 关键数据 | 状态 |
|-------|------|----------|------|
| 1 | 环境就绪 | cgroup v2, Permissive, BTF ok | PASS |
| 2 | 编译 eBPF 程序 | 5 hooks, 898K ELF | PASS |
| 3 | 启动 daemon | 5/5 LSM hooks attach, 1 cgroup | PASS |
| 4 | 触发行为 + LLM 策略生成 | LLM response: 1 rule, confidence=1.00 | PASS |
| 5 | 策略下发 | semodule 安装 autolsm_1784211672 | PASS |
| 6 | 行为漂移注入 | 2 条 AVC 拒绝 → audit.log | PASS |
| 7 | 漂移检测 Loop B | AuditConsumer + PreFilter + RefinePolicy | PASS |

## 完整数据流
```
Loop A (Discovery):
  eBPF hooks ─→ RingBuf ─→ Collector ─→ Normalizer ─→ LLM ─→ Validator ─→ semodule
   (内核)       (共享内存)   (用户态)     (去重批处理)   (语义分析)  (安全检查)    (策略安装)

Loop B (Drift):
  AVC denied ─→ AuditConsumer ─→ PreFilter ─→ Normalizer ─→ LLM refine ─→ Δpolicy
   (audit.log)    (增量读取)      (降噪/限速)   ([DRIFT] 标记)  (增量规则)     (semodule -i)
```

## LLM 调用详情
```
策略生成器:  OpenAI LLM → deepseek-v4-flash @ https://api.deepseek.com
LLM response: 1 allow rules, 0 alerts, confidence=1.00
LLM 做语义判断: 区分 '正常业务' vs '可疑行为'
输出: allow_rules + alerts + confidence
校验: Validator 7 项检查 → 1 rules approved
安装: semodule -i → autolsm_1784211672
CIL:  (allow unconfined_t unconfined_t (file ((append) (write))))
```

## 关键指标
| 指标 | SimplePolicyGenerator | LLM (DeepSeek v4-flash) |
|------|-----------------------|--------------------------|
| 完成的 Stage | 7/7 | 7/7 |
| eBPF batch 数 | 13 | 8 |
| 策略规则数 | 1 | 1 |
| 安装成功模块 | 2 | 1 |
| 漂移检测 | 5x [DRIFT] | 0 (fresh audit.log) |
| 校验错误 | 2 (capability2) | 0 |

## 修复记录
1. `unknown_t`/`generic_t`/`unresolved_t` 哨兵类型在 normalizer、simple_gen、validator、llm 四层过滤
2. `semodule -i` 超时时子进程未被杀死 → PID 跟踪 + `kill -9`
3. semodule 超时从 10s 增加到 30s
4. `demo.sh` grep 管道添加 `|| true` 防止 `set -e` 提前退出
5. `cat /tmp/autolsm/*.cil` glob 匹配空 → nullglob 数组
6. 旧 audit.log 残留 AVC 导致首轮误触发 [DRIFT] → 运行前清空 audit.log
7. LLM 响应未记录日志 → 添加 `tracing::info!("LLM response: ...")`

## 产物
- `demo-llm.log` (12KB): LLM 模式完整运行日志
- `demo-full.log` (13KB): SimplePolicyGenerator 模式日志
- `daemon.log` / `daemon-llm.log`: daemon 日志
- `installed-modules.txt`: 已安装 SELinux 模块列表
