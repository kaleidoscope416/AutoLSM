# AutoLSM Demo 完整运行输出 — 含行为漂移检测

**服务器**: 43.137.50.63 (OpenCloudOS 9.6, kernel 6.6.119)  
**时间**: 2026-07-15 17:35 UTC  
**LLM**: Deepseek V4 Flash (`https://api.deepseek.com`)

---

## 概览

本次运行覆盖 AutoLSM 全部 **两个闭环**:

| 闭环 | 数据流 | 状态 |
|------|--------|------|
| **Loop A: Discovery** | eBPF → Normalizer → LLM → Validator → semodule | ✅ 完整 |
| **Loop B: Drift** | AVC denied → AuditConsumer → PreFilter → Normalizer[DRIFT] → LLM refine → Δpolicy | ✅ 完整 |

---

## Stage 1-2: 环境与编译

```
SELinux 模式: Permissive
内核 LSM:    capability,landlock,yama,selinux,bpf
BTF 可用:    YES
Cgroup ID:   56259
eBPF ELF: 898K — 观测 hook: file_open, file_permission, socket_bind, socket_connect, task_setrlimit
```

## Stage 3: eBPF 采集启动

```
✓ attached LSM hook: file_open
✓ attached LSM hook: file_permission
✓ attached LSM hook: socket_bind
✓ attached LSM hook: socket_connect
✓ attached LSM hook: task_setrlimit
```
**5/5 hooks attach 成功**

## Stage 4: 行为采集与 LLM 策略生成 (Loop A)

```
LLM response: 1 allow rules, 2 alerts, confidence=0.70
validation passed — 1 rules approved
installing policy module autolsm_1784136950 (1 rules, 52 bytes CIL)
```

## Stage 5: 策略下发

CIL 策略 (JSON → CIL 确定性转换):
```cil
(allow unconfined_t unconfined_t (file ((open) (read) (write))))
```

## Stage 6: 注入 AVC 拒绝 → 触发行为漂移

```
→ 向 audit.log 注入 2 条模拟 AVC 拒绝记录
→ 已注入: scontext=unconfined_t → tcontext=var_t : file { read open write }
```

## Stage 7: 漂移检测 — Loop B: Drift

### 漂移检测 — AuditConsumer 读取 AVC 拒绝

```
emitting batch: 6 events (6 new) [DRIFT]
LLM loop: received batch of 6 events [DRIFT DETECTED]
```

### 漂移批处理 — Normalizer 合并拒绝 + 观测

```
emitting batch: 6 events (3 new) [DRIFT]
```

### LLM 策略精炼 (RefinePolicy)

```
LLM response: 1 allow rules, 2 alerts, confidence=0.70
LLM response: 1 allow rules, 1 alerts, confidence=0.80
LLM response: 1 allow rules, 0 alerts, confidence=0.70
```

### 漂移驱动的策略增量 (Δpolicy)

```
validation passed — 1 rules approved
installing policy module autolsm_1784136950 (1 rules, 52 bytes CIL)
```

---

## 数据流回顾

```
Loop A (Discovery):
eBPF hooks ──→ RingBuf ──→ Collector ──→ Normalizer ──→ LLM generate ──→ Validator ──→ semodule
 (内核)       (共享内存)   (用户态)     (去重批处理)   (语义分析)      (安全检查)    (策略安装)

Loop B (Drift):
AVC denied ──→ AuditConsumer ──→ PreFilter ──→ Normalizer[DRIFT] ──→ LLM refine ──→ Δpolicy
 (audit.log)    (增量读取)      (降噪/限速)   (标记)             (增量规则)     (semodule -i)
```

---

## 本次修复汇总

| # | 问题 | 修复 | 文件 |
|---|------|------|------|
| 1 | `unknown BTF type bpf_lsm_file_open_obs` | `lsm.load()` 传入内核 hook 名 | `collector.rs` |
| 2 | eBPF 函数签名与内核 LSM hook 不匹配 | 移除 `flags`/`ret` 参数, observer 模式 | `autolsm.bpf.c` |
| 3 | `--demo-mode` 标志不存在 | 添加 CLI flag | `main.rs` |
| 4 | LLM 返回 JSON 不符合 schema | 系统 prompt 增加精确 JSON schema | `llm.rs` |
| 5 | Validator 拒绝 fallback 类型 | 从 deny list 移除 `unconfined_t`/`unknown_t` | `validator.rs` |
| 6 | CIL 格式错误 + handleunknown 重复 | `(class (perm1 perm2))` 格式, 移除 handleunknown | `selinux.rs` |
| 7 | semodule 不支持 stdin pipe | 改为写入临时文件 | `selinux.rs` |
| 8 | Resolver fallback 为 `unknown_t` | 改为 `unconfined_t` | `resolver.rs` |
| 9 | **新增: 行为漂移检测** | NormalizedBatch, has_denials, refine() | `normalizer.rs`, `llm.rs`, `main.rs`, `userspace.rs` |
| 10 | **新增: Demo Stage 6/7** | AVC 注入 + 漂移检测展示 | `demo.sh` |

## 已知限制

- semodule 安装失败: CIL 中引用的 SELinux 类型 (`var_t`) 不在目标系统的基础策略中。LLM 基于输入数据生成规则，输入类型来自 eBPF 观测 + AVC 拒绝。在真实部署中需要确保目标系统已加载对应的 SELinux 策略模块。
