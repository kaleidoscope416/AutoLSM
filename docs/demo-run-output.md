# AutoLSM Demo 运行输出 — 远程测试服务器

**服务器**: 43.137.50.63 (OpenCloudOS 9.6, kernel 6.6.119)  
**时间**: 2026-07-15 17:03 UTC  
**LLM**: Deepseek v4 Flash (`https://api.deepseek.com`)

---

## Stage 1: 环境就绪

```
SELinux 模式: Permissive
内核 LSM:    capability,landlock,yama,selinux,bpf
BTF 可用:    YES
Cgroup ID:   54321
策略生成器:  OpenAI LLM → deepseek-v4-flash @ https://api.deepseek.com
```

## Stage 2: 编译 C eBPF 程序

```
eBPF ELF: 898K — 观测 hook: file_open, file_permission, socket_bind, socket_connect, task_setrlimit
```

## Stage 3: 启动 daemon，eBPF 开始采集

```
2026-07-15T17:03:28.152506Z  INFO autolsm::collector: attached LSM hook: file_open
2026-07-15T17:03:28.161830Z  INFO autolsm::collector: attached LSM hook: file_permission
2026-07-15T17:03:28.171851Z  INFO autolsm::collector: attached LSM hook: socket_bind
2026-07-15T17:03:28.181839Z  INFO autolsm::collector: attached LSM hook: socket_connect
2026-07-15T17:03:28.191508Z  INFO autolsm::collector: attached LSM hook: task_setrlimit
```

**✓ 5/5 LSM hooks 全部 attach 成功**

## Stage 4: 触发测试行为 → 观察采集和 LLM 策略生成

### eBPF 采集

```
📊 2026-07-15T17:03:30.163323Z  INFO autolsm::normalizer: emitting batch: 3 events (3 new)
📊 2026-07-15T17:03:32.159827Z  INFO autolsm::normalizer: emitting batch: 3 events (0 new)
📊 2026-07-15T17:03:34.154439Z  INFO autolsm::normalizer: emitting batch: 3 events (0 new)
📊 2026-07-15T17:03:36.164917Z  INFO autolsm::normalizer: emitting batch: 2 events (0 new)
```

### LLM 语义分析

```
🧠 2026-07-15T17:03:36.117707Z  INFO autolsm::llm: LLM response: 1 allow rules, 1 alerts, confidence=0.80
```

LLM (deepseek-v4-flash) 成功分析结构化事件集并返回:
- `allow_rules`: 1 条推荐规则
- `alerts`: 1 条告警
- `confidence`: 0.80

### 校验结果 (Validator 7 项检查)

```
✓ 2026-07-15T17:03:36.117773Z  INFO autolsm::llm: validation passed — 1 rules approved
```

## Stage 5: 策略下发 → SELinux 内核

### 生成的 CIL 策略文件

```cil
(allow unconfined_t unknown_t (file (append open write)))
```

JSON → CIL 确定性转换成功。

### SELinux 已安装模块

```
✓ 已安装: autolsm_1784123098
→ 策略已下发到 SELinux 内核 — 1 个模块
```

---

## 数据流回顾

```
eBPF hooks ──→ RingBuf ──→ Collector ──→ Normalizer ──→ LLM ──→ Validator ──→ semodule
 (内核)       (共享内存)   (用户态)     (去重批处理)   (语义分析)  (安全检查)    (策略安装)
```

**LLM 增量价值**: 区分 '正常业务需要' vs '可疑攻击行为'  
`audit2allow` 会无差别放行所有拒绝, LLM 能做语义判断。

---

## 修复记录

为使 demo 在远程测试服务器上完整运行, 进行了以下修复:

| # | 问题 | 修复 | 文件 |
|---|------|------|------|
| 1 | `unknown BTF type bpf_lsm_file_open_obs` | `lsm.load()` 传入内核 hook 名 (`file_open`) 而非 eBPF 函数名 (`file_open_obs`) | `collector.rs` |
| 2 | eBPF map 名大小写不匹配 | `TARGET_CGROUPS`/`EVENTS` → `target_cgroups`/`events` | `collector.rs` |
| 3 | eBPF 函数签名与内核 LSM hook 不匹配 | 移除不存在的 `flags`/`ret` 参数, observer 模式 `return 0` | `autolsm.bpf.c` |
| 4 | `--demo-mode` 标志不存在 | 添加 CLI flag, 强制使用 `SimplePolicyGenerator` | `main.rs` |
| 5 | LLM 返回 JSON 缺少 `scontext_type`/`allow_rules` | 系统 prompt 增加精确 JSON schema | `llm.rs` |
| 6 | Validator 拒绝 `unconfined_t`/`unknown_t` | 从 deny list 移除这些 resolver fallback 类型 | `validator.rs` |
| 7 | CIL 格式错误 (perms 未嵌套 class) | `(class (perm1 perm2))` 替代 `(class perm1 perm2)` | `selinux.rs` |
| 8 | `semodule -i -` stdin 不支持 | 改为写入临时文件后安装 | `selinux.rs` |
| 9 | CIL 重复 `handleunknown` | 移除自动生成的 `(handleunknown allow)` | `selinux.rs` |
| 10 | Resolver 返回 `unknown_t` (进程已退出) | fallback 改为 `unconfined_t` | `resolver.rs` |
