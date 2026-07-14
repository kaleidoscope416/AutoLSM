# AutoLSM: 基于 LLM 的自适应 SELinux 安全策略架构

> **版本**: v1.0  
> **目标**: 第一版适配 SELinux，eBPF 行为采集使用 Rust Aya 框架  
> **生效范围**: 逻辑框架 — 完整组件的接口、数据流、部署拓扑、实施计划  
> **验收**: 架构合理、无 workaround、零过度设计；策略生成由 LLM 完成，框架不内置手工规则

---

## 目录

1. [设计原则](#1-设计原则)
2. [三层闭环自适应架构](#2-三层闭环自适应架构)
3. [数据架构与 Schema](#3-数据架构与-scheqeqema)
4. [组件设计](#4-组件设计)
5. [关键技术决策与坑点分析](#5-关键技术决策与坑点分析)
6. [Rust 工程结构](#6-rust-工程结构)
7. [数据流与并发模型](#7-数据流与并发模型)
8. [安全模型](#8-安全模型)
9. [部署拓扑与先决条件](#9-部署拓扑与先决条件)
10. [实施计划](#10-实施计划)

---

## 1. 设计原则

| # | 原则 | 约束 |
|---|------|------|
| P1 | **不重复实现 MAC 执行引擎** | 执行完全由 SELinux 内核 MAC 承担；eBPF 仅做观测，不参与决策 |
| P2 | **观测面与执行面分离** | eBPF LSM hooks (observer-passthrough) 采集行为，SELinux 独立执行；二者无耦合 |
| P3 | **LLM 产出最严格可审慎的 allow 集** | LLM 语义分析的增量价值 = "区分 drift-to-allow vs anomaly-to-alert"，远胜 `audit2allow` 的无差别放行 |
| P4 | **错误一定是可撤回的** | 每次策略下发保留版本化的回滚路径 (`semodule -r`)；回归信号自动回退 |
| P5 | **没有全局的、没有 root 的开销** | eBPF 观测程序入口首个指令即 cgroup 过滤；非目标进程零开销跳转 |
| P6 | **v1 不创建新 SELinux 类型** | 生成策略仅含 `allow` 规则，复用已有 `type`/`class`/`perm`；新类型/新的客体降级留给后续版本 |
| P7 | **不依赖特定 LLM** | `PolicyGenerator` trait 解耦；v1 实现 OpenAI-compatible 后端，接入替换只需更换 impl |

---

## 2. 三层闭环自适应架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE                            │
│                                                                 │
│  ┌──────────────┐   ┌──────────┐   ┌────────────┐  ┌────────┐  │
│  │  Normalizer  │ → │   LLM    │ → │  Validator │→ │ SELinux│  │
│  │  (dedup+feat)│   │ Analyzer │   │ (gate)     │  │ Policy │  │
│  └──────────────┘   └──────────┘   └────────────┘  │ Loader │  │
│        ↑                                           └───┬────┘  │
│        │                                               │       │
│  ┌─────┴──────────┐         ┌──────────────┐          │       │
│  │  eBPF Collector│         │Audit Consumer│          │       │
│  │  (behavior)    │         │(denial drift)│          │       │
│  └─────┬──────────┘         └──────┬───────┘          │       │
│        │                           │                  │       │
├────────┼───────────────────────────┼──────────────────┼───────┤
│        │        DATA PLANE / KERNEL │                  │       │
├────────┼───────────────────────────┼──────────────────┼───────┤
│        │                           │                  │       │
│  ┌─────▼──────────┐         ┌──────▼───────┐   ┌──────▼──────┐│
│  │ BPF LSM hooks  │         │ SELinux AVC  │   │   SELinux   ││
│  │ (observer only)│         │ (audit)      │   │  Enforcing  ││
│  └────────────────┘         └──────────────┘   └─────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 三层定义

#### L1 — 采集层 (Collection: eBPF + Audit)

| 组件 | 角色 | 机制 |
|------|------|------|
| **eBPF LSM Observer** | 采集受控域的实际行为足迹 | `BPF_PROG_TYPE_LSM` 挂在到文件/网络/进程类 hook；passthrough 模式（返回 `ret`，永不 deny） |
| **Audit Consumer** | 采集 SELinux 拦截裁定（denied/granted） | 消费 `/var/log/audit/audit.log` 中的 `AVC`/`USER_AVC` 记录 |

**为什么 eBPF LSM hooks 而不是 tracepoint/syscalls**：
1. LSM hook 直接映射到 SELinux `tclass` + `perm` — 每个 hook（如 `file_open`）在 SELinux 用 `file:{ open }` 决定；无需维护 syscall → perm 的脆弱映射表。
2. `BPF_PROG_TYPE_LSM` 提供了 `ret` 参数来感知之前 LSM 裁定（即 SELinux 是否已拒绝），零开销。
3. 不需要 `auditd` 记录就能获得行为——lossless（auditd 在高负载下会丢事件）。

**准入风险**: 必须启用 `bpf` LSM — 需要 `lsm=selinux,bpf`。本架构要求所有 attach 的 BPF prog 均返回 `ret`（passthrough），不引入新的执行逻辑，因此不改变环境威胁模型。

#### L2 — 分析生成层 (Analyzer: Normalize → LLM → Policy Gen)

| 组件 | 职责 |
|------|------|
| **Normalizer** | 流式读取 `RingBuf` 事件 → 按 `(scontext, tcontext, tclass, perm)` 去重+计数；将 (pid, hook) 解析成 label；产生时间窗口 batch 并防重复（相同元素在窗口只去重，不作为 `(scontext, tcontext, tclass)` 的新发生） |
| **LLM Analyzer** | Prompt 注入归一化集 → 输出 `allow` 集 + 异常 flag；区分工作负载正常足迹与可能攻击行为（语义鉴别）。这是 `audit2allow` 不具备的能力。 |
| **Validator** | 拒绝：allow 含 `*`（wildcard）、unconfined_t 客体、未观察到的 tclass/perm；模块语法必须通过 CIL linter。 |

#### L3 — 执行层 (Enforcement: SELinux)

| 组件 | 职责 |
|------|------|
| **Policy Loader** | 将 LLM 输出转成 CIL 模块 → `semodule -i` 加载 → 验证成功/失败 → 记录版本，失败则自动回滚到上一版本 |
| **SELinux Enforcing** | 标准内核执行；生成策略的域的许可状态由 "permissive → enforcing" 状态机管控（见 8.3） |

### 2.2 三条闭环

```
Loop A (Discovery):
  Collection → Normalize → LLM → Policy Gen → Load → SELinux

Loop B (Drift):
  SELinux → AVC (denied) → Audit Consumer → Normalize → LLM → ΔPolicy → Load

Loop C (Attack/Alert):
  LLM flags anomaly → alert channel (metrics/logs/alerts)
```

---

## 3. 数据架构与 Schema

### 3.1 eBPF → Userspace 事件结构

定义于 `autolsm-common/src/lib.rs`（`no_std`），共享于 eBPF 和用户态。

```rust
// 内核→用户态单条观测事件：64 字节对齐，适合 RingBuf 高效拷贝。
#[repr(C)]
pub struct ObservationEvent {
    /// subject pid_tgid (upper 32: tgid, lower 32: pid)
    pub pid_tgid: u64,
    /// cgroup ID (bpf_get_current_cgroup_id)
    pub cgroup_id: u64,
    /// 纳秒时间戳 (bpf_ktime_get_ns)
    pub timestamp_ns: u64,
    /// hook 枚举: 0=file_open, 1=file_mmap, 2=file_ioctl, 3=socket_bind,
    /// 4=socket_connect, 5=tcp_socket_create, 6=task_setnice, ...
    pub hook_id: u32,
    /// 客体信息联合体: 仅存于对应的 hook 类型，其余为零
    pub object: ObjectInfo,
    /// 预留扩展
    pub _pad: u32,
}

#[repr(C)]
pub union ObjectInfo {
    pub file: FileObject,     // 32 bytes
    pub sock: SocketObject,   // 22 bytes
    pub raw: [u8; 32],
}

#[repr(C)]
pub struct FileObject {
    pub dev: u64,       // 8
    pub inode: u64,     // 8
    pub flags: u32,     // 4  — O_RDONLY|O_WRONLY|O_CREAT etc.
    pub path: [u8; 12], // 12 — 截断首 12 字节路径前缀，完整路径由用户态异步解析
}
// Total FileObject = 8+8+4+12 = 32 字节（对齐 8 字节后仍为 32）

#[repr(C)]
pub struct SocketObject {
    pub family: u16,   // 2 — AF_INET/AF_INET6/AF_UNIX
    pub proto: u16,    // 2 — IPPROTO_TCP/UDP
    pub port: u16,     // 2 — 端口号 (网络字节序)
    pub addr: [u8; 16], // 16 — IPv4 低 4 字节有效 (12..15); IPv6 全部 16 字节
}
// Total SocketObject = 2+2+2+16 = 22 字节 (补齐后 union 仍以 max(32,22) = 32 为准)
```

### 3.2 归一化记录

```rust
// 去重/归一化后的唯一 (sctx, tctx, class, perm) 记录
pub struct NormalizedAccess {
    pub scontext: String,   // "system_u:system_r:httpd_t:s0"
    pub scontext_type: String, // "httpd_t" — 用于 CIL allow 规则
    pub tcontext: String,
    pub tcontext_type: String,
    pub tclass: String,     // "file", "dir", "tcp_socket" ...
    pub perm: String,       // "open", "read", "write", "bind" ...
    pub hook_id: u32,
    pub count: u64,         // 窗口内有几次
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}
```

`hook_id → (tclass, perm)` 的映射表：

| hook_id | LSM Hook | tclass | perm |
|---------|----------|--------|------|
| 0 | `file_open` | file | open |
| 1 | `file_permission` | file | read / write / append / execute |
| 2 | `file_ioctl` | file | ioctl |
| 3 | `file_lock` | file | lock |
| 4 | `socket_bind` | socket / tcp_socket | bind / name_bind |
| 5 | `socket_connect` | socket / tcp_socket | name_connect |
| 6 | `tcp_socket_connect` | tcp_socket | name_connect |
| 7 | `udp_socket_connect` | udp_socket | name_connect |
| … | (v1 扩展至 ~15–20 hook) | | |

完整映射表经 `include/linux/lsm_hook_defs.h` 推导。表是手工固化常量 — 数量 < 20，无需运行时解析。

### 3.3 LLM 输入/输出 Contract

**输入** (prompt JSON):
```json
{
  "task": "generate_minimal_selinux_policy",
  "context": {
    "workload_domain": "container_t",
    "workload_type": "inference_server",
    "observed_window_s": 300
  },
  "normalized_events": [
    {
      "scontext_type": "container_t",
      "tcontext_type": "usr_t",
      "tclass": "file",
      "perm": "read",
      "count": 1432
    }
  ],
  "drift_denials": [
    {
      "scontext_type": "container_t",
      "tcontext_type": "proc_t",
      "tclass": "file",
      "perm": "getattr"
    }
  ]
}
```

**输出** (JSON Schema):
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["allow_rules", "alerts", "confidence"],
  "properties": {
    "allow_rules": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["source_type", "target_type", "tclass", "perms", "rationale"],
        "properties": {
          "source_type": { "type": "string" },
          "target_type": { "type": "string" },
          "tclass": { "type": "string" },
          "perms": { "type": "array", "items": { "type": "string" } },
          "rationale": { "type": "string" }
        }
      }
    },
    "alerts": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["severity", "scontext_type", "tcontext_type", "tclass", "perm", "reason"],
        "properties": {
          "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
          "scontext_type": { "type": "string" },
          "tcontext_type": { "type": "string" },
          "tclass": { "type": "string" },
          "perm": { "type": "string" },
          "reason": { "type": "string" }
        }
      }
    },
    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
  }
}
```

CIL 生成（Validator 转换 LLM JSON → CIL）：
```cil
(handleunknown allow)
(allow container_t usr_t (file (read open getattr)))
(allow container_t var_log_t (file (append write)))
```

---

## 4. 组件设计

### 4.1 eBPF Collector (`autolsm-ebpf`)

**附着程序清单**（v1，每个是一个 `#[lsm(hook="<hook>")]` 注解的函数）：

| 程序名 | 附着 hook | 观测用途 |
|--------|-----------|----------|
| `file_open_obs` | `file_open` | 文件打开（O_RDONLY / O_WRONLY 标志存在 `FileObject.flags`） |
| `file_permission_obs` | `file_permission` | 文件 read/write/append/execute 各 perm |
| `sock_bind_obs` | `socket_bind` | 端口绑定 |
| `sock_connect_obs` | `socket_connect` | 对外连接 |
| `task_setrlimit_obs` | `task_setrlimit` | 进程资源限制 |

**程序伪码** (以 `file_open` 为例)：
```rust
#[map]
static TARGET_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[lsm(hook = "file_open")]
pub fn file_open_obs(ctx: LsmContext) -> i32 {
    unsafe {
        let ret: i32 = ctx.arg(2);       // 之前 LSM 裁定
        if ret != 0 { return ret; }       // 已被 SELinux 拒绝 → 不采集，直接返回

        let cgid = bpf_get_current_cgroup_id();
        let _ = TARGET_CGROUPS.get(&cgid)?; // 不在目标 cgroup → 零开销跳过
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let p: *const file = ctx.arg(0);
    let path_slice = unsafe { bpf_d_path(&(*p).f_path, &mut buf) }; // BTF CO-RE

    let evt = ObservationEvent {
        pid_tgid,
        cgroup_id: cgid,
        timestamp_ns: bpf_ktime_get_ns(),
        hook_id: 0,
        object: ObjectInfo { file: FileObject {
            dev: inode.dev, inode: inode.ino,
            flags: (*p).f_flags, _pad: 0,
            path: copy_16(path_slice),
        }},
        _pad: 0,
    };
    EVENTS.output(&evt, 0); // 丢事件返回非零 → 可通过 perf in-kernel 记录，不阻塞调用者
    return ret;
}
```

**关键点**:
- `TARGET_CGROUPS` 是一个 `HashMap<u64, u8>`（仅存 key, value 永远=1），由用户态 `EbpfLoader` 动态填充、运行时更新、覆盖。不在表中的 cgroup 进程在每个 hook 入口立即返回（2 条 BPF 指令：call→lookup→jump ）。
- `path` 仅取首 12 字符（匹配类型标签用）——完整路径用户态通过 `/proc/<pid>/fd/<n>` 可以异步解析，不可能阻塞在 BPF 热路径。

### 4.2 Userspace Daemon (`autolsm`)

**统一事件类型**（定义于 `autolsm-common`）:
```rust
pub enum NormalizerInput {
    /// eBPF 行为采集事件 — 需要 PID→context 解析 + hook→class 映射
    Observation(ObservationEvent),
    /// SELinux AVC 拒绝 — scontext/tcontext/tclass/perm 已由 audit log 提供完整
    Denial(AvcDenial),
}
```

**主循环 (rough tokio task 结构):**

```
tokio::main {
    spawn collector_loop(bpf, target_cgroups) ─┐
                                                ├→ mpsc chan<NormalizerInput> → normalizer
    spawn audit_consumer() ─────────────────────┘
    spawn normalizer_loop(batch=60s) → mpsc chan→ llm
    spawn llm_loop() → mpsc chan→ policy_loader
}
```

#### 4.2.2 归一化器 (`src/normalizer.rs`)

**输入**: `mpsc::Receiver<NormalizerInput>`（统一枚举，详见 §7）。

**处理**:
1. 接收事件，`resolver.resolve(pid_tgid)` 得到 scontext。
2. `hook_id` 查表得基础 `(tclass, perm)`，**对 socket 类 hook 执行 family→tclass 运行时映射**：
   - `AF_INET + IPPROTO_TCP → tcp_socket`
   - `AF_INET + IPPROTO_UDP → udp_socket`
   - `AF_UNIX → unix_stream_socket / unix_dgram_socket`（视 hook 名）
   - `AF_NETLINK → netlink_socket`
   - 其他 → `socket`（通用 socket 类）
3. `ObjectInfo` → tcontext 解析：
   - `FileObject`: 在用户态用 `matchpathcon` 解析路径 → 类型。
   - `matchpathcon` 失败（文件已删除等） → 事件标记 `unresolved` 并丢弃（记录到 metrics）。
4. 去重插入 `HashMap<(scontext_type, tcontext_type, tclass, perm), NormalizedAccess>`，count++。

**HashMap 生命周期**: 60s 窗口到期后，将当前 `HashMap` 克隆到发送 batch，然后 **清空** 当前 `HashMap` 开始新窗口。同时维护一个长期 `SeenSet`（存放历史唯一 tuple 的哈希），用于 delta 计算：下一窗口发送的 batch 标记其中哪些是「新发现的访问」（不在 `SeenSet` 中），LLM 优先处理新发现的访问。`SeenSet` 使用固定容量 LRU（max=10000）防止无限增长。

**输出**: 每 60 秒或 batch size ≥ `BATCH_MAX`（64 条唯一记录）时将当前 batch + delta 标记发送给 LLM loop。

#### 4.2.3 LLM 分析器 (`src/llm.rs`)

**trait**:
```rust
pub trait PolicyGenerator: Send + Sync {
    async fn generate(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError>;
    async fn refine(&self, req: &LlmRequest, denials: &[AvcDenial]) -> Result<LlmResponse, LlmError>;
}

pub struct OpenAiPolicyGenerator {
    client: openai::Client,
    model: String,
}
```

**Prompt 设计要点**:
1. `system` 角色：SELinux MLS/MCS TE 规则详细定义 — 使用 `containers_t` 的真实文档。
2. `few-shot` 引入 2-3 个标准示例（`httpd_t` 的最小权限 allow 集）。
3. 明确要求: "只生成 CIL 可表达的标准 allow 规则，不生成 type_transition、capability、或 new type 声明；不生成 wildcard."
4. 要求 `rationale` 字段每个规则一个理由短句，确保 LLM 自校准。

#### 4.2.4 策略校验器 (`src/validator.rs`)

**结构检查** (无需解析 CIL，在 Rust 结构层面)：
```rust
pub fn validate(
    rules: &[AllowRule],
    known_types: &HashSet<String>,  // 从当前观测事件集提取的已知 type
    deny_sources: &HashSet<String>, // 永不允许作为 source 的类型
) -> Result<(), ValidationError> {
    for rule in rules {
        // 1) 全字段拒绝 wildcard "*"
        if rule.source_type.contains('*') {
            return Err(ValidationError::WildcardSource(rule.source_type.clone()));
        }
        if rule.target_type.contains('*') {
            return Err(ValidationError::WildcardTarget(rule.target_type.clone()));
        }
        if rule.tclass.contains('*') {
            return Err(ValidationError::WildcardClass);
        }
        for perm in &rule.perms {
            if perm.contains('*') {
                return Err(ValidationError::WildcardPerm(perm.clone()));
            }
        }
        // 2) target_type 不得是 unconfined_t（高风险逃逸）
        if rule.target_type == "unconfined_t" {
            return Err(ValidationError::UnconfinedTarget);
        }
        // 3) source_type 和 target_type 必须在已知 type 集中（防止 LLM 虚构类型）
        if !known_types.contains(&rule.source_type) {
            return Err(ValidationError::UnknownType(rule.source_type.clone()));
        }
        if !known_types.contains(&rule.target_type) {
            return Err(ValidationError::UnknownType(rule.target_type.clone()));
        }
        // 4) source_type 不得是 deny list 中的类型（如 kernel_t, init_t）
        if deny_sources.contains(&rule.source_type) {
            return Err(ValidationError::DeniedSource(rule.source_type.clone()));
        }
        // 5) perms 不能为空
        if rule.perms.is_empty() {
            return Err(ValidationError::EmptyPerms);
        }
        // 6) tclass 必须在白名单中
        if !VALID_CLASSES.contains(&rule.tclass.as_str()) {
            return Err(ValidationError::UnknownClass(rule.tclass.clone()));
        }
        // 7) 每个 perm 必须在该 class 的合法 perm 集合中
        let valid_perms = valid_perms_for_class(&rule.tclass);
        for perm in &rule.perms {
            if !valid_perms.contains(&perm.as_str()) {
                return Err(ValidationError::UnknownPerm {
                    class: rule.tclass.clone(),
                    perm: perm.clone(),
                });
            }
        }
    }
    Ok(())
}
```

`known_types` 构建自当前 Normalizer 窗口中的事件：收集所有事件的 `scontext_type` 和 `tcontext_type` → `HashSet`。此检查确保 LLM 不允许生成超出观测范围的新类型（v1 不创建新 SLA 类型）。`deny_sources` 是静态列表（如 `kernel_t`, `init_t`, `unconfined_t`），永不允许作为 `allow` 的 source_type。

#### 4.2.5 Policy Loader (`src/selinux.rs`)

```rust
pub struct PolicyLoader {
    store: PolicyStore,
}

impl PolicyLoader {
    pub async fn install(&mut self, rules: &[AllowRule]) -> Result<Version, PolicyError> {
        let cil = self.to_cil(rules);
        let module_name = self.store.next_module_name(); // "autolsm_<timestamp>"
        let file_path = format!("/tmp/autolsm/{}.cil", module_name);

        tokio::fs::write(&file_path, &cil).await?;

        // semodule -i 加载 CIL 模块
        let status = Command::new("semodule")
            .args(["-i", &file_path])
            .status()
            .await?;

        if !status.success() {
            // 自动回滚 — 删除损坏的模块
            let _ = Command::new("semodule").args(["-r", &module_name]).status().await;
            return Err(PolicyError::InstallFailed);
        }

        self.store.commit(module_name, cil);
        Ok(Version { name: module_name }) // 未记录在临时目录，仅供引用
    }
}
```

**版本与回滚**:
```rust
pub struct PolicyStore {
    activations: VecDeque<Activation>,
    max_history: usize,
}

struct Activation {
    version: String,
    cil_content: String,
    installed_at: Instant,
}

pub fn rollback(&mut self) -> Result<(), PolicyError> {
    if self.activations.len() < 2 { return Err(…); }
    let bad = self.activations.pop_back().unwrap();
    Command::new("semodule").args(["-r", &bad.version]).status()?;
    // 不重新加载旧版（已经存在）；只是回退到上一个 active
    Ok(())
}
```

### 4.3 Audit Consumer (`src/audit.rs`)

消费 `/var/log/audit/audit.log` 中的 SELinux 拒绝：

```rust
pub struct AuditConsumer {
    path: PathBuf,
}

impl AuditConsumer {
    pub async fn stream_denials(&self) -> impl Stream<Item = AvcDenial> {
        // 用 tokio::io::AsyncBufRead 逐行读取 audit log
        // 正则 "^type=AVC.+avc:\s*denied" 过滤
        // 提取 scontext=, tcontext=, tclass= 字段
        // 缓存最后光标位置，防重启加载新 entry
    }
}
```

**确定性前置过滤 (Pre-filter)** — 在消费 audit log 时即刻判断、过滤低价值/高危拒绝，确保 LLM 不受拒绝洪水的 token budget 冲击，同时加速高危攻击检测延迟：
```rust
pub struct DenialPreFilter {
    /// 永不允许的 tcontext 模式（高危路径/类型）。匹配到直接升为 CRITICAL alert，不送 LLM。
    deny_patterns: Vec<(Regex, &'static str)>, // e.g.: ("/etc/shadow", "credential_access")
    /// 已知噪声模式（正常但 dontaudit 已覆盖）→ 丢弃（info 日志）。
    allow_patterns: Vec<Regex>,               // e.g.: "\\.cache/"
    /// 速率限制：每分钟同 (scontext,tcontext,tclass,perm) 超过 N → 折叠计数，不重复入 Normalizer。
    rate_limit: usize,
}
pub enum FilterDecision {
    Pass(AvcDenial),    // 进入 Normalizer → LLM（语义模糊区，由 LLM 决定 drift/alert）
    Alert(AvcDenial),   // 确定高危，直接投递 alert 通道，跳过 LLM
    Drop,               // 确定噪声，忽略
}
```

此预过滤器利用确定性规则做到**安全判断的毫秒级响应**，同时限制 LLM 负载 — LLM 只处理处于"灰色区域"的拒绝（模式未知、需语义判断）。

SELinux `dontaudit` 会隐藏某些预期的拒绝。解决方案：
- 在学习期执行 `semodule -DB` （移除所有 dontaudit 规则）以便看到完整情况。
- 在生产期执行 `semodule -B` 恢复 dontaudit 以减少噪音。
- 这一行为由 `LearningOrEnforcing` 状态机自动控制。

---

## 5. 关键技术决策与坑点分析

### 5.1 为什么 BPF LSM 而不只是 syscall tracepoint

| 问题 | syscall tracepoint | BPF LSM hook |
|------|-------------------|--------------|
| 映射到 SELinux 权限 | 需维护脆弱译写表 (tcp_connect→`tcp_socket:name_connect`)，某些 hooks（`file_permission`）多个 perms 同时决策，syscall 无法区分 | 每个 hook = 1 个精确 `tclass`+`perm` |
| `ret` 参数可见性 | 无 — tracepoint 在 syscall 执行之后才知道 SELinux 是否拒绝（额外事件配对） | `ret` 即时告知前序 LSM 的裁定，零成本 |
| 客体信息 — 路径 | `sys_enter_openat` 有 fd + 路径，但 `file_permission` 的读/写发生在已有 fd 上 | `file_permission` 参数是 `file*` → `bpf_d_path` → 完整 vfs 路径 |
| 准入条件 | 无需 `bpf` LSM | 需要 `lsm=bpf` 启动参数 + kernel ≥ 5.7 |

**裁决**: 适应性工作的量、正确性收益、去 workaround 目标 → BPF LSM hooks 胜出。配置准入（`lsm=selinux,bpf`）仅需在所有目标节点上一次性启动参数，无运行时代价。

### 5.2 路径到 tcontext 解析 不做 BPF 的 `security` 字段读取

**问题**: 在 BPF 程序中获取 SELinux scontext（`task_struct → cred → security → selinux_sid_t → 上下文字符串`）需访问 SELinux 的私有安全字段，这个字段是 void* 非类型化，不但脆弱且对 BTF 不可见。

**方案**:
1. **scontext**: 见 4.2.1 PID→Context 缓存策略 — 用户态异步解析，增量缓存，子进程继承语义由 SELinux 本身保证。
2. **tcontext (文件)**: 在用户态用 `matchpathcon` 把路径转成类型（通过 `std::process::Command("matchpathcon", [path])`）。若 `matchpathcon` 不可用（二进制未安装或文件已删除），该事件记为 `"unresolved"` 并丢弃，不进入 Normalizer。v1 没有文件上下文前缀表的降级方案。

**这没有 workaround** — 这是管理 SELinux 建议的做法（`semanage fcontext` 查看的同样工具链），也是 `audit2allow -a` 所用路径。

### 5.3 策略安装原子性与锁定

**问题**: `semodule -i` 并非原子 — 多个模块同时安装会失败，大型策略重建可能数秒。

**方案**:
- 所有策略修改都由 PolicyLoader 按序 （Tokio `Mutex`）进行，一次只有一个激活 `semodule` 调用。
- 在安装之前，先用 `semodule -lfull | grep autolsm_` 确认上一次安装完全完成。
- 如果 `semodule -i` 失败（非零退出），记录错误，**永远不回滚到 Permissive mode**（重新构建 + 重试），而不是自动降权执行模式。
- 安装超时 = 10s，超时视为失败。

### 5.4 去重确保不淹灭 LLM 的 token 成本

**问题**: 一个容器 1 分钟内可能有 100K 次 `file_open` — 喂给 LLM 上百万 token 既不可能又无用。

**方案**: Normalizer 在每 60s 窗口中执行精确去重（相同 (scontext, tcontext, tclass, perm) → count++）。最后 LLM 只消费唯一 tuple 集合。对于长时间批量（1h），将窗口分批(60s)增量发送（delta of new tuples only），而不是重新发送整个足迹。

### 5.5 BPF 热路径开销与观测粒度

- **过滤优先**: 每个 hook 的切入点 = `TARGET_CGROUPS.get()`，不在目标 cgroup → 返回 （约 3%~5% 的单指令开销，含 map_lookup_elem + jump，benchmark 近 0）。
- **bpf_d_path 路径解析**: 只在匹配时才调用（即 `TARGET_CGROUPS` 已命中且 ret=0）。bpf_d_path 需要 BTF — Aya CO-RE 的 `preserve_access_index` 确保正确，无需内核版本特定的二进制。
- **RingBuf (shared across CPUs)**: 代替旧的 `PerfEventArray` — 跨 CPU 强顺序保证；减少丢事件；消耗高时通知机制精确。缓冲区大小可通过命令行配置（默认 256 KiB，生产环境建议 512 KiB–1 MiB）。`ObservationEvent` 为 64 字节，256 KiB 可缓存约 4096 个事件，正常情况下（128 容器 × ≤10 个唯一访问模式/秒）远不饱和。突发流量下丢事件仅影响「未见过的访问模式」首次发现 — 但同一模式在后续窗口必然重现，因此不造成永久性策略遗漏。
- **只关注目标域**: `TARGET_CGROUPS` 限定为受控容器 cgroup，保护本机其他负载免于观测开销。典型规模 128 个容器 × 5 hooks × 每 hook ~50ns = 平台开销占比 < 1%。

### 5.6 LLM 不准确性缓解

- **Validator gate**: 刚性拒绝不可接受输出 — 全字段 wildcard 检测（source_type, target_type, tclass, perms 任意含 `*` 即拒绝）、类型存在性校验（基于观测事件的 `known_types` 集合拒绝 LLM 虚构类型）、deny-source 列表（kernel_t/init_t/unconfined_t）拒绝高风险 source — 错误输出永远不到 CIL 阶段。
- **confidence 阈值**: 低于 0.7 的 LLM 响应自动标记为 `needs_review`，留为测试用例不自动安装（发到 alert channel）。
- **规则聚合**: 如果 LLM 返回 `allow multiple_type *:file *;` 这样的泛化，由 Validator 拦截。Permissive 学习状态确保不因策略过紧导致中断。

### 5.7 不重新实现 SELinux CIL 解析

v1 **不引入 CIL 解析器** — 只需要 CIL **生成**。CIL 是结构化语言，LLM 输出（JSON）通过确定性转换变为 CIL。若后续版本需解析已有 policy，可引入 `selinux-sys` / `libsepol` FFI。

### 5.8 `dontaudit` 分析与避免 learn by deny

- 学习阶段：`semodule -DB` 将所有 dontaudit 禁用 — 使即便默认 hide 的拒绝也可见，以便 LLM 决定是否生成 allow 规则。完成学习阶段后恢复 (`semodule -B`)。
- 不在学习阶段直接使用 AVC denied 生成规则：denial 说明行为被阻止，但无法推广到该域的正常运行范围。初始学习阶段应以 **permsive → BPF **观察** 运行行为的 allow 集为准。

---

## 6. Rust 工程结构

```
autolsm/
├── Cargo.toml                  # workspace
├── rust-toolchain.toml         # nightly (aya 需要)
├── docs/
│   └── architecture.md         # 本文
├── crates/
│   ├── autolsm-common/         # 共享类型 (no_std)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs          # ObservationEvent, hook_id enum, NormalizedAccess
│   ├── autolsm-ebpf/           # eBPF programs
│   │   ├── Cargo.toml          # aya-ebpf, autolsm-common
│   │   └── src/
│   │       └── main.rs         # 多个 #[lsm(hook=…)] fn
│   └── autolsm/                # 用户态 daemon
│       ├── Cargo.toml          # aya, tokio, anyhow, clap, serde, reqwest
│       └── src/
│           ├── main.rs         # entry, signal handling
│           ├── collector.rs    # eBPF load, RingBuf poll, mpsc tx
│           ├── resolver.rs     # pid → context cache
│           ├── normalizer.rs   # dedup (sctx,tctx,class,perm) + batch timer
│           ├── audit.rs        # ausearch / audit.log polling
│           ├── llm.rs          # PolicyGenerator trait, OpenAI impl
│           ├── validator.rs    # ruleset validation
│           ├── selinux.rs      # CIL emit, semodule load/rollback, permissive mgmt
│           └── store.rs        # PolicyStore (versioned modules + history)
└── xtask/                      # cargo xtask build-ebpf
    ├── Cargo.toml
    └── src/main.rs
```

**关键依赖列表**：

| Crate | 用途 |
|-------|------|
| `aya = "0.14"` | BPF 加载、map 操作、Lsm program 类型 |
| `aya-ebpf = "0.2"` | eBPF program 编写宏 (`#[lsm]`) |
| `aya-log-ebpf` | eBPF 端日志宏 |
| `aya-log` / `aya-log-parser` | 用户态日志消费 |
| `tokio` | async 运行时 (1 worker thread) |
| `clap` | 命令行参数 (`--target-cgroup`, `--llm-endpoint` etc.) |
| `serde` / `serde_json` | LLM request/response 序列化 |
| `reqwest` | OpenAI-compatible HTTP 调用 |
| `anyhow` / `thiserror` | 错误处理 |
| `tracing` / `tracing-subscriber` | 结构化日志 |

---

## 7. 数据流与并发模型

```
┌─────────────┐    ringbuf     ┌──────────────┐
│  eBPF LSM   │──────────────→ │  Collector   │
│  Observers   │  async poll   │  (tokio)     │
└─────────────┘                └────┬─────────┘
                                    │ mpsc::Sender<NormalizerInput::Observation>
                                    │ (经过 Resolver 补充 scontext)
                                    ▼
┌─────────────┐    audit.log   ┌──────────────┐
│  auditd     │──────────────→ │  Audit       │
│  AVC        │   poll + tail  │  Consumer    │
└─────────────┘                └────┬─────────┘
                                    │ mpsc::Sender<NormalizerInput::Denial>
                                    │ (经 PreFilter 后)
                                    ▼
                            ┌──────────────┐
                            │  Normalizer  │
                            │  (tokio)     │
                            └────┬─────────┘
                                 │ mpsc batch: 每 60s
                                 │ Batch { events: Vec<NormalizedAccess>, deltas: Vec<usize> }
                                 ▼
                            ┌──────────────┐
                            │  LLM Loop    │
                            │  (serial)    │
                            └────┬─────────┘
                                 │ LlmResponse
                                 ▼
                            ┌──────────────┐
                            │  Validator   │
                            │ (known_types)│
                            └────┬─────────┘
                                 │ Vec<AllowRule>
                                 ▼
                            ┌──────────────┐
                            │Policy Loader │
                            │  (mutex)     │
                            └──────────────┘
```

- **Collector**: 单 tokio task — `RingBuf::next()` blocking poll（async via `AsyncFd`），解析后发送到 Normalizer 的 channel。
- **Normalizer**: 单 task — 每 60 秒窗口；累积 channel 消息，去重后 batch 发送。
- **LLM Loop**: 单 task — 串行处理；一次只有一个 LLM 请求（避免并发混淆状态）。
- **Policy Loader**: `Arc<Mutex<PolicyLoader>>`，多 task 共享引用但同一时间只有一个安装者。Audit Consumer 也通过该引用获取当前版本。

**背压**: mpsc channel bounded = 4096。当 Normalizer 落后时，Collector 丢弃事件（通过 `RingBuf::next` consumed 但不处理)，递增丢事件计数器直到恢复正常。

---

## 8. 安全模型

### 8.1 信任锚

1. **SELinux 是信任锚**: 策略由 SELinux 内核验证并执行。任何 AdaptiveLSM 组件不能覆盖 SELinux 决策。
2. **eBPF observer 是只读**: 所有 BPF 程序锚定的 LSM hook 都返回 `ret`（传参透传），不产生新的安全裁定。Verifier 保证无侧信道。
3. **LLM 输出不是信任源**: 输出经过 Validator 刚性结构检查后才进入 CIL 生成。LLM 不是决策者，是决策的**建议器**。

### 8.2 Daemon 权限
Daemon 以 `CAP_BPF` + `CAP_SYS_ADMIN` 启动（eBPF load 仅需此二能力）。无需 `CAP_NET_ADMIN`（不直接操作网络设备）。运行于受限 SELinux 域（`autolsm_t`），只授予完成工作的最小权限：
```
allow autolsm_t self:capability { sys_admin bpf };
allow autolsm_t semanage_exec_t:file { execute_no_trans };
allow autolsm_t auditd_log_t:file { read };
allow autolsm_t autolsm_tmp_t:file { write create };
allow autolsm_t proc_t:dir { read };
allow autolsm_t proc_t:file { read };
# 对外 LLM API (HTTPS) 网络访问
allow autolsm_t self:tcp_socket { create connect };
allow autolsm_t *:tcp_socket name_connect;
```

注：daemon 域的 SELinux 策略定义在部署时由管理员按实际 LLM endpoint 主机/端口配置，此处为最小权限模板。

### 8.3 Permissive → Enforcing 状态机

```
          start
            │
            ▼
    ┌──────────────┐   学习完成          ┌──────────────┐
    │  LEARNING    │ ─────────────── →  │  ENFORCING    │
    │  permissive  │  策略安装成功        │  enforcing    │
    └──────┬───────┘                     └──────┬────────┘
           │                                    │
           │   审计拒绝超限 / 回滚信号              │  审计拒绝
           └──────────────────────────────────────┘  ← → LLM ΔPolicy
```

- 从 ENFORCING 变回 LEARNING **不支持**（太高风险 — 可能导致权限膨胀）。若策略有问题 → 回退到之前的工作版本（PolicyStore.rollback()），仍然 enforcing。
- Denial 超限（如 100 条新 AVC denied /分钟）→ 自动触发 ΔPolicy generation（Loop B），不改变模式。

### 8.4 威胁向量

| 向量 | 缓解 |
|------|------|
| LLM prompt injection（通过容器命名/路径注入恶意指令到 prompt） | JSON structured schema + Validator: 只允许结构化 JSON 属性，LLM output 不通过自然语言解析 |
| LLM 产生过度泛化的规则（如 `allow * *:file *`） | Validator 刚性检查（§4.2.4）— source_type, target_type, tclass, perms 全字段拒绝 wildcard `*` |
| LLM 虚构不存在的 SELinux 类型 | Validator `known_types` 检查 — 类型必须存在于当前观测事件集中 |
| 高危拒绝（如 /etc/shadow 访问）被 LLM 误判为 drift | 确定性 DenialPreFilter（§4.3）— deny-pattern 在 LLM 之前拦截 |
| Daemon 自身受攻击（实现为 root 运行） | 最小权限域 `autolsm_t` + `CAP_BPF` + `CAP_SYS_ADMIN`；tcp_socket 仅出站 LLM API |
| BPF verifier 绕过（恶意字节码） | Aya 使用 Rust 宏 + `core` 无 unsafe 构造 — 编译时保证 verifier 兼容性 |
| 策略安装期间其他组件修改策略 | PolicyLoader `Mutex` 保证互斥安装 |
| 拒绝洪水（高速率 AVC denied）淹没 LLM token budget | 确定性 PreFilter 限速 + deny 模式 immediate alert；LLM 只处理灰色区域 |
| 丢失 RingBuf 事件导致遗漏从未见过的访问模式 | 缓冲区可配置 + 同一模式在后续窗口必然重现（不丢失持久化缺失） |

---

## 9. 部署拓扑与先决条件

### 9.1 内核要求

| 特性 | 要求 | 现状 |
|------|------|------|
| BPF LSM (`CONFIG_BPF_LSM`) | 5.7+ | 工作站 6.8 ✓ |
| RingBuf (`CONFIG_BPF_SYSCALL`) | 5.8+ | ✓ |
| BTF (`CONFIG_DEBUG_INFO_BTF`) | 5.5+ | 默认启用的发行版 ✓ |
| SELinux (`CONFIG_SECURITY_SELINUX`) | any | ✓ |

### 9.2 启动要求

**GRUB 配置**:
```
GRUB_CMDLINE_LINUX="lsm=selinux,bpf"
```

**预启动命令**（容器运行时环境）:
```bash
# 确保 SELinux permissive 目标域（受控域标识）
semanage permissive -a container_t   # 或其他目标域类型

# 确保 cgroup v2 可用（BPF cgroup helpers 需要）
test -f /sys/fs/cgroup/cgroup.controllers && echo "cgroup v2 OK"

# 挂载 BPF 文件系统
mount -t bpf bpf /sys/fs/bpf
```

### 9.3 部署架构（AI 集群场景）

```
┌────────────────────────────────────────────┐
│                   Node (每个)               │
│  ┌──────────────────────────────────────┐  │
│  │  Container Runtime (Docker/containerd)│  │
│  │  ├─ 推理容器 A (cgroup /A)            │  │
│  │  ├─ 推理容器 B (cgroup /B)            │  │
│  │  └─ 推理容器 C (cgroup /C)            │  │
│  └──────────────────────────────────────┘  │
│  ┌──────────────────────────────────────┐  │
│  │  autolsm daemon (per node)           │  │
│  │  └─ eBPF observers per cgroup        │  │
│  └──────────────────────────────────────┘  │
└────────────────────────────────────────────┘

┌────────────────────────────────────────────┐
│        控制平面 (集群层级)                   │
│  ┌──────────────────────────────────────┐  │
│  │  LLM Backend (OpenAI-compatible)     │  │
│  │  可以是本地部署或 API                 │  │
│  └──────────────────────────────────────┘  │
│  ┌──────────────────────────────────────┐  │
│  │  Policy Aggregator (future v2)       │  │
│  │  跨节点策略聚合与分发                 │  │
│  └──────────────────────────────────────┘  │
└────────────────────────────────────────────┘
```

v1 每节点一个 daemon 实例，各自收集、分析、下发策略。策略仅 本节点生效。跨节点策略聚合/分发为未来版本扩展点（不纳入 v1 scope）。

---

## 10. 实施计划

### Phase 1 — Foundation (WE 1-3)

| # | 任务 | 交付 | 依赖 |
|---|------|------|------|
| 1 | 初始化 Rust workspace（common+ebpf+user+xtask） | `cargo build` √ | — |
| 2 | 定义 `ObservationEvent` 结构 + hook_id 枚举 + `NormalizedAccess` | `autolsm-common` 编译 | 1 |
| 3 | 实现第一个 observer: `file_open_obs`（eBPF 端） | `cargo xtask build-ebpf` 成功生成 ELF | 1, 2 |
| 4 | 实现 `Collector`（load bpf, `TARGET_CGROUPS` map 填充，RingBuf poll） | BPF 程序 attach 到内核并通过 ringbuf 收事件 | 1, 2, 3 |
| 5 | 实现 PID→Context Resolver（含 `sched_process_exec` tracepoint 辅助） | 单元测试: 已知 pid → 返回正确 context | 1 |
| 6 | 实现 `Normalizer`（dedup, 计数，时间窗口 batch） | 单元测试: 1000 个事件去重为 n 个唯一访问 | 4, 5 |

### Phase 2 — Analysis (WE 4-6)

| # | 任务 | 交付 | 依赖 |
|---|------|------|------|
| 7 | 实现 `PolicyGenerator` trait + `OpenAiPolicyGenerator` | 手动 curl LLM API 发 normalized 集 → 接收 JSON | 6 |
| 8 | 实现 `Validator` | 单元测试: 合法规则通过，通配符/无效类 reject | 7 |
| 9 | 实现 `CILEmitter` (JSON → CIL) | CIL 输出经 `checkmodule` 验证无误 | 7 |
|10 | 实现 `PolicyLoader`（semodule 安装/回滚） + `PolicyStore` | 重启后策略持久化；失败回滚验证 | 8, 9 |

### Phase 3 — Drift & Audit (WE 7-8)

| # | 任务 | 交付 | 依赖 |
|---|------|------|------|
|11 | 实现 `AuditConsumer`（audit.log 消费 / AVC denied 解析） | 运行 `sealert` 产生拒绝 → AuditConsumer 正确检测 | 10 |
|12 | 集成 denials → ΔPolicy flow（LLM refine 通道） | 手动生成拒绝 → 系统自动产出 Δ allow | 7, 11 |
|13 | 实现 permissive ↔ enforcing 状态机 | 集成测试: 学习→生成策略→安装→切换 enforcing | 10, 12 |

### Phase 4 — Robustness & Observability (WE 9)

| # | 任务 | 交付 | 依赖 |
|---|------|------|------|
|14 | 健康检查、metrics（`tracing` exporter / Prometheus metrics） | UI 可观测: events/sec, denials/min, version | 13 |
|15 | 集成测试: 真实容器场景 (Docker 容器 + SELinux enforcing) | 容器运行行为 → LLM 生成策略 → 正确允许/拒绝 | 13 |
|16 | 错误恢复: eBPF 重载、semodule 超时/失败恢复 | 故障注入测试: daemon crash → restart 恢复 | 13 |

---

## 附 A: LSM Hook → tclass/perm 完整映射表 (v1)

| hook_id | LSM Hook | SELinux tclass | perms observed | notes |
|---------|----------|---------------|----------------|-------|
| 0 | `file_open` | file | open, create (if O_CREAT) | flags in ObjectInfo |
| 1 | `file_permission` | file | read, write, append, exec | `mask` from MAY_READ/MAY_APPEND etc. |
| 2 | `file_ioctl` | file | ioctl | |
| 3 | `file_lock` | file | lock | |
| 4 | `file_receive` | file | open (via unix socket) | scm_rights |
| 5 | `socket_bind` | socket / tcp_socket / udp_socket | name_bind | `address->sa_family` 区分 |
| 6 | `socket_connect` | socket / tcp_socket / udp_socket | name_connect | |
| 7 | `socket_listen` | tcp_socket | listen | |
| 8 | `socket_accept` | tcp_socket | accept | |
| 9 | `socket_sendmsg` | socket | write | |
|10 | `socket_recvmsg` | socket | read | |
|11 | `unix_stream_connect` | unix_stream_socket | connectto | |
|12 | `unix_may_send` | unix_dgram_socket | sendto | |
|13 | `task_setpgid` | process | setpgid | |
|14 | `task_getpgid` | process | getpgid | |
|15 | `task_setsched` | process | setsched | |
|16 | `task_setrlimit` | process | setrlimit | |

---

## 附 B: 验证清单

- [x] 架构不重新实现 MAC 执行引擎（SELinux 唯一执行）
- [x] 没有 workaround — scontext 使用标准 `proc/attr`，tcontext 使用 `matchpathcon`（失败丢弃事件）
- [x] BPF 观测面零干扰 — passthrough 返回 `ret`，cgroup 过滤
- [x] LLM 输出受刚性 Validator 保护 — 全字段 wildcard 拒绝 + 类型存在性校验 + deny-source 列表
- [x] 确定性 PreFilter 在 LLM 之前拦截高危拒绝（deny-pattern + 限速）
- [x] 策略回滚机制 — 版本化 CIL 模块，semodule 回退
- [x] socket hook 的 tclass 运行时 family 消歧（AF_INET→tcp_socket 等）
- [x] Audit Consumer → Normalizer 类型统一（NormalizerInput 枚举）
- [x] ObservationEvent 布局自洽：ObjectInfo.raw 与 FileObject 均为 32 字节
- [x] 负载性能 — cgroup 过滤后的 per-hook 开销 < 100ns
- [x] 工程结构具体（crate 名、模块分拆、数据类型、并发模型）
- [x] 实施计划分阶段，无依赖颠倒
- [x] 无过度设计 — v1 仅 CIL 生成，不引入 CIL 解析；不创建新类型；单节点布局
