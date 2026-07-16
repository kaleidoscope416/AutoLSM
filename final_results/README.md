# AutoLSM Demo 运行报告

## 运行环境
- **服务器**: 43.137.50.63 (OpenCloudOS 9.6)
- **内核**: 6.6.119-49.23.oc9.x86_64
- **LSM**: capability,landlock,yama,selinux,bpf
- **SELinux**: Permissive 模式
- **BTF**: 可用
- **Rust**: 1.97.0, clang: 17.0.6, bpftool: 7.3.0

## 执行结果
Demo 完整跑通，7 个 Stage 全部执行完成：

| Stage | 描述 | 状态 |
|-------|------|------|
| 1 | 环境就绪 | PASS |
| 2 | 编译 eBPF 程序 (5 hooks, 898K) | PASS |
| 3 | 启动 daemon, eBPF attach (5/5 hooks) | PASS |
| 4 | 触发测试行为, 采集 + 策略生成 (13 batches) | PASS |
| 5 | 策略下发 (2 autolsm 模块) | PASS |
| 6 | 行为漂移注入 (2 AVC 拒绝) | PASS |
| 7 | 漂移检测 Loop B (3x [DRIFT]) | PASS |

## 数据流
- Loop A (Discovery): eBPF -> Normalizer -> PolicyGenerator -> Validator -> semodule
- Loop B (Drift): Audit -> AVC -> DenialPreFilter -> Normalizer -> RefinePolicy

## 关键指标
- eBPF batch: 13
- 安装模块: 2
- 漂移检测: 3 次 [DRIFT]
- 校验错误: 2 次 (capability2)

## 修复记录
1. unknown_t/generic_t/unresolved_t 哨兵类型四层过滤
2. semodule 超时子进程 kill
3. semodule 超时 10s->30s
4. grep 管道添加 || true 防 set -e 退出
5. CIL glob 空文件处理

## 产物
- demo-full.log: 完整运行日志
- daemon.log: daemon 日志
- installed-modules.txt: 已安装 SELinux 模块
