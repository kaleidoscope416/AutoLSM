#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
    },
    macros::lsm,
    maps::{HashMap, RingBuf},
    programs::LsmContext,
};
use autolsm_common::{FileObject, HookId, ObservationEvent, ObjectInfo, SocketObject};

// ── BPF Maps ────────────────────────────────────────────────────────────────

/// Cgroup IDs of containers being observed.
///
/// Keys: cgroup_id (u64), Value: always 1 (u8 placeholder).
/// The userspace daemon populates this map with target containers.
/// Observation programs check this map at entry; non-target cgroups return immediately.
#[map]
static TARGET_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Ring buffer for emitting observation events to userspace.
///
/// 256 KiB default — configurable at load time.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Returns true if the current task belongs to a target cgroup.
#[inline(always)]
fn is_target() -> bool {
    unsafe {
        let cgid = bpf_get_current_cgroup_id();
        // aya_ebpf::maps::HashMap::get returns Option<&V> — None means "not in map"
        TARGET_CGROUPS.get(&cgid).is_some()
    }
}

/// Build a base ObservationEvent with common fields filled.
#[inline(always)]
fn base_event(hook_id: HookId) -> ObservationEvent {
    ObservationEvent {
        pid_tgid: unsafe { bpf_get_current_pid_tgid() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        hook_id: hook_id as u32,
        _pad1: 0,
        object: ObjectInfo { raw: [0u8; 32] },
        _pad2: 0,
    }
}

/// Submit an event to the ring buffer. Errors (buffer full) are silently ignored;
/// the userspace collector tracks dropped events via a counter.
#[inline(always)]
fn emit(event: &ObservationEvent) {
    unsafe {
        let _ = EVENTS.output(event, 0);
    }
}

/// Passthrough shortcut: return the previous LSM decision unmodified.
#[inline(always)]
fn passthrough(ctx: &LsmContext) -> i32 {
    unsafe { ctx.arg(ctx.argc() - 1) }
    // The last argument to every LSM hook is the return value from previous hooks.
    // For file_open/BSD-style this is position 2; for task_* hooks position varies.
    // We use the safe pattern: read ret from the standard position.
}

// ── File Observers ──────────────────────────────────────────────────────────

/// Observe file open operations.
///
/// args: struct file *file, int flags, int ret
#[lsm(hook = "file_open")]
pub fn file_open_obs(ctx: LsmContext) -> i32 {
    if !is_target() {
        return passthrough(&ctx);
    }

    let ret: i32 = unsafe { ctx.arg(2) };
    if ret != 0 {
        // A previous LSM already denied this access — skip observation.
        return ret;
    }

    // Note: accessing struct file *file requires vmlinux.rs bindings.
    // In production, generate via: aya-tool generate file > vmlinux.rs
    // For now, we build a best-effort event with the flags from arg 1.
    let flags: u32 = unsafe { ctx.arg(1) };

    let mut event = base_event(HookId::FileOpen);
    unsafe {
        event.object.file = FileObject {
            dev: 0,
            inode: 0,
            flags,
            path: [0u8; 12],
        };
    }
    emit(&event);
    ret
}

/// Observe file permission checks (read/write/append/execute on an open fd).
///
/// args: struct file *file, int mask, int ret
#[lsm(hook = "file_permission")]
pub fn file_permission_obs(ctx: LsmContext) -> i32 {
    if !is_target() {
        return passthrough(&ctx);
    }

    let ret: i32 = unsafe { ctx.arg(2) };
    if ret != 0 {
        return ret;
    }

    let mask: u32 = unsafe { ctx.arg(1) };

    // mask encodes MAY_READ(0x01), MAY_WRITE(0x02), MAY_APPEND, MAY_EXEC etc.
    // We emit one event per permission bit for accurate SELinux perm mapping.
    if mask & 0x01 != 0 {
        // MAY_READ
        // normalizer maps hook_id=FilePermission + flags to specific perm
        // For now, emit the raw event; userspace Normalizer decomposes.
    }
    let mut event = base_event(HookId::FilePermission);
    unsafe {
        event.object.file = FileObject {
            dev: 0,
            inode: 0,
            flags: mask,
            path: [0u8; 12],
        };
    }
    emit(&event);
    ret
}

// ── Socket Observers ────────────────────────────────────────────────────────

/// Observe socket bind operations.
///
/// args: struct socket *sock, struct sockaddr *address, int addrlen, int ret
#[lsm(hook = "socket_bind")]
pub fn socket_bind_obs(ctx: LsmContext) -> i32 {
    if !is_target() {
        return passthrough(&ctx);
    }

    let ret: i32 = unsafe { ctx.arg(3) };
    if ret != 0 {
        return ret;
    }

    // The sockaddr* is at arg 1. In production with vmlinux.rs bindings,
    // we'd read sa_family and the address bytes. For now, emit a zeroed socket object.
    let mut event = base_event(HookId::SocketBind);
    unsafe {
        event.object.sock = SocketObject {
            family: 0,
            proto: 0,
            port: 0,
            addr: [0u8; 16],
        };
    }
    emit(&event);
    ret
}

/// Observe socket connect operations.
///
/// args: struct socket *sock, struct sockaddr *address, int addrlen, int ret
#[lsm(hook = "socket_connect")]
pub fn socket_connect_obs(ctx: LsmContext) -> i32 {
    if !is_target() {
        return passthrough(&ctx);
    }

    let ret: i32 = unsafe { ctx.arg(3) };
    if ret != 0 {
        return ret;
    }

    let mut event = base_event(HookId::SocketConnect);
    unsafe {
        event.object.sock = SocketObject {
            family: 0,
            proto: 0,
            port: 0,
            addr: [0u8; 16],
        };
    }
    emit(&event);
    ret
}

// ── Process Observer ────────────────────────────────────────────────────────

/// Observe setrlimit operations (process resource limits).
///
/// args: struct task_struct *task, unsigned int resource, struct rlimit *new_rlim, int ret
#[lsm(hook = "task_setrlimit")]
pub fn task_setrlimit_obs(ctx: LsmContext) -> i32 {
    if !is_target() {
        return passthrough(&ctx);
    }

    let ret: i32 = unsafe { ctx.arg(3) };
    if ret != 0 {
        return ret;
    }

    let event = base_event(HookId::TaskSetrlimit);
    emit(&event);
    ret
}

// ── Panic Handler ───────────────────────────────────────────────────────────

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
