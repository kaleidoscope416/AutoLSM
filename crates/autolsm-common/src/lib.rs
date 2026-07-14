//! autolsm-common — Shared types for the AutoLSM framework.
//!
//! This crate is used by both the eBPF programs (no_std) and the userspace daemon.
//! Types used in eBPF MUST be `#[repr(C)]`, no_std compatible, and never heap-allocate.
//! Types gated behind `feature = "userspace"` may use `std` and `serde`.

#![cfg_attr(not(feature = "userspace"), no_std)]

// ── eBPF-compatible: always available (no_std) ─────────────────────────────

/// Hook identifier: maps 1:1 to SELinux LSM hooks observed by the framework.
///
/// Values correspond to the hook positions in the mapper table (§3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum HookId {
    FileOpen = 0,
    FilePermission = 1,
    FileIoctl = 2,
    FileLock = 3,
    FileReceive = 4,
    SocketBind = 5,
    SocketConnect = 6,
    SocketListen = 7,
    SocketAccept = 8,
    SocketSendmsg = 9,
    SocketRecvmsg = 10,
    UnixStreamConnect = 11,
    UnixMaySend = 12,
    TaskSetpgid = 13,
    TaskGetpgid = 14,
    TaskSetsched = 15,
    TaskSetrlimit = 16,
}

impl HookId {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::FileOpen),
            1 => Some(Self::FilePermission),
            2 => Some(Self::FileIoctl),
            3 => Some(Self::FileLock),
            4 => Some(Self::FileReceive),
            5 => Some(Self::SocketBind),
            6 => Some(Self::SocketConnect),
            7 => Some(Self::SocketListen),
            8 => Some(Self::SocketAccept),
            9 => Some(Self::SocketSendmsg),
            10 => Some(Self::SocketRecvmsg),
            11 => Some(Self::UnixStreamConnect),
            12 => Some(Self::UnixMaySend),
            13 => Some(Self::TaskSetpgid),
            14 => Some(Self::TaskGetpgid),
            15 => Some(Self::TaskSetsched),
            16 => Some(Self::TaskSetrlimit),
            _ => None,
        }
    }
}

/// File object information captured from LSM hooks.
///
/// Total size: 8+8+4+12 = 32 bytes (8-byte aligned).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FileObject {
    /// Device number (major << 20 | minor)
    pub dev: u64,
    /// Inode number
    pub inode: u64,
    /// Open flags (O_RDONLY, O_WRONLY, O_CREAT, etc.)
    pub flags: u32,
    /// Truncated path prefix (first 12 bytes of the VFS path).
    /// Full path is resolved asynchronously in userspace via /proc/<pid>/fd/<n>.
    pub path: [u8; 12],
}

/// Socket object information captured from LSM hooks.
///
/// Total size: 2+2+2+16 = 22 bytes (padded to 32 in union).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SocketObject {
    /// Address family (AF_INET=2, AF_INET6=10, AF_UNIX=1, AF_NETLINK=16)
    pub family: u16,
    /// Protocol (IPPROTO_TCP=6, IPPROTO_UDP=17)
    pub proto: u16,
    /// Port number (network byte order)
    pub port: u16,
    /// IP address: IPv4 in bytes 12..16; IPv6 in all 16 bytes
    pub addr: [u8; 16],
}

/// Union of object information variants.
#[derive(Copy, Clone)]
#[repr(C)]
pub union ObjectInfo {
    pub file: FileObject,
    pub sock: SocketObject,
    pub raw: [u8; 32],
}

// Manual Debug: unions can't derive Debug
impl core::fmt::Debug for ObjectInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unsafe { f.debug_struct("ObjectInfo").field("raw", &self.raw).finish() }
    }
}

/// A single observation event emitted by an eBPF LSM observer program.
///
/// Total size: 8+8+8+4+4+32+4 = 68 bytes (padded to 72 for alignment).
/// This is intentionally kept small to fit efficiently in a RingBuf.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ObservationEvent {
    /// Subject pid_tgid (upper 32 = tgid, lower 32 = tid)
    pub pid_tgid: u64,
    /// Cgroup ID from bpf_get_current_cgroup_id()
    pub cgroup_id: u64,
    /// Timestamp in nanoseconds (bpf_ktime_get_ns)
    pub timestamp_ns: u64,
    /// Which LSM hook produced this event
    pub hook_id: u32,
    /// Padding for alignment
    pub _pad1: u32,
    /// Hook-specific object data
    pub object: ObjectInfo,
    /// Reserved for future use
    pub _pad2: u32,
}

// ── Network protocol constants ─────────────────────────────────────────────

/// Address family constants matching Linux AF_* values.
pub mod af {
    pub const AF_UNIX: u16 = 1;
    pub const AF_INET: u16 = 2;
    pub const AF_INET6: u16 = 10;
    pub const AF_NETLINK: u16 = 16;
}

/// Protocol constants matching Linux IPPROTO_* values.
pub mod proto {
    pub const IPPROTO_TCP: u16 = 6;
    pub const IPPROTO_UDP: u16 = 17;
}

// ── userspace-only types ────────────────────────────────────────────────────

#[cfg(feature = "userspace")]
mod userspace;

#[cfg(feature = "userspace")]
pub use userspace::*;
