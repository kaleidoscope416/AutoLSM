// SPDX-License-Identifier: GPL-2.0
// AutoLSM eBPF LSM observer programs
//
// Build:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c autolsm.bpf.c -o autolsm.bpf.o
//
// Aya loads: EbpfLoader::load_file("autolsm.bpf.o")

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET  2
#define AF_INET6 10
#endif

// ── Event layout (must match autolsm_common::ObservationEvent) ──────────────

#define PATH_MAX_PREFIX 12

struct file_event {
    __u64 dev;
    __u64 inode;
    __u32 flags;
    __u8  path[PATH_MAX_PREFIX];
};

struct sock_event {
    __u16 family;
    __u16 proto;
    __u16 port;
    __u8  addr[16];
};

union obj_info {
    struct file_event file;
    struct sock_event sock;
    __u8 raw[32];
};

struct observation_event {
    __u64 pid_tgid;
    __u64 cgroup_id;
    __u64 timestamp_ns;
    __u32 hook_id;
    __u32 _pad1;
    union obj_info object;
    __u32 _pad2;
};

// ── Hook IDs ────────────────────────────────────────────────────────────────

#define HOOK_FILE_OPEN       0
#define HOOK_FILE_PERMISSION 1
#define HOOK_SOCKET_BIND     5
#define HOOK_SOCKET_CONNECT  6
#define HOOK_TASK_SETRLIMIT  16

// ── Maps ────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} target_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// ── Helpers ─────────────────────────────────────────────────────────────────

static __always_inline int is_target(void) {
    __u64 cgid = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&target_cgroups, &cgid) != NULL;
}

static __always_inline void fill_base(struct observation_event *e, int hook_id) {
    e->pid_tgid = bpf_get_current_pid_tgid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->hook_id = hook_id;
    e->_pad1 = 0;
    __builtin_memset(&e->object, 0, sizeof(e->object));
    e->_pad2 = 0;
}

static __always_inline void emit(struct observation_event *e) {
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

// ── File Open ───────────────────────────────────────────────────────────────

SEC("lsm/file_open")
int BPF_PROG(file_open_obs, struct file *file)
{
    if (!is_target())
        return 0;

    struct observation_event e = {};
    fill_base(&e, HOOK_FILE_OPEN);

    struct inode *ino;
    bpf_core_read(&ino, sizeof(ino), &file->f_inode);
    e.object.file.dev = (__u64)(unsigned long)ino;
    e.object.file.inode = BPF_CORE_READ(ino, i_ino);
    e.object.file.flags = BPF_CORE_READ(file, f_flags);

    // Copy dentry name prefix
    struct dentry *d;
    bpf_core_read(&d, sizeof(d), &file->f_path.dentry);
    const unsigned char *name;
    bpf_core_read(&name, sizeof(name), &d->d_name.name);
    __u32 name_len;
    bpf_core_read(&name_len, sizeof(name_len), &d->d_name.len);
    int len = name_len < PATH_MAX_PREFIX ? name_len : PATH_MAX_PREFIX;
    bpf_probe_read_kernel_str(e.object.file.path, len + 1, name);

    emit(&e);
    return 0;
}

// ── File Permission ─────────────────────────────────────────────────────────

SEC("lsm/file_permission")
int BPF_PROG(file_permission_obs, struct file *file, int mask)
{
    if (!is_target())
        return 0;

    struct observation_event e = {};
    fill_base(&e, HOOK_FILE_PERMISSION);

    struct inode *ino;
    bpf_core_read(&ino, sizeof(ino), &file->f_inode);
    e.object.file.dev = (__u64)(unsigned long)ino;
    e.object.file.inode = BPF_CORE_READ(ino, i_ino);
    e.object.file.flags = mask;

    struct dentry *d;
    bpf_core_read(&d, sizeof(d), &file->f_path.dentry);
    const unsigned char *name;
    bpf_core_read(&name, sizeof(name), &d->d_name.name);
    __u32 name_len;
    bpf_core_read(&name_len, sizeof(name_len), &d->d_name.len);
    int len = name_len < PATH_MAX_PREFIX ? name_len : PATH_MAX_PREFIX;
    bpf_probe_read_kernel_str(e.object.file.path, len + 1, name);

    emit(&e);
    return 0;
}

// ── Socket Bind ─────────────────────────────────────────────────────────────

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind_obs, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
    if (!is_target())
        return 0;

    struct observation_event e = {};
    fill_base(&e, HOOK_SOCKET_BIND);

    if (address) {
        struct sockaddr_in sin;
        bpf_core_read(&sin, sizeof(sin), address);
        e.object.sock.family = sin.sin_family;
        if (sin.sin_family == AF_INET || sin.sin_family == AF_INET6) {
            e.object.sock.port = bpf_ntohs(sin.sin_port);
        }
    }

    emit(&e);
    return 0;
}

// ── Socket Connect ──────────────────────────────────────────────────────────

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect_obs, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
    if (!is_target())
        return 0;

    struct observation_event e = {};
    fill_base(&e, HOOK_SOCKET_CONNECT);

    if (address) {
        struct sockaddr_in sin;
        bpf_core_read(&sin, sizeof(sin), address);
        e.object.sock.family = sin.sin_family;
        if (sin.sin_family == AF_INET || sin.sin_family == AF_INET6) {
            e.object.sock.port = bpf_ntohs(sin.sin_port);
        }
    }

    emit(&e);
    return 0;
}

// ── Task Setrlimit ──────────────────────────────────────────────────────────

SEC("lsm/task_setrlimit")
int BPF_PROG(task_setrlimit_obs, struct task_struct *task,
             unsigned int resource, struct rlimit *new_rlim)
{
    if (!is_target())
        return 0;

    struct observation_event e = {};
    fill_base(&e, HOOK_TASK_SETRLIMIT);
    emit(&e);
    return 0;
}
