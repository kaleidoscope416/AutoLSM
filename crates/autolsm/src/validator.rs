//! Policy validator — rigid structural gate between LLM output and SELinux policy installation.

use autolsm_common::AllowRule;
use std::collections::HashSet;

pub static VALID_CLASSES: &[&str] = &[
    "file", "dir", "lnk_file", "chr_file", "blk_file", "fifo_file", "sock_file",
    "tcp_socket", "udp_socket", "rawip_socket", "netlink_socket", "packet_socket",
    "unix_stream_socket", "unix_dgram_socket",
    "process", "capability", "capability2", "filesystem",
    "fd", "key", "sem", "msgq", "shm", "anon_inode",
];

pub fn valid_perms_for_class(class: &str) -> &'static [&'static str] {
    match class {
        "file" => &["read", "write", "open", "create", "getattr", "setattr", "lock",
            "relabelfrom", "relabelto", "append", "link", "unlink", "rename",
            "execute", "execute_no_trans", "entrypoint", "ioctl", "map", "quotaon",
            "mounton", "audit_access"],
        "dir" => &["read", "write", "open", "create", "getattr", "setattr", "lock",
            "relabelfrom", "relabelto", "append", "link", "unlink", "rename",
            "search", "rmdir", "add_name", "remove_name", "reparent", "audit_access"],
        "tcp_socket" => &["create", "connect", "listen", "accept", "read", "write",
            "send_msg", "recv_msg", "name_bind", "name_connect", "getattr", "setattr",
            "node_bind", "relabelto", "relabelfrom"],
        "udp_socket" => &["create", "connect", "read", "write", "send_msg", "recv_msg",
            "name_bind", "name_connect", "getattr", "setattr", "node_bind", "relabelto", "relabelfrom"],
        "unix_stream_socket" => &["create", "connectto", "listen", "accept", "read", "write",
            "sendto", "getattr", "setattr", "relabelto"],
        "unix_dgram_socket" => &["create", "sendto", "read", "write", "getattr", "setattr", "relabelto"],
        "netlink_socket" => &["create", "read", "write", "getattr", "setattr", "relabelto"],
        "process" => &["fork", "transition", "sigkill", "sigstop", "signull", "signal",
            "ptrace", "getsched", "setsched", "getsession", "getpgid", "setpgid",
            "getcap", "setcap", "share", "getattr", "setexec", "setfscreate",
            "noatsecure", "siginh", "setrlimit", "rlimitinh", "dyntransition",
            "setcurrent", "execmem", "execstack", "execheap", "setkeycreate", "setsockcreate"],
        "capability" => &["chown", "dac_override", "dac_read_search", "fowner", "fsetid",
            "kill", "setgid", "setuid", "setpcap", "linux_immutable",
            "net_bind_service", "net_broadcast", "net_admin", "net_raw",
            "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot",
            "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
            "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease",
            "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin",
            "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore"],
        "filesystem" => &["mount", "remount", "unmount", "getattr", "relabelfrom",
            "relabelto", "associate", "quotamod", "quotaget"],
        _ => &["read", "write", "create", "getattr", "setattr"],
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("wildcard in source_type: {0}")]
    WildcardSource(String),
    #[error("wildcard in target_type: {0}")]
    WildcardTarget(String),
    #[error("wildcard in tclass")]
    WildcardClass,
    #[error("wildcard in perm: {0}")]
    WildcardPerm(String),
    #[error("target_type must not be unconfined_t")]
    UnconfinedTarget,
    #[error("unknown SELinux type: {0}")]
    UnknownType(String),
    #[error("source_type {0} is in deny list")]
    DeniedSource(String),
    #[error("target_type {0} is in deny list")]
    DeniedTarget(String),
    #[error("perms list is empty")]
    EmptyPerms,
    #[error("unknown SELinux class: {0}")]
    UnknownClass(String),
    #[error("unknown perm '{perm}' for class '{class}'")]
    UnknownPerm { class: String, perm: String },
}

/// Validate allow rules against known types and deny lists.
pub fn validate(
    rules: &[AllowRule],
    known_types: &HashSet<String>,
    deny_sources: &HashSet<String>,
) -> Result<(), ValidationError> {
    for rule in rules {
        // 1) Full-field wildcard rejection
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
        // 2) Unconfined target
        if rule.target_type == "unconfined_t" {
            return Err(ValidationError::UnconfinedTarget);
        }
        // 3) Type existence
        if !known_types.contains(&rule.source_type) {
            return Err(ValidationError::UnknownType(rule.source_type.clone()));
        }
        if !known_types.contains(&rule.target_type) {
            return Err(ValidationError::UnknownType(rule.target_type.clone()));
        }
        // 4) Deny sources AND deny targets
        if deny_sources.contains(&rule.source_type) {
            return Err(ValidationError::DeniedSource(rule.source_type.clone()));
        }
        if deny_sources.contains(&rule.target_type) {
            return Err(ValidationError::DeniedTarget(rule.target_type.clone()));
        }
        // 5) Non-empty perms
        if rule.perms.is_empty() {
            return Err(ValidationError::EmptyPerms);
        }
        // 6) Valid tclass
        if !VALID_CLASSES.contains(&rule.tclass.as_str()) {
            return Err(ValidationError::UnknownClass(rule.tclass.clone()));
        }
        // 7) Valid perms
        let valid = valid_perms_for_class(&rule.tclass);
        for perm in &rule.perms {
            if !valid.contains(&perm.as_str()) {
                return Err(ValidationError::UnknownPerm {
                    class: rule.tclass.clone(),
                    perm: perm.clone(),
                });
            }
        }
    }
    Ok(())
}

pub fn default_deny_sources() -> HashSet<String> {
    [
        "kernel_t", "init_t", "unconfined_t", "unlabeled_t",
        "unknown_t", "unresolved_t",
    ].iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(source: &str, target: &str, class: &str, perms: &[&str]) -> AllowRule {
        AllowRule {
            source_type: source.into(),
            target_type: target.into(),
            tclass: class.into(),
            perms: perms.iter().map(|s| s.to_string()).collect(),
            rationale: "test".into(),
        }
    }

    #[test]
    fn test_valid_rule_passes() {
        let rules = vec![make_rule("httpd_t", "var_log_t", "file", &["read", "append"])];
        let mut known = HashSet::new();
        known.insert("httpd_t".into());
        known.insert("var_log_t".into());
        assert!(validate(&rules, &known, &default_deny_sources()).is_ok());
    }

    #[test]
    fn test_wildcard_source_rejected() {
        let rules = vec![make_rule("*", "var_log_t", "file", &["read"])];
        let mut known = HashSet::new();
        known.insert("var_log_t".into());
        assert!(matches!(validate(&rules, &known, &default_deny_sources()), Err(ValidationError::WildcardSource(_))));
    }

    #[test]
    fn test_unknown_t_rejected() {
        let mut known = HashSet::new();
        known.insert("unknown_t".into());
        known.insert("var_log_t".into());
        let rules = vec![make_rule("unknown_t", "var_log_t", "file", &["read"])];
        assert!(matches!(validate(&rules, &known, &default_deny_sources()), Err(ValidationError::DeniedSource(_))));
    }

    #[test]
    fn test_deny_target_rejected() {
        let denys = default_deny_sources();
        let mut known = HashSet::new();
        known.insert("httpd_t".into());
        known.insert("kernel_t".into());
        let rules = vec![make_rule("httpd_t", "kernel_t", "file", &["read"])];
        assert!(matches!(validate(&rules, &known, &denys), Err(ValidationError::DeniedTarget(_))));
    }
}
