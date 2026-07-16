//! Integration tests for AutoLSM core pipeline.
//! Tests run without eBPF, SELinux, or LLM — pure Rust logic validation.

use autolsm_common::{AllowRule, FileObject, HookId, ObservationEvent, ObjectInfo, SocketObject};
use std::collections::HashSet;

// ── Event builders ─────────────────────────────────────────────────────────

fn make_file_open(tgid: u32) -> ObservationEvent {
    ObservationEvent {
        pid_tgid: ((tgid as u64) << 32) | 1,
        cgroup_id: 1234,
        timestamp_ns: 1_000_000_000,
        hook_id: HookId::FileOpen as u32,
        _pad1: 0,
        object: ObjectInfo { file: FileObject { dev: 1, inode: 42, flags: 0, path: *b"/var/log/ap\0" } },
        _pad2: 0,
    }
}

fn make_socket_bind(family: u16, proto: u16, port: u16) -> ObservationEvent {
    ObservationEvent {
        pid_tgid: 1000_u64 << 32,
        cgroup_id: 1234,
        timestamp_ns: 2_000_000_000,
        hook_id: HookId::SocketBind as u32,
        _pad1: 0,
        object: ObjectInfo { sock: SocketObject { family, proto, port: port.to_be(), addr: [0u8; 16] } },
        _pad2: 0,
    }
}

fn make_task_setrlimit() -> ObservationEvent {
    ObservationEvent {
        pid_tgid: 1000_u64 << 32,
        cgroup_id: 1234,
        timestamp_ns: 3_000_000_000,
        hook_id: HookId::TaskSetrlimit as u32,
        _pad1: 0,
        object: ObjectInfo { raw: [0u8; 32] },
        _pad2: 0,
    }
}

// ── Hook mapping ────────────────────────────────────────────────────────────

#[test]
fn hook_file_open_id() {
    assert_eq!(HookId::from_u32(0), Some(HookId::FileOpen));
}

#[test]
fn hook_file_permission_id() {
    assert_eq!(HookId::from_u32(1), Some(HookId::FilePermission));
}

#[test]
fn hook_socket_bind_id() {
    assert_eq!(HookId::from_u32(5), Some(HookId::SocketBind));
}

#[test]
fn hook_task_setrlimit_id() {
    assert_eq!(HookId::from_u32(16), Some(HookId::TaskSetrlimit));
}

#[test]
fn unknown_hook_id_is_none() {
    assert_eq!(HookId::from_u32(99), None);
}

// ── Validator tests ─────────────────────────────────────────────────────────

use autolsm::validator::{self, ValidationError};

fn rule(src: &str, tgt: &str, cls: &str, perms: &[&str]) -> AllowRule {
    AllowRule {
        source_type: src.into(), target_type: tgt.into(), tclass: cls.into(),
        perms: perms.iter().map(|s| s.to_string()).collect(), rationale: "test".into(),
    }
}

fn deny_set() -> HashSet<String> {
    ["kernel_t","init_t","unlabeled_t"]
        .iter().map(|s| s.to_string()).collect()
}

fn known(types: &[&str]) -> HashSet<String> {
    types.iter().map(|s| s.to_string()).collect()
}

#[test]
fn valid_rules_pass() {
    let rules = vec![rule("httpd_t", "var_log_t", "file", &["read","append"])];
    assert!(validator::validate(&rules, &known(&["httpd_t","var_log_t"]), &deny_set()).is_ok());
}

#[test]
fn wildcard_source_rejected() {
    let r = vec![rule("*", "var_log_t", "file", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["var_log_t"]), &deny_set()), Err(ValidationError::WildcardSource(_))));
}

#[test]
fn wildcard_target_rejected() {
    let r = vec![rule("httpd_t", "*", "file", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["httpd_t"]), &deny_set()), Err(ValidationError::WildcardTarget(_))));
}

#[test]
fn wildcard_class_rejected() {
    let r = vec![rule("httpd_t", "log_t", "*", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["httpd_t","log_t"]), &deny_set()), Err(ValidationError::WildcardClass)));
}

#[test]
fn wildcard_perm_rejected() {
    let r = vec![rule("httpd_t", "log_t", "file", &["*"])];
    assert!(matches!(validator::validate(&r, &known(&["httpd_t","log_t"]), &deny_set()), Err(ValidationError::WildcardPerm(_))));
}

#[test]
fn unconfined_target_allowed() {
    let r = vec![rule("httpd_t", "unconfined_t", "file", &["read"])];
    assert!(validator::validate(&r, &known(&["httpd_t","unconfined_t"]), &deny_set()).is_ok());
}

#[test]
fn unknown_type_rejected() {
    let r = vec![rule("hallucinated_t", "log_t", "file", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["log_t"]), &deny_set()), Err(ValidationError::UnknownType(_))));
}

#[test]
fn deny_source_rejected() {
    let r = vec![rule("kernel_t", "log_t", "file", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["kernel_t","log_t"]), &deny_set()), Err(ValidationError::DeniedSource(_))));
}

#[test]
fn deny_target_rejected() {
    let r = vec![rule("httpd_t", "kernel_t", "file", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["httpd_t","kernel_t"]), &deny_set()), Err(ValidationError::DeniedTarget(_))));
}

#[test]
fn kernel_t_denied_as_source() {
    let r = vec![rule("kernel_t", "log_t", "file", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["kernel_t","log_t"]), &deny_set()), Err(ValidationError::DeniedSource(_))));
}

#[test]
fn empty_perms_rejected() {
    let r = vec![rule("httpd_t", "log_t", "file", &[])];
    assert!(matches!(validator::validate(&r, &known(&["httpd_t","log_t"]), &deny_set()), Err(ValidationError::EmptyPerms)));
}

#[test]
fn unknown_class_rejected() {
    let r = vec![rule("httpd_t", "log_t", "magic_class", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["httpd_t","log_t"]), &deny_set()), Err(ValidationError::UnknownClass(_))));
}

#[test]
fn invalid_perm_rejected() {
    let r = vec![rule("httpd_t", "log_t", "file", &["fly"])];
    assert!(matches!(validator::validate(&r, &known(&["httpd_t","log_t"]), &deny_set()), Err(ValidationError::UnknownPerm{..})));
}

#[test]
fn partial_wildcard_source_rejected() {
    let r = vec![rule("container_*", "log_t", "file", &["read"])];
    assert!(matches!(validator::validate(&r, &known(&["container_*","log_t"]), &deny_set()), Err(ValidationError::WildcardSource(_))));
}

// ── Store tests ─────────────────────────────────────────────────────────────

use autolsm::store::PolicyStore;

#[test]
fn store_module_naming() {
    let s = PolicyStore::new(10);
    assert!(s.next_module_name().starts_with("autolsm_"));
}

#[test]
fn store_rollback_needs_two_versions() {
    let mut s = PolicyStore::new(10);
    assert!(s.rollback().is_err());
    s.commit("autolsm_1".into(), "cil1".into());
    assert!(s.rollback().is_err());
    s.commit("autolsm_2".into(), "cil2".into());
    assert!(s.rollback().is_ok());
}

#[test]
fn store_evicts_old_entries() {
    let mut s = PolicyStore::new(3);
    for i in 0..5 {
        s.commit(format!("autolsm_{}", i), format!("cil_{}", i));
    }
    let v = s.versions();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0], "autolsm_2");
}

// ── Resolver tests ──────────────────────────────────────────────────────────

use autolsm::resolver::extract_type;

#[test]
fn extract_type_standard() {
    assert_eq!(extract_type("system_u:system_r:httpd_t:s0"), "httpd_t");
}

#[test]
fn extract_type_mls() {
    assert_eq!(extract_type("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"), "unconfined_t");
}

#[test]
fn extract_type_container() {
    assert_eq!(extract_type("system_u:system_r:container_t:s0:c123,c456"), "container_t");
}

#[test]
fn extract_type_invalid() {
    assert_eq!(extract_type("incomplete"), "unknown_t");
    assert_eq!(extract_type(""), "unknown_t");
}

// ── Audit parsing tests ─────────────────────────────────────────────────────

use autolsm::audit::AuditConsumer;

#[test]
fn parse_standard_avc_denied() {
    let line = r#"type=AVC msg=audit(1243332701.744:101): avc:  denied  { getattr } for  pid=2714 comm="ls" path="/usr/lib/locale" dev=dm-0 ino=353593 scontext=system_u:object_r:unlabeled_t:s0 tcontext=system_u:object_r:locale_t:s0 tclass=file"#;
    let d = AuditConsumer::parse_avc_line(line).unwrap();
    assert_eq!(d.scontext_type, "unlabeled_t");
    assert_eq!(d.tcontext_type, "locale_t");
    assert_eq!(d.tclass, "file");
    assert_eq!(d.perms, vec!["getattr"]);
    assert_eq!(d.pid, 2714);
}

#[test]
fn parse_avc_multiple_perms() {
    let line = r#"type=AVC msg=audit(1.0:1): avc:  denied  { read write open } for  pid=100 comm="app" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file"#;
    let d = AuditConsumer::parse_avc_line(line).unwrap();
    assert_eq!(d.perms.len(), 3);
    assert!(d.perms.contains(&"read".to_string()));
}

#[test]
fn non_avc_line_returns_none() {
    assert!(AuditConsumer::parse_avc_line("type=SYSCALL msg=audit(1.0:1): ...").is_none());
    assert!(AuditConsumer::parse_avc_line("random text").is_none());
}

#[test]
fn avc_granted_skipped() {
    let line = r#"type=AVC msg=audit(1.0:1): avc:  granted  { read } for  pid=1 comm="init" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file"#;
    assert!(AuditConsumer::parse_avc_line(line).is_none());
}

// ── PreFilter tests ─────────────────────────────────────────────────────────

use autolsm::audit::{DenialPreFilter, FilterDecision};
use autolsm_common::AvcDenial;

fn mk_denial(raw: &str) -> AvcDenial {
    AvcDenial {
        timestamp_sec: 1.0, serial: 1,
        scontext: "system_u:system_r:httpd_t:s0".into(), scontext_type: "httpd_t".into(),
        tcontext: "system_u:object_r:etc_t:s0".into(), tcontext_type: "etc_t".into(),
        tclass: "file".into(), perms: vec!["read".into()], pid: 100,
        comm: "test".into(), raw: raw.into(),
    }
}

#[test]
fn prefilter_blocks_shadow() {
    let mut f = DenialPreFilter::new();
    match f.filter(&mk_denial("denied { read } path=/etc/shadow")) {
        FilterDecision::Alert(_, r) => assert!(r.contains("credential")),
        _ => panic!("expected Alert"),
    }
}

#[test]
fn prefilter_blocks_ssh_key() {
    let mut f = DenialPreFilter::new();
    match f.filter(&mk_denial("denied { read } path=/root/.ssh/authorized_keys")) {
        FilterDecision::Alert(_, r) => assert!(r.contains("ssh_key")),
        _ => panic!("expected Alert"),
    }
}

#[test]
fn prefilter_drops_cache() {
    let mut f = DenialPreFilter::new();
    match f.filter(&mk_denial("denied { write } path=/home/user/.cache/app/tmp")) {
        FilterDecision::Drop => {}
        _ => panic!("expected Drop for .cache"),
    }
}

#[test]
fn prefilter_passes_normal() {
    let mut f = DenialPreFilter::new();
    match f.filter(&mk_denial("denied { read } scontext=httpd_t:s0 tcontext=var_t:s0 tclass=file")) {
        FilterDecision::Pass(_) => {}
        _ => panic!("expected Pass"),
    }
}

#[test]
fn prefilter_rate_limits() {
    let mut f = DenialPreFilter::new();
    for _ in 0..10 {
        assert!(matches!(f.filter(&mk_denial("denied { read } scontext=httpd_t:s0 tcontext=var_t:s0 tclass=file")), FilterDecision::Pass(_)));
    }
    assert!(matches!(f.filter(&mk_denial("denied { read } scontext=httpd_t:s0 tcontext=var_t:s0 tclass=file")), FilterDecision::Drop));
}
