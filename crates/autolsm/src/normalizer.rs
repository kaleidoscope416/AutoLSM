use autolsm_common::{
    HookId, NormalizedAccess, NormalizedBatch, NormalizerInput, ObservationEvent,
    af, proto,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};

use crate::resolver::Resolver;

const BATCH_MAX: usize = 64;
const SEEN_MAX: usize = 10000;

pub async fn run(
    mut rx: mpsc::Receiver<NormalizerInput>,
    tx: mpsc::Sender<NormalizedBatch>,
    resolver: Arc<Mutex<Resolver>>,
    window_s: u64,
) -> anyhow::Result<()> {
    let mut tick = interval(Duration::from_secs(window_s));
    let mut batch: HashMap<(String, String, String, String), NormalizedAccess> = HashMap::new();
    let mut has_denials = false;
    let mut seen: lru::LruCache<u64, u8> = lru::LruCache::new(
        std::num::NonZeroUsize::new(SEEN_MAX).unwrap(),
    );

    tracing::info!("normalizer started (window={}s, batch_max={})", window_s, BATCH_MAX);

    loop {
        tokio::select! {
            Some(input) = rx.recv() => {
                match input {
                    NormalizerInput::Observation(event) => {
                        process_observation(
                            &event,
                            &mut batch,
                            &mut seen,
                            &resolver,
                        ).await;
                    }
                    NormalizerInput::Denial(denial) => {
                        has_denials = true;
                        for perm in &denial.perms {
                            let key = (
                                denial.scontext_type.clone(),
                                denial.tcontext_type.clone(),
                                denial.tclass.clone(),
                                perm.clone(),
                            );
                            let entry = batch.entry(key.clone()).or_insert_with(|| NormalizedAccess {
                                scontext: denial.scontext.clone(),
                                scontext_type: denial.scontext_type.clone(),
                                tcontext: denial.tcontext.clone(),
                                tcontext_type: denial.tcontext_type.clone(),
                                tclass: denial.tclass.clone(),
                                perm: perm.clone(),
                                hook_id: 0,
                                count: 0,
                                first_seen_ns: 0,
                                last_seen_ns: 0,
                                is_new: true,
                            });
                            entry.count += 1;
                        }
                    }
                }
                if batch.len() >= BATCH_MAX {
                    emit_batch(&mut batch, &mut seen, &tx, &mut has_denials).await;
                }
            }
            _ = tick.tick() => {
                if !batch.is_empty() {
                    emit_batch(&mut batch, &mut seen, &tx, &mut has_denials).await;
                }
            }
            else => {
                tracing::info!("normalizer channel closed");
                break;
            }
        }
    }
    Ok(())
}

async fn process_observation(
    event: &ObservationEvent,
    batch: &mut HashMap<(String, String, String, String), NormalizedAccess>,
    seen: &mut lru::LruCache<u64, u8>,
    resolver: &Arc<Mutex<Resolver>>,
) {
    let tgid = (event.pid_tgid >> 32) as u32;
    let (scontext, scontext_type) = resolver.lock().await.resolve(tgid).await;

    let hook = HookId::from_u32(event.hook_id).unwrap_or(HookId::FileOpen);
    let tclass = hook_to_class(hook, event);

    // Decompose: file_permission may produce multiple perms
    let perms_to_emit: Vec<&'static str> = match hook {
        HookId::FilePermission => {
            let mask = unsafe { event.object.file.flags };
            let mut perms = Vec::new();
            if mask & 0x01 != 0 { perms.push("read"); }
            if mask & 0x02 != 0 { perms.push("write"); }
            if mask & 0x04 != 0 { perms.push("append"); }
            if mask & 0x08 != 0 { perms.push("execute"); }
            if perms.is_empty() { perms.push("getattr"); }
            perms
        }
        _ => {
            match hook_to_perm(hook, event) {
                Some(p) => vec![p],
                None => return,
            }
        }
    };

    // Resolve tcontext
    let (tcontext, tcontext_type) = resolve_tcontext(event, hook, &tclass);

    // Drop unresolved/generic/unknown events — sentinel types that indicate resolution failure
    if tcontext_type == "unresolved_t" || tcontext_type == "unknown_t" || tcontext_type == "generic_t" {
        return;
    }

    for perm in &perms_to_emit {
        let key = (
            scontext_type.clone(),
            tcontext_type.clone(),
            tclass.to_string(),
            perm.to_string(),
        );

        let hash = hash_key(&key.0, &key.1, &key.2, perm);
        let is_new = !seen.contains(&hash);
        if is_new {
            seen.put(hash, 1);
        }

        let entry = batch.entry(key.clone()).or_insert_with(|| NormalizedAccess {
            scontext: scontext.clone(),
            scontext_type: key.0.clone(),
            tcontext: tcontext.clone(),
            tcontext_type: key.1.clone(),
            tclass: key.2.clone(),
            perm: key.3.clone(),
            hook_id: event.hook_id,
            count: 0,
            first_seen_ns: event.timestamp_ns,
            last_seen_ns: event.timestamp_ns,
            is_new,
        });
        entry.count += 1;
        entry.last_seen_ns = event.timestamp_ns;
    }
}

fn hook_to_class(hook: HookId, event: &ObservationEvent) -> &'static str {
    match hook {
        HookId::FileOpen | HookId::FilePermission | HookId::FileIoctl
        | HookId::FileLock | HookId::FileReceive => "file",
        HookId::SocketBind | HookId::SocketConnect => {
            let family = unsafe { event.object.sock.family };
            let proto_num = unsafe { event.object.sock.proto };
            match (family, proto_num) {
                (af::AF_INET, proto::IPPROTO_TCP) | (af::AF_INET6, proto::IPPROTO_TCP) =>
                    "tcp_socket",
                (af::AF_INET, proto::IPPROTO_UDP) | (af::AF_INET6, proto::IPPROTO_UDP) =>
                    "udp_socket",
                (af::AF_UNIX, _) => "unix_stream_socket",
                _ => "socket",
            }
        }
        HookId::SocketListen | HookId::SocketAccept => "tcp_socket",
        HookId::SocketSendmsg | HookId::SocketRecvmsg => "socket",
        HookId::UnixStreamConnect => "unix_stream_socket",
        HookId::UnixMaySend => "unix_dgram_socket",
        HookId::TaskSetpgid | HookId::TaskGetpgid | HookId::TaskSetsched
        | HookId::TaskSetrlimit => "process",
    }
}

fn hook_to_perm(hook: HookId, _event: &ObservationEvent) -> Option<&'static str> {
    match hook {
        HookId::FileOpen => Some("open"),
        HookId::FilePermission => Some("read"), // unused: perms are decomposed above
        HookId::FileIoctl => Some("ioctl"),
        HookId::FileLock => Some("lock"),
        HookId::FileReceive => Some("open"),
        HookId::SocketBind => Some("name_bind"),
        HookId::SocketConnect => Some("name_connect"),
        HookId::SocketListen => Some("listen"),
        HookId::SocketAccept => Some("accept"),
        HookId::SocketSendmsg => Some("write"),
        HookId::SocketRecvmsg => Some("read"),
        HookId::UnixStreamConnect => Some("connectto"),
        HookId::UnixMaySend => Some("sendto"),
        HookId::TaskSetpgid => Some("setpgid"),
        HookId::TaskGetpgid => Some("getpgid"),
        HookId::TaskSetsched => Some("setsched"),
        HookId::TaskSetrlimit => Some("setrlimit"),
    }
}

fn resolve_tcontext(
    event: &ObservationEvent,
    hook: HookId,
    tclass: &str,
) -> (String, String) {
    match hook {
        HookId::FileOpen | HookId::FilePermission | HookId::FileIoctl
        | HookId::FileLock | HookId::FileReceive => {
            let path = unsafe { event.object.file.path };
            let path_str = String::from_utf8_lossy(&path)
                .trim_end_matches('\0')
                .to_string();
            if !path_str.is_empty() {
                match std::process::Command::new("/usr/sbin/matchpathcon")
                    .arg(&path_str)
                    .output()
                {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if let Some(ctx) = stdout.split('\t').nth(1) {
                            let ctx = ctx.trim().to_string();
                            let short = crate::resolver::extract_type(&ctx);
                            return (ctx, short);
                        }
                    }
                    Err(_) => {}
                }
            }
            ("unconfined_u:unconfined_r:unconfined_t:s0".into(), "unconfined_t".into())
        }
        _ if tclass.contains("socket") => {
            let family = unsafe { event.object.sock.family };
            let port = u16::from_be(unsafe { event.object.sock.port });
            (format!("socket_{}:{}", family, port), format!("socket_{}_t", family))
        }
        _ => ("unconfined_u:unconfined_r:unconfined_t:s0".into(), "unconfined_t".into())
    }
}

fn hash_key(a: &str, b: &str, c: &str, d: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = seahash::SeaHasher::new();
    a.hash(&mut hasher);
    b.hash(&mut hasher);
    c.hash(&mut hasher);
    d.hash(&mut hasher);
    hasher.finish()
}
async fn emit_batch(
    batch: &mut HashMap<(String, String, String, String), NormalizedAccess>,
    _seen: &mut lru::LruCache<u64, u8>,
    tx: &mpsc::Sender<NormalizedBatch>,
    has_denials: &mut bool,
) {
    let events: Vec<NormalizedAccess> = batch.drain().map(|(_, v)| v).collect();
    let new_count = events.iter().filter(|e| e.is_new).count();
    tracing::info!("emitting batch: {} events ({} new){}",
        events.len(), new_count,
        if *has_denials { " [DRIFT]" } else { "" });
    if tx.send(NormalizedBatch { events, has_denials: *has_denials }).await.is_err() {
        tracing::warn!("LLM channel closed");
    }
    *has_denials = false;
}
