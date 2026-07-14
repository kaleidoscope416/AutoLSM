use autolsm_common::{
    HookId, NormalizedAccess, NormalizerInput, ObservationEvent,
    af, proto,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};

use crate::resolver::Resolver;

/// Maximum unique entries before forced batch emission.
const BATCH_MAX: usize = 64;
/// Maximum LRU size for SeenSet.
const SEEN_MAX: usize = 10000;

/// Run the normalizer: deduplicate events, batch by time window, send to LLM.
pub async fn run(
    mut rx: mpsc::Receiver<NormalizerInput>,
    tx: mpsc::Sender<Vec<NormalizedAccess>>,
    resolver: Arc<Mutex<Resolver>>,
    window_s: u64,
) -> anyhow::Result<()> {
    let mut tick = interval(Duration::from_secs(window_s));
    let mut batch: HashMap<(String, String, String, String), NormalizedAccess> = HashMap::new();
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
                        // Denials already have scontext/tcontext/tclass/perms — insert directly.
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
                                hook_id: 0, // not applicable for denials
                                count: 0,
                                first_seen_ns: 0,
                                last_seen_ns: 0,
                                is_new: true,
                            });
                            entry.count += 1;
                        }
                    }
                }

                // Force emit if batch size exceeds threshold
                if batch.len() >= BATCH_MAX {
                    emit_batch(&mut batch, &mut seen, &tx).await;
                }
            }
            _ = tick.tick() => {
                if !batch.is_empty() {
                    emit_batch(&mut batch, &mut seen, &tx).await;
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
    let (scontext, scontext_type) = resolver.lock().await.resolve(tgid);

    // Map hook_id → (tclass, perm) with family disambiguation for sockets
    let hook = HookId::from_u32(event.hook_id).unwrap_or(HookId::FileOpen);

    let (tclass, perm) = match hook_to_class_perm(hook, event) {
        Some(v) => v,
        None => return, // unknown hook → skip
    };

    // Resolve tcontext from object info (best-effort via matchpathcon or socket info)
    let (tcontext, tcontext_type) = resolve_tcontext(event, hook, &tclass);

    // Build unique key
    let key = (
        scontext_type.clone(),
        tcontext_type.clone(),
        tclass.to_string(),
        perm.to_string(),
    );

    // Delta detection
    let hash = seahash::hash(
        &[
            key.0.as_bytes(),
            key.1.as_bytes(),
            key.2.as_bytes(),
            key.3.as_bytes(),
        ].concat(),
    );
    let is_new = !seen.contains(&hash);
    if is_new {
        seen.put(hash, 1);
    }

    let entry = batch.entry(key.clone()).or_insert_with(|| NormalizedAccess {
        scontext,
        scontext_type: key.0,
        tcontext,
        tcontext_type: key.1,
        tclass: key.2,
        perm: key.3,
        hook_id: event.hook_id,
        count: 0,
        first_seen_ns: event.timestamp_ns,
        last_seen_ns: event.timestamp_ns,
        is_new,
    });
    entry.count += 1;
    entry.last_seen_ns = event.timestamp_ns;
}

/// Map hook_id + socket family/proto → (tclass, perm).
fn hook_to_class_perm(hook: HookId, event: &ObservationEvent) -> Option<(&'static str, &'static str)> {
    match hook {
        HookId::FileOpen => Some(("file", "open")),
        HookId::FilePermission => {
            // permission mask is in event.object.file.flags
            let mask = unsafe { event.object.file.flags };
            if mask & 0x01 != 0 { Some(("file", "read")) }
            else if mask & 0x02 != 0 { Some(("file", "write")) }
            else if mask & 0x04 != 0 { Some(("file", "append")) }
            else if mask & 0x08 != 0 { Some(("file", "execute")) }
            else { Some(("file", "getattr")) }
        }
        HookId::FileIoctl => Some(("file", "ioctl")),
        HookId::FileLock => Some(("file", "lock")),
        HookId::FileReceive => Some(("file", "open")),
        HookId::SocketBind => {
            let family = unsafe { event.object.sock.family };
            let proto_num = unsafe { event.object.sock.proto };
            match (family, proto_num) {
                (af::AF_INET, proto::IPPROTO_TCP) | (af::AF_INET6, proto::IPPROTO_TCP) =>
                    Some(("tcp_socket", "name_bind")),
                (af::AF_INET, proto::IPPROTO_UDP) | (af::AF_INET6, proto::IPPROTO_UDP) =>
                    Some(("udp_socket", "name_bind")),
                (af::AF_UNIX, _) => Some(("unix_stream_socket", "name_bind")),
                _ => Some(("socket", "name_bind")),
            }
        }
        HookId::SocketConnect => {
            let family = unsafe { event.object.sock.family };
            let proto_num = unsafe { event.object.sock.proto };
            match (family, proto_num) {
                (af::AF_INET, proto::IPPROTO_TCP) | (af::AF_INET6, proto::IPPROTO_TCP) =>
                    Some(("tcp_socket", "name_connect")),
                (af::AF_INET, proto::IPPROTO_UDP) | (af::AF_INET6, proto::IPPROTO_UDP) =>
                    Some(("udp_socket", "name_connect")),
                (af::AF_UNIX, _) => Some(("unix_stream_socket", "name_connect")),
                _ => Some(("socket", "name_connect")),
            }
        }
        HookId::SocketListen => Some(("tcp_socket", "listen")),
        HookId::SocketAccept => Some(("tcp_socket", "accept")),
        HookId::SocketSendmsg => Some(("socket", "write")),
        HookId::SocketRecvmsg => Some(("socket", "read")),
        HookId::UnixStreamConnect => Some(("unix_stream_socket", "connectto")),
        HookId::UnixMaySend => Some(("unix_dgram_socket", "sendto")),
        HookId::TaskSetpgid => Some(("process", "setpgid")),
        HookId::TaskGetpgid => Some(("process", "getpgid")),
        HookId::TaskSetsched => Some(("process", "setsched")),
        HookId::TaskSetrlimit => Some(("process", "setrlimit")),
    }
}

/// Resolve target context from observation event.
fn resolve_tcontext(
    event: &ObservationEvent,
    hook: HookId,
    tclass: &str,
) -> (String, String) {
    match hook {
        HookId::FileOpen | HookId::FilePermission | HookId::FileIoctl
        | HookId::FileLock | HookId::FileReceive => {
            // Try matchpathcon for the file path prefix
            let path = unsafe { event.object.file.path };
            let path_str = String::from_utf8_lossy(&path)
                .trim_end_matches('\0')
                .to_string();
            if !path_str.is_empty() {
                match std::process::Command::new("matchpathcon")
                    .arg(&path_str)
                    .output()
                {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        // matchpathcon output: "path\tsystem_u:object_r:type_t:s0"
                        if let Some(ctx) = stdout.split('\t').nth(1) {
                            let ctx = ctx.trim().to_string();
                            let short = crate::resolver::extract_type(&ctx);
                            return (ctx, short);
                        }
                    }
                    Err(_) => {}
                }
            }
            // Fallback: unresolved
            ("unresolved".into(), "unresolved_t".into())
        }
        _ if tclass.contains("socket") => {
            let family = unsafe { event.object.sock.family };
            let port = u16::from_be(unsafe { event.object.sock.port });
            let mut tcontext = format!("socket_{}", family);
            if port != 0 {
                tcontext.push_str(&format!(":{}", port));
            }
            (tcontext.clone(), tcontext)
        }
        _ => {
            ("generic".into(), "generic_t".into())
        }
    }
}

/// Emit the current batch to the LLM channel and clear it.
async fn emit_batch(
    batch: &mut HashMap<(String, String, String, String), NormalizedAccess>,
    _seen: &mut lru::LruCache<u64, u8>,
    tx: &mpsc::Sender<Vec<NormalizedAccess>>,
) {
    let events: Vec<NormalizedAccess> = batch.drain().map(|(_, v)| v).collect();
    let new_count = events.iter().filter(|e| e.is_new).count();
    tracing::info!(
        "emitting batch: {} events ({} new)",
        events.len(),
        new_count,
    );
    if tx.send(events).await.is_err() {
        tracing::warn!("LLM channel closed");
    }
}
