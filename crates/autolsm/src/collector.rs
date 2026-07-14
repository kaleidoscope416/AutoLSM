use anyhow::Context;
use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, EbpfLoader};
use autolsm_common::{NormalizerInput, ObservationEvent};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Mutex};

use crate::resolver::Resolver;

/// Run the eBPF collector: load programs, attach to LSM hooks, poll RingBuf.
pub async fn run(
    target_cgroups: Vec<u64>,
    ringbuf_size: u32,
    tx: mpsc::Sender<NormalizerInput>,
    _resolver: Arc<Mutex<Resolver>>,
) -> anyhow::Result<()> {
    tracing::info!("Loading eBPF programs (ringbuf={} bytes)", ringbuf_size);

    let elf_path = std::env::var("AUTOLSM_EBPF_PATH")
        .unwrap_or_else(|_| format!("{}/autolsm_ebpf", env!("OUT_DIR")));

    let mut bpf = if std::path::Path::new(&elf_path).exists() {
        EbpfLoader::new()
            .map_max_entries("TARGET_CGROUPS", 256)
            .load_file(&elf_path)?
    } else {
        tracing::warn!("eBPF ELF not found at {} — collector running in no-op mode", elf_path);
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            tracing::debug!("collector: no-op tick (no eBPF ELF loaded)");
        }
    };

    let btf = Btf::from_sys_fs().context("failed to load BTF from /sys/kernel/btf/vmlinux")?;
    let hook_names = &[
        "file_open_obs",
        "file_permission_obs",
        "socket_bind_obs",
        "socket_connect_obs",
        "task_setrlimit_obs",
    ];

    for name in hook_names {
        match bpf.program_mut(*name) {
            Some(prog) => {
                let lsm: &mut Lsm = prog.try_into().context("program is not an Lsm type")?;
                lsm.load(name, &btf)?;
                lsm.attach()?;
                tracing::info!("attached LSM hook: {}", name);
            }
            None => {
                tracing::warn!("LSM program not found in ELF: {}", name);
            }
        }
    }

    // Populate TARGET_CGROUPS map
    if !target_cgroups.is_empty() {
        let mut cgroup_map: AyaHashMap<&mut MapData, u64, u8> =
            AyaHashMap::try_from(bpf.map_mut("TARGET_CGROUPS").unwrap())?;
        for cgid in &target_cgroups {
            cgroup_map.insert(*cgid, 1, 0)?;
            tracing::info!("added target cgroup: {}", cgid);
        }
    }

    // Initialize RingBuf polling
    let ringbuf: RingBuf<&mut MapData> =
        RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::with_interest(ringbuf, tokio::io::Interest::READABLE)?;

    tracing::info!(
        "collector running — {} target cgroups, {} hooks",
        target_cgroups.len(),
        hook_names.len(),
    );

    let _dropped_count: u64 = 0;
    let mut event_buf = [0u8; std::mem::size_of::<ObservationEvent>()];

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let rb = guard.get_inner_mut();

        while let Some(item) = rb.next() {
            let data = item.as_ref();
            if data.len() >= std::mem::size_of::<ObservationEvent>() {
                event_buf[..data.len()].copy_from_slice(data);
                let event: ObservationEvent =
                    unsafe { std::ptr::read(event_buf.as_ptr() as *const ObservationEvent) };


                // Normalizer handles authoritative PID→context resolution.

                if tx.send(NormalizerInput::Observation(event)).await.is_err() {
                    tracing::warn!("normalizer channel closed — collector exiting");
                    return Ok(());
                }
            }
        }


        guard.clear_ready();
    }
}
