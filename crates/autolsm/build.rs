use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let out_dir = std::env::var("OUT_DIR").context("OUT_DIR missing")?;
    let xtask_out = std::env::var("XTASK_OUT_DIR").unwrap_or_else(|_| out_dir.clone());

    // If xtask ran, copy its output; otherwise just note the expected path.
    let elf_src = format!("{}/autolsm_ebpf", xtask_out);
    let elf_dst = format!("{}/autolsm_ebpf", out_dir);

    if std::path::Path::new(&elf_src).exists() {
        std::fs::copy(&elf_src, &elf_dst)
            .context("failed to copy eBPF ELF from xtask output")?;
    }

    // The eBPF ELF will be embedded via include_bytes_aligned! at compile time.
    // The path is resolved relative to OUT_DIR.
    println!("cargo:rerun-if-changed=../autolsm-ebpf/");
    Ok(())
}
