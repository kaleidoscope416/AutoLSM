use std::process::Command;

fn main() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--manifest-path",
            "crates/autolsm-ebpf/Cargo.toml",
        ])
        .status()?;

    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(1);
    }

    // Copy the built ELF to the userspace crate's expected location
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| "target/bpfel-unknown-none/release".into());
    let src = "target/bpfel-unknown-none/release/autolsm_ebpf";
    let dst = format!("{}/autolsm_ebpf", out_dir);
    println!("Copying eBPF ELF: {} -> {}", src, dst);
    std::fs::copy(&src, &dst)?;

    println!("cargo:rerun-if-changed=crates/autolsm-ebpf/");
    Ok(())
}
