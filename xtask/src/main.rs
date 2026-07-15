use std::process::Command;

fn main() -> anyhow::Result<()> {
    let ebpf_dir = "crates/autolsm-ebpf";

    // Step 1: Generate vmlinux.h from BTF (if not already present)
    let vmlinux_path = format!("{}/vmlinux.h", ebpf_dir);
    if !std::path::Path::new(&vmlinux_path).exists() {
        println!("Generating vmlinux.h from /sys/kernel/btf/vmlinux...");
        let output = Command::new("bpftool")
            .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
            .output()?;
        if output.status.success() {
            std::fs::write(&vmlinux_path, &output.stdout)?;
            println!("  -> {} ({:.1} KB)",
                vmlinux_path,
                output.stdout.len() as f64 / 1024.0);
        } else {
            eprintln!("bpftool failed: {}", String::from_utf8_lossy(&output.stderr));
            return Err(anyhow::anyhow!("bpftool BTF dump failed"));
        }
    }

    // Step 2: Compile autolsm.bpf.c with clang
    println!("Compiling autolsm.bpf.c -> autolsm.bpf.o...");
    let status = Command::new("clang")
        .args([
            "-O2", "-g",
            "-target", "bpf",
            "-D__TARGET_ARCH_x86",
            "-c", &format!("{}/autolsm.bpf.c", ebpf_dir),
            "-o", &format!("{}/autolsm.bpf.o", ebpf_dir),
        ])
        .status()?;

    if !status.success() {
        eprintln!("clang build failed");
        std::process::exit(1);
    }

    // Step 3: Copy to OUT_DIR for the userspace crate
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| "target".into());
    let src = format!("{}/autolsm.bpf.o", ebpf_dir);
    let dst = format!("{}/autolsm.bpf.o", out_dir);
    std::fs::copy(&src, &dst)?;
    println!("Copied: {} -> {}", src, dst);

    println!("cargo:rerun-if-changed={}/", ebpf_dir);
    Ok(())
}
