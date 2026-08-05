fn main() {
    // Only attempt to compile the eBPF program on Linux.
    // On macOS, Windows, and inside Docker (without bpf-linker),
    // the server uses software enforcement automatically.
    #[cfg(target_os = "linux")]
    {
        // Check if bpf-linker is installed before attempting compilation
        if is_bpf_linker_available() {
            compile_ebpf_program();
        } else {
            println!("cargo:warning=bpf-linker not found — skipping eBPF compilation.");
            println!("cargo:warning=Software enforcement will be used (install bpf-linker for kernel enforcement).");
            // Create a dummy empty object file so include_bytes! doesn't fail
            create_dummy_bpf_object();
        }
    }

    // On non-Linux: always create the dummy object file
    #[cfg(not(target_os = "linux"))]
    {
        println!(
            "cargo:warning=Non-Linux build — eBPF XDP not available. Software enforcement active."
        );
        create_dummy_bpf_object();
    }

    // Re-run if source changes
    println!("cargo:rerun-if-changed=../kelan-ebpf-program/src/main.rs");
    println!("cargo:rerun-if-changed=../kelan-ebpf-program/Cargo.toml");
}

#[cfg(target_os = "linux")]
fn is_bpf_linker_available() -> bool {
    std::process::Command::new("bpf-linker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn compile_ebpf_program() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--package",
            "kelan-ebpf-program",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .current_dir(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../kelan-ebpf-program"
        ))
        .env("CARGO_CFG_BPF", "1")
        .status()
        .expect("Failed to run cargo for eBPF program");

    if !status.success() {
        // Don't panic — fall back to software enforcement
        println!("cargo:warning=eBPF program compilation failed — using software enforcement.");
        create_dummy_bpf_object();
        return;
    }

    let bpf_obj_candidates = [
        format!("{}/../../../bpfel-unknown-none/release/kelan_xdp", out_dir),
        "../../target/bpfel-unknown-none/release/kelan_xdp".to_string(),
    ];

    let dest = format!("{}/kelan_xdp.o", out_dir);

    for candidate in &bpf_obj_candidates {
        if std::path::Path::new(candidate).exists() {
            std::fs::copy(candidate, &dest).expect("Failed to copy compiled eBPF object");
            println!("cargo:warning=eBPF XDP program compiled successfully.");
            return;
        }
    }

    println!("cargo:warning=eBPF object not found at expected path — using software enforcement.");
    create_dummy_bpf_object();
}

/// Create an empty placeholder so include_bytes! compiles on non-Linux.
fn create_dummy_bpf_object() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = format!("{}/kelan_xdp.o", out_dir);
    // Write minimal valid ELF header so the file isn't empty
    // The software enforcement path never reads this file
    std::fs::write(&dest, b"").expect("Failed to create dummy BPF object");
}
