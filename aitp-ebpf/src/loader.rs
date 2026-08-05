//! eBPF program loader — user-space interface.
//!
//! Loads the compiled XDP BPF program and manages the permit_map
//! from user-space. This module provides the bridge between the
//! AITP transport engine and the kernel-level enforcement layer.
//!
//! # Requirements
//!
//! - Linux kernel >= 5.15
//! - Root / CAP_SYS_ADMIN / CAP_NET_ADMIN capabilities
//! - Compiled BPF object files (`.bpf.o`)
//!
//! # macOS Note
//!
//! eBPF is not available on macOS. This module is a stub when
//! compiled on non-Linux targets.

/// Stub: eBPF loader is only functional on Linux.
///
/// On macOS (and other non-Linux platforms), this module compiles
/// but all operations are no-ops that log warnings.
#[cfg(not(target_os = "linux"))]
pub mod loader {
    /// Load the AITP XDP filter. (No-op on non-Linux)
    pub fn load_xdp_filter() -> Result<(), String> {
        tracing::warn!("eBPF XDP filter not available on this platform");
        Ok(())
    }

    /// Insert a permit entry into the BPF map. (No-op on non-Linux)
    pub fn insert_permit(_session_id: u64, _trust_score: u8) -> Result<(), String> {
        Ok(())
    }

    /// Remove a permit entry (revocation). (No-op on non-Linux)
    pub fn remove_permit(_session_id: u64) -> Result<(), String> {
        Ok(())
    }
}

// Future: #[cfg(target_os = "linux")] implementation using libbpf-rs
