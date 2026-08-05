//! Linux-specific eBPF/XDP loader implementation.
//!
//! This module handles loading and attaching eBPF programs
//! to network interfaces via XDP hooks on Linux.
//! On non-Linux platforms, this module is not compiled.

use std::path::Path;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum EbpfLoaderError {
    #[error("Failed to load eBPF object file: {0}")]
    LoadError(String),

    #[error("Failed to attach XDP program to interface {iface}: {msg}")]
    AttachError { iface: String, msg: String },

    #[error("BPF map not found: {0}")]
    MapNotFound(String),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("eBPF not supported on this kernel: {0}")]
    KernelUnsupported(String),
}

/// Represents a loaded and attached eBPF XDP program
pub struct EbpfLoader {
    interface: String,
    attached: bool,
    // When bpf-linker is available, this holds
    // the actual program handle / BPF context
    #[cfg(feature = "ebpf-native")]
    _bpf: std::sync::Mutex<Option<aya::Bpf>>,
}

impl EbpfLoader {
    /// Load eBPF object and attach to network interface
    pub fn load_and_attach(
        interface: &str,
        bpf_object_path: &Path,
    ) -> Result<Self, EbpfLoaderError> {
        info!("Loading eBPF XDP program onto interface: {}", interface);

        // Verify interface exists
        if !interface_exists(interface) {
            return Err(EbpfLoaderError::InterfaceNotFound(interface.to_string()));
        }

        // Verify eBPF object file exists
        if !bpf_object_path.exists() {
            warn!(
                "eBPF object not found at {:?}, \
                 using software enforcement",
                bpf_object_path
            );
            return Ok(Self {
                interface: interface.to_string(),
                attached: false,
                #[cfg(feature = "ebpf-native")]
                _bpf: std::sync::Mutex::new(None),
            });
        }

        #[cfg(feature = "ebpf-native")]
        {
            Self::load_native(interface, bpf_object_path)
        }

        #[cfg(not(feature = "ebpf-native"))]
        {
            // bpf-linker not available — software fallback
            warn!(
                "bpf-linker not available. \
                 Software enforcement active. \
                 Install bpf-linker for kernel enforcement."
            );

            Ok(Self {
                interface: interface.to_string(),
                attached: false,
            })
        }
    }

    #[cfg(feature = "ebpf-native")]
    fn load_native(interface: &str, bpf_object_path: &Path) -> Result<Self, EbpfLoaderError> {
        use aya::{
            programs::{Xdp, XdpFlags},
            Bpf,
        };

        let mut bpf = Bpf::load_file(bpf_object_path)
            .map_err(|e| EbpfLoaderError::LoadError(e.to_string()))?;

        let program: &mut Xdp = bpf
            .program_mut("kelan_xdp")
            .ok_or_else(|| {
                EbpfLoaderError::LoadError("kelan_xdp program not found in object".into())
            })?
            .try_into()
            .map_err(|e: _| EbpfLoaderError::LoadError(format!("Not an XDP program: {}", e)))?;

        program
            .load()
            .map_err(|e| EbpfLoaderError::LoadError(e.to_string()))?;

        program
            .attach(interface, XdpFlags::default())
            .map_err(|e| EbpfLoaderError::AttachError {
                iface: interface.to_string(),
                msg: e.to_string(),
            })?;

        info!("✓ eBPF XDP program attached to interface {}", interface);

        Ok(Self {
            interface: interface.to_string(),
            attached: true,
            _bpf: std::sync::Mutex::new(Some(bpf)),
        })
    }

    /// Returns true if XDP is active in kernel space
    pub fn is_kernel_enforcing(&self) -> bool {
        self.attached
    }

    /// Get the interface this loader is attached to
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Update PERMIT_MAP: allow session through XDP
    pub fn permit_session(
        &self,
        _session_id: u64,
        _src_ip: u32,
        _dst_ip: u32,
        _expiry_ts: u64,
    ) -> Result<(), EbpfLoaderError> {
        if !self.attached {
            // Software mode — enforcement handled in userspace
            return Ok(());
        }

        #[cfg(feature = "ebpf-native")]
        {
            use aya::maps::HashMap;
            use crate::SessionPermit;

            if let Some(ref mut bpf) = *self._bpf.lock().unwrap() {
                let mut permit_map = HashMap::try_from(
                    bpf.map_mut("PERMIT_MAP")
                        .map_err(|e| EbpfLoaderError::MapNotFound(e.to_string()))?
                ).map_err(|e| EbpfLoaderError::LoadError(e.to_string()))?;

                let permit = SessionPermit {
                    source_entity_prefix: [0; 8],
                    dest_entity_prefix: [0; 8],
                    intent: 0,
                    trust_score: 100,
                    verdict: 1, // 1 = permit
                    expires_at: _expiry_ts,
                    _pad: [0; 4],
                };

                permit_map.insert(_session_id, permit, 0)
                    .map_err(|e| EbpfLoaderError::LoadError(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Update DENY_MAP: drop all packets from src_ip
    pub fn deny_ip(&self, _src_ip: u32, _drop_until_ts: u64) -> Result<(), EbpfLoaderError> {
        if !self.attached {
            return Ok(());
        }

        #[cfg(feature = "ebpf-native")]
        {
            use aya::maps::HashMap;

            if let Some(ref mut bpf) = *self._bpf.lock().unwrap() {
                let mut blacklist_map = HashMap::try_from(
                    bpf.map_mut("ip_blacklist_map")
                        .map_err(|e| EbpfLoaderError::MapNotFound(e.to_string()))?
                ).map_err(|e| EbpfLoaderError::LoadError(e.to_string()))?;

                blacklist_map.insert(_src_ip, 1u8, 0)
                    .map_err(|e| EbpfLoaderError::LoadError(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Remove expired sessions from PERMIT_MAP
    pub fn cleanup_expired(&self, _current_ts: u64) -> Result<u32, EbpfLoaderError> {
        if !self.attached {
            return Ok(0);
        }

        #[cfg(feature = "ebpf-native")]
        {
            use aya::maps::HashMap;
            use crate::SessionPermit;

            if let Some(ref mut bpf) = *self._bpf.lock().unwrap() {
                let mut permit_map = HashMap::try_from(
                    bpf.map_mut("PERMIT_MAP")
                        .map_err(|e| EbpfLoaderError::MapNotFound(e.to_string()))?
                ).map_err(|e| EbpfLoaderError::LoadError(e.to_string()))?;

                let mut expired_keys = Vec::new();
                for item in permit_map.keys() {
                    if let Ok(key) = item {
                        if let Ok(permit) = permit_map.get(&key, 0) {
                            if permit.expires_at > 0 && permit.expires_at < _current_ts {
                                expired_keys.push(key);
                            }
                        }
                    }
                }
                let count = expired_keys.len() as u32;
                for key in expired_keys {
                    let _ = permit_map.remove(&key);
                }
                return Ok(count);
            }
        }

        Ok(0)
    }
}

impl Drop for EbpfLoader {
    fn drop(&mut self) {
        if self.attached {
            info!("Detaching eBPF XDP from interface {}", self.interface);
            // XDP program auto-detaches when handle dropped
        }
    }
}

/// Check if a network interface exists on this system
fn interface_exists(interface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{}", interface)).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_loader_graceful_fallback_no_object() {
        // Should not panic when eBPF object missing
        let result = EbpfLoader::load_and_attach("lo", &PathBuf::from("/nonexistent/path.o"));
        // Should succeed with software fallback
        assert!(result.is_ok());
        let loader = result.unwrap();
        assert!(!loader.is_kernel_enforcing());
    }

    #[test]
    fn test_permit_session_software_mode() {
        let loader = EbpfLoader {
            interface: "lo".to_string(),
            attached: false,
            #[cfg(feature = "ebpf-native")]
            _bpf: std::sync::Mutex::new(None),
        };
        // Software mode permit should always succeed
        assert!(loader
            .permit_session(12345, 0x7f000001, 0x7f000001, 9999999999)
            .is_ok());
    }

    #[test]
    fn test_deny_ip_software_mode() {
        let loader = EbpfLoader {
            interface: "lo".to_string(),
            attached: false,
            #[cfg(feature = "ebpf-native")]
            _bpf: std::sync::Mutex::new(None),
        };
        assert!(loader.deny_ip(0x7f000001, 9999999999).is_ok());
    }
}
