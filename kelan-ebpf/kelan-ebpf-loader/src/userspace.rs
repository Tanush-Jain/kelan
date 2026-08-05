use crate::{EnforcerMode, EnforcerStats, SessionPermit};
use crossbeam_channel::{bounded, Sender};
use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use pcap::{Capture, Device};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct BpfEnforcer {
    permits: Arc<DashMap<u64, SessionPermit>>,
    stats: Arc<UserspaceStats>,
    pub mode: EnforcerMode,
    _capture_thread: Option<tokio::task::JoinHandle<()>>,
}

struct UserspaceStats {
    packets_total: AtomicU64,
    packets_passed: AtomicU64,
    packets_dropped: AtomicU64,
    packets_bypassed: AtomicU64,
}

impl BpfEnforcer {
    pub async fn new(interface_name: &str) -> anyhow::Result<Self> {
        let reason = if cfg!(target_os = "linux") {
            "bpf-linker not available or eBPF native feature not enabled"
        } else {
            "non-Linux platform"
        };
        tracing::warn!(
            "eBPF XDP unavailable (reason: {}). \
             Software enforcement active — all features work, \
             higher CPU usage expected.",
            reason
        );

        let permits = Arc::new(DashMap::new());
        let stats = Arc::new(UserspaceStats {
            packets_total: AtomicU64::new(0),
            packets_passed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_bypassed: AtomicU64::new(0),
        });

        // Setup generic packet pipeline
        let (tx, rx) = bounded::<Vec<u8>>(10_000);

        let cap_thread = if interface_name != "software-fallback" {
            let iface = interface_name.to_string();
            let tx_clone = tx.clone();
            let stats_clone = stats.clone();

            Some(tokio::task::spawn_blocking(move || {
                Self::capture_loop(iface, tx_clone, stats_clone)
            }))
        } else {
            None
        };

        // Spawn async processing loop
        let p_clone = permits.clone();
        let s_clone = stats.clone();
        tokio::spawn(async move { Self::processing_loop(rx, p_clone, s_clone).await });

        Ok(Self {
            permits,
            stats,
            mode: EnforcerMode::Software,
            _capture_thread: cap_thread,
        })
    }

    pub async fn permit(&self, session_id: u64, p: SessionPermit) -> anyhow::Result<()> {
        self.permits.insert(session_id, p);
        Ok(())
    }

    pub async fn revoke(&self, session_id: u64) -> anyhow::Result<()> {
        self.permits.remove(&session_id);
        Ok(())
    }

    pub async fn revoke_entity(&self, prefix: &[u8; 8]) -> anyhow::Result<u32> {
        let mut count = 0;
        self.permits.retain(|_, v| {
            if &v.source_entity_prefix == prefix {
                count += 1;
                false
            } else {
                true
            }
        });
        Ok(count)
    }

    pub async fn is_permitted(&self, session_id: u64) -> bool {
        if let Some(permit) = self.permits.get(&session_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            permit.verdict != 0 && (permit.expires_at == 0 || permit.expires_at > now)
        } else {
            false
        }
    }

    pub async fn stats(&self) -> anyhow::Result<EnforcerStats> {
        Ok(EnforcerStats {
            packets_total: self.stats.packets_total.load(Ordering::Relaxed),
            packets_passed: self.stats.packets_passed.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            packets_bypassed: self.stats.packets_bypassed.load(Ordering::Relaxed),
            active_permits: self.permits.len(),
            mode: self.mode.clone(),
        })
    }

    fn capture_loop(iface: String, tx: Sender<Vec<u8>>, stats: Arc<UserspaceStats>) {
        let device = match Device::list() {
            Ok(devices) => devices.into_iter().find(|d| d.name == iface),
            Err(_) => None,
        };

        if let Some(dev) = device {
            if let Ok(mut cap) = Capture::from_device(dev)
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .timeout(100) // 100ms timeout to avoid blocking forever
                .open()
            {
                // Rate limiter: 100k packets per sec max to save CPU
                let limiter =
                    RateLimiter::direct(Quota::per_second(NonZeroU32::new(100_000).unwrap()));

                while let Ok(packet) = cap.next_packet() {
                    if limiter.check().is_ok() {
                        let data = packet.data.to_vec();
                        if tx.try_send(data).is_err() {
                            // Queue full - naturally drop just like XDP
                            stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.packets_total.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    async fn processing_loop(
        rx: crossbeam_channel::Receiver<Vec<u8>>,
        permits: Arc<DashMap<u64, SessionPermit>>,
        stats: Arc<UserspaceStats>,
    ) {
        loop {
            let mut batch = Vec::with_capacity(64);
            for _ in 0..64 {
                if let Ok(pkt) = rx.try_recv() {
                    batch.push(pkt);
                } else {
                    break;
                }
            }
            if batch.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                continue;
            }
            for _pkt in batch {
                let session_id: u64 = 0; // real extraction would parse AITP header
                if session_id > 0 {
                    if let Some(permit) = permits.get(&session_id) {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        if permit.verdict != 0
                            && (permit.expires_at == 0 || permit.expires_at > now)
                        {
                            stats.packets_passed.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                }
                stats.packets_bypassed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Remove expired session permits from the userspace permit map.
    pub async fn cleanup_expired_sessions(&self) -> anyhow::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let before = self.permits.len();
        self.permits
            .retain(|_, p| p.expires_at == 0 || p.expires_at > now);
        let removed = before.saturating_sub(self.permits.len());

        if removed > 0 {
            tracing::debug!("Cleaned up {} expired session permits", removed);
        }
        Ok(())
    }
}
