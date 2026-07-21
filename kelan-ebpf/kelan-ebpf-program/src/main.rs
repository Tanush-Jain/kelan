#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray},
    programs::XdpContext,
};

// ── Shared scope declaration (written by userspace via PERMIT_MAP) ────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScopeDeclaration {
    pub source_entity_prefix: [u8; 8],
    pub dest_entity_prefix:   [u8; 8],
    pub intent:     u16,
    pub trust_score: u8,
    pub verdict:    u8,
    pub expires_at: u64,
    pub _pad:       [u8; 4],
}

// ── Per-CPU rate-limit entry ─────────────────────────────────────────────────
//
// Using PerCpuArray avoids all atomic contention — each CPU has its own slot.
// The key is a 32-bit hash of the source IPv4 address (FNV-1a).
// Windows are time-based (bpf_ktime_get_ns), reset when window expires.
//
// NOTE: PerCpuArray max_entries = 65536 covers the full 16-bit FNV hash space.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateEntry {
    pub count:         u32,  // packets seen this window
    pub last_reset_ns: u64,  // window start (ktime nanoseconds)
}

// ── Rate-limit tuning constants ──────────────────────────────────────────────
//
// These are conservative defaults for a public-facing AITP endpoint.
// Lower = stricter protection; raise if legitimate clients hit limits.

/// Max UDP packets per source IP per second (limits generic UDP floods)
const MAX_UDP_PER_SEC:  u32 = 200;

/// Max SYN-flagged AITP packets per source IP per second (limits handshake floods)
/// AITP SYN = flags byte bit 0x01 set in AitpMinHdr
const MAX_SYN_PER_SEC:  u32 = 50;

/// Rate-limit window = 1 second in nanoseconds
const TIME_WINDOW_NS:   u64 = 1_000_000_000;

// ── BPF maps ─────────────────────────────────────────────────────────────────

/// Scope declaration map — written by userspace trust engine on Allow verdict
#[map]
static PERMIT_MAP: HashMap<u64, ScopeDeclaration> = HashMap::with_max_entries(65536, 0);

/// Per-CPU packet stats (index meanings):
///   0 = total IP packets seen
///   1 = packets passed (allow verdict)
///   2 = packets dropped (deny verdict / no permit)
///   3 = packets bypassed (non-AITP / non-target port)
///   4 = packets dropped by UDP rate limit
///   5 = packets dropped by SYN rate limit
#[map]
static STATS_MAP: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

/// Per-CPU UDP rate-limit counters (key = FNV hash of src IPv4 addr)
#[map]
static mut UDP_RATE: PerCpuArray<RateEntry> = PerCpuArray::with_max_entries(65536, 0);

/// Per-CPU SYN rate-limit counters (key = FNV hash of src IPv4 addr)
#[map]
static mut SYN_RATE: PerCpuArray<RateEntry> = PerCpuArray::with_max_entries(65536, 0);

// ── XDP entry point ───────────────────────────────────────────────────────────

#[xdp]
pub fn kelan_xdp(ctx: XdpContext) -> u32 {
    match try_kelan_xdp(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_kelan_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr   = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth_proto = u16::from_be(unsafe { (*ethhdr).ether_type });

    // ── Only process IPv4 and IPv6 frames ─────────────────────────────
    if eth_proto != ETH_P_IP && eth_proto != ETH_P_IPV6 {
        increment_stat(3); // bypassed
        return Ok(xdp_action::XDP_PASS);
    }

    increment_stat(0); // total IP

    // ── IPv6: pass through for now (IPv6 XDP support is Days 8–15) ────
    // The existing code had a critical bug: it parsed eth_proto as IPv6
    // but then immediately cast to Ipv4Hdr, causing wrong offsets.
    // FIXED: return XDP_PASS for IPv6 until proper dual-stack support.
    if eth_proto == ETH_P_IPV6 {
        increment_stat(3); // bypass — IPv6 path not yet implemented
        return Ok(xdp_action::XDP_PASS);
    }

    // ── IPv4 path ─────────────────────────────────────────────────────
    let ipv4hdr  = ptr_at::<Ipv4Hdr>(&ctx, ETH_HDR_LEN)?;
    let proto    = unsafe { (*ipv4hdr).proto };
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // We only gate UDP traffic on port 9999 (AITP transport)
    if proto != IPPROTO_UDP {
        increment_stat(3); // bypass — not UDP
        return Ok(xdp_action::XDP_PASS);
    }

    // ── UDP rate-limit: runs before permit map, 0-copy ─────────────────
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let src_key = fnv_hash(src_addr) as u32; // 16-bit bucket via truncation

    let udp_rate_drop = check_rate(
        unsafe { &mut UDP_RATE },
        src_key,
        now_ns,
        MAX_UDP_PER_SEC,
    );

    if udp_rate_drop {
        increment_stat(4); // dropped by UDP rate limit
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Parse UDP header ──────────────────────────────────────────────
    let ip_hdr_len = ((unsafe { (*ipv4hdr).ihl_version } & 0x0F) * 4) as usize;
    let udphdr     = ptr_at::<UdpHdr>(&ctx, ETH_HDR_LEN + ip_hdr_len)?;
    let dst_port   = u16::from_be(unsafe { (*udphdr).dest });

    if dst_port != AITP_PORT {
        increment_stat(3); // bypass — wrong port
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Parse AITP minimum header ─────────────────────────────────────
    let udp_payload_offset = ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN;
    let aitp_hdr = ptr_at::<AitpMinHdr>(&ctx, udp_payload_offset)?;

    let version    = unsafe { (*aitp_hdr).version };
    let flags      = unsafe { (*aitp_hdr).flags };
    let session_id = u64::from_be(unsafe { (*aitp_hdr).session_id });

    // ── SYN rate-limit: applied on top of UDP rate limit ─────────────
    // AITP SYN = flags bit 0x01 set AND bit 0x02 (ACK) NOT set
    let is_syn = (flags & 0x01 != 0) && (flags & 0x02 == 0);
    if is_syn {
        let syn_rate_drop = check_rate(
            unsafe { &mut SYN_RATE },
            src_key,
            now_ns,
            MAX_SYN_PER_SEC,
        );

        if syn_rate_drop {
            increment_stat(5); // dropped by SYN rate limit
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // ── Version check ─────────────────────────────────────────────────
    if version != AITP_VERSION {
        increment_stat(2); // dropped
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Session permit map lookup ─────────────────────────────────────
    let permit = unsafe { PERMIT_MAP.get(&session_id) };

    match permit {
        None => {
            // No permit yet — allow SYN through so userspace can evaluate
            if is_syn {
                increment_stat(3); // bypass (new session handshake)
                return Ok(xdp_action::XDP_PASS);
            }
            increment_stat(2); // drop — established session with no permit
            Ok(xdp_action::XDP_DROP)
        }
        Some(permit) => {
            if permit.verdict == 0 {
                increment_stat(2); // drop — explicit deny verdict
                return Ok(xdp_action::XDP_DROP);
            }
            increment_stat(1); // pass — valid permit
            Ok(xdp_action::XDP_PASS)
        }
    }
}

// ── Rate limit check (per-CPU, no contention) ────────────────────────────────
//
// Returns true if the packet should be DROPPED (rate exceeded).
// Uses per-CPU PerCpuArray keyed by FNV hash bucket.
// Each CPU tracks its own window independently — slightly imprecise for
// distributed traffic but avoids all atomic ops and spinlocks.

#[inline(always)]
fn check_rate(
    map:       &mut PerCpuArray<RateEntry>,
    key:       u32,
    now_ns:    u64,
    threshold: u32,
) -> bool {
    // PerCpuArray key must be < max_entries; we modulo to stay in bounds.
    // 65536 = 2^16, FNV hash is already well-distributed.
    let bucket = key & 0xFFFF; // keep within 65536 entries

    let entry = unsafe { map.get_ptr_mut(bucket) };
    let entry = match entry {
        Some(e) => e,
        None => return false, // map lookup failure → pass (fail open)
    };

    let entry = unsafe { &mut *entry };

    // Check if the window has expired
    if now_ns.saturating_sub(entry.last_reset_ns) >= TIME_WINDOW_NS {
        // New window — reset counter
        entry.last_reset_ns = now_ns;
        entry.count = 1;
        return false; // first packet in window always passes
    }

    // Window still active — increment and check
    entry.count = entry.count.saturating_add(1);
    entry.count > threshold
}

// ── FNV-1a 32-bit hash (fast, verifier-friendly, no division) ────────────────
//
// Used to map a 32-bit IPv4 source address to a hash bucket.
// FNV-1a is ideal for eBPF: no branches, purely multiplicative.

#[inline(always)]
fn fnv_hash(src_ip: u32) -> u16 {
    const FNV_PRIME:  u32 = 0x01000193;
    const FNV_OFFSET: u32 = 0x811c9dc5;

    let bytes = src_ip.to_be_bytes();
    let mut hash = FNV_OFFSET;

    // Unrolled — eBPF verifier prefers no loops
    hash ^= bytes[0] as u32; hash = hash.wrapping_mul(FNV_PRIME);
    hash ^= bytes[1] as u32; hash = hash.wrapping_mul(FNV_PRIME);
    hash ^= bytes[2] as u32; hash = hash.wrapping_mul(FNV_PRIME);
    hash ^= bytes[3] as u32; hash = hash.wrapping_mul(FNV_PRIME);

    // Fold to 16 bits for the PerCpuArray key
    ((hash ^ (hash >> 16)) & 0xFFFF) as u16
}

// ── Protocol header structs ───────────────────────────────────────────────────

#[repr(C)]
struct EthHdr {
    dst_mac:    [u8; 6],
    src_mac:    [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    ihl_version: u8,
    tos:         u8,
    tot_len:     u16,
    id:          u16,
    frag_off:    u16,
    ttl:         u8,
    proto:       u8,
    check:       u16,
    src_addr:    u32,
    dst_addr:    u32,
}

#[repr(C)]
struct UdpHdr {
    source: u16,
    dest:   u16,
    len:    u16,
    check:  u16,
}

#[repr(C)]
struct AitpMinHdr {
    version:    u8,
    flags:      u8,
    intent:     u16,
    session_id: u64,
}

// ── Constants ────────────────────────────────────────────────────────────────

const ETH_P_IP:   u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;
const AITP_PORT:  u16 = 9999;
const AITP_VERSION: u8 = 4; // updated: protocol is now v4 per AitpHeaderV4
const ETH_HDR_LEN: usize = 14;
const UDP_HDR_LEN: usize = 8;

// ── Utility: increment a STATS_MAP counter ───────────────────────────────────

#[inline(always)]
fn increment_stat(key: u32) {
    if let Some(count) = unsafe { STATS_MAP.get_ptr_mut(&key) } {
        unsafe { *count += 1 };
    }
}

// ── Bounds-safe pointer helper ────────────────────────────────────────────────

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end   = ctx.data_end();
    let len   = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// ── panic handler (required for no_std BPF) ──────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
