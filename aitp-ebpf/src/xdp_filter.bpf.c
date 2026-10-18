/*
 * XDP packet filter for AITP — eBPF enforcement layer.
 */

#include "common.h"

#if defined(__linux__) && __has_include(<linux/bpf.h>)
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#else
/* Portable fallbacks for non-Linux/IDE environments */
#define XDP_PASS 2
#define XDP_DROP 1
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#ifndef bpf_htons
static inline __u16 bpf_htons(__u16 x) { return (x << 8) | (x >> 8); }
#endif

/* BPF map type constants (defined in linux/bpf.h on Linux) */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9

/* BPF map update flags */
#define BPF_NOEXIST 1

struct xdp_md {
  __u32 data;
  __u32 data_end;
};
struct ethhdr {
  __u16 h_proto;
};
struct iphdr {
  __u8 ihl;
  __u8 protocol;
  __u32 saddr; /* source IPv4 address */
};
struct udphdr {
  __u16 dest;
};

#ifndef bpf_map_lookup_elem
static inline void *bpf_map_lookup_elem(void *map, void *key) {
  (void)map;
  (void)key;
  return 0;
}
#endif
#ifndef bpf_map_update_elem
static inline int bpf_map_update_elem(void *map, void *key, void *value,
                                      __u64 flags) {
  (void)map;
  (void)key;
  (void)value;
  (void)flags;
  return 0;
}
#endif
#endif

#define AITP_PORT 9999

/* eBPF hash map: session_id → permit_entry. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u64);
  __type(value, struct permit_entry);
} permit_map SEC(".maps");

/* Packet drop counter (per-CPU array for performance). */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} drop_counter SEC(".maps");

/*
 * IP blacklist: src IPv4 → 1 (present means blocked).
 * Updated by the user-space control plane when an IP is blacklisted.
 * O(1) hash lookup — cheapest possible check.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);  /* IPv4 source address */
  __type(value, __u8); /* 1 = blocked */
} ip_blacklist_map SEC(".maps");

/*
 * Per-IP SYN rate counter (LRU hash so old entries are auto-evicted).
 * Each UDP packet to the AITP port from a given IP increments its counter.
 * If the counter exceeds SYN_RATE_THRESHOLD the packet is dropped at wire
 * speed.
 */
#define SYN_RATE_THRESHOLD 200
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);   /* IPv4 source address */
  __type(value, __u32); /* packet count (reset by user-space periodically) */
} ip_syn_rate_map SEC(".maps");

SEC("xdp")
int aitp_xdp_filter(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  /* Parse Ethernet header */
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  /* Only process IPv4 */
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  /* Parse IP header */
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  /* Only process UDP */
  if (ip->protocol != IPPROTO_UDP)
    return XDP_PASS;

  /* Parse UDP header */
  struct udphdr *udp = (void *)((__u8 *)ip + (ip->ihl * 4));
  if ((void *)(udp + 1) > data_end)
    return XDP_PASS;

  /* Check destination port */
  if (udp->dest != bpf_htons(AITP_PORT))
    return XDP_PASS;

  /* ── Layer 0 defense: blacklist check (runs before permit lookup) ──
   * If the source IP is in ip_blacklist_map, drop immediately.
   * User-space control plane updates this map; cost here is one hash lookup. */
  __u32 src_ip = ip->saddr;
  __u8 *blocked = bpf_map_lookup_elem(&ip_blacklist_map, &src_ip);
  if (blocked && *blocked) {
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&drop_counter, &key);
    if (counter)
      __sync_fetch_and_add(counter, 1);
    return XDP_DROP;
  }

  /* ── Layer 1 defense: per-IP SYN rate limiting ──
   * Increment the packet counter for this source IP and compare against
   * SYN_RATE_THRESHOLD. If exceeded, drop at wire speed (zero user-space CPU).
   */
  __u32 *rate = bpf_map_lookup_elem(&ip_syn_rate_map, &src_ip);
  if (rate) {
    __u32 count = __sync_fetch_and_add(rate, 1);
    if (count >= SYN_RATE_THRESHOLD) {
      __u32 key = 0;
      __u64 *counter = bpf_map_lookup_elem(&drop_counter, &key);
      if (counter)
        __sync_fetch_and_add(counter, 1);
      return XDP_DROP;
    }
  } else {
    /* First packet from this IP — insert initial counter. */
    __u32 init = 1;
    bpf_map_update_elem(&ip_syn_rate_map, &src_ip, &init, BPF_NOEXIST);
  }

  /* Extract session_id (offset 3 of AITP header, 8 bytes) */
  __u8 *aitp_payload = (void *)(udp + 1);
  if ((void *)(aitp_payload + 11) > data_end)
    return XDP_DROP;

  __u64 session_id = 0;
#pragma unroll
  for (int i = 0; i < 8; i++) {
    session_id = (session_id << 8) | aitp_payload[3 + i];
  }

  /* Look up in permit map */
  struct permit_entry *permit = bpf_map_lookup_elem(&permit_map, &session_id);
  if (permit) {
    /* Optional: Add expiration check if bpf_ktime_get_real_ns is available.
     * For now, we rely on user-space cleanup for maximum compatibility. */
    return XDP_PASS;
  }

  /* No permit — drop and increment counter */
  __u32 key = 0;
  __u64 *counter = bpf_map_lookup_elem(&drop_counter, &key);
  if (counter)
    __sync_fetch_and_add(counter, 1);

  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
