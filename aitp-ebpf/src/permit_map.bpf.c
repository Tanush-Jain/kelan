/*
 * eBPF permit map definitions.
 *
 * This file defines the eBPF maps shared between the XDP filter
 * (kernel-space) and the AITP transport engine (user-space).
 */

#include "common.h"

/*
 * Try to include standard BPF helpers, but common.h
 * provides fallbacks for the structure below.
 */
#if defined(__linux__) && __has_include(<linux/bpf.h>)
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#endif

/*
 * The permit map: session_id (u64) → permit_entry.
 *
 * User-space writes entries when sessions are established.
 * User-space removes entries on revocation (immediate kernel enforcement).
 * XDP program reads entries to decide PASS/DROP.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u64);
  __type(value, struct permit_entry);
} permit_map SEC(".maps");

char _license[] SEC("license") = "GPL";
