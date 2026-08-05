#ifndef AITP_EBPF_COMMON_H
#define AITP_EBPF_COMMON_H

/*
 * BPF type compatibility.
 * Use __has_include to determine if we are in a real Linux/BPF environment.
 */
#if defined(__linux__) && __has_include(<linux/types.h>)
#include <linux/types.h>
#else
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
#endif

/*
 * BPF map and section macros.
 */
#ifndef SEC
#if defined(__APPLE__)
/* Mach-O requires segment,section */
#define SEC(name) __attribute__((section("__DATA," name), used))
#elif defined(__linux__) && __has_include(<bpf/bpf_helpers.h>)
#include <bpf/bpf_helpers.h>
#else
#define SEC(name) __attribute__((section(name), used))
#endif
#endif

#ifndef __uint
#define __uint(name, val) int(*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

/* BPF Map Type fallbacks */
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif

/* Permit entry — mirrors the Rust PermitMapEntry struct. */
struct permit_entry {
  __u64 session_id;
  __u8 trust_score;
  __u64 expires_at; /* Unix timestamp (seconds) */
  __u8 flags;       /* Reserved for future use */
};

#endif
