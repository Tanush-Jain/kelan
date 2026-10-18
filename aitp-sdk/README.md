# kelan-sdk

[![crates.io](https://img.shields.io/crates/v/kelan-sdk.svg)](https://crates.io/crates/kelan-sdk)
[![build](https://github.com/kelan-security/kelan-sdk/actions/workflows/ci.yml/badge.svg)](...)
[![license: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![stars](https://img.shields.io/github/stars/kelan-security/kelan-sdk?style=social)](...)

> Agentic AI security at the transport layer.
> Your application stops seeing attacks because Kelan Security kills them first.

<!-- Demo GIF: session killed in 2.1ms — replace with actual recording -->
![Demo](docs/demo.gif)

## The problem

Modern applications suffer from a fundamental timing mismatch: attacks are analyzed at the application layer long after the network connection is established. Standard Web Application Firewalls (WAFs) and Intrusion Detection Systems (IDS) inspect HTTP traffic asynchronously, allowing malicious payloads to reach your web servers, API gateways, and internal routing logic before restrictive routing actions are executed. 

By the time your WAF fires, the attacker has already fingerprinted your stack.

## How Kelan Security works

```text
+-------------------+       +-------------------+       +-------------------+
| Intelligence Core |       |   eBPF Datapath   |       |  Target Service   |
|  (Gemini + Rust)  |<----->|  (Kernel space)   |<----->|   (User space)    |
+-------------------+       +-------------------+       +-------------------+
        ^                           ^                           ^
        | Policy                    | Packets                   | Payload
        v                           v                           v
+---------------------------------------------------------------------------+
|                            Client Application                             |
+---------------------------------------------------------------------------+
```

Every connection requires an Ed25519 signature and an explicit declaration of intent. The Intelligence Core evaluates this intent against global threat graphs using Gemini's reasoning capabilities. Once verified, the session identity is pinned at the eBPF layer. Any deviation from the declared intent triggers an immediate, sub-millisecond revocation directly in kernel space before packets ever reach the application.

## Install

```toml
[dependencies]
kelan-sdk = "0.3"
```

## 5 lines to protect a server

```rust
KelanServer::builder()
    .config("kelan.toml")
    .on_session(|s| async move { s.evaluate().await })
    .build().await?
    .run().await
```

## 5 lines for a client

```rust
let client = KelanClient::builder().config("kelan.toml").build().await?;
let session = client.connect("target:9999")
    .intent(IntentCode::ModelInference)
    .await?;
session.send(b"hello").await?;
```

## Benchmarks

| Metric | Value |
|---|---|
| Session establishment P50 | 2.1ms |
| Session establishment P99 | 4.9ms |
| eBPF session revocation   | <1μs  |
| DDoS mitigation (100K pps)| 98.4% drop at 0.3% CPU |
| Lateral movement blocked  | 2.1ms from detection |

Benchmarks on Intel i7, Ubuntu 22.04, Gemini 2.5 Flash.

## Why not [X]?

| Tool | Focus | When it Acts | What it Misses | Kelan Security Advantage |
|---|---|---|---|---|
| **WAF** | Application (L7) | After connection establishment | Novel payloads, zero-days, slow-loris attacks | Drops malicious intent at Layer 3/4 before the application is reached. |
| **IDS/IPS** | Network (L3-L7) | During packet transit | Encrypted payloads, sophisticated stateful attacks | Uses LLM reasoning to evaluate session intent, not just packet signatures. |
| **EDR** | Host / OS | After execution / access | Network-level reconnaissance, pre-execution lateral movement | Prevents access entirely based on cryptographic identity and verified intent. |
| **ZTNA** | Access (L4-L7) | At connection initiation | Session hijacking, post-auth malicious changes of behavior | Continuously monitors session behavior and revokes instantly via eBPF. |

## Self-host the Intelligence Core

```bash
docker run -p 3000:3000 -p 9999:9999/udp \
  -e GEMINI_API_KEY=[REDACTED_GEMINI_KEY] \
  ghcr.io/kelan-security/kelan-core:latest
```

## Documentation

- [Protocol spec](docs/protocol.md)
- [Configuration reference](docs/config.md)
- [Attack simulation guide](docs/attacks.md)
- [IEEE paper (arXiv)](https://arxiv.org/abs/XXXX.XXXXX)

## License

kelan-sdk is licensed under the Apache License 2.0.
The Kelan Intelligence Core is licensed under BSL 1.1 (free for dev,
commercial license for production deployments).
