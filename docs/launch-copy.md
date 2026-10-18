# 📣 Kelan Security — Launch Copy

## Hacker News: "Show HN" Post

**Title (78 chars):**
```
Show HN: Kelan – eBPF + Post-Quantum + Gemini AI for AI-to-AI network security
```

---

**Body (≤400 words):**

```
I've been building Kelan Security for the past few months — it's an open-source
network security daemon that enforces trust decisions at the kernel level before a
single application byte is exchanged.

Here's the core idea: TCP/IP was designed for static hosts. It has no concept of
"this is a GPT-4o agent requesting access to a financial database with the intent
of exfiltrating training data." Kelan tries to fix that at the transport layer, not
in your middleware.

How it actually works:

1. Clients speak AITP (Adaptive Intent Transport Protocol) over UDP/9999. Each
   connection declares a signed IntentCode (ModelInference, DataSync, ControlSignal, etc).

2. On SYN, the server runs a trust evaluation: static rules (~0.1ms) blended with a
   Gemini 2.5 Flash call (<5ms in hybrid mode) to score the session 0–255.

3. Based on the verdict (Allow/Monitor/Deny), a session permit is written into an
   XDP eBPF map. Malicious sessions get XDP_DROP at wire speed — never touch userspace.

4. Crypto is hybrid: Ed25519 + ML-KEM-768 (FIPS 203) for KEM and ML-DSA-65
   (FIPS 204 / Dilithium3) for signatures. Both must verify — if either breaks,
   the session is denied.

Current state: v0.3.0, alpha. The eBPF XDP filter and rules engine work. The Gemini
hybrid trust evaluation works. The handshake crypto is implemented but the server
currently bypasses full PQ verification in the hot path for throughput — that's the
next thing I'm fixing. I'm being honest about this because I'd rather you tell me
the right way to do it than oversell it.

One-command install (Ubuntu 22.04+, Linux ARM64 too):
  curl -sSL https://raw.githubusercontent.com/YOUR_ORG/kelan-core/main/install.sh | bash

Or Docker:
  docker pull ghcr.io/YOUR_ORG/kelan-core:latest

You can also deploy free to Oracle Cloud's always-free Ampere A1 (4 OCPU / 24 GB) —
instructions are in deploy/oracle-cloud/README.md.

Repo: https://github.com/YOUR_ORG/kelan-core

I'm especially interested in feedback on: (1) the AITP protocol design, (2) whether
the eBPF handshake enforcement gap is a dealbreaker for your threat model, and (3) if
the hybrid AI trust scoring is actually useful or just security theater.
```

---

## X / Twitter Post (280 chars)

```
Show HN submission live 🧵

Kelan Security: eBPF + ML-KEM-768 (Post-Quantum) + Gemini AI trust engine for AI-to-AI network security.

One-command install. Runs free on Oracle Cloud ARM.
Still rough (v0.3.0), but the XDP kernel filtering works.

github.com/YOUR_ORG/kelan-core
```

---

## Posting Checklist

### Before you post:
- [ ] Replace `YOUR_ORG` with your actual GitHub org/username
- [ ] Ensure `https://github.com/YOUR_ORG/kelan-core` is **public**
- [ ] Ensure `curl .../install.sh | bash` actually works end-to-end on a clean Ubuntu VM
- [ ] Set up free Formspree account → get form ID → replace `REPLACE_WITH_FORMSPREE_ID` in `index.html`
- [ ] Create free Calendly account → replace the link in `index.html`
- [ ] Confirm `https://demo.kelan.dev/api/stats` responds (or update the URL)

### HN tips:
- Post on a **Tuesday–Thursday**, between **8–10 AM US Eastern** for max HN traffic
- Do NOT post the same day as any major tech news cycle
- Respond to every comment within the first 4 hours — HN rewards engagement
- Don't say "revolutionary" or "paradigm shift" — the body above avoids this deliberately

### After posting:
- Share on r/netsec, r/rust, and r/selfhosted (different communities, different pitches)
- DM 5–10 people building AI agents on X and ask for honest feedback
- Search X for "LLM API security" or "AI agent DDoS" — reply to those threads with the GH link
