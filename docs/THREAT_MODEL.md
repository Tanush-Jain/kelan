# Threat Model — Kelan Community Edition

**Scope:** this document covers `Tanush-Jain/kelan` (Community Edition) only.
Kelan Pro's enforcement engine, AITP, and kernel-level components have a
separate, private threat model and are out of scope here.

## What Community Is

A local, audit-only scanner: SAST (tree-sitter + deterministic rules +
local LLM triage), DAST (crawler + deterministic probe grading), SCA
(dependency matching against a local, periodically-updated vulnerability
database), and a local dashboard for reviewing results. It finds and
reports; it does not block, drop, or intercept anything.

## Assets

- The user's source code and the findings derived from it.
- The local SQLite store: scan history, findings, and the cached
  vulnerability intelligence feed (CVE/KEV/EPSS/OSV/GHSA data).
- The local Ollama model and its inference output.

## Trust Boundaries

| Boundary | Description |
| --- | --- |
| Localhost dashboard | FastAPI backend binds `127.0.0.1` only; a bearer token is required for all API routes. Not intended to cross a network boundary. |
| Network egress | Disabled by default for scanning. `--allow-network` enables live OSV.dev lookups per package. `kelan update` fetches public advisory feeds (NVD, CISA KEV, FIRST EPSS, OSV, GHSA) on an explicit, user-triggered basis — never automatically, never silently. |
| Local LLM | Ollama runs locally; prompts and responses do not leave the machine. We do not verify the integrity of model weights beyond what Ollama's own registry provides — pull models from Ollama's official registry, not third-party mirrors. |
| Scanned target | The codebase or URL being scanned is treated as the asset under test. A scanned *repository*, however, is partially untrusted input to our own parser (see below). |

## Threats Considered

1. **A locally co-resident malicious process reads scan findings or the
   dashboard token.** Mitigation: dashboard binds to loopback only;
   findings database uses standard OS file permissions. We do not currently
   encrypt the local SQLite store at rest — if your threat model requires
   that, use full-disk encryption.
2. **A malicious or malformed input file exploits a parser bug in
   tree-sitter or our chunker when scanning an adversarial repository**
   (e.g., a booby-trapped open-source dependency you're auditing).
   Mitigation: tree-sitter grammars are widely used and audited upstream;
   we do not currently sandbox the scan process. Treat scanning an
   untrusted third-party repo with the same caution as cloning and opening
   it in an editor. A sandboxed-scan mode is on our roadmap and will be
   noted here when shipped.
3. **A compromised dependency in Kelan's own supply chain.** Mitigation:
   pinned dependency versions, SBOM published per release, SHA-256
   checksums on release artifacts, and our own `kelan scan` runs against
   this repository in CI.
4. **A malicious actor tampers with a downloaded release binary in
   transit.** Mitigation: SHA-256 checksums published alongside every
   release (`SHA256SUMS.txt`); verify before running, especially on
   Windows where unsigned-binary warnings are expected until our
   code-signing step is in place (tracked separately — current releases
   are not yet code-signed; see release notes).

## Explicitly Out of Scope for This Document

- Kernel-level packet enforcement, eBPF/XDP, any AI-gated enforcement
  decision pipeline, or post-quantum handshake protocols — these belong to
  Kelan Pro's private threat model, not this public document.
- Multi-tenant or fleet-management concerns — Community has no concept of
  a client, tenant, or fleet.
