# Security Policy

Kelan Community Edition is an audit-only security scanner: it finds and
reports issues in your code and dependencies. It does not perform inline
network enforcement, blocking, or traffic interception. If you need
enforcement, see Kelan Pro.

## Supported Versions

| Version | Supported |
| --- | --- |
| Latest `stable` release | Yes |
| Previous `stable` release | Security fixes only, for 90 days after superseding release |
| `beta` / `nightly` | No — use at your own risk, no security-fix guarantee |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Email **kelansecurity@gmail.com** with:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof of concept.
- The version/commit you tested against.

**Response targets:**
- Acknowledgement within 3 business days.
- Initial assessment (confirmed / not applicable / needs more info) within 7
  business days.
- A fix or mitigation plan communicated within 30 days for confirmed
  high/critical issues; 90 days is our outside target for public coordinated
  disclosure, extendable by mutual agreement if a fix needs more time.

## Scope

**In scope:**
- The `kelan` CLI, its plugins (SAST/DAST/SCA/recon/cloud/chains), and the
  local intelligence store.
- The local FastAPI backend and React dashboard (`kelan-dashboard`), as
  shipped in this repository.
- The Windows/macOS/Linux installers and packaging scripts in this
  repository.

**Out of scope:**
- Kelan Pro (private, separately licensed) — report issues for Pro through
  your pilot/support contact, not this policy.
- Denial-of-service testing against our infrastructure, social engineering,
  and physical access attacks.
- Vulnerabilities in third-party dependencies we consume — please report
  those to the upstream project, though we'd appreciate a heads-up so we can
  track and update.
- Findings from automated scanners with no demonstrated impact (e.g., a bare
  dependency-version flag with no reachability or exploitability shown).

## Safe Harbor

We will not pursue legal action against good-faith security research that
follows this policy: stays within scope, avoids privacy violations and
service disruption, and reports before public disclosure. We ask for
reasonable time to respond before any public disclosure.

## What Kelan Community Does and Does Not Do (relevant to your own risk assessment)

- Runs entirely on your machine by default. No code, findings, or scan
  results leave your network unless you explicitly pass `--allow-network`
  (which enables live OSV.dev queries) or run `kelan update` (which fetches
  public vulnerability feeds — never sends your data).
- The local dashboard binds to `127.0.0.1` only and requires a token. It is
  not designed to be exposed on a network interface; doing so is unsupported
  and at your own risk.
- Local LLM inference (via Ollama) runs on your machine. We do not control
  or audit third-party model weights you choose to pull.
