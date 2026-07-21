# ChatGPT / Codex MCP Submission Notes

> **What this document is**: Operational guidance for the human who submits
> Kelan AgentBound to the ChatGPT App directory as an MCP-backed plugin.
> It documents the *platform requirements* — nothing here should be
> hardcoded into `server.py` or any other code artifact.

---

## Platform Requirements (as of mid-2026)

### 1. Organisation Verification
- Complete identity verification in the **OpenAI Platform Dashboard** before
  opening a submission ticket.
- Choose **Business Verification** (for "Kelan Security") rather than
  individual verification.
- The account must have the `Apps Management: Write` permission role.

### 2. Publicly Accessible MCP Server
The ChatGPT App directory requires a **remotely hosted** MCP server — the
local `stdio`-transport `server.py` used by Claude Code / Gemini CLI /
Antigravity / Grok Build **cannot** be submitted as-is.

**Required step before submission**:
Deploy `kelan-agentbound-mcp/server.py` behind an HTTP/SSE transport layer
(e.g., using the MCP Python SDK's `mcp.server.fastapi` adapter or a
`FastAPI` + Uvicorn wrapper) and host it at a stable public URL
(e.g., `https://agentbound.tanush-jain.dev/mcp` or any stable public domain you control).

The OpenAI review portal will crawl this endpoint to validate tool metadata.

### 3. Tool Hint Annotations (Submission Blockers)

Every MCP tool exposed must carry the three required hints.
They must be set **in the server tool definitions** (not here):

| Tool | `readOnlyHint` | `destructiveHint` | `openWorldHint` |
|---|---|---|---|
| `start_monitoring` | `false` | `false` | `false` |
| `get_divergence_events` | `true` | `false` | `false` |
| `get_session_summary` | `true` | `false` | `false` |
| `stop_monitoring` | `false` | `false` | `false` |

Add these to the `inputSchema` annotations of each tool in `server.py` when
preparing the remote HTTP variant. **Do not add them to the stdio server** —
the other four host platforms do not use/require them and they would add
noise.

### 4. App Metadata to Prepare

| Field | Value |
|---|---|
| Display Name | `Kelan AgentBound` |
| Subtitle (≤ 30 chars) | `AI agent behavior monitor` |
| Description | See `README.md` §AgentBound section |
| Category | `BUSINESS` or `SECURITY` (whichever is available) |

### 5. Content Security Policy
Define a CSP that covers only the domains `server.py` fetches from —
currently none externally (all local eBPF + Ollama). If a remote Ollama
endpoint is configured, add its domain here.

### 6. Private / Developer Mode Alternative
For internal team use only (no public listing required), use
**OpenAI Developer Mode** to load the remote MCP URL without going through
the review process.

---

## Relationship to Other Platform Manifests

This is the **only** platform that requires a remote HTTP server.
The four stdio-based manifests (Claude Code, Gemini CLI, Antigravity, Grok
Build) all point directly to `kelan-agentbound-mcp/server.py` and need no
changes for their respective hosts.

When the remote HTTP variant is ready, create a separate
`kelan-agentbound-mcp/server_http.py` (or equivalent adapter) — do **not**
modify `server.py`, which must remain a clean stdio server for the other
four hosts.
