# Kelan Community — Windows 10/11 x64 Packaging & Installation Guide

This document details the architecture, packaging, installation, code signing, and operational characteristics of the Kelan Community edition on Microsoft Windows 10 and 11 (64-bit).

---

## 1. Platform Scope & Architectural Boundaries

| Capability | Linux | macOS | Windows 10/11 x64 |
| :--- | :---: | :---: | :---: |
| **SAST (Static Application Security Testing)** | ✅ Full | ✅ Full | ✅ Full |
| **DAST (Dynamic Application Security Testing)** | ✅ Full | ✅ Full | ✅ Full |
| **SCA (Software Composition Analysis)** | ✅ Full | ✅ Full | ✅ Full |
| **Local Vulnerability Intelligence Store** | ✅ Full | ✅ Full | ✅ Full |
| **Local LLM Reasoning via Ollama** | ✅ Full | ✅ Full | ✅ Full |
| **Basic Port Reconnaissance (TCP connect)** | ✅ Full | ✅ Full | ✅ Full |
| **Advanced Raw Recon (`scapy`, `netifaces`)** | ✅ Full | ✅ Full | ⚠️ Requires `kelan[recon]` + Npcap |
| **Kernel eBPF / XDP Network Enforcement** | ✅ Ring-0 Kernel | ❌ Simulation only | ❌ Simulation only |

> [!NOTE]
> **Enforcement Boundary:** Kernel eBPF/XDP network filtering operates strictly at Ring 0 within the Linux kernel. On Windows and macOS, Kelan operates in **audit mode** and **simulation mode**. All analysis, AST parsing, web probing, lockfile matching, and intelligence indexing features are fully operational on Windows.

---

## 2. Installation Options

### Option A: Windows Installer (`KelanSetup.exe`) — Recommended
Built with Inno Setup 6, this installs Kelan into `C:\Program Files\Kelan`:
1. Adds `kelan.exe` to System `PATH`.
2. Creates Start Menu shortcuts for Kelan CLI and Kelan Dashboard.
3. Automatically prompts to run `kelan setup` upon installation.
4. Clean uninstaller: Prompts whether to retain your configuration and local vulnerability intelligence database (`%LOCALAPPDATA%\kelan`). Defaults to keeping user data safe unless explicitly confirmed.

### Option B: PowerShell Installation Script
You can download and verify the installation using [`scripts/install.ps1`](../scripts/install.ps1):
```powershell
# Run from an elevated PowerShell prompt:
.\scripts\install.ps1
```
The script:
- Queries the latest release from `https://github.com/Tanush-Jain/kelan/releases`.
- Downloads the installer and `SHA256SUMS.txt`.
- Verifies the cryptographic SHA-256 checksum **before executing or unpacking any binary**.
- Aborts immediately if the hash does not match.

### Option C: Python Package (`pip`)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install kelan

# For advanced raw packet capture (requires Npcap):
pip install "kelan[recon]"
```

---

## 3. Guided Setup (`kelan setup`)

After installing Kelan, run:
```powershell
kelan setup
```
This automated wizard performs:
1. **OS & Architecture Verification:** Confirms Windows 10/11 x64 and reminds the user of the Linux-only eBPF boundary.
2. **Disk Space Check:** Verifies at least 5.0 GB of free space is available on the target drive for Ollama model weights and the offline vulnerability intelligence database.
3. **Ollama Service Detection:** Probes `http://127.0.0.1:11434/api/version`. If not detected, prints the official download link: `https://ollama.com/download/OllamaSetup.exe`.
4. **Model Provisioning:** Offers to pull the recommended model (`qwen2.5-coder:latest`) directly through the Ollama streaming API with interactive progress bars.
5. **Standard Storage Initialisation:**
   - Data directory: `%LOCALAPPDATA%\kelan` (`C:\Users\<user>\AppData\Local\kelan`)
   - Config directory: `%APPDATA%\kelan` (`C:\Users\<user>\AppData\Roaming\kelan`)
   - Writes standard `config.toml` if not already present.
6. **Intelligence Sync:** Triggers the initial offline-first sync across CISA KEV, FIRST EPSS, OSV, GHSA, and NVD.
7. **Scheduled Daily Update:** Offers (never forces) an automatic background sync configured via the native **Windows Task Scheduler**:
   ```cmd
   schtasks /create /tn "KelanIntelUpdate" /tr "kelan update" /sc daily /st 03:00 /f
   ```
8. **Environment Doctor:** Executes `kelan doctor` to verify system readiness.

---

## 4. PyInstaller Spec & Build Configuration

The PyInstaller spec file [`kelan.spec`](../kelan.spec) bundles:
- Tree-sitter grammars: `tree_sitter_python`, `tree_sitter_javascript`, `tree_sitter_typescript`.
- Web dashboard static assets from `kelan-dashboard/dist` and `static/`.
- Dynamic imports for Cryptography, FastAPI, Uvicorn, and Rich.
- Excludes heavy or Linux-only libraries (`kelan_pro`, GUI toolkits).

---

## 5. Verification Status & Measurements

> [!IMPORTANT]
> **Environment Verification Notice:**
> In accordance with the Kelan project rules:
> - *Never state a performance, accuracy, or latency number in code, docs, or UI unless a test or benchmark in this repo produces it.*
> - *If something cannot be verified in this environment, say so in the final report.*
>
> The authoring and unit test environment for this release is macOS (`Darwin`). PyInstaller builds native PE binaries strictly for the host OS and does not cross-compile Windows PE binaries from macOS.
>
> Consequently:
> - The PyInstaller specification (`kelan.spec`), Inno Setup configuration (`packaging/windows/installer.iss`), PowerShell installer (`scripts/install.ps1`), and CI automated test workflow (`.github/workflows/windows-release.yml`) are fully constructed and syntactically validated in this repo.
> - The live execution of `kelan.exe` on Windows 10/11 x64 is built and verified via the GitHub Actions `windows-latest` continuous integration pipeline.

### Benchmark Measurement Procedure on Windows:
Once built in CI or locally on Windows, cold-start latency and binary sizes are measured using PowerShell:

```powershell
# 1. Binary Size Measurement:
Get-Item .\dist\kelan\kelan.exe | Select-Object Name, @{Name="Size (MB)"; Expression={ "{0:N2}" -f ($_.Length / 1MB) }}

# 2. Cold-Start Startup Time Measurement (Average of 5 runs):
1..5 | ForEach-Object {
    (Measure-Command { .\dist\kelan\kelan.exe --plugins | Out-Null }).TotalMilliseconds
} | Measure-Object -Average | Select-Object @{Name="Avg Startup (ms)"; Expression={ "{0:N1}" -f $_.Average }}
```

---

## 6. Code Signing & Windows Defender SmartScreen

### Code Signing Architecture
In the continuous integration pipeline ([`.github/workflows/windows-release.yml`](../.github/workflows/windows-release.yml)), code signing is handled using `signtool.exe` against Authenticode specifications:
- **Signer Tool:** Microsoft Windows SDK `signtool.exe`
- **Digest Algorithm:** SHA-256 (`/fd SHA256`)
- **Timestamp Server:** DigiCert RFC-3161 Timestamping Authority (`/tr http://timestamp.digicert.com /td SHA256`)
- **CI Secrets Required:**
  - `WINDOWS_CERT_BASE64`: Base64-encoded PKCS#12 (`.pfx`) code signing certificate.
  - `WINDOWS_CERT_PASSWORD`: Passphrase protecting the certificate.

### Windows Defender SmartScreen Notice
If a build is produced without a commercial EV (Extended Validation) code signing certificate, Windows Defender SmartScreen may display an alert upon first launch:
> *"Windows protected your PC — Microsoft Defender SmartScreen prevented an unrecognized app from starting."*

To run an unsigned community build:
1. Click **More info**.
2. Click **Run anyway**.
3. Verify that the SHA-256 hash matches the published hash in `SHA256SUMS.txt`:
   ```powershell
   Get-FileHash KelanSetup.exe -Algorithm SHA256
   ```

