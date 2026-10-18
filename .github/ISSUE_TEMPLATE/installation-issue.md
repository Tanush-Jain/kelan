---
name: Installation Issue
about: Report a problem during the setup, installation, compilation, or service launch
  of Kelan
title: Issues
labels: dependencies
assignees: ''
type: Task

---

# Installation Issue Report

Thank you for reporting your installation trouble. Setting up complex security layers involving eBPF toolchains, Rust compilations, and distributed AI environments can hit unexpected environmental friction. This template will help us pinpoint exactly what went wrong.

---

## Installation Method

Which deployment path were you following when the failure occurred? *(Check only one)*

* [ ] **`./install.sh` Automated Script** (Local venv installation workflow)
* [ ] **Docker Compose** (Multi-container architecture setup)
* [ ] **Kubernetes** (Helm charts or manifest deployments)
* [ ] **Manual Installation** (Step-by-step compilation from source)

---

## Environment Matrix

To diagnose compiler, module, or package conflicts, please fill out your system profile below:

### Host Operating System
* [ ] Ubuntu (Version)
* [ ] Debian (Version)
* [ ] Kali Linux (Version)
* [ ] macOS (M1/M2/M3/M4) (Version)
* [ ] Windows Subsystem for Linux (WSL2)
* [ ] Other (Please specify)

### System Details
* **Architecture:** `x86_64` / `arm64` / `aarch64` / Other: 
* **Kernel Version (`uname -r`):** * **Virtual Environment Tool:** `venv` / `conda` / `poetry` / None

### Core Dependency Versions
* **Python Version (`python3 --version`):** * **Rust Version (`rustc --version`):** * **Docker Version (`docker --version`):** * **Docker Compose Version (`docker compose version`):** ---

## Command Executed

Provide the exact command(s) you ran leading up to the error. 

```bash
# Example: ./install.sh
# Paste your actual command sequence below:
