# README.md for ONRE_Toolkit_k8s

## Overview

**ONRE_Toolkit_k8s** (ONRE) is a lightweight, extendable Kubernetes penetration testing toolkit designed for checking common attacks verctors on ypur cluster mentioned in Kubernetes GOAT. It provides a collection of non-destructive tools to enumerate and assess Kubernetes clusters, focusing on common security checks like privileged containers, RBAC permissions, ingress vulnerabilities, and more.

### Key Features
- **Single-file Python script**: Easy to read, extend, and run.
- **Non-destructive by default**: No changes are applied without explicit user confirmation (e.g., shows `kubectl apply` commands but doesn't execute them).
- **Modular design**: Add new commands by defining functions and registering them in the `COMMANDS` list.
- **Tools included**:
  1. **pod2node**: Generate privileged pod YAML for node targeting.
  2. **privscan**: Scan for privileged containers.
  3. **rbac**: Scan RBAC tokens for dangerous permissions.
  4. **ingress**: Check ingress controllers for CVE-2025-1974 and assist with PoC.
  5. **nodeport**: Scan NodePort services and suggest external access checks.
  6. **envinfo**: Gather environment info from pods (env vars, hosts, etc.).
  7. **registryscan**: Search for container registries and check accessibility.
  8. **nsbypass**: Check namespace access bypass via RBAC.
  9. **corecheck**: Audit core components (API server, etcd, kubelet).
  10. **shell**: Spawn a shell within the tool.

This tool is intended for authorized penetration testing and audits only. Use responsibly in test environments.

## Prerequisites
- Python 3.8+ (tested on 3.12).
- `kubectl` configured with access to the target Kubernetes cluster.
- Optional: `curl`, `nmap` (for NodePort scanning), `etcdctl` (for etcd checks).
- Editors like `nano`, `vi`, or set `$EDITOR` for YAML editing.

Install dependencies via:
```
pip install -r requirements.txt
```

## Installation
1. Clone or download the script.
2. Install requirements:
   ```
   pip install -r requirements.txt
   ```
3. Ensure `kubectl` is in your PATH and configured for the target cluster.

## Usage
Run the script in a terminal with `kubectl` access:
```
python3 ONRE_Toolkit_k8s.py
bash ONRE_Toolkit_k8s.sh
```
- A banner and menu will appear.
- Select options by number or command name (e.g., `4` or `ingress`).
- Follow prompts for each tool.
- Quit with `q`.

**Important Notes**:
- The tool runs in your current `kubectl` context/namespace.
- Privileged operations (e.g., applying YAML) require manual execution.
- For the ingress checker (CVE-2025-1974 PoC): Use in controlled environments; it may create resources.
- Extend the tool by adding functions to the script and updating `COMMANDS`.

## Dependencies (requirements.txt)
See `requirements.txt` for Python libraries.

## Contributing
- Add new modules by creating a function and adding it to `COMMANDS`.
- Pull requests welcome for improvements or new features.

## Disclaimer
This tool is for educational and authorized testing purposes only. The author is not responsible for misuse. Always obtain permission before auditing systems.

Author: Generated with Grok assistance. Inspired by Kubernetes security best practices.

---

# requirements.txt

loguru==0.7.2
packaging==24.1
requests==2.32.3
