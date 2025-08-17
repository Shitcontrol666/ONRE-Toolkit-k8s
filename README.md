# k8s-pentest-framework

A small, extendable Kubernetes pentest toolkit for AppSec audits written by AI, for fast security checks mentioned in kubernetes goat.

## Features
- Pod to node privileged pod generator
- Privileged container scanner
- RBAC token scanner
- Ingress checker with CVE-2025-1974 PoC support
- NodePort scanner with optional nmap port scan
- Environment information gathering from pods
- Registry scanner with /v2/_catalog check for auth
- Namespace bypass check
- Core components check (apiserver flags, etcd no-TLS, kubelet anon access, etcdctl access)
- Spawn shell and return to menu

## Installation
1. Ensure Python 3 is installed.
2. Install dependencies:
   - packaging: `pip install packaging`
   - For full functionality, install system tools:
     - kubectl
     - curl
     - nmap (for NodePort scanning)
     - etcdctl (for etcd access check)
3. Download the script: `curl -O [https://raw.githubusercontent.com/ONRE-Toolkit-k8s/main/onre_k8s_framework.py](https://raw.githubusercontent.com/Shitcontrol666/ONRE-Toolkit-k8s/refs/heads/main/ONRE_Toolkit_k8s.py)`
4. Make executable: `chmod +x ONRE_Toolkit_k8s.py`

## Usage
Run the script: `./ONRE_Toolkit_k8s.py` or `python3 ONRE_Toolkit_k8s.py`
- Select commands from the menu.
- Use responsibly in authorized test environments only.

## Extension
Add new modules by creating functions and registering in COMMANDS list.

## Disclaimer
This tool is for educational and authorized testing purposes only. Do not use on production systems without permission.
