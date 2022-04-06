#!/bin/bash
set -euo pipefail

__hostname_for_this=$1
__fqdn_this_cluster=$2

cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: cluster-issuer-subca
spec:
  ca:
    secretName: "$__fqdn_this_cluster"
EOF