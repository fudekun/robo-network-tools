#!/bin/bash
set -euo pipefail

__hostname_for_this=$1
__base_fqdn=$2
__fqdn_this_cluster=$3

cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: "${__fqdn_this_cluster}"
  namespace: "${__hostname_for_this}"
spec:
  isCA: true
  commonName: "${__fqdn_this_cluster}"
  dnsNames:
    - "${__fqdn_this_cluster}"
  duration: 87600h
  secretName: "${__fqdn_this_cluster}"
  privateKey:
    algorithm: RSA
    size: 4096
  issuerRef:
    name: cluster-issuer-ca.${__base_fqdn}
    kind: ClusterIssuer
    group: cert-manager.io
EOF