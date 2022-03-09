#!/bin/bash
set -euo pipefail

__hostname_for_certmanager=$1
__fqdn_this_cluster=$2

cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: selfsigned-cacert
  namespace: ${__hostname_for_certmanager}
spec:
  isCA: true
  commonName: "${__fqdn_this_cluster}"
  dnsNames:
    - "${__fqdn_this_cluster}"
    - "*.${__fqdn_this_cluster}"
  duration: 8760h
  secretName: selfsigned-cacert
  privateKey:
    algorithm: RSA
    size: 4096
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
    group: cert-manager.io
EOF
    # NOTE
    # ClusterIssuer is namespace independent