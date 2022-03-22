#!/bin/bash
set -euo pipefail

__hostname_for_this=$1
__csr_base64=$2

cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $__hostname_for_this
spec:
  groups:
  - system:authenticated
  signerName: kubernetes.io/kube-apiserver-client
  request: $__csr_base64
  usages:
  - digital signature
  - key encipherment
  - client auth
EOF