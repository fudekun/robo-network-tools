#!/bin/bash
set -euo pipefail

__hostname_for_this=$1
__fqdn_for_this=$2

cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: getambassador.io/v3alpha1
kind: TLSContext
metadata:
  name: ${__hostname_for_this}
  namespace: ${__hostname_for_this}
spec:
  hosts:
    - ${__fqdn_for_this}
  secret: ${__hostname_for_this}
EOF