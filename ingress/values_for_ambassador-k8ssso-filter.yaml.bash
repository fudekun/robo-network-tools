#!/bin/bash
set -euo pipefail

__hostname_for_this=$1
  # ambassador-k8ssso
__fqdn_this_cluster=$2
  # ambassador-k8ssso.rdbox.172-16-0-110.nip.io
__rep_name=$3
  # ambassador
__jwks_uri=$4
  # https://keycloak.rdbox.172-16-0-110.nip.io/auth/realms/rdbox/protocol/openid-connect/certs


cat <<EOF | kubectl apply --timeout 90s --wait -f -
---
apiVersion: getambassador.io/v3alpha1
kind: Filter
metadata:
  name: "$__hostname_for_this"
  namespace: "$__rep_name"
spec:
  JWT:
    jwksURI: "$__jwks_uri"
    injectRequestHeaders:
    - name: "Impersonate-User"
      value: "{{ .token.Claims.preferred_username }}"
    - name: "Impersonate-Group"
      value: "{{range .token.Claims.groups}}{{ . }}{{end}}"
---
apiVersion: getambassador.io/v3alpha1
kind: FilterPolicy
metadata:
  name: "$__hostname_for_this"
  namespace: "$__rep_name"
spec:
  rules:
  - host: "$__fqdn_this_cluster"
    path: "*"
    filters:
    - name: "$__hostname_for_this"
EOF