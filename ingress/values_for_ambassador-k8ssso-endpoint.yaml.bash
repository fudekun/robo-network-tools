#!/bin/bash
set -euo pipefail

__hostname_for_this=$1
  # ambassador-k8ssso
__fqdn_this_cluster=$2
  # ambassador-k8ssso.rdbox.172-16-0-110.nip.io
__rep_name=$3
  # ambassador

cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: getambassador.io/v3alpha1
kind: TLSContext
metadata:
  name: "$__hostname_for_this"
  namespace: "$__rep_name"
  labels:
    app.kubernetes.io/component: "$__hostname_for_this"
spec:
  hosts:
  - "$__fqdn_this_cluster"
  secret: "$__hostname_for_this"
---
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: "$__hostname_for_this"
  namespace: "$__rep_name"
  labels:
    app.kubernetes.io/component: "$__hostname_for_this"
spec:
  host: "$__fqdn_this_cluster"
  prefix: /
  allow_upgrade:
  - spdy/3.1
  service: https://kubernetes.default.svc
  timeout_ms: 0
  tls: "$__hostname_for_this"
---
apiVersion: getambassador.io/v3alpha1
kind: Host
metadata:
  name: "$__hostname_for_this"
  namespace: "$__rep_name"
  labels:
    app.kubernetes.io/component: "$__hostname_for_this"
spec:
  hostname: "$__fqdn_this_cluster"
  requestPolicy:
    insecure:
      action: Route
  tlsSecret:
    name: "$__hostname_for_this"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: "$__hostname_for_this"
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: "$__hostname_for_this"
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: "$__hostname_for_this"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: "$__hostname_for_this"
EOF