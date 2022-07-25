#!/usr/bin/env bash
set -euo pipefail

function main() {
  local __namespace_for_k8s_dashboard=$1
  local __hostname_for_k8s_dashboard_main=$2
  local __hostname_for_k8s_dashboard_k8ssso=$3
  local __base_fqdn=$4

  local __name
  local __token
  local __ca
  local __server
  __name=$(kubectl -n "${__namespace_for_k8s_dashboard}" get secrets -o name | grep "kubernetes-dashboard-token")
  __token=$(kubectl -n "${__namespace_for_k8s_dashboard}" get "${__name}" -o jsonpath='{.data.token}' | base64 --decode)
  __ca=$(kubectl -n cert-manager get secret "${__base_fqdn}" -o jsonpath='{.data.tls\.crt}')
  __server=https://${__hostname_for_k8s_dashboard_k8ssso}.${__hostname_for_k8s_dashboard_main}.${__base_fqdn}

  echo "---
apiVersion: v1
kind: Config
clusters:
- name: default-cluster
  cluster:
    certificate-authority-data: ${__ca}
    server: ${__server}
contexts:
- name: default-context
  context:
    cluster: default-cluster
    namespace: ${__namespace_for_k8s_dashboard}
    user: default-user
current-context: default-context
users:
- name: default-user
  user:
    token: ${__token}
"
}

main "$@"
exit $?