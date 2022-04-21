#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  showHeader
  return $?
}

function main() {
  showHeaderCommand
  cmdWithLoding \
    "executor $*" \
    "Deleteing Cluster"
  showVerifierCommand $?
}

function showVerifierCommand() {
  local result
  result=${1}
  showFooter "${result}"
  return $?
}

function executor() {
  cmdWithIndent "delete_all $*"
  return $?
}

function delete_all() {
  local __cluster_name
  local __ctx_name
  __cluster_name=${1}
  __ctx_name=$(getContextName4Kubectl)
  echo "Deleteing Context ..."
  if kubectl config use-context kind-"${__cluster_name}" > /dev/null 2>&1; then
    kubectl config use-context kind-"${__cluster_name}"
  fi
  if kubectl config delete-cluster "${__ctx_name}" > /dev/null 2>&1; then
    kubectl config delete-user "${__ctx_name}"
    kubectl config delete-context "${__ctx_name}"
  fi
  echo "Deleteing Cluster ..."
  kind delete cluster --name "${__cluster_name}" 2>&1
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?