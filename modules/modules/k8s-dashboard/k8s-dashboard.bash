#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing k8s-dashboard ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "k8s-dashboard")"
  return $?
}

function showVerifierCommand() {
  local namespace
  namespace=$(getNamespaceName "k8s-dashboard")
  echo ""
  echo "## USAGE"
  echo "### k8s-dashboard has been installed. Check its status by running:"
  echo "    kubectl -n ${namespace} get deployments -o wide"
  return $?
}

function __executor() {
  local __SPECIFIC_SECRETS="specific-secrets"
  local __namespace_for_dashboard
  ## 1. Config extra secrets
  ##
  echo ""
  echo "### Setting Config of k8s-dashboard ..."
  __namespace_for_dashboard="$(getNamespaceName "k8s-dashboard")"
  if ! kubectl create namespace "${__namespace_for_dashboard}" 2>/dev/null; then
    echo "already exist the namespace (${__namespace_for_dashboard}) ...ok"
  fi
  if kubectl -n "${__namespace_for_dashboard}" get secret "${__SPECIFIC_SECRETS}" 2>/dev/null; then
    echo "already exist the secrets (${__SPECIFIC_SECRETS}.${__namespace_for_dashboard}) ...ok"
  else
    kubectl -n "${__namespace_for_dashboard}" create secret generic "${__SPECIFIC_SECRETS}" \
      --from-literal=k8s-default-cluster-sso-aes-secret="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')"
  fi
  ## 2. Setup a dummy endpoint of kube-apiserver for the k8s-dashboard
  ##
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?
