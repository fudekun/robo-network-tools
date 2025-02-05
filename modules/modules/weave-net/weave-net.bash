#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing the weave-net ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "weave-net")"
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### Weave-Net has been installed. Check its status by running:"
  echo "    kubectl -n kube-system get daemonsets weave-net -o wide"
  return $?
}

function __executor() {
  kubectl apply -f https://github.com/weaveworks/weave/releases/download/v2.8.1/weave-daemonset-k8s.yaml
  kubectl wait --timeout=300s -n kube-system --for=condition=ready pod -l name=weave-net
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?