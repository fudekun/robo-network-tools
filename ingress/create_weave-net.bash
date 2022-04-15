#!/bin/bash
set -euo pipefail

showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing Weave-Net ..."
  return $?
}

main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor"
  showVerifierCommand > "$(getFullpathOfVerifyMsgs "weave-net")"
  return $?
}

showVerifierCommand() {
  echo ""
  echo "---"
  echo "## Weave-Net has been installed. Check its status by running:"
  echo "    kubectl -n kube-system get daemonsets weave-net -o wide"
  return $?
}

__executor() {
  kubectl apply -f https://cloud.weave.works/k8s/net?k8s-version="$(kubectl version | base64 | tr -d '\n')"
  kubectl wait --timeout=300s -n kube-system --for=condition=ready pod -l name=weave-net
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?