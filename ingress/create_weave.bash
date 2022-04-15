#!/bin/bash
set -euo pipefail

header() {
  echo ""
  echo "---"
  echo "## Installing Weave-Net ..."
}

main() {
  set -x
  kubectl apply -f https://cloud.weave.works/k8s/net?k8s-version="$(kubectl version | base64 | tr -d '\n')"
  kubectl wait --timeout=300s -n kube-system --for=condition=ready pod -l name=weave-net
  return $?
  set +x
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
header "$@"
cmdWithIndent "main"
exit $?