#!/bin/bash

deleteAll() {
  local __cluster_name
  __cluster_name=$(getClusterName)
  __cluster_name=${__cluster_name:-rdbox}
  local __ctx_name
  __ctx_name=$(getContextName4Kubectl)
  kubectl config use-context kind-"${__cluster_name}"
  kubectl config delete-cluster "${__ctx_name}"
  kubectl config delete-user "${__ctx_name}"
  kubectl config delete-context "${__ctx_name}"
  kind delete cluster --name "${__cluster_name}"
}

main() {
  cmdWithLoding \
    "deleteAll" \
    "Deleteing Cluster"
  return $?
}

## Set the base directory for RDBOX scripts!!
##
set -euo pipefail
RDBOX_WORKDIR_OF_SCRIPTS_BASE=${RDBOX_WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
RDBOX_WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$RDBOX_WORKDIR_OF_SCRIPTS_BASE")
export RDBOX_WORKDIR_OF_SCRIPTS_BASE=$RDBOX_WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
set +euo pipefail
main "$@"
exit $?