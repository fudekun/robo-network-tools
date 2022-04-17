#!/bin/bash
set -euo pipefail

main() {
  local __cluster_name
  local __workbase_dirs
  ## 0. Initialize WorkDir
  __cluster_name="$1"
  __workbase_dirs=$(initializeWorkdirOfWorkbase "$__cluster_name")
  ## 1. Create the k8s cluster
  script -q /dev/null "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}"/create_k8s-cluster.bash "$@" 2>&1 \
    | tee >(awk -F'\r' 'BEGIN{RS="\r\n" ; ORS="\n"}{print $NF; fflush()}' \
      > "$(echo "$__workbase_dirs" | awk -F ' ' '{print $2}')/rdbox.log")
}

## Set the base directory for RDBOX scripts!!
##
RDBOX_WORKDIR_OF_SCRIPTS_BASE=${RDBOX_WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
RDBOX_WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$RDBOX_WORKDIR_OF_SCRIPTS_BASE")
export RDBOX_WORKDIR_OF_SCRIPTS_BASE=$RDBOX_WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
showHeader
main "$@"
exit $?