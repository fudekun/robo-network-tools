#!/bin/bash
set -euo pipefail

main() {
  ## 1. Initialize WorkDir
  local __cluster_name
  local __workbase_dirs
  local _logfile_path
  __cluster_name="$1"
  __workbase_dirs=$(initializeWorkdirOfWorkbase "$__cluster_name")
  __logfile_path=$(echo "$__workbase_dirs" | awk -F ' ' '{print $2}')/rdbox.log
  ## 0. Create the k8s cluster
  script -q /dev/null "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}"/.run_tasks.bash "$@" 2>&1 | \
    tee >(awk -F'\r' 'BEGIN{RS="\r\n" ; ORS="\n"}{print $NF; fflush()}' > "${__logfile_path}")
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