#!/bin/bash
set -euo pipefail

main() {
  local __workbase_dirs
  __workbase_dirs=$(initializeWorkdirOfWorkbase "$@")
  local _logfile_dir
  _logfile_path=$(echo "$__workbase_dirs" | awk -F ' ' '{print $2}')/rdbox.log
  ## 1. Create the k8s cluster
  script -q /dev/null "${WORKDIR_OF_SCRIPTS_BASE}"/run_tasks.bash "$@" 2>&1 | \
    tee >(awk -F'\r' 'BEGIN{RS="\r\n" ; ORS="\n"}{print $NF; fflush()}' > "${_logfile_path}")
}

## Set the base directory for RDBOX scripts!!
##
export WORKDIR_OF_SCRIPTS_BASE=${WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
  # Values can also be inserted externally
source "${WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
showHeader
main "$@"
exit $?