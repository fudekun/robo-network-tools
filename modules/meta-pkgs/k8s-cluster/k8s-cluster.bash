#!/usr/bin/env bash
set -euo pipefail

###############################################################################
## Execute k8s-cluster(Meta-Package) configuration
###############################################################################

function showHeaderCommand() {
  local operating=${1^}
  echo ""
  echo "---"
  echo "## ${operating} k8s-cluster ..."
  return 0
}

## 1. Input Argument Checking
##
function checkArgs() {
  return $?
}

function main() {
  checkArgs "$@"
  local operation=${1}
  showHeaderCommand "${operation}"
  if [ "${operation}" = "create" ]; then
    source "$(dirname "${0}")/crud/create.bash"
    create "${@}"
  elif [ "${operation}" = "delete" ]; then
    source "$(dirname "${0}")/crud/delete.bash"
    delete "${@}"
  elif [ "${operation}" = "update" ]; then
    source "$(dirname "${0}")/crud/update.bash"
    update "${@}"
  else
    echo "Operation Not found"
    return 1
  fi
  return $?
}

## Set the base directory for RDBOX scripts!!
##
RDBOX_WORKDIR_OF_SCRIPTS_BASE=${RDBOX_WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
RDBOX_WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$RDBOX_WORKDIR_OF_SCRIPTS_BASE")
export RDBOX_WORKDIR_OF_SCRIPTS_BASE=$RDBOX_WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?