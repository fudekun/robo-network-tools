#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Operating a cluster-info
# Globals:
#   RDBOX_MODULE_NAME_CLUSTER_INFO
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   CREATES_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function showHeaderCommand() {
  local operating=${1^}
  echo ""
  echo "---"
  echo "## ${operating} ${MODULE_NAME} ..."
  return 0
}

function main() {
  #######################################################
  ## Define version of the manifest
  ##
  readonly __VERSION_OF_MANIFEST="v1beta1"
  ##
  local MODULE_NAME
  MODULE_NAME="${RDBOX_MODULE_NAME_CLUSTER_INFO}"
  #######################################################
  showHeaderCommand "${@}"
  local operation=${1}
  if [ "${operation}" = "create" ]; then
    source "$(dirname "${0}")/crud/create.bash"
    create "${@:2}"
  elif [ "${operation}" = "delete" ]; then
    source "$(dirname "${0}")/crud/delete.bash"
    delete "${@:2}"
  elif [ "${operation}" = "update" ]; then
    source "$(dirname "${0}")/crud/update.bash"
    update "${@:2}"
  else
    echo "Operation Not found"
    return 1
  fi
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?

