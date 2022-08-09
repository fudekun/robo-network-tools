#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Operating a impersonator
# Globals:
#   RDBOX_MODULE_NAME_IMPERSONATOR
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   CREATES_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function main() {
  #######################################################
  local MODULE_NAME
  MODULE_NAME="${RDBOX_MODULE_NAME_IMPERSONATOR}"
  echo "${MODULE_NAME}" > /dev/null 2>&1
  #######################################################
  local operation=${1}
  if [ "${operation}" = "create" ]; then
    source "$(dirname "${0}")/crud/create.bash"
    create "${*:2}"
  elif [ "${operation}" = "delete" ]; then
    source "$(dirname "${0}")/crud/delete.bash"
    delete "${*:2}"
  elif [ "${operation}" = "update" ]; then
    source "$(dirname "${0}")/crud/update.bash"
    update "${*:2}"
  else
    echo "Operation Not found"
    return 1
  fi
  return $?
}

TEMP_DIR=$(mktemp -d)
trap 'rm -rf $TEMP_DIR' EXIT

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?