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

function showHeaderCommand() {
  local operating=${1^}
  echo ""
  echo "---"
  echo "## ${operating} ${MODULE_NAME} ..."
  cmdWithIndent "showParams $*"
  return $?
}

function showParams() {
  echo "---"
  printf "ARGS:\n%q (%s arg(s))\n" "$*" "$#"
  printf "ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x //')"
  echo ""
  echo NAMESPACE="${NAMESPACE}"
  echo RELEASE="${RELEASE}"
  echo BASE_FQDN="${BASE_FQDN}"
  echo "---"
  return $?
}

function main() {
  #######################################################
  local MODULE_NAME
  MODULE_NAME="${RDBOX_MODULE_NAME_IMPERSONATOR}"
  local NAMESPACE
  NAMESPACE="$(getNamespaceName "${MODULE_NAME}")"
  local RELEASE
  RELEASE="$(getReleaseName "${MODULE_NAME}")"
  local BASE_FQDN
  BASE_FQDN=$(getBaseFQDN)
  #######################################################
  local operation=${1}
  showHeaderCommand "${@}"
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