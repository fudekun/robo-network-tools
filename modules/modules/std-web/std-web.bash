#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Operating a std-web
# Globals:
#   RDBOX_MODULE_NAME_STD_WEB
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

# shellcheck disable=SC2317
function showParams() {
  echo "---"
  echo ""
  echo CLUSTER_NAME="${CLUSTER_NAME}"
  echo NAMESPACE="${NAMESPACE}"
  echo RELEASE="${RELEASE}"
  echo BASE_FQDN="${BASE_FQDN}"
  echo "---"
  return 0
}

function main() {
  local operation=${1}
  #######################################################
  local MODULE_NAME
  MODULE_NAME="${RDBOX_MODULE_NAME_STD_WEB}"
  if [ "${operation}" = "create" ]; then
    update_cluster_info
  fi
  ############################
  local CLUSTER_NAME
  CLUSTER_NAME=$(getClusterName)
  local NAMESPACE
  NAMESPACE="$(getNamespaceName "${MODULE_NAME}")"
  local RELEASE
  RELEASE="$(getReleaseName "${MODULE_NAME}")"
  local BASE_FQDN
  BASE_FQDN=$(getBaseFQDN)
  #######################################################
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

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?

