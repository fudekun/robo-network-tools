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

# shellcheck disable=SC2317
function create_error_handler() {
  local cluster=${1}
  local module=${2}
  cmdWithIndent "echo ''"
  cmdWithIndent "echo Error detected"
  cmdWithIndent "echo Rollback in progress ..."
  if bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}"/main.rdbox delete --name "${cluster}" --module "${module}" > /dev/null 2>&1; then
    cmdWithIndent "echo Rollback succeeded"
  else
    cmdWithIndent "echo Rollback failed"
  fi
  cmdWithIndent "echo ''"
}

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
  printf "ARGS:\n%q (%s arg(s))\n" "$*" "$#"
  printf "ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x //')"
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
  MODULE_NAME="${RDBOX_MODULE_NAME_IMPERSONATOR}"
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
    # shellcheck disable=SC2064
    trap "create_error_handler '${CLUSTER_NAME}' '${MODULE_NAME}'" ERR
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