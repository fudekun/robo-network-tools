#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Operating a grafana
# Globals:
#   RDBOX_MODULE_NAME_GRAFANA
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
  echo CLUSTER_NAME="${CLUSTER_NAME}"
  echo NAMESPACE="${NAMESPACE}"
  echo RELEASE="${RELEASE}"
  echo BASE_FQDN="${BASE_FQDN}"
  echo ""
  echo HELM_VERSION_SPECIFIED="${HELM_VERSION_SPECIFIED}"
  echo HELM_REPO_NAME="${HELM_REPO_NAME}"
  echo HELM_PKG_NAME="${HELM_PKG_NAME}"
  echo HELM_NAME="${HELM_NAME}"
  echo HELM_VERSION="${HELM_VERSION}"
  echo "---"
  return $?
}

function main() {
  local operation=${1}
  #######################################################
  local MODULE_NAME
  MODULE_NAME="${RDBOX_MODULE_NAME_GRAFANA}"
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
  ############################
  local HELM_VERSION_SPECIFIED
  HELM_VERSION_SPECIFIED=$(getHelmPkgVersion "${MODULE_NAME}")
  local HELM_REPO_NAME
  HELM_REPO_NAME=$(getHelmRepoName "${MODULE_NAME}")
  local HELM_PKG_NAME
  HELM_PKG_NAME=$(getHelmPkgName "${MODULE_NAME}")
  local HELM_NAME
  HELM_NAME="${HELM_REPO_NAME}/${HELM_PKG_NAME}"
  local HELM_VERSION
  HELM_VERSION=${HELM_VERSION_SPECIFIED:-$(curl -s https://artifacthub.io/api/v1/packages/helm/"${HELM_NAME}" | jq -r ".version")}
    ### NOTE
    ### If "HELM_VERSION_SPECIFIED" is not specified, the latest version retrieved from the Web is applied.
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

