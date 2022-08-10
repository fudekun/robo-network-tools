#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Deleting a metallb
# Globals:
#   MODULE_NAME
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Deleting ${MODULE_NAME} ..."
  return $?
}

function checkArgs() {
  return $?
}

function delete() {
  #######################################################
  local SPECIFIC_SECRETS
  SPECIFIC_SECRETS="specific-secrets"
  #######################################################
  showHeaderCommand "$@"
  local NAMESPACE
  NAMESPACE="$(getNamespaceName "${MODULE_NAME}")"
  local RELEASE
  RELEASE="$(getReleaseName "${MODULE_NAME}")"
  local BASE_FQDN
  BASE_FQDN=$(getBaseFQDN)
  #######
  checkArgs "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
  return $?
}

function showVerifierCommand() {
  return $?
}

function __executor() {
  ## 0. Prepare Helm chart
  ##
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
  # prepare_helm_repo
  ## 1. Delete metallb
  echo ""
  echo "### Delete the metallb ..."
  delete_main
  return $?
}

function delete_main() {
  ## 1. Delete a Entry
  ##
  # echo ""
  # echo "### Deleting Entry ..."
  # __delete_entry
  ## 3. Delete manifest
  ##
  echo ""
  echo "### Deleting Manifest ..."
  local args
  IFS=' ' read -r -a args <<< "$(get_args_of_files_for_kubectl_delete)"
  kubectl delete "${args[@]}"
  ## 2. Delete Helm
  ##
  echo ""
  echo "### Deleting Helm ..."
  helm -n "${NAMESPACE}" uninstall "${RELEASE}"
  ## 4. Purge this items from cluster-info
  ##
  echo ""
  echo "### Purging from ${__RDBOX_CLUSTER_INFO_NAMENAME}.${__RDBOX_CLUSTER_INFO_NAMESPACE} ..."
  purge_cluster_info
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"