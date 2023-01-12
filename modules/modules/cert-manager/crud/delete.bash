#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Deleting a cert-manager
# Globals:
#   MODULE_NAME
#   NAMESPACE
#   RELEASE
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function checkArgs() {
  return $?
}

function delete() {
  checkArgs "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
  return 0
}

function showVerifierCommand() {
  return $?
}

function __executor() {
  ## 1. Delete cert-manager
  echo ""
  echo "### Delete the cert-manager ..."
  set +euo pipefail
  delete_main
  set -euo pipefail
  return $?
}

function delete_main() {
  ## 1. Delete manifest
  ##
  echo ""
  echo "### Deleting Manifest ..."
  local args
  IFS=' ' read -r -a args <<< "$(get_args_of_files_for_kubectl_delete)"
  kubectl delete "${args[@]}"
    ### NOTE
    ### Cert-Manager manifest depends on the CRD
    ### Therefore, it is processed first.
  ## 2. Delete Helm
  ##
  echo ""
  echo "### Deleting Helm ..."
  helm -n "${NAMESPACE}" uninstall "${RELEASE}"
  ## 3. Purge this items from cluster-info
  ##
  echo ""
  echo "### Purging from ${__RDBOX_CLUSTER_INFO_NAMENAME}.${__RDBOX_CLUSTER_INFO_NAMESPACE} ..."
  purge_cluster_info
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"