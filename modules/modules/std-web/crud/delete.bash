#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Deleting a std-web
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
  #######################################################
  local SPECIFIC_SECRETS
  SPECIFIC_SECRETS="specific-secrets"
  #######################################################
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
  ## 1. Delete std-web
  echo ""
  echo "### Delete the std-web ..."
  delete_main
  return $?
}

function delete_main() {
  ## 1. Delete a Entry
  ##
  echo ""
  echo "### Deleting Entry ..."
  __delete_entry
  ## 2. Delete manifest
  ##
  echo ""
  echo "### Deleting Manifest ..."
  local args
  IFS=' ' read -r -a args <<< "$(get_args_of_files_for_kubectl_delete)"
  kubectl delete "${args[@]}"
  ## 3. Purge this items from cluster-info
  ##
  echo ""
  echo "### Purging from ${__RDBOX_CLUSTER_INFO_NAMENAME}.${__RDBOX_CLUSTER_INFO_NAMESPACE} ..."
  purge_cluster_info
  return $?
}

#######################################
# Delete a std-web client by keycloak
# Globals:
#   NAMESPACE         namespace for std-web
#   SPECIFIC_SECRETS  secret(v1) for std-web
# Arguments:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function __delete_entry() {
  ## 1. Start a session
  ##
  local token
  local realm
  #token=$(get_access_token "master" "${user}" "${pass}")
  realm=$(getClusterName)
  token=$(get_access_token_of_sa "${realm}")
  ### 1. Delete a old client if they exist
  ###
  if ! delete_entry "${realm}" "${token}" "clients" "${NAMESPACE}"; then
    echo "The Client(${NAMESPACE}) is Not Found ...ok"
  fi
  ## 2. Stop a session
  ##
  revoke_access_token "master" "${token}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"