#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Deleting a grafana
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
  ## 1. Delete grafana
  echo ""
  echo "### Delete the grafana ..."
  delete_main
  return $?
}

function delete_main() {
  ## 1. Delete a Entry
  ##
  echo ""
  echo "### Deleting Entry ..."
  __delete_entry
  ## 2. Delete Helm
  ##
  echo ""
  echo "### Deleting Helm ..."
  helm -n "${NAMESPACE}" uninstall "${RELEASE}"
  ## 3. Delete manifest
  ##
  echo ""
  echo "### Deleting Manifest ..."
  local args
  IFS=' ' read -r -a args <<< "$(get_args_of_files_for_kubectl_delete)"
  kubectl delete "${args[@]}"
  ## 4. Purge this items from cluster-info
  ##
  echo ""
  echo "### Purging from ${__RDBOX_CLUSTER_INFO_NAMENAME}.${__RDBOX_CLUSTER_INFO_NAMESPACE} ..."
  purge_cluster_info
  return $?
}

#######################################
# Delete a grafana client by keycloak
# Globals:
#   NAMESPACE         namespace for grafana
#   SPECIFIC_SECRETS  secret(v1) for grafana
# Arguments:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function __delete_entry() {
  ## 1. Prepare various parameters
  ##
  local namespace_for_keycloak
  namespace_for_keycloak="$(getNamespaceName "keycloak")"
  local user
  local pass
  user=$(getPresetKeycloakSuperAdminName "${namespace_for_keycloak}")
  pass=$(kubectl -n "${namespace_for_keycloak}" get secrets "${SPECIFIC_SECRETS}" \
        -o jsonpath='{.data.adminPassword}' \
        | base64 --decode)
  ## 2. Start a session
  ##
  local token
  local realm
  token=$(get_access_token "master" "${user}" "${pass}")
  realm=$(getClusterName)
  ### 1. Delete a old client if they exist
  ###
  if ! delete_entry "${realm}" "${token}" "clients" "${NAMESPACE}"; then
    echo "The Client(${NAMESPACE}) is Not Found ...ok"
  fi
  ## 3. Stop a session
  ##
  revoke_access_token "master" "${token}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"