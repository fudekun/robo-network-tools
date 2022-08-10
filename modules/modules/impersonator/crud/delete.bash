#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Deleting a impersonator
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
  ## 1. Delete impersonator
  echo ""
  echo "### Delete the impersonator ..."
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
  # echo ""
  # echo "### Deleting Helm ..."
  # helm -n "${NAMESPACE}" uninstall "${RELEASE}"
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
  ## 5. Delete context
  ##
  local ctx_name
  ctx_name=$(getKubectlContextName4SSO)
  if ! kubectl config delete-context "${ctx_name}" > /dev/null 2>&1; then
    echo "The Context(${ctx_name}) is Not Found ...ok"
  fi
  if ! kubectl config delete-user "${ctx_name}" 2>/dev/null; then
    echo "The UserContext(${ctx_name}) is Not Found ...ok"
  fi
  if ! kubectl config delete-cluster "${ctx_name}" 2>/dev/null; then
    echo "The ClusterContext(${ctx_name}) is Not Found ...ok"
  fi
  return $?
}

#######################################
# Delete a impersonator client by keycloak
# Globals:
#   NAMESPACE         namespace for impersonator
#   SPECIFIC_SECRETS  secret(v1) for impersonator
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