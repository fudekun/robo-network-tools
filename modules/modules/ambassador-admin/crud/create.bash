#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a ambassador-admin
# Globals:
#   RDBOX_MODULE_NAME_AMBASSADOR_ADMIN
#   MODULE_NAME
#   NAMESPACE
#   RELEASE
#   HELM_NAME
#   HELM_REPO_NAME
#   HELM_PKG_NAME
#   HELM_VERSION
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   CREATES_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function checkArgs() {
  return $?
}

function create() {
  #######################################################
  local SPECIFIC_SECRETS
  SPECIFIC_SECRETS="specific-secrets"
  #######################################################
  if cmdWithIndent "executor $*"; then
    verify_string=$(showVerifierCommand)
    echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
    return 0
  else
    return 1
  fi
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### ${MODULE_NAME} has been installed. Check its status by running:"
  echo "    kubectl -n ${NAMESPACE} get deployments -o wide"
  return $?
}

function executor() {
  if __executor "${@}"; then
    exit 0
  else
    exit 1
  fi
}

function __executor() {
  ## 1. Create a namespace
  ##
  echo ""
  echo "### Create a namespace of ambassador-admin ..."
  kubectl_r create namespace "${NAMESPACE}"
  ## 2. Create a Secret
  ##
  echo ""
  echo "### Activating Secret ..."
  kubectl_r -n "${NAMESPACE}" create secret generic "${SPECIFIC_SECRETS}" \
    --from-literal=client-secret="$(< /dev/urandom tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
  ## 3. Create a Entry
  ##
  echo ""
  echo "### Activating Entry ..."
  __create_entry
  ## 4. Create a Filter
  ##
  echo ""
  echo "### Activating Filter ..."
  __create_filter
  return $?
}

#######################################
# Create a ambassador-admin client by keycloak
# Globals:
#   NAMESPACE         namespace for ambassador-admin
#   SPECIFIC_SECRETS  secret(v1) for ambassador-admin
# Arguments:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function __create_entry() {
  ## 1. Prepare various parameters
  ##
  local secret
  secret=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.client-secret}' | base64 -d)
  local redirectUris
  redirectUris="https://$(getHostName "${MODULE_NAME}" "main").${BASE_FQDN}/.ambassador/oauth2/redirection-endpoint"
  local src_filepath
  src_filepath=$(getFullpathOfOnesBy "${NAMESPACE}" confs entry)/client.jq.json
  local entry_json
  entry_json=$(parse_jq_temlate "${src_filepath}" \
                "clientId ${NAMESPACE}" \
                "redirectUris ${redirectUris}" \
                "secret ${secret}" \
              )
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
  ### 2. Create a new client
  ###
  create_entry "${realm}" "${token}" "clients" "${entry_json}"
  ## 3. Stop a session
  ##
  revoke_access_token "master" "${token}"
  return $?
}

#######################################
# Create a ambassador-admin Filter by the AES
# Access via OAuth2 Filter
#   - filterpolicy.getambassador.io
#   - filter.getambassador.io
# Globals:
#   NAMESPACE         namespace for ambassador-admin
#   SPECIFIC_SECRETS  secret(v1) for ambassador-admin
# Arguments:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://www.getambassador.io/docs/edge-stack/latest/topics/using/filters/oauth2/
#######################################
function __create_filter() {
  local realm
  realm=$(getClusterName)
  local authorization_url
  authorization_url=$(get_authorization_url "${realm}")
  local secret
  secret=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
                  -o jsonpath='{.data.client-secret}' | base64 -d)
  local hostname_for_this
  hostname_for_this="$(getHostName "${MODULE_NAME}" "main")"
  local release_ambassador ns_ambassador port_ambassador
  release_ambassador="$(getReleaseName "${RDBOX_MODULE_NAME_AMBASSADOR}")"
  ns_ambassador="$(getNamespaceName "${RDBOX_MODULE_NAME_AMBASSADOR}")"
  port_ambassador=$(kubectl -n "${ns_ambassador}" get service "${release_ambassador}-admin" -o json \
    | jq -r --arg name "${release_ambassador}-admin" '.spec.ports[] | select (.name==$name) | .port')
  local service_for_ambassador
  service_for_ambassador="http://${release_ambassador}-admin.${ns_ambassador}.svc:${port_ambassador}"
  local jwks_uri
  jwks_uri="https://$(getHostName "${RDBOX_MODULE_NAME_KEYCLOAK}" "main").${BASE_FQDN}/realms/$(getClusterName)/protocol/openid-connect/certs"
  local allowed_group
  allowed_group=$(getPresetClusterAdminGroupName)
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    ambassadorAdmin.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    ambassadorAdmin.dynamics.main.hostname="${hostname_for_this}" \
                    ambassadorAdmin.dynamics.certificate.create="true" \
                    ambassadorAdmin.dynamics.ingress.create="true" \
                    ambassadorAdmin.dynamics.ingress.service="${service_for_ambassador}" \
                    ambassadorAdmin.dynamics.filter.create="true" \
                    ambassadorAdmin.dynamics.filter.authorizationURL="${authorization_url}" \
                    ambassadorAdmin.dynamics.filter.secret="\"${secret}\"" \
                    ambassadorAdmin.dynamics.filter.jwksUri="${jwks_uri}" \
                    ambassadorAdmin.dynamics.filter.allowedGroup="${allowed_group}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"