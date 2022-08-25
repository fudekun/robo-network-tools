#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a grafana
# Globals:
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
  checkArgs "$@"
  if cmdWithIndent "executor $*"; then
    verify_string=$(showVerifierCommand)
    echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
    return 0
  else
    return 1
  fi
  return $?
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
  ## 0. Prepare Helm chart
  ##
  prepare_helm_repo
  ## 1. Create a namespace
  ##
  echo ""
  echo "### Create a namespace of grafana ..."
  kubectl_r create namespace "${NAMESPACE}"
  ## 2. Create a Secret
  ##
  echo ""
  echo "### Activating Secret ..."
  kubectl_r -n "${NAMESPACE}" create secret generic "${SPECIFIC_SECRETS}" \
    --from-literal=client-secret="$(< /dev/urandom tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
    ### NOTE
    ### create a client secret for keycloak
    ###
  local hostname
  hostname=$(getHostName "${MODULE_NAME}" "main")
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    grafana.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    grafana.dynamics.main.hostname="${hostname}" \
                    grafana.dynamics.certificate.create="true"
    ### NOTE
    ### create a server cert for this
    ###
  ## 3. Create a Entry
  ##
  echo ""
  echo "### Activating Entry ..."
  __create_entry
  ## 4. Install grafana-operator
  ##
  echo ""
  echo "### Installing with helm ..."
  local authorization_url secret
  authorization_url=$(get_authorization_url "${CLUSTER_NAME}")
    ### NOTE
    ### ex) https://keycloak.rdbox.172-16-0-110.nip.io/realms/rdbox
  secret=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.client-secret}' | base64 -d)
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
      --version "${HELM_VERSION}" \
      --create-namespace \
      --wait \
      --timeout 600s \
      --description "CREATES_RELEASE_ID=r${CREATES_RELEASE_ID}" \
      --set commonAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set grafana.config.server.root_url="https://${hostname}.${BASE_FQDN}" \
      --set grafana.config.auth\\.generic_oauth.client_id="${RELEASE}" \
      --set grafana.config.auth\\.generic_oauth.client_secret="${secret}" \
      --set grafana.config.auth\\.generic_oauth.auth_url="${authorization_url}/protocol/openid-connect/auth" \
      --set grafana.config.auth\\.generic_oauth.token_url="${authorization_url}/protocol/openid-connect/token" \
      --set grafana.config.auth\\.generic_oauth.api_url="${authorization_url}/protocol/openid-connect/userinfo" \
      --set grafana.config.auth\\.generic_oauth.tls_client_ca="/etc/grafana-secrets/${hostname}/ca.crt" \
      --set grafana.secrets\[0\]="${hostname}" \
      -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  ## 5. Setup Ingress and TLSContext
  ##
  echo ""
  echo "### Activating the Ingress and TLS ..."
  local port service
  port=$(kubectl -n "${NAMESPACE}" get service "${RELEASE}-service" -o json \
    | jq -r '.spec.ports[] | select (.name=="grafana") | .port')
  service="http://${RELEASE}-service.${NAMESPACE}.svc:${port}"
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    grafana.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    grafana.dynamics.main.hostname="${hostname}" \
                    grafana.dynamics.ingress.create="true" \
                    grafana.dynamics.ingress.service="${service}"
      ### NOTE
      ### Tentative solution to the problem
      ### that TLSContext is not generated automatically from Ingress (v2.2.2)
  ## ６. Setup GrafanaDataSource
  ##
  echo ""
  echo "### Activating the GrafanaDataSource ..."
  local release_prometheus hostname_prometheus_main url_prometheus_main
  release_prometheus=$(getReleaseName "${RDBOX_MODULE_NAME_PROMETHEUS}")
  hostname_prometheus_main=$(getHostName "${RDBOX_MODULE_NAME_PROMETHEUS}" "main")
  url_prometheus_main="https://${hostname_prometheus_main}.${BASE_FQDN}"
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    grafana.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    grafana.dynamics.main.hostname="${hostname}" \
                    grafana.dynamics.grafanaDataSource.create="true" \
                    grafana.dynamics.grafanaDataSource.name="${release_prometheus}" \
                    grafana.dynamics.grafanaDataSource.url="${url_prometheus_main}" \
                    grafana.dynamics.grafanaDataSource.secureJsonData.tlsCACert="__file\{/etc/grafana-secrets/${hostname}/ca.crt\}"
  return $?
}

#######################################
# Create a grafana-operator client by keycloak
# Globals:
#   NAMESPACE         namespace for grafana-operator
#   SPECIFIC_SECRETS  secret(v1) for grafana-operator
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
  redirectUris="https://$(getHostName "${MODULE_NAME}" "main").${BASE_FQDN}/login/generic_oauth"
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

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"