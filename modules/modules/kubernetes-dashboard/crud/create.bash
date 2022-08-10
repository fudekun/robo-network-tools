#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a kubernetes-dashboard
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
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### kubernetes-dashboard has been installed. Check its status by running:"
  echo "    kubectl -n ${NAMESPACE} get deployments -o wide"
  return $?
}

function __executor() {
  ## 0. Prepare Helm chart
  ##
  prepare_helm_repo
  ## 1. Create a namespace
  ##
  echo ""
  echo "### Create a namespace of kubernetes-dashboard ..."
  kubectl_r create namespace "${NAMESPACE}"
  ## 2. Create a dummy endpoint of kube-apiserver for the kubernetes-dashboard
  ##
  echo ""
  echo "### Create a specific kubeapi for kubernetes-dashboard ..."
  create_specific_kubeapi
  ## 3. Install kubernetes-dashboard
  ##
  echo ""
  echo "### Create a kubernetes-dashboard ..."
  create_main
  return $?
}

#######################################
# Create a specific kubeapi endpoint for kubernetes-dashboar
# Globals:
#   NAMESPACE         namespace for kubernetes-dashboard
#   SPECIFIC_SECRETS  secret(v1) for kubernetes-dashboard
# Arguments:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function create_specific_kubeapi() {
  local __hostname_for_k8s_dashboard
  local __hostname_for_k8ssso
  local __fqdn_for_k8s_dashboard_main
  local __clientTlsContext
  local __clientNamespace
  local __ca_full_path
  __hostname_for_k8s_dashboard=$(getHostName "${MODULE_NAME}" "main")
  echo ""
  echo "### Issueing cert for kubernetes-dashboard ..."
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    kubernetesDashboard.dynamics.main.hostname="${__hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.certificate.create="true"
  __fqdn_for_k8s_dashboard_main=${__hostname_for_k8s_dashboard}.${BASE_FQDN}
  waitForSuccessOfCommand \
    "kubectl -n ${NAMESPACE} get secrets ${__fqdn_for_k8s_dashboard_main}"
    ### NOTE
    ### Wait until cert is issued
  echo ""
  echo "### Activating k8s SSO Endpoint ..."
  __hostname_for_k8ssso=$(getHostName "${MODULE_NAME}" "k8ssso")
  __filterName=$(getHostName "${RDBOX_MODULE_NAME_IMPERSONATOR}" "main")-$(getHostName "${RDBOX_MODULE_NAME_IMPERSONATOR}" "k8ssso")
  __filterNamespace="$(getNamespaceName "${RDBOX_MODULE_NAME_IMPERSONATOR}")"
  __clientTlsContext=$(getHostName "${RDBOX_MODULE_NAME_IMPERSONATOR}" "main")-$(getHostName "${RDBOX_MODULE_NAME_IMPERSONATOR}" "k8ssso")
  __clientNamespace="$(getNamespaceName "${RDBOX_MODULE_NAME_IMPERSONATOR}")"
    ### NOTE
    ### Use the deployed single sign-on filter "k8ssso.ambassador"
    ### Therefore, a client certificate is specified
    ### This client certificate indicates the user to whom the Impersonate cluster role is bound
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    kubernetesDashboard.dynamics.main.hostname="${__hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.k8ssso.create="true" \
                    kubernetesDashboard.dynamics.k8ssso.hostname="${__hostname_for_k8ssso}" \
                    kubernetesDashboard.dynamics.k8ssso.filter.name="${__filterName}" \
                    kubernetesDashboard.dynamics.k8ssso.filter.namespace="${__filterNamespace}" \
                    kubernetesDashboard.dynamics.k8ssso.client.tlsContext="${__clientTlsContext}" \
                    kubernetesDashboard.dynamics.k8ssso.client.namespace="${__clientNamespace}"
  echo ""
  echo "### Testing k8s SSO Endpoint ..."
  __ca_full_path="${TEMP_DIR}"/tls.crt
  kubectl -n "${NAMESPACE}" get secrets "${__fqdn_for_k8s_dashboard_main}" \
    -o jsonpath="{.data.tls\.crt}" | base64 -d > "${__ca_full_path}"
  waitForSuccessOfCommand \
    "curl -fs --cacert ${__ca_full_path} \
      https://${__hostname_for_k8ssso}.${__fqdn_for_k8s_dashboard_main}/version" \
    | jq > /dev/null 2>&1
  echo "No errors were detected in the test"
    ### NOTE
    ### Connection test
  return $?
}

function create_main() {
  ## 1. Define the app version of kubernetes-dashboard
  ##
  local __app_version
  __app_version=$(curl -s "https://artifacthub.io/api/v1/packages/helm/${HELM_NAME}/${HELM_VERSION}" \
                | jq -r ".app_version")
  ## 2. Bind a specific ServiceAccount to the Helm application "kubernetes-dashboard"
  ##   - However, this is limited to cases where **a self-signed certificate is used**
  ##   - This Helm application(kubernetes-dashboard) accepts DI for service accounts via ".kube/config"
  ##   - Save the account information once as a file
  ##   - The above contents are imported into the cluster as a ConfigMap (use --from-file).
  ##
  ### .1 Create a service account with RBAC
  ###
  echo ""
  echo "### Create a service account with RBAC(kubernetes.dashboard) ..."
  kubectl_r apply \
    -f https://raw.githubusercontent.com/kubernetes/dashboard/v"${__app_version}"/aio/deploy/recommended/05_dashboard-rbac.yaml \
    -f https://raw.githubusercontent.com/kubernetes/dashboard/v"${__app_version}"/aio/deploy/recommended/01_dashboard-serviceaccount.yaml
  ### .2 Setup .kube/config
  ###
  local __name_cm_kubeconfig="kubeconfig"
  local __kubeconfig_file_name="values.kubeconfig.yaml"
  echo ""
  echo "### Activating kubeconfig ..."
  if ! kubectl -n "${NAMESPACE}" delete cm "${__name_cm_kubeconfig}" 2>/dev/null; then
    echo "The ${__name_cm_kubeconfig}.${NAMESPACE} is Not Found ...ok"
  fi
  local __hostname_for_k8ssso
  local __hostname_for_k8s_dashboard
  __hostname_for_k8s_dashboard=$(getHostName "${MODULE_NAME}" "main")
  __hostname_for_k8ssso=$(getHostName "${MODULE_NAME}" "k8ssso")
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/${MODULE_NAME}/subs/values.kubeconfig.bash" \
    "${NAMESPACE}" \
    "${__hostname_for_k8s_dashboard}" \
    "${__hostname_for_k8ssso}" \
    "${BASE_FQDN}" > "${TEMP_DIR}/${__kubeconfig_file_name}"
  ### .3 Create a ConfigMap from the file of .kube/config
  ###
  kubectl_r -n "${NAMESPACE}" create cm "${__name_cm_kubeconfig}" \
    --from-file "${TEMP_DIR}/${__kubeconfig_file_name}"
  ## 3. Install kubernetes-dashboard
  ##
  echo ""
  echo "### Installing with helm ..."
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
    --version "${HELM_VERSION}" \
    --create-namespace \
    --wait \
    --timeout 600s \
    --description "CREATES_RELEASE_ID=r${CREATES_RELEASE_ID}" \
    --set commonAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
    --set extraArgs\[0\]="--apiserver-host=https://${__hostname_for_k8ssso}.${__hostname_for_k8s_dashboard}.${BASE_FQDN}" \
    --set extraArgs\[1\]="--kubeconfig=/original-kubeconfig/${__kubeconfig_file_name}" \
    --set extraVolumes\[0\].secret.secretName="${__hostname_for_k8s_dashboard}.${BASE_FQDN}" \
    --set extraVolumes\[1\].configMap.name="${__name_cm_kubeconfig}" \
    -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  ## 4. Create a Ingress
  ##
  echo ""
  echo "### Activating Ingress ..."
  local __service_port
  __service_port=$(kubectl -n "${NAMESPACE}" get service "${RELEASE}" \
                  -o jsonpath="{.spec.ports[].port}")
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    kubernetesDashboard.dynamics.main.hostname="${__hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.ingress.create="true" \
                    kubernetesDashboard.dynamics.ingress.port="${__service_port}"
  ## 5. Create a Secret
  ##
  echo ""
  echo "### Activating Secret ..."
  kubectl_r -n "${NAMESPACE}" create secret generic "${SPECIFIC_SECRETS}" \
    --from-literal=client-secret="$(< /dev/urandom tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
  ## 6. Create a Entry
  ##
  echo ""
  echo "### Activating Entry ..."
  __create_entry
  ## 7. Create a Filter
  ##
  echo ""
  echo "### Activating Filter ..."
  __create_filter
  return $?
}

#######################################
# Create a kubernetes-dashboard client by keycloak
# Globals:
#   NAMESPACE         namespace for kubernetes-dashboard
#   SPECIFIC_SECRETS  secret(v1) for kubernetes-dashboard
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
# Create a kubernetes-dashboard Filter by the AES
# Access via OAuth2 Filter
#   - filterpolicy.getambassador.io
#   - filter.getambassador.io
# Globals:
#   NAMESPACE         namespace for kubernetes-dashboard
#   SPECIFIC_SECRETS  secret(v1) for kubernetes-dashboard
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
  local hostname_for_k8s_dashboard
  hostname_for_k8s_dashboard="$(getHostName "${MODULE_NAME}" "main")"
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    kubernetesDashboard.dynamics.main.hostname="${hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.filter.create="true" \
                    kubernetesDashboard.dynamics.filter.authorizationURL="${authorization_url}" \
                    kubernetesDashboard.dynamics.filter.secret="\"${secret}\""
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"