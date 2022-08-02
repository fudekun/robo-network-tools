#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a keycloak
# Globals:
#   RDBOX_MODULE_NAME_KEYCLOAK
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   ESSENTIALS_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing ${MODULE_NAME} ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  #######################################################
  local MODULE_NAME
  MODULE_NAME="${RDBOX_MODULE_NAME_KEYCLOAK}"
  local NAMESPACE
  NAMESPACE="$(getNamespaceName "${MODULE_NAME}")"
  local RELEASE
  RELEASE="$(getReleaseName "${MODULE_NAME}")"
  local BASE_FQDN
  BASE_FQDN=$(getBaseFQDN)
  local HELM_NAME
  HELM_NAME="bitnami/keycloak"
  local HELM_VERSION_SPECIFIED
  HELM_VERSION_SPECIFIED="9.6.0"
  local HELM_VERSION
  HELM_VERSION=${HELM_VERSION_SPECIFIED:-$(curl -s https://artifacthub.io/api/v1/packages/helm/${HELM_NAME} | jq -r ".version")}
    ### NOTE
    ### If "HELM_VERSION_SPECIFIED" is not specified, the latest version retrieved from the Web is applied.
  #######################################################
  local SPECIFIC_SECRETS
  SPECIFIC_SECRETS="specific-secrets"
  #######################################################
  showHeaderCommand "$@"
  checkArgs "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
  return $?
}

function showVerifierCommand() {
  cat "$(getFullpathOfVerifyMsgs "$(getNamespaceName "${MODULE_NAME}")")"
  return $?
}

function __executor() {
  local __hostname_for_keycloak_main
  local __fqdn_for_keycloak_main
  local __rootca_file
  local __http_code
  ## 1. Config extra secrets
  ##
  echo ""
  echo "### Create a namespace of keycloak ..."
  kubectl_r create namespace "${NAMESPACE}"
  if kubectl -n "${NAMESPACE}" get secret "${SPECIFIC_SECRETS}" 2>/dev/null; then
    echo "already exist the secrets (${SPECIFIC_SECRETS}.${NAMESPACE}) ...ok"
  else
    echo ""
    echo "### Activating Secret ..."
    local database_password
    database_password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')"
    kubectl_r -n "${NAMESPACE}" create secret generic "${SPECIFIC_SECRETS}" \
      --from-literal=adminPassword="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=managementPassword="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=postgres-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=password="${database_password}" \
      --from-literal=databasePassword="${database_password}" \
      --from-literal=k8s-default-cluster-admin-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=k8s-default-cluster-sso-aes-secret="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')"
        ### NOTE
        ### The postgresql-postgres-password is password for root user
        ### The postgresql-password is password for the unprivileged user
        ### The k8s-default-cluster-sso-aes-secret is used for K8s SSO via ambassador
  fi
  ## 2. Install Keycloak
  ##
  echo ""
  echo "### Installing with helm ..."
  __hostname_for_keycloak_main=$(getHostName "keycloak" "main")
  __fqdn_for_keycloak_main=${__hostname_for_keycloak_main}.${BASE_FQDN}
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
    --version "${HELM_VERSION}" \
    --create-namespace \
    --wait \
    --timeout 600s \
    --set ingress.hostname="${__fqdn_for_keycloak_main}" \
    --set ingress.extraTls\[0\].hosts\[0\]="${__fqdn_for_keycloak_main}" \
    --set ingress.annotations."cert-manager\.io/cluster-issuer"="cluster-issuer-ca.${BASE_FQDN}" \
    --set ingress.extraTls\[0\].secretName="${__fqdn_for_keycloak_main}" \
    --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
    --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://"${__fqdn_for_keycloak_main}" \
    -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  ## 3. Setup TLSContext
  ##
  echo ""
  echo "### Activating the TLSContext ..."
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${ESSENTIALS_RELEASE_ID}" \
                    180s \
                    keycloak.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    keycloak.dynamics.main.hostname="${__hostname_for_keycloak_main}" \
                    keycloak.dynamics.main.tlsContext.create="true"
      ### NOTE
      ### Tentative solution to the problem
      ### that TLSContext is not generated automatically from Ingress (v2.2.2)
  waitForSuccessOfCommand \
    "kubectl -n ${NAMESPACE} get secrets ${__fqdn_for_keycloak_main}"
      ### NOTE
      ### Wait until SubCA is issued
  echo ""
  echo "### Testing to access the endpoint ..."
  __rootca_file=$(getFullpathOfRootCA)
  __http_code=$(waitForSuccessOfCommand \
              "curl -fs -w '%{http_code}' -o /dev/null --cacert ${__rootca_file} https://${__fqdn_for_keycloak_main}/")
  echo "The HTTP Status is ${__http_code} ...ok"
    ### NOTE
    ### Use the RootCA (e.g. outputs/ca/rdbox.172-16-0-110.nip.io.ca.crt)
  ## 4. Setup preset-entries
  ##
  echo ""
  echo "### Activating essential entries of the keycloak ..."
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/keycloak/subs/entry.bash" \
    "${NAMESPACE}" \
    "${__rootca_file}"
  ## 5. Setup Authz
  ##
  echo ""
  echo "### Setup the sample RBAC ..."
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${ESSENTIALS_RELEASE_ID}" \
                    180s \
                    keycloak.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    keycloak.dynamics.main.hostname="${__hostname_for_keycloak_main}" \
                    keycloak.dynamics.main.rbac.create="true"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?