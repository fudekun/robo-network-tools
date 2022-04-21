#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing keycloak ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "keycloak")"
  return $?
}

function showVerifierCommand() {
  cat "$(getFullpathOfVerifyMsgs "$(getNamespaceName "keycloak")")"
  return $?
}

function __executor() {
  local __SPECIFIC_SECRETS="specific-secrets"
  local __namespace_for_keycloak
  local __base_fqdn
  local __hostname_for_keycloak_main
  local __fqdn_for_keycloak_main
  local __cluster_issuer
  local __conf_of_helm
  local __rootca_file
  local __http_code
  ## 1. Config extra secrets
  ##
  echo ""
  echo "### Setting Config of keycloak ..."
  __namespace_for_keycloak=$(getNamespaceName "keycloak")
  if ! kubectl create namespace "${__namespace_for_keycloak}" 2>/dev/null; then
    echo "already exist the namespace (${__namespace_for_keycloak}) ...ok"
  fi
  if kubectl -n "${__namespace_for_keycloak}" get secret "${__SPECIFIC_SECRETS}" 2>/dev/null; then
    echo "already exist the secrets (${__SPECIFIC_SECRETS}.${__namespace_for_keycloak}) ...ok"
  else
    kubectl -n "${__namespace_for_keycloak}" create secret generic "${__SPECIFIC_SECRETS}" \
      --from-literal=admin-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=management-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=postgresql-postgres-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=postgresql-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=tls-keystore-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=tls-truestore-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
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
  __base_fqdn=$(getBaseFQDN)
  __hostname_for_keycloak_main=$(getHostName "keycloak" "main")
  __fqdn_for_keycloak_main=${__hostname_for_keycloak_main}.${__base_fqdn}
  __cluster_issuer=cluster-issuer-ca."${__base_fqdn}"
  __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_keycloak}" confs helm)
  helm -n "${__namespace_for_keycloak}" upgrade --install "${__hostname_for_keycloak_main}" bitnami/keycloak \
    --create-namespace \
    --wait \
    --timeout 600s \
    --set ingress.hostname="${__fqdn_for_keycloak_main}" \
    --set ingress.extraTls\[0\].hosts\[0\]="${__fqdn_for_keycloak_main}" \
    --set ingress.annotations."cert-manager\.io/cluster-issuer"="${__cluster_issuer}" \
    --set ingress.extraTls\[0\].secretName="${__hostname_for_keycloak_main}" \
    --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
    --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://"${__fqdn_for_keycloak_main}/auth" \
    -f "${__conf_of_helm}"
  ## 3. Setup TLSContext
  ##
  echo ""
  echo "### Activating the TLSContext ..."
  applyManifestByDI "${__namespace_for_keycloak}" \
                    "${__hostname_for_keycloak_main}" \
                    "${__RELEASE_ID}" \
                    180s \
                    keycloak.dynamics.common.baseFqdn="${__base_fqdn}" \
                    keycloak.dynamics.main.hostname="${__hostname_for_keycloak_main}" \
                    keycloak.dynamics.main.tlsContext.create=true
      ### NOTE
      ### Tentative solution to the problem
      ### that TLSContext is not generated automatically from Ingress (v2.2.2)
  waitForSuccessOfCommand \
    "kubectl -n ${__namespace_for_keycloak} get secrets ${__hostname_for_keycloak_main}"
      ### NOTE
      ### Wait until SubCA is issued
  echo ""
  echo "### Testing to access the endpoint ..."
  __rootca_file=$(getFullpathOfRootCA)
  __http_code=$(waitForSuccessOfCommand \
              "curl -fs -w '%{http_code}' -o /dev/null --cacert ${__rootca_file} https://${__fqdn_for_keycloak_main}/auth/")
  echo "The HTTP Status is ${__http_code} ...ok"
    ### NOTE
    ### Use the RootCA (e.g. outputs/ca/rdbox.172-16-0-110.nip.io.ca.crt)
  ## 4. Setup preset-entries
  ##
  echo ""
  echo "### Activating essential entries of the keycloak ..."
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_keycloak-entry.bash" \
    "${__namespace_for_keycloak}" \
    "${__rootca_file}"
  ## 5. Setup Authz
  ##
  echo ""
  echo "### Setup the sample RBAC ..."
  applyManifestByDI "${__namespace_for_keycloak}" \
                    "${__hostname_for_keycloak_main}" \
                    "${__RELEASE_ID}" \
                    180s \
                    keycloak.dynamics.common.baseFqdn="${__base_fqdn}" \
                    keycloak.dynamics.main.hostname="${__hostname_for_keycloak_main}" \
                    keycloak.dynamics.main.rbac.create=true
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?