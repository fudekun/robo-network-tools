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
  local base_url
  base_url=https://$(helm -n "${NAMESPACE}" get values "${RELEASE}" -o json | jq -r '.ingress.hostname')
  echo ""
  echo "## USAGE"
  echo "### The basic keycloak entry has been inserted. Check its status by running:"
  echo "  ### For all realms"
  echo "  ${base_url}/admin"
  echo "    echo Username: \$(helm -n ${NAMESPACE} get values ${RELEASE} -o json | jq -r '.auth.adminUser')"
  echo "    echo Password: \$(kubectl -n ${NAMESPACE} get secrets ${SPECIFIC_SECRETS} -o jsonpath='{.data.adminPassword}' | base64 --decode)"
  echo "  ### For this k8s cluster only (ClusterName: $(getClusterName))"
  echo "  ${base_url}/realms/$(getClusterName)/protocol/openid-connect/auth?client_id=security-admin-console"
  echo "    echo Username: $(getPresetClusterAdminUserName "${MODULE_NAME}")"
  echo "    echo Password: \$(kubectl -n ${NAMESPACE} get secrets ${SPECIFIC_SECRETS} -o jsonpath='{.data.k8s-default-cluster-admin-password}' | base64 --decode)"
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
  __create_entry
  ## 5. Set Context
  ##
  local context
  local realm
  local secret
  context=$(getKubectlContextName4SSO)
  realm=$(getClusterName)
  secret=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.k8s-default-cluster-sso-aes-secret}' | base64 -d)
  echo ""
  echo "### Setting Cluster Context ..."
  if ! kubectl config delete-user "${context}" 2>/dev/null; then
    echo "The ClusterContext(${context}) is Not Found ...ok"
  fi
  kubectl config set-credentials "${context}" \
      --exec-api-version=client.authentication.k8s.io/v1beta1 \
      --exec-command=kubectl \
      --exec-arg=oidc-login \
      --exec-arg=get-token \
      --exec-arg=--oidc-issuer-url="$(get_authorization_url "${realm}")" \
      --exec-arg=--oidc-client-id=ambassador \
      --exec-arg=--oidc-client-secret="${secret}" \
      --exec-arg=--certificate-authority-data="$(< "${__rootca_file}" base64 | tr -d '\n' | tr -d '\r')" \
      --exec-arg=--listen-address=0.0.0.0:8000
  ## 6. Setup Authz
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

function __create_entry() {
  ## 1. Prepare various parameters
  ##
  local admin_password
  local realm
  local first_name
  local last_name
  local fullname_array
  #---
  local src_filepath
  local entry_json
  realm=$(getClusterName)
  IFS="-" read -r -a fullname_array <<< "$(getPresetClusterAdminUserName)"
  first_name=${fullname_array[1]}
  last_name=${fullname_array[0]}
  admin_password=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.k8s-default-cluster-admin-password}' | base64 -d)
  # secret_data=$(generate_secret "${admin_password}")
  local cred_hash_array
  cred_hash_array=()
  while IFS='' read -r line; do cred_hash_array+=("$line"); done < <(getHashedPasswordByPbkdf2Sha256 "$admin_password")
  local salt
  local hashed_salted_value
  local hash_iterations
  salt=${cred_hash_array[0]}
  hashed_salted_value=${cred_hash_array[1]}
  hash_iterations=${cred_hash_array[2]}
  local secret_data
  local credential_data
  secret_data="{\"value\":\"${hashed_salted_value}\",\"salt\":\"${salt}\"}"
  credential_data="{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":${hash_iterations}}"
  #
  src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/realm.jq.json
  entry_json=$(parse_jq_temlate "${src_filepath}" \
                "cluster_name ${realm}" \
                "preset_group_name $(getPresetClusterAdminGroupName)" \
                "preset_cadmi_name $(getPresetClusterAdminUserName)" \
                "first_name ${first_name}" \
                "last_name ${last_name}" \
                "secret_data ${secret_data}" \
                "credential_data ${credential_data}"
              )
  local user
  local pass
  user=$(getPresetKeycloakSuperAdminName "${NAMESPACE}")
  pass=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
        -o jsonpath='{.data.adminPassword}' \
        | base64 --decode)
  ## 2. Start a session
  ##
  local token
  token=$(get_access_token "master" "${user}" "${pass}")
  ### .1 Create a new realm
  ###
  create_entry "__NONE__" "${token}" "__NONE__" "${entry_json}"
  ### .2 Create a new ClientScope(This name is the "groups". pointer the "oidc-group-membership-mapper")
  ###
  src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/client_scope.jq.json
  entry_json=$(cat "${src_filepath}")
  create_entry "${realm}" "${token}" "client-scopes" "${entry_json}"
  ### .3 Create a new Client(ambassador)
  ###
  local secret
  secret=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.k8s-default-cluster-sso-aes-secret}' | base64 -d)
  echo "${secret}"
  src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/client.jq.json
  entry_json=$(parse_jq_temlate "${src_filepath}" \
                "client_secret ${secret}" \
                "client_id ambassador" \
              )
  create_entry "${realm}" "${token}" "clients" "${entry_json}"
  ## 3. Stop a session
  ##
  revoke_access_token "master" "${token}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"
main "$@"
exit $?