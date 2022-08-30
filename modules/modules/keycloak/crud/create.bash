#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a keycloak
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
  echo "### Create a namespace of keycloak ..."
  kubectl_r create namespace "${NAMESPACE}"
  ## 2. Install Keycloak
  ##
  echo ""
  echo "### Create a Keycloak ..."
  create_main
  ## 3. Setup preset-entries
  ##
  echo ""
  echo "### Activating realm entries of the keycloak ..."
  create_entries
  ## 4. Setup Authz
  ##
  echo ""
  echo "### Activating realm entries of the k8s RBAC ..."
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    keycloak.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    keycloak.dynamics.main.hostname="$(getHostName "${MODULE_NAME}" "main")" \
                    keycloak.dynamics.main.rbac.create="true" \
                    keycloak.dynamics.main.rbac.presetClusterAdminGroup="cluster" \
                    keycloak.dynamics.main.rbac.presetRegularGroup="guest"
  return $?
}

function create_main() {
  local hostname_for_keycloak_main
  local rootca_file
  local http_code
  ## 1. Create a Secret
  ##
  echo ""
  echo "### Activating Secret ..."
  if kubectl -n "${NAMESPACE}" get secret "${SPECIFIC_SECRETS}" 2>/dev/null; then
    echo "Already exist the secrets (${SPECIFIC_SECRETS}.${NAMESPACE}) ...ok"
  else
    local database_password
    database_password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')"
    kubectl_r -n "${NAMESPACE}" create secret generic "${SPECIFIC_SECRETS}" \
      --from-literal=adminPassword="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=managementPassword="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=postgres-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
      --from-literal=password="${database_password}" \
      --from-literal=databasePassword="${database_password}" \
      --from-literal=k8s-default-cluster-admin-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')"
        ### NOTE
        ### The postgresql-postgres-password is password for root user
        ### The postgresql-password is password for the unprivileged user
  fi
  ## 2. Install Keycloak
  ##
  echo ""
  echo "### Installing with helm ..."
  hostname_for_keycloak_main=$(getHostName "${MODULE_NAME}" "main")
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
    --version "${HELM_VERSION}" \
    --create-namespace \
    --wait \
    --timeout 600s \
    --description "CREATES_RELEASE_ID=r${CREATES_RELEASE_ID}" \
    --set commonAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
    --set ingress.hostname="${hostname_for_keycloak_main}.${BASE_FQDN}" \
    --set ingress.extraTls\[0\].hosts\[0\]="${hostname_for_keycloak_main}.${BASE_FQDN}" \
    --set ingress.annotations."cert-manager\.io/cluster-issuer"="cluster-issuer-ca.${BASE_FQDN}" \
    --set ingress.extraTls\[0\].secretName="${hostname_for_keycloak_main}.${BASE_FQDN}" \
    --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
    --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://"${hostname_for_keycloak_main}.${BASE_FQDN}" \
    -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  ## 3. Setup TLSContext
  ##
  echo ""
  echo "### Activating the TLSContext ..."
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    keycloak.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    keycloak.dynamics.main.hostname="${hostname_for_keycloak_main}" \
                    keycloak.dynamics.main.tlsContext.create="true"
      ### NOTE
      ### Tentative solution to the problem
      ### that TLSContext is not generated automatically from Ingress (v2.2.2)
  waitForSuccessOfCommand \
    "kubectl -n ${NAMESPACE} get secrets ${hostname_for_keycloak_main}.${BASE_FQDN}"
      ### NOTE
      ### Wait until SubCA is issued
  ## 4. Connection test
  ##   - be curl to the Ingress endpoin(GET)
  ##
  echo ""
  echo "### Testing to access the endpoint ..."
  rootca_file=$(getFullpathOfRootCA)
  http_code=$(waitForSuccessOfCommand \
              "curl -fs -w '%{http_code}' -o /dev/null --cacert ${rootca_file} https://${hostname_for_keycloak_main}.${BASE_FQDN}/")
  if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 299 ];then
    echo "The HTTP Status is ${http_code} ...ok"
    return 0
  else
    echo "The HTTP Status is ${http_code} ...ng"
    return 1
  fi
  return $?
}

function create_entries() {
  ## 1. Start a session
  ##
  local token user pass
  user=$(getPresetKeycloakSuperAdminName "${NAMESPACE}")
  pass=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
        -o jsonpath='{.data.adminPassword}' \
        | base64 --decode)
  token=$(get_access_token "master" "${user}" "${pass}")
  ### .1 Create a new realm
  ###    - A preset user and group, that is using for admin
  ###
  local admin_password
  local realm
  local first_name
  local last_name
  local fullname_array
  realm=$(getClusterName)
  IFS="-" read -r -a fullname_array <<< "$(getPresetClusterAdminUserName)"
  first_name=${fullname_array[1]}
  last_name=${fullname_array[0]}
  admin_password=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.k8s-default-cluster-admin-password}' | base64 -d)
  local cred_hash_array
  cred_hash_array=()
  while IFS='' read -r line; do cred_hash_array+=("$line"); done < <(getHashedPasswordByPbkdf2Sha256 "$admin_password")
  local salt hashed_salted_value hash_iterations
  salt=${cred_hash_array[0]}
  hashed_salted_value=${cred_hash_array[1]}
  hash_iterations=${cred_hash_array[2]}
  local secret_data credential_data
  secret_data="{\"value\":\"${hashed_salted_value}\",\"salt\":\"${salt}\"}"
  credential_data="{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":${hash_iterations}}"
  local src_filepath entry_json
  ###
  # if ! delete_entry "__NONE__" "${token}" "__NONE__" "${realm}"; then
  #   echo "The Client(${NAMESPACE}) is Not Found ...ok"
  # fi
  src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/realm.jq.json
  entry_json=$(parse_jq_temlate "${src_filepath}" \
                "cluster_name ${realm}" \
                "preset_group_name $(getPresetClusterAdminGroupName)" \
                "preset_cadmi_name $(getPresetClusterAdminUserName)" \
                "first_name ${first_name}" \
                "last_name ${last_name}" \
                "secret_data ${secret_data}" \
                "credential_data ${credential_data}" \
              )
  create_entry "__NONE__" "${token}" "__NONE__" "${entry_json}"
  ### .2 Create a new groups for test use
  ###
  # src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/groups.jq.json
  # entry_json=$(parse_jq_temlate "${src_filepath}" \
  #               "name guest" \
  #             )
  # create_entry "${realm}" "${token}" "groups" "${entry_json}"
  ### .2 Create a new users for test use
  ###
  local cred_hash_array
  cred_hash_array=()
  while IFS='' read -r line; do cred_hash_array+=("$line"); done < <(getHashedPasswordByPbkdf2Sha256 "password")
  local salt hashed_salted_value hash_iterations
  salt=${cred_hash_array[0]}
  hashed_salted_value=${cred_hash_array[1]}
  hash_iterations=${cred_hash_array[2]}
  local secret_data credential_data
  secret_data="{\"value\":\"${hashed_salted_value}\",\"salt\":\"${salt}\"}"
  credential_data="{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":${hash_iterations}}"
  ###
  src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/users.jq.json
  entry_json=$(parse_jq_temlate "${src_filepath}" \
                "username guest" \
                "first_name guest" \
                "last_name guest" \
                "totp" false\
                "secret_data ${secret_data}" \
                "credential_data ${credential_data}" \
                "group /guest/admin" \
              )
  create_entry "${realm}" "${token}" "users" "${entry_json}"
  ### .4 Create a new ClientScope(This name is the "groups". pointer the "oidc-group-membership-mapper")
  ###
  src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/client_scope.jq.json
  entry_json=$(cat "${src_filepath}")
  create_entry "${realm}" "${token}" "client-scopes" "${entry_json}"
  ## 2. Stop a session
  ##
  revoke_access_token "master" "${token}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"