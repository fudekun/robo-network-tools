#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing ${MODULE_NAME} ..."
  return $?
}

function checkArgs() {
  return $?
}

function create() {
  #######################################################
  local MODULE_NAME
  MODULE_NAME="${RDBOX_MODULE_NAME_IMPERSONATOR}"
  #######################################################
  local SPECIFIC_SECRETS
  SPECIFIC_SECRETS="specific-secrets"
  #######################################################
  showHeaderCommand "$@"
  #######
  update_cluster_info
  #######
  local NAMESPACE
  NAMESPACE="$(getNamespaceName "${MODULE_NAME}")"
  local RELEASE
  RELEASE="$(getReleaseName "${MODULE_NAME}")"
  local BASE_FQDN
  BASE_FQDN=$(getBaseFQDN)
  #######
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### **ContainerOS** Execute the following command to run kubectl with single sign-on:"
  echo "  ### **ContainerOS**"
  echo "  ### Access the URL included in the command execution result using a web browser of the host OS (e.g., Chrome)"
  echo "      And you should perform the login operation"
  echo "      - (If the message **Success SSO Login** is printed, the login was successful.)"
  echo "      - (It does not matter if negative wording such as Forbidden is included.)"
  echo "    rdbox login --name $(getClusterName)"
  echo ""
  echo ""
  echo "### If you want to operate your Kubernetes cluster from HostOS, also run the following command"
  echo "  ### **HostOS**"
  echo "  ### Execute the following command to run kubectl with single sign-on:"
  echo "  ### **HostOS** First, If you have not installed kubectl"
  echo "      References: https://kubernetes.io/docs/tasks/tools/#kubectl"
  echo "  ### **HostOS** Next, You need to install the krew(Plug-In manager for kubectl)"
  echo "      References: https://krew.sigs.k8s.io/docs/user-guide/quickstart/"
  echo "  ### **HostOS** Next, You need to install the oidc-login (krew's Plug-In)"
  echo "      References: https://github.com/int128/kubelogin"
  echo "  ### **HostOS** Finally, Execute the following command"
  echo "  ### Your default browser will launch and you should perform the login operation"
  echo "    kubectl config use-context $(getKubectlContextName4SSO)"
  echo "    kubectl get node          # whatever is okay, just choose the one you like"
  return $?
}

function __executor() {
  ## 1. Create a namespace
  ##
  echo ""
  echo "### Create a namespace of impersonator ..."
  kubectl_r create namespace "${NAMESPACE}"
  ## 2. Create a dummy endpoint of kube-apiserver for the impersonator
  ##
  echo ""
  echo "### Create a specific kubeapi for kubectl ..."
  create_specific_kubeapi
  ## 3. Set Cluster Context
  ##
  echo ""
  echo "### Setting Cluster Context ..."
  create_cluster_context
  ## 4. Create a Secret
  ##
  echo ""
  echo "### Activating Secret ..."
  kubectl_r -n "${NAMESPACE}" create secret generic "${SPECIFIC_SECRETS}" \
    --from-literal=k8s-default-cluster-sso-aes-secret="$(< /dev/urandom tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
    ### NOTE
    ### The k8s-default-cluster-sso-aes-secret is used for K8s SSO via ambassador
  ## 5. Setup preset-entries
  ##
  echo ""
  echo "### Activating impersonator entries of the keycloak ..."
  create_entries
  ## 6. Setup User Context
  ##
  echo ""
  echo "### Setting User Context ..."
  create_user_context
  ## 7. Install Filter
  ##
  echo ""
  echo "### Applying the filter for Impersonate-Group/User ..."
  local jwks_uri
  jwks_uri="https://$(getHostName "${RDBOX_MODULE_NAME_KEYCLOAK}" "main").${BASE_FQDN}/realms/$(getClusterName)/protocol/openid-connect/certs"
    ### NOTE
    ### https://keycloak.rdbox.172-16-0-110.nip.io/realms/rdbox/protocol/openid-connect/certs
  local hostname_for_impersonator_k8ssso
  hostname_for_impersonator_k8ssso="$(getHostName "${MODULE_NAME}" "main")-$(getHostName "${MODULE_NAME}" "k8ssso")"
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    impersonator.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    impersonator.dynamics.main.hostname="$(getHostName "${MODULE_NAME}" "main")" \
                    impersonator.dynamics.k8ssso.hostname="${hostname_for_impersonator_k8ssso}" \
                    impersonator.dynamics.k8ssso.filter.jwksUri="${jwks_uri}"
  ## 8. Set Context
  ##
  echo ""
  echo "### Setting Context ..."
  local ctx_name
  ctx_name=$(getKubectlContextName4SSO)
  if ! kubectl config delete-context "${ctx_name}" > /dev/null 2>&1; then
    echo "The Context(context) is Not Found ...ok"
  fi
  kubectl config set-context "${ctx_name}" \
      --cluster="${ctx_name}" \
      --user="${ctx_name}"
  return $?
}

#######################################
# Create a specific kubeapi endpoint for kubectl
#   -  Authenticate Ambassador Edge Stack with Kubernetes API
# Globals:
#   NAMESPACE
#   MODULE_NAME
#   BASE_FQDN
#   TEMP_DIR
#   CREATES_RELEASE_ID
#   BASE_FQDN
#   RELEASE
# Arguments:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
#######################################
function create_specific_kubeapi() {
  ### .1 Delete the openapi mapping from the Ambassador namespace
  ###
  if ! kubectl -n "${NAMESPACE}" delete ambassador-devportal-api 2>/dev/null; then
    echo "The openapi-mapping(ambassador-devportal-api.${NAMESPACE}) is Not Found ...ok"
  fi
  ### .2 private key using root key of this clsters.
  ###
  local __hostname_for_impersonator_k8ssso
  local __private_key_file
  local __server_cert_file
  local __aes_cert_file
  __hostname_for_impersonator_k8ssso=$(getHostName "${RELEASE}" "main")-$(getHostName "${RELEASE}" "k8ssso")
  __private_key_file=${TEMP_DIR}/${__hostname_for_impersonator_k8ssso}.key
  __server_cert_file=${TEMP_DIR}/${__hostname_for_impersonator_k8ssso}.crt
  __aes_cert_file=${TEMP_DIR}/aes_cert.crt
  echo ""
  echo "### Issueing Private Key for impersonator ..."
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    impersonator.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    impersonator.dynamics.main.hostname="$(getHostName "${RELEASE}" "main")" \
                    impersonator.dynamics.k8ssso.hostname="${__hostname_for_impersonator_k8ssso}" \
                    impersonator.dynamics.k8ssso.certificate.useCa="true"
  waitForSuccessOfCommand \
      "kubectl -n ${NAMESPACE} get secrets ${__hostname_for_impersonator_k8ssso}.${BASE_FQDN}"
    ### NOTE
    ### Wait until SubCA is issued
  kubectl -n "${NAMESPACE}" get secrets "${__hostname_for_impersonator_k8ssso}.${BASE_FQDN}" -o json \
      | jq -r '.data["tls.key"]' \
      | base64 -d \
      > "${__private_key_file}"
  kubectl -n "${NAMESPACE}" get secrets "${__hostname_for_impersonator_k8ssso}.${BASE_FQDN}" -o json \
      | jq -r '.data["tls.crt"]' \
      | base64 -d \
      > "${__aes_cert_file}"
    ### NOTE
    ### As a temporary file to issue CSRs
  ### .3 Create a file a CNF and a certificate signing request with the CNF file.
  ### .4 Same as above
  ###
  echo ""
  echo "### Activating CertificateSigningRequest ..."
  local __csr
  __csr="$(bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/${MODULE_NAME}/subs/k8ssso-csr.cnf.bash" \
                    "${__hostname_for_impersonator_k8ssso}" \
                    "${__hostname_for_impersonator_k8ssso}.${BASE_FQDN}" \
                    "${__private_key_file}" \
                    | base64 \
                    | tr -d '\n' \
                    | tr -d '\r' \
                    )"
  ### .5 Create and apply the following YAML for a CertificateSigningRequest.
  ###
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    impersonator.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    impersonator.dynamics.main.hostname="$(getHostName "${RELEASE}" "main")" \
                    impersonator.dynamics.k8ssso.hostname="${__hostname_for_impersonator_k8ssso}" \
                    impersonator.dynamics.k8ssso.certificateSigningRequest.request="${__csr}"
  ### .6 Confirmation
  ###
  echo ""
  echo "### Approving CertificateSigningRequest ..."
  kubectl certificate approve "${__hostname_for_impersonator_k8ssso}"
  ### .7 Get the resulting certificate
  ###
  echo ""
  echo "### Exporting TLS Secret ..."
  kubectl get csr "${__hostname_for_impersonator_k8ssso}" -o jsonpath="{.status.certificate}" \
      | base64 -d \
      > "${__server_cert_file}"
  ### .8 Create a TLS Secret using our private key and public certificate.
  ###
  if ! kubectl -n "${NAMESPACE}" delete secret "${__hostname_for_impersonator_k8ssso}" 2>/dev/null; then
    echo "The secret(${__hostname_for_impersonator_k8ssso}.${NAMESPACE}) is Not Found ...ok"
  fi
  kubectl_r -n "${NAMESPACE}" create secret tls "${__hostname_for_impersonator_k8ssso}" \
      --cert "${__server_cert_file}" \
      --key "${__private_key_file}"
  ### .9 Create a Mapping and TLSContext and RBAC for the Kube API.
  ### .10 Same as above
  ###
  echo ""
  echo "### Activating k8s SSO Endpoint ..."
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    impersonator.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    impersonator.dynamics.main.hostname="$(getHostName "${RELEASE}" "main")" \
                    impersonator.dynamics.k8ssso.hostname="${__hostname_for_impersonator_k8ssso}" \
                    impersonator.dynamics.k8ssso.endpoint.rbac.create="true"
  ### .11 As a quick check
  ###
  if kubectl -n "${NAMESPACE}" get filters "${__hostname_for_impersonator_k8ssso}" 2>/dev/null; then
    echo "already exist the filters (${__hostname_for_impersonator_k8ssso}.${NAMESPACE}) ...ok"
    echo "skip a quick check ...ok"
    return 0
  else
    echo "The filters(${__hostname_for_impersonator_k8ssso}.${NAMESPACE}) is Not Found ...ok"
    waitForSuccessOfCommand \
      "curl -fs --cacert ${__aes_cert_file} https://${__hostname_for_impersonator_k8ssso}.${BASE_FQDN}/api | jq"
    return $?
  fi
    ### NOTE
    ### Wait until to startup the Host
  return 0
}

#######################################
# Create a context for kubectl command
# Globals:
#   NAMESPACE         namespace for kubernetes-dashboard
#   MODULE_NAME
#   BASE_FQDN
#   TEMP_DIR
# Arguments:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function create_cluster_context() {
  local ctx_name
  ctx_name=$(getKubectlContextName4SSO)
  if ! kubectl config delete-cluster "${ctx_name}" 2>/dev/null; then
    echo "The ClusterContext(${ctx_name}.${NAMESPACE}) is Not Found ...ok"
  fi
  local hostname_for_impersonator_k8ssso
  local ctx_cert_file
  hostname_for_impersonator_k8ssso="$(getHostName "${RELEASE}" "main")-$(getHostName "${RELEASE}" "k8ssso")"
  ctx_cert_file=${TEMP_DIR}/ctx_cert.crt
  kubectl -n "${NAMESPACE}" get secrets "${hostname_for_impersonator_k8ssso}.${BASE_FQDN}" -o json \
      | jq -r '.data["tls.crt"]' \
      | base64 -d \
      > "${ctx_cert_file}"
  kubectl config set-cluster "${ctx_name}" \
      --server=https://"${hostname_for_impersonator_k8ssso}.${BASE_FQDN}" \
      --certificate-authority="${ctx_cert_file}" \
      --embed-certs
  return $?
}

function create_user_context() {
  local context
  local realm
  local secret
  context=$(getKubectlContextName4SSO)
  realm=$(getClusterName)
  secret=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.k8s-default-cluster-sso-aes-secret}' | base64 -d)
  if ! kubectl config delete-user "${context}" 2>/dev/null; then
    echo "The ClusterContext(${context}) is Not Found ...ok"
  fi
  local rootca_file
  rootca_file=$(getFullpathOfRootCA)
  kubectl config set-credentials "${context}" \
      --exec-api-version=client.authentication.k8s.io/v1beta1 \
      --exec-command=kubectl \
      --exec-arg=oidc-login \
      --exec-arg=get-token \
      --exec-arg=--oidc-issuer-url="$(get_authorization_url "${realm}")" \
      --exec-arg=--oidc-client-id="${NAMESPACE}" \
      --exec-arg=--oidc-client-secret="${secret}" \
      --exec-arg=--certificate-authority-data="$(< "${rootca_file}" base64 | tr -d '\n' | tr -d '\r')" \
      --exec-arg=--listen-address=0.0.0.0:8000
  return $?
}

function create_entries() {
  local namespace_for_keycloak
  namespace_for_keycloak="$(getNamespaceName "${RDBOX_MODULE_NAME_KEYCLOAK}")"
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
  local secret
  local src_filepath
  local entry_json
  src_filepath=$(getFullpathOfOnesBy "${MODULE_NAME}" confs entry)/client.jq.json
  secret=$(kubectl -n "${NAMESPACE}" get secrets "${SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.k8s-default-cluster-sso-aes-secret}' | base64 -d)
  entry_json=$(parse_jq_temlate "${src_filepath}" \
                "client_secret ${secret}" \
                "client_id ${NAMESPACE}" \
              )
  create_entry "${realm}" "${token}" "clients" "${entry_json}"
  ## 3. Stop a session
  ##
  revoke_access_token "master" "${token}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"