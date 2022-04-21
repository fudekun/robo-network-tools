#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing ambassador ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "ambassador")"
  return $?
}

function showVerifierCommand() {
  local namespace
  namespace=$(getNamespaceName "ambassador")
  echo ""
  echo "## USAGE"
  echo "### ambassador has been installed. Check its status by running:"
  echo "    kubectl -n ${namespace} get deployments  -o wide"
  return $?
}

function __executor() {
  local __aes_app_version
  local __namespace_for_ambassador
  local __hostname_for_ambassador_main
  local __conf_of_helm
  ## 1. Install Ambassador's CRD
  ##
  echo ""
  echo "### Activating a CRD of the ambassador ..."
  __aes_app_version=$(curl -s https://api.github.com/repos/emissary-ingress/emissary/releases/latest \
                    | jq -r ".tag_name" \
                    | cut -b 2-)
  kubectl apply -f https://app.getambassador.io/yaml/edge-stack/"${__aes_app_version}"/aes-crds.yaml
  kubectl wait --timeout=180s --for=condition=available deployment emissary-apiext -n emissary-system
  ## 2. Install Ambassador Instance
  ##
  echo ""
  echo "### Installing with helm ..."
  __namespace_for_ambassador=$(getNamespaceName "ambassador")
  __hostname_for_ambassador_main=$(getHostName "ambassador" "main")
  __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_ambassador}" confs helm)
  helm -n "${__namespace_for_ambassador}" upgrade --install "${__hostname_for_ambassador_main}" edge-stack/edge-stack \
      --create-namespace \
      --wait \
      --timeout 600s \
      -f "${__conf_of_helm}"
  ## 3. Authenticate Ambassador Edge Stack with Kubernetes API
  ##
  ## References
  ## https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
  ##
  ##
  ## 1. Delete the openapi mapping from the Ambassador namespace
  ##
  if ! kubectl delete -n "${__namespace_for_ambassador}" ambassador-devportal-api 2>/dev/null; then
    echo "The openapi-mapping(ambassador-devportal-api) is Not Found ...ok"
  fi
  ## 2. private key using root key of this clsters.
  ##
  local __base_fqdn
  local __hostname_for_ambassador_k8ssso
  local __fqdn_for_ambassador_k8ssso
  local __private_key_file
  local __server_cert_file
  __base_fqdn=$(getBaseFQDN)
  __hostname_for_ambassador_k8ssso=$(getHostName "ambassador" "k8ssso")
  __fqdn_for_ambassador_k8ssso=${__hostname_for_ambassador_k8ssso}.${__base_fqdn}
  __private_key_file=${TEMP_DIR}/${__hostname_for_ambassador_k8ssso}.key
  __server_cert_file=${TEMP_DIR}/${__hostname_for_ambassador_k8ssso}.crt
  echo ""
  echo "### Issueing Private Key for ambassador ..."
  applyManifestByDI "${__namespace_for_ambassador}" \
                    "${__hostname_for_ambassador_k8ssso}" \
                    "${__RELEASE_ID}" \
                    90s \
                    ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                    ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                    ambassador.dynamics.k8ssso.certificate.useCa=true
  waitForSuccessOfCommand \
    "kubectl -n ${__namespace_for_ambassador} get secrets ${__fqdn_for_ambassador_k8ssso}"
    ### NOTE
    ### Wait until SubCA is issued
  kubectl -n "${__namespace_for_ambassador}" get secrets "${__fqdn_for_ambassador_k8ssso}" -o json \
      | jq -r '.data["tls.key"]' \
      | base64 -d \
      > "${__private_key_file}"
    ### NOTE
    ### As a temporary file to issue CSRs
  ## 3. Create a file a CNF and a certificate signing request with the CNF file.
  ## 4. Same as above
  ##
  echo ""
  echo "### Activating CertificateSigningRequest ..."
  local __csr
  __csr=$(bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_ambassador-k8ssso-csr.cnf.bash" \
      "${__hostname_for_ambassador_k8ssso}" \
      "${__fqdn_for_ambassador_k8ssso}" \
      "${__private_key_file}" | base64)
  ## 5. Create and apply the following YAML for a CertificateSigningRequest.
  ##
  applyManifestByDI "${__namespace_for_ambassador}" \
                    "${__hostname_for_ambassador_k8ssso}" \
                    "${__RELEASE_ID}" \
                    180s \
                    ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                    ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                    ambassador.dynamics.k8ssso.certificateSigningRequest.request="${__csr}"
  ## 6. Confirmation
  ##
  echo ""
  echo "### Approving CertificateSigningRequest ..."
  kubectl certificate approve "${__hostname_for_ambassador_k8ssso}"
  ## 7. Get the resulting certificate
  ##
  echo ""
  echo "### Exporting TLS Secret ..."
  kubectl get csr "${__hostname_for_ambassador_k8ssso}" -o jsonpath="{.status.certificate}" \
      | base64 -d \
      > "${__server_cert_file}"
  ## 8. Create a TLS Secret using our private key and public certificate.
  ##
  if ! kubectl -n "${__namespace_for_ambassador}" delete secret "${__hostname_for_ambassador_k8ssso}" 2>/dev/null; then
    echo "The secret(${__hostname_for_ambassador_k8ssso}.${__namespace_for_ambassador}) is Not Found ...ok"
  fi
  kubectl -n "${__namespace_for_ambassador}" create secret tls "${__hostname_for_ambassador_k8ssso}" \
      --cert "${__server_cert_file}" \
      --key "${__private_key_file}"
  ## 9. Create a Mapping and TLSContext and RBAC for the Kube API.
  ## 10. Same as above
  ##
  echo ""
  echo "### Activating k8s SSO Endpoint ..."
  applyManifestByDI "${__namespace_for_ambassador}" \
                    "${__hostname_for_ambassador_k8ssso}" \
                    "${__RELEASE_ID}" \
                    180s \
                    ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                    ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                    ambassador.dynamics.k8ssso.endpoint.rbac.create=true
  ## 11. As a quick check
  ##
  if kubectl -n "${__namespace_for_ambassador}" get filters "${__hostname_for_ambassador_k8ssso}" 2>/dev/null; then
    echo "already exist the filters (${__hostname_for_ambassador_k8ssso}.${__namespace_for_ambassador}) ...ok"
    echo "skip a quick check ...ok"
  else
    echo "The filters(${__hostname_for_ambassador_k8ssso}.${__namespace_for_ambassador}) is Not Found ...ok"
    waitForSuccessOfCommand \
      "curl -fs --cacert ${__server_cert_file} https://${__fqdn_for_ambassador_k8ssso}/api | jq"
  fi
    ### NOTE
    ### Wait until to startup the Host
  ## 12. Set Context
  echo ""
  echo "### Setting Cluster Context ..."
  local __ctx_name
  __ctx_name=$(getContextName4Kubectl)
  if ! kubectl config delete-cluster "${__ctx_name}" 2>/dev/null; then
    echo "The ClusterContext(cluster) is Not Found ...ok"
  fi
  kubectl config set-cluster "${__ctx_name}" \
      --server=https://"${__fqdn_for_ambassador_k8ssso}" \
      --certificate-authority="${__server_cert_file}" \
      --embed-certs
  return $?
}

TEMP_DIR=$(mktemp -d)
trap 'rm -rf $TEMP_DIR' EXIT

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?