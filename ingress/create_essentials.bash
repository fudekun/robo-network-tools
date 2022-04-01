#!/bin/bash
set -euo pipefail

###############################################################################
## Execute essentials(module) configuration
###############################################################################

## 0. Initializing
##
initializingEssentials() {
  ## 0-1. Input Argument Checking
  ##
  checkingArgs() {
    local __flag_secret_operation="new-rootca" # or recycle(For Developpers)
    local __base_fqdn
    if [ $# -eq 1 ]; then
      __flag_secret_operation=$1
    fi
    echo "Mode: $__flag_secret_operation"
    __base_fqdn=$(getBaseFQDN)
    export BASE_FQDN=$__base_fqdn
    export FLAG_SECRET_OPERATION=$__flag_secret_operation
    return $?
  }
  echo ""
  echo "---"
  echo "Initializing essentials ..."
  ## 0-1. Input Argument Checking
  ##
  checkingArgs "$@"
  ## 0-2. Update Helm
  updateHelm
}

## 1. Install Cert-Manager
##
installCertManager() {
  ## 1-1. Install Cert-Manager
  ##
  HOSTNAME_FOR_CERTMANAGER=${HOSTNAME_FOR_CERTMANAGER:-cert-manager}
  export HOSTNAME_FOR_CERTMANAGER=$HOSTNAME_FOR_CERTMANAGER
  HISTORY_DIR=${HISTORY_DIR:-.history.${BASE_FQDN}}
  HISTORY_FILE=${HISTORY_FILE:-${HISTORY_DIR}/selfsigned-ca.${BASE_FQDN}.ca.yaml}
  ROOTCA_FILE=${ROOTCA_FILE:-${BASE_FQDN}.ca.crt}
  export ROOTCA_FILE=${ROOTCA_FILE}
  echo ""
  echo "---"
  echo "Installing cert-manager ..."
  cmdWithLoding \
    "helm -n ${HOSTNAME_FOR_CERTMANAGER} upgrade --install ${HOSTNAME_FOR_CERTMANAGER} jetstack/cert-manager \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f values_for_cert-manager-instance.yaml" \
    "Activating cert-manager"
  ## 1-2. Setup RootCA (You can recycle a previous RootCA certificates (For Developpers))
  ##
  echo ""
  echo "---"
  echo "Setup RootCA and Specific Issuer ..."
  echo "Mode: $FLAG_SECRET_OPERATION"
  cmdWithLoding \
      "kubectl -n $HOSTNAME_FOR_CERTMANAGER apply -f values_for_cert-manager-issuer-rootca.yaml" \
      "Activating RootCA Issuer"
  if [ "$FLAG_SECRET_OPERATION" = "new-rootca" ]; then
    cmdWithLoding \
      "source ./values_for_cert-manager-rootca.yaml.bash $HOSTNAME_FOR_CERTMANAGER $BASE_FQDN" \
      "Activating RootCA"
    while ! kubectl -n "$HOSTNAME_FOR_CERTMANAGER" get secret "$BASE_FQDN" 2>/dev/null; do
      # NOTE
      # Wait until RootCA is issued
      echo -ne ".   waiting for the process to be completed\r"
      sleep 0.5
      echo -ne "..  waiting for the process to be completed\r"
      sleep 0.5
      echo -ne "... waiting for the process to be completed\r"
      sleep 0.5
      echo -ne "\r\033[K"
      echo -ne "    waiting for the process to be completed\r"
      sleep 0.5
    done
    mkdir -p "$HISTORY_DIR"
    chmod 0700 "$HISTORY_DIR"
    kubectl -n "$HOSTNAME_FOR_CERTMANAGER" get secrets "$BASE_FQDN" -o yaml > "$HISTORY_FILE"
    kubectl -n "$HOSTNAME_FOR_CERTMANAGER" get secrets "$BASE_FQDN" -o json | jq -r '.data["ca.crt"]' | base64 -d > "$ROOTCA_FILE"
      # NOTE
      # Save the History file and the RootCA
  elif [ "$FLAG_SECRET_OPERATION" = "recycle" ]; then
    if [ -e "$HISTORY_FILE" ]; then
      kubectl -n "$HOSTNAME_FOR_CERTMANAGER" apply -f "$HISTORY_FILE"
    else
      echo "No history file found. Please generate a new RootCA."
      exit 1
    fi
  else
    if [ -e "$HISTORY_FILE" ]; then
      kubectl -n "$HOSTNAME_FOR_CERTMANAGER" apply -f "$HISTORY_FILE"
    else
      echo "No history file found. Please generate a new RootCA."
      exit 1
    fi
  fi
  echo -e "\033[32mok!\033[m Activating RootCA"
  ## 1-3. Setup Specific Issuer
  ##
  cmdWithLoding \
    "source ./values_for_cert-manager-issuer-subca.yaml.bash $HOSTNAME_FOR_CERTMANAGER $BASE_FQDN" \
    "Activating Specific Issuer"
      # NOTE
      # ClusterIssuer is namespace independent
      # However, it depends on selfsigned-cacert
      #                        (Name of $BASE_FQDN, like rdbox.rdbox.172-16-0-110.nip.io)
  return $?
}

## 2. Install MetalLB
##
installMetalLB() {
  ## 2-1. Config MetalLB with L2 Mode
  ##
  HOSTNAME_FOR_METALLB=${HOSTNAME_FOR_METALLB:-metallb}
  export HOSTNAME_FOR_METALLB=$HOSTNAME_FOR_METALLB
  local __docker_network_ip
  local __docker_network_prefix
  local __docker_network_range
  echo ""
  echo "---"
  echo "Installing metallb ..."
  __docker_network_ip=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $1}')
  __docker_network_prefix=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $2}')
  if [ "$__docker_network_prefix" -le 16 ]; then
    __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s-%s.%s.%s", $1, $2, "255.200", $1, $2, "255.250"}')
  elif [ "$__docker_network_prefix" -gt 16 ] && [ "$__docker_network_prefix" -le 24 ]; then
    __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s.%s-%s.%s.%s.%s", $1, $2, $3, "200", $1, $2, $3, "250"}')
  else
    echo ""
    echo "---"
    echo "WARN: Your Docker network configuration is not expected;"
    echo "- You will need to execute the MetalLB configuration yourself."
    echo "- https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
    exit 1
  fi
  echo "MetalLB will reserve the following IP address ranges."
  echo "- $__docker_network_range"
  cmdWithLoding \
    "helm -n ${HOSTNAME_FOR_METALLB} upgrade --install ${HOSTNAME_FOR_METALLB} metallb/metallb \
        --create-namespace \
        --wait \
        --timeout 600s \
        --set configInline.address-pools\[0\].addresses\[0\]=$__docker_network_range \
        -f values_for_metallb.yaml" \
    "Activating metallb"
  return $?
}

## 3. Install Ambassador
##
installAmbassador() {
  HOSTNAME_FOR_AMBASSADOR=${HOSTNAME_FOR_AMBASSADOR:-ambassador}
  SUFFIX_FOR_AMBASSADOR_K8SSSO=${SUFFIX_FOR_AMBASSADOR_K8SSSO:-k8ssso}
  export HOSTNAME_FOR_AMBASSADOR=$HOSTNAME_FOR_AMBASSADOR
  export SUFFIX_FOR_AMBASSADOR_K8SSSO=$SUFFIX_FOR_AMBASSADOR_K8SSSO
  echo ""
  echo "---"
  echo "Installing ambassador ..."
  ## 3-1. Install Ambassador's CRD
  ##
  local __aes_app_version
  __aes_app_version=$(curl -s https://api.github.com/repos/emissary-ingress/emissary/releases/latest | jq -r ".tag_name" | cut -b 2-)
  cmdWithLoding \
    "kubectl apply -f https://app.getambassador.io/yaml/edge-stack/${__aes_app_version}/aes-crds.yaml" \
    "Installing ambassador (CRD)"
  cmdWithLoding \
    "kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system" \
    "Activating ambassador (CRD)"
  ## 3-2. Install Ambassador Instance
  ##
  cmdWithLoding \
    "helm -n ${HOSTNAME_FOR_AMBASSADOR} upgrade --install ${HOSTNAME_FOR_AMBASSADOR} edge-stack/edge-stack \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f values_for_ambassador-instance.yaml" \
    "Activating ambassador (Instance)"
  ## 3-3. Authenticate Ambassador Edge Stack with Kubernetes API
  ##
  ## References
  ## https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
  ##
  ##
  ## 1. Delete the openapi mapping from the Ambassador namespace
  ##
  if ! bash -c "kubectl delete -n ambassador ambassador-devportal-api"; then
    echo "CRD(ambassador-devportal-api) is Not Found ...ok"
  fi
  ## 2. private key using root key of this clsters.
  ##
  local __hostname_ambassador_k8ssso=${HOSTNAME_FOR_AMBASSADOR}-${SUFFIX_FOR_AMBASSADOR_K8SSSO}
  export HOSTNAME_AMBASSADOR_K8SSSO=${__hostname_ambassador_k8ssso}
  local __fqdn_for_ambassador_k8ssso=${__hostname_ambassador_k8ssso}.${BASE_FQDN}
  local __private_key_file=${TEMP_DIR}/${__hostname_ambassador_k8ssso}.key
  local __server_cert_file=${TEMP_DIR}/${__hostname_ambassador_k8ssso}.crt
  cmdWithLoding \
    "source ./values_for_ambassador-k8ssso-subca.yaml.bash \
      ${HOSTNAME_FOR_AMBASSADOR} \
      ${__fqdn_for_ambassador_k8ssso} \
    " \
    "Issueing Private Key for ambassador (k8ssso)"
  while ! kubectl -n "${HOSTNAME_FOR_AMBASSADOR}" get secret "${__fqdn_for_ambassador_k8ssso}" 2>/dev/null; do
    # NOTE
    # Wait until SubCA is issued
    echo -ne ".   waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "..  waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "... waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "\r\033[K"
    echo -ne "    waiting for the process to be completed\r"
    sleep 0.5
  done
  kubectl -n "${HOSTNAME_FOR_AMBASSADOR}" get secrets "${__fqdn_for_ambassador_k8ssso}" -o json \
        | jq -r '.data["tls.key"]' \
        | base64 -d > "${__private_key_file}"
  ## 3. Create a file a CNF and a certificate signing request with the CNF file.
  ## 4. Same as above
  ##
  local __csr
  __csr=$(source ./values_for_ambassador-k8ssso-csr.cnf.bash \
          "${__hostname_ambassador_k8ssso}" \
          "${__fqdn_for_ambassador_k8ssso}" \
          "${__private_key_file}" \
        | base64)
  ## 5. Create and apply the following YAML for a CertificateSigningRequest.
  ##
  cmdWithLoding \
    "source values_for_ambassador-k8ssso-csr.yaml.bash \
      ${__hostname_ambassador_k8ssso} \
      ${__csr}" \
    "Activating CertificateSigningRequest"
  ## 6. Confirmation
  ##
  cmdWithLoding \
    "kubectl certificate approve ${__hostname_ambassador_k8ssso}" \
    "Approving CertificateSigningRequest"
  ## 7. Get the resulting certificate
  ##
  kubectl get csr "${__hostname_ambassador_k8ssso}" -o jsonpath="{.status.certificate}" \
        | base64 -d > "${__server_cert_file}"
  ## 8. Create a TLS Secret using our private key and public certificate.
  ##
  cmdWithLoding \
    "kubectl -n ${HOSTNAME_FOR_AMBASSADOR} create secret tls ${__hostname_ambassador_k8ssso} \
      --cert ${__server_cert_file} \
      --key ${__private_key_file} \
    " \
    "Exporting TLS Secret"
  ## 9. Create a Mapping and TLSContext and RBAC for the Kube API.
  ## 10. Same as above
  ##
  cmdWithLoding \
    "source ./values_for_ambassador-k8ssso-endpoint.yaml.bash \
      ${__hostname_ambassador_k8ssso} \
      ${__fqdn_for_ambassador_k8ssso} \
      ${HOSTNAME_FOR_AMBASSADOR}" \
    "Activating k8s SSO Endpoint"
  ## 11. As a quick check
  ##
  while ! curl -fs --cacert "$__server_cert_file" https://"$__fqdn_for_ambassador_k8ssso"/api | jq 2>/dev/null; do
    # NOTE
    # Wait until to startup the Host
    echo -ne ".   waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "..  waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "... waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "\r\033[K"
    echo -ne "    waiting for the process to be completed\r"
    sleep 0.5
  done
  ## 12. Set Context
  cmdWithLoding \
    "kubectl config set-cluster $(getContextName) \
      --server=https://${__fqdn_for_ambassador_k8ssso} \
      --certificate-authority=${__server_cert_file} \
      --embed-certs \
    " \
    "Setting Cluster Context"
  return $?
}

## 4. Install Keycloak
##
installKeycloak() {
  HOSTNAME_FOR_KEYCLOAK=${HOSTNAME_FOR_KEYCLOAK:-keycloak}
  export HOSTNAME_FOR_KEYCLOAK=$HOSTNAME_FOR_KEYCLOAK
  local __fqdn_for_keycloak=${HOSTNAME_FOR_KEYCLOAK}.${BASE_FQDN}
  echo ""
  echo "---"
  echo "Installing keycloak ..."
  ## 4-1. Config extra secrets
  ##
  cmdWithLoding \
    "kubectl create namespace ${HOSTNAME_FOR_KEYCLOAK}" \
    "Getting Ready keycloak"
  kubectl -n "$HOSTNAME_FOR_KEYCLOAK" create secret generic specific-secrets \
    --from-literal=admin-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
    --from-literal=management-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
    --from-literal=postgresql-postgres-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
    --from-literal=postgresql-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
    --from-literal=tls-keystore-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
    --from-literal=tls-truestore-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
    --from-literal=k8s-default-cluster-admin-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
    --from-literal=k8s-default-cluster-sso-aes-secret="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')"
      # NOTE
      # The postgresql-postgres-password is password for root user
      # The postgresql-password is password for the unprivileged user
      # The k8s-default-cluster-sso-aes-secret is used for K8s SSO via ambassador
  ## 4-2. Install Keycloak
  ##
  cmdWithLoding \
    "helm -n ${HOSTNAME_FOR_KEYCLOAK} upgrade --install ${HOSTNAME_FOR_KEYCLOAK} bitnami/keycloak \
        --wait \
        --timeout 600s \
        --set ingress.hostname=$__fqdn_for_keycloak \
        --set ingress.extraTls\[0\].hosts\[0\]=$__fqdn_for_keycloak \
        --set ingress.extraTls\[0\].secretName=$HOSTNAME_FOR_KEYCLOAK \
        --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
        --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://$__fqdn_for_keycloak/auth \
        -f values_for_keycloak-instance.yaml" \
    "Activating keycloak"
  ## 4-3. Setup TLSContext
  ##
  cmdWithLoding \
    "source ./values_for_tlscontext.yaml.bash \
        ${HOSTNAME_FOR_KEYCLOAK} \
        ${__fqdn_for_keycloak} \
      1> /dev/null" \
    "Activating TLSContext"
      # NOTE
      # Tentative solution to the problem
      # that TLSContext is not generated automatically from Ingress (v2.2.2)
  while ! kubectl -n "$HOSTNAME_FOR_KEYCLOAK" get secret "$HOSTNAME_FOR_KEYCLOAK" 2>/dev/null; do
    # NOTE
    # Wait until SubCA is issued
    echo -ne ".   waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "..  waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "... waiting for the process to be completed\r"
    sleep 0.5
    echo -ne "\r\033[K"
    echo -ne "    waiting for the process to be completed\r"
    sleep 0.5
  done
  cmdWithLoding \
    "curl -fs --cacert ${ROOTCA_FILE} https://${__fqdn_for_keycloak}/auth/ >/dev/null 2>&1" \
    "Testing keycloak"
  ## 4-4. Setup preset-entries
  ##
  cmdWithLoding \
    "source ./create_keycloak-entry.bash ${HOSTNAME_FOR_KEYCLOAK} ${ROOTCA_FILE} 1> /dev/null" \
    "Activating Keycloak-entries"
  return $?
}

## 5. Install Filter
##
installFilter() {
  local __hostname_ambassador_k8ssso=${HOSTNAME_AMBASSADOR_K8SSSO}
    # ambassador-k8ssso
  local __fqdn_for_ambassador_k8ssso=${__hostname_ambassador_k8ssso}.${BASE_FQDN}
    # ambassador.rdbox.172-16-0-110.nip.io
  local __hostname_for_ambassador=${HOSTNAME_FOR_AMBASSADOR}
    # ambassador
  local __hostname_for_keycloak=${HOSTNAME_FOR_KEYCLOAK}
    # keycloak
  local __fqdn_for_keycloak=${__hostname_for_keycloak}.${BASE_FQDN}
    # keycloak.rdbox.172-16-0-110.nip.io
  local __cluster_name
  __cluster_name=$(getClusterName)
    # rdbox
  local __jwks_uri=http://${__hostname_for_keycloak}.${__hostname_for_keycloak}/auth/realms/${__cluster_name}/protocol/openid-connect/certs
    # https://keycloak.rdbox.172-16-0-110.nip.io/auth/realms/rdbox/protocol/openid-connect/certs
  echo ""
  echo "---"
  echo "Installing filter ..."
  ## Install Filter
  ##
  cmdWithLoding \
    "source ./values_for_ambassador-k8ssso-filter.yaml.bash \
      ${__hostname_ambassador_k8ssso} \
      ${__fqdn_for_ambassador_k8ssso} \
      ${__hostname_for_ambassador} \
      ${__jwks_uri} \
      " \
    "Activating filter"
  ## Set Context
  ##
  local __ctx_name
  __ctx_name=$(getContextName)
  cmdWithLoding \
    "kubectl config set-context ${__ctx_name} \
      --cluster=${__ctx_name} \
      --user=${__ctx_name} \
    " \
    "Setting Cluster Context"
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  local __ctx_name
  __ctx_name=$(getContextName)
  echo ""
  echo "---"
  echo "The basic network modules has been installed. Check its status by running:"
  echo "  kubectl -n ${HOSTNAME_FOR_CERTMANAGER} get pod"
  echo "  kubectl -n ${HOSTNAME_FOR_METALLB} get pod"
  echo "  kubectl -n ${HOSTNAME_FOR_AMBASSADOR} get pod"
  echo "  kubectl -n ${HOSTNAME_FOR_KEYCLOAK} get pod"
  echo ""
  echo "---"
  echo "Trust CA with your browser and operating system. Check its file:"
  echo "  openssl x509 -in ${ROOTCA_FILE} -text"
  echo "  ---"
  echo "  This information is for reference to trust The CA file:"
  echo "    (Windows) https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores"
  echo "    (MacOS  ) https://support.apple.com/guide/keychain-access/kyca2431/mac"
  echo "    (Ubuntu ) https://ubuntu.com/server/docs/security-trust-store"
  # ""
  # ---
  cat ./"${HOSTNAME_FOR_KEYCLOAK}".verifier_command.txt
  # ""
  echo ""
  echo "---"
  echo "Execute the following command to run kubectl with single sign-on:"
  echo "  # Execute the following command"
  echo "  # This will open your default browser, and execute the login operation"
  echo "  kubectl config use-context ${__ctx_name}"
  echo "  kubectl get node          # whatever is okay, just choose the one you like"
  echo ""
  drawMaxColsSeparator "#" "34"
  return $?
}

main() {
  ## 0. Initializing
  ##
  initializingEssentials "$@"
  ## 1. Install Cert-Manager
  ##
  installCertManager
  ## 2. Install MetalLB
  ##
  installMetalLB
  ## 3. Install Ambassador
  ##
  installAmbassador
  ## 4. Install Keycloak
  ##
  installKeycloak
  ## 5. Install Filter
  ##
  installFilter
  ## 99. Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

TEMP_DIR=$(mktemp -d)
trap 'rm -rf $TEMP_DIR' EXIT

source ./create_common.bash
main "$@"
exit $?