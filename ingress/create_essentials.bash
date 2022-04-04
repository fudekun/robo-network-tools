#!/bin/bash
set -euo pipefail

###############################################################################
## Execute essentials(module) configuration
###############################################################################

## 0. Input Argument Checking
##
checkArgs() {
  local __flag_secret_operation="new-rootca" # or recycle(For Developpers)
  local __base_fqdn
  if [ $# -eq 1 ]; then
    if [ "$1" = "help" ]; then
      echo "# Args"
      echo "(opt)\${1} Specify if a previously generated self-signed certificate is to be reused"
      echo ""
      echo "# EnvironmentVariable"
      echo "  (recommend: Use automatic settings)"
      echo "| Name                          | e.g.                        |"
      echo "| :---------------------------- | :-------------------------- |"
      echo "| NAMESPACE_FOR_CERTMANAGER     | cert-manager                |"
      echo "| HOSTNAME_FOR_CERTMANAGER_MAIN | cert-manager                |"
      exit 1
    else
      __flag_secret_operation=$1
    fi
  fi
  echo "Mode: $__flag_secret_operation"
  __base_fqdn=$(getBaseFQDN)
  export BASE_FQDN=$__base_fqdn
  export FLAG_SECRET_OPERATION=$__flag_secret_operation
  return $?
}

## 1. Initialize
##
initializeEssentials() {
  echo ""
  echo "---"
  echo "## Initializing essentials ..."
  ## 1. Update Helm
  updateHelm
}

## 2. Install Cert-Manager
##
installCertManager() {
  ## 1. Install Cert-Manager
  ##
  NAMESPACE_FOR_CERTMANAGER=${NAMESPACE_FOR_CERTMANAGER:-$(getNamespaceName "cert_manager")}
  export NAMESPACE_FOR_CERTMANAGER=${NAMESPACE_FOR_CERTMANAGER}
  local __hostname_for_certmanager_main_from_cm
  __hostname_for_certmanager_main_from_cm=$(getHostName "cert_manager" "main")
  HOSTNAME_FOR_CERTMANAGER_MAIN=${__hostname_for_certmanager_main_from_cm:-$NAMESPACE_FOR_CERTMANAGER}
  export HOSTNAME_FOR_CERTMANAGER_MAIN=$HOSTNAME_FOR_CERTMANAGER_MAIN
    ## Environment Variable
  echo ""
  echo "---"
  echo "## Installing cert-manager ..."
  cmdWithLoding \
    "helm -n ${NAMESPACE_FOR_CERTMANAGER} upgrade --install ${HOSTNAME_FOR_CERTMANAGER_MAIN} jetstack/cert-manager \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f values_for_cert-manager-instance.yaml" \
    "Activating cert-manager"
  ## 2. Setup RootCA (You can recycle a previous RootCA certificates (For Developpers))
  ##
  local __history_dir
  __history_dir=$(getDirNameFor outputs)/.history.${BASE_FQDN}
  local __history_file=${__history_dir}/selfsigned-ca.${BASE_FQDN}.ca.yaml
  #export __history_file=$__history_file
  local __rootca_dir
  __rootca_dir=$(getDirNameFor outputs)/ca
  ROOTCA_FILE=${__rootca_dir}/${BASE_FQDN}.ca.crt
  export ROOTCA_FILE=${ROOTCA_FILE}
  echo ""
  echo "---"
  echo "## Setup RootCA and Specific Issuer ..."
  echo "Mode: $FLAG_SECRET_OPERATION"
  cmdWithLoding \
      "kubectl -n $NAMESPACE_FOR_CERTMANAGER apply -f values_for_cert-manager-issuer-rootca.yaml" \
      "Activating RootCA Issuer"
  if [ "$FLAG_SECRET_OPERATION" = "new-rootca" ]; then
    cmdWithLoding \
      "bash ./values_for_cert-manager-rootca.yaml.bash $NAMESPACE_FOR_CERTMANAGER $BASE_FQDN" \
      "Activating RootCA"
    while ! kubectl -n "$NAMESPACE_FOR_CERTMANAGER" get secret "$BASE_FQDN" 2>/dev/null; do
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
    mkdir -p "$__history_dir" "$__rootca_dir"
    chmod 0700 "$__history_dir" "$__rootca_dir"
    kubectl -n "$NAMESPACE_FOR_CERTMANAGER" get secrets "$BASE_FQDN" -o yaml > "$__history_file"
    kubectl -n "$NAMESPACE_FOR_CERTMANAGER" get secrets "$BASE_FQDN" -o json | jq -r '.data["ca.crt"]' | base64 -d > "$ROOTCA_FILE"
      # NOTE
      # Save the History file and the RootCA
  elif [ "$FLAG_SECRET_OPERATION" = "recycle" ]; then
    if [ -e "$__history_file" ]; then
      kubectl -n "$NAMESPACE_FOR_CERTMANAGER" apply -f "$__history_file"
    else
      echo "No history file found. Please generate a new RootCA."
      exit 1
    fi
  else
    if [ -e "$__history_file" ]; then
      kubectl -n "$NAMESPACE_FOR_CERTMANAGER" apply -f "$__history_file"
    else
      echo "No history file found. Please generate a new RootCA."
      exit 1
    fi
  fi
  echo -e "\033[32mok!\033[m Activating RootCA"
  ## 3. Setup Specific Issuer
  ##
  cmdWithLoding \
    "bash ./values_for_cert-manager-issuer-subca.yaml.bash $NAMESPACE_FOR_CERTMANAGER $BASE_FQDN" \
    "Activating Specific Issuer"
      # NOTE
      # ClusterIssuer is namespace independent
      # However, it depends on selfsigned-cacert
      #                        (Name of $BASE_FQDN, like rdbox.rdbox.172-16-0-110.nip.io)
  return $?
}

## 3. Install MetalLB
##
installMetalLB() {
  ## 1. Config MetalLB with L2 Mode
  ##
  NAMESPACE_FOR_METALLB=${NAMESPACE_FOR_METALLB:-$(getNamespaceName "metallb")}
  export NAMESPACE_FOR_METALLB=$NAMESPACE_FOR_METALLB
  local __hostname_for_metallb_main_from_cm
  __hostname_for_metallb_main_from_cm=$(getHostName "metallb" "main")
  HOSTNAME_FOR_METALLB_MAIN=${__hostname_for_certmanager_main_from_cm:-$NAMESPACE_FOR_CERTMANAGER}
  export HOSTNAME_FOR_METALLB_MAIN=$HOSTNAME_FOR_METALLB_MAIN
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
  ## 2. Install MetalLB Instance
  ##
  cmdWithLoding \
    "helm -n ${NAMESPACE_FOR_METALLB} upgrade --install ${HOSTNAME_FOR_METALLB_MAIN} metallb/metallb \
        --create-namespace \
        --wait \
        --timeout 600s \
        --set configInline.address-pools\[0\].addresses\[0\]=$__docker_network_range \
        -f values_for_metallb.yaml" \
    "Activating metallb"
  return $?
}

## 4. Install Ambassador
##
installAmbassador() {
  NAMESPACE_FOR_AMBASSADOR=${NAMESPACE_FOR_AMBASSADOR:-$(getNamespaceName "ambassador")}
  export NAMESPACE_FOR_AMBASSADOR=$NAMESPACE_FOR_AMBASSADOR
  local __hostname_for_ambassador_main_from_cm
  __hostname_for_ambassador_main_from_cm=$(getHostName "ambassador" "main")
  HOSTNAME_FOR_AMBASSADOR_MAIN=${__hostname_for_ambassador_main_from_cm:-$NAMESPACE_FOR_AMBASSADOR}
  export HOSTNAME_FOR_AMBASSADOR_MAIN=$HOSTNAME_FOR_AMBASSADOR_MAIN
  echo ""
  echo "---"
  echo "## Installing ambassador ..."
  ## 1. Install Ambassador's CRD
  ##
  local __aes_app_version
  __aes_app_version=$(curl -s https://api.github.com/repos/emissary-ingress/emissary/releases/latest | jq -r ".tag_name" | cut -b 2-)
  cmdWithLoding \
    "kubectl apply -f https://app.getambassador.io/yaml/edge-stack/${__aes_app_version}/aes-crds.yaml" \
    "Installing ambassador (CRD)"
  cmdWithLoding \
    "kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system" \
    "Activating ambassador (CRD)"
  ## 2. Install Ambassador Instance
  ##
  cmdWithLoding \
    "helm -n ${NAMESPACE_FOR_AMBASSADOR} upgrade --install ${HOSTNAME_FOR_AMBASSADOR_MAIN} edge-stack/edge-stack \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f values_for_ambassador-instance.yaml" \
    "Activating ambassador (Instance)"
  ## 3. Authenticate Ambassador Edge Stack with Kubernetes API
  ##
  ## References
  ## https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
  ##
  ##
  ## 1. Delete the openapi mapping from the Ambassador namespace
  ##
  # if ! bash -c "kubectl delete -n ${NAMESPACE_FOR_AMBASSADOR} ambassador-devportal-api"; then
  #   echo "CRD(ambassador-devportal-api) is Not Found ...ok"
  # fi
  ## 2. private key using root key of this clsters.
  ##
  local __hostname_for_ambassador_k8ssso_from_cm
  __hostname_for_ambassador_k8ssso_from_cm=$(getHostName "ambassador" "k8ssso")
  HOSTNAME_FOR_AMBASSADOR_K8SSSO=${__hostname_for_ambassador_k8ssso_from_cm}
  export HOSTNAME_FOR_AMBASSADOR_K8SSSO=${HOSTNAME_FOR_AMBASSADOR_K8SSSO}
  local __fqdn_for_ambassador_k8ssso=${HOSTNAME_FOR_AMBASSADOR_K8SSSO}.${BASE_FQDN}
  local __private_key_file=${TEMP_DIR}/${HOSTNAME_FOR_AMBASSADOR_K8SSSO}.key
  local __server_cert_file=${TEMP_DIR}/${HOSTNAME_FOR_AMBASSADOR_K8SSSO}.crt
  cmdWithLoding \
    "bash ./values_for_ambassador-k8ssso-subca.yaml.bash \
      ${NAMESPACE_FOR_AMBASSADOR} \
      ${__fqdn_for_ambassador_k8ssso} \
    " \
    "Issueing Private Key for ambassador (k8ssso)"
  while ! kubectl -n "${NAMESPACE_FOR_AMBASSADOR}" get secret "${__fqdn_for_ambassador_k8ssso}" 2>/dev/null; do
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
  kubectl -n "${NAMESPACE_FOR_AMBASSADOR}" get secrets "${__fqdn_for_ambassador_k8ssso}" -o json \
        | jq -r '.data["tls.key"]' \
        | base64 -d > "${__private_key_file}"
  ## 3. Create a file a CNF and a certificate signing request with the CNF file.
  ## 4. Same as above
  ##
  local __csr
  __csr=$(bash ./values_for_ambassador-k8ssso-csr.cnf.bash \
          "${HOSTNAME_FOR_AMBASSADOR_K8SSSO}" \
          "${__fqdn_for_ambassador_k8ssso}" \
          "${__private_key_file}" \
        | base64)
  ## 5. Create and apply the following YAML for a CertificateSigningRequest.
  ##
  cmdWithLoding \
    "bash values_for_ambassador-k8ssso-csr.yaml.bash \
      ${HOSTNAME_FOR_AMBASSADOR_K8SSSO} \
      ${__csr}" \
    "Activating CertificateSigningRequest"
  ## 6. Confirmation
  ##
  cmdWithLoding \
    "kubectl certificate approve ${HOSTNAME_FOR_AMBASSADOR_K8SSSO}" \
    "Approving CertificateSigningRequest"
  ## 7. Get the resulting certificate
  ##
  kubectl get csr "${HOSTNAME_FOR_AMBASSADOR_K8SSSO}" -o jsonpath="{.status.certificate}" \
        | base64 -d > "${__server_cert_file}"
  ## 8. Create a TLS Secret using our private key and public certificate.
  ##
  cmdWithLoding \
    "kubectl -n ${NAMESPACE_FOR_AMBASSADOR} create secret tls ${HOSTNAME_FOR_AMBASSADOR_K8SSSO} \
      --cert ${__server_cert_file} \
      --key ${__private_key_file} \
    " \
    "Exporting TLS Secret"
  ## 9. Create a Mapping and TLSContext and RBAC for the Kube API.
  ## 10. Same as above
  ##
  cmdWithLoding \
    "bash ./values_for_ambassador-k8ssso-endpoint.yaml.bash \
      ${HOSTNAME_FOR_AMBASSADOR_K8SSSO} \
      ${__fqdn_for_ambassador_k8ssso} \
      ${NAMESPACE_FOR_AMBASSADOR}" \
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
    "kubectl config set-cluster $(getContextName4Kubectl) \
      --server=https://${__fqdn_for_ambassador_k8ssso} \
      --certificate-authority=${__server_cert_file} \
      --embed-certs \
    " \
    "Setting Cluster Context"
  return $?
}

## 5. Install Keycloak
##
installKeycloak() {
  NAMESPACE_FOR_KEYCLOAK=${NAMESPACE_FOR_KEYCLOAK:-$(getNamespaceName "keycloak")}
  export NAMESPACE_FOR_KEYCLOAK=$NAMESPACE_FOR_KEYCLOAK
  local __hostname_for_ambassador_k8ssso_from_cm
  __hostname_for_ambassador_k8ssso_from_cm=$(getHostName "keycloak" "main")
  HOSTNAME_FOR_KEYCLOAK_MAIN=${__hostname_for_ambassador_k8ssso_from_cm:-$NAMESPACE_FOR_KEYCLOAK}
  export HOSTNAME_FOR_KEYCLOAK_MAIN=$HOSTNAME_FOR_KEYCLOAK_MAIN
  local __fqdn_for_keycloak_main=${HOSTNAME_FOR_KEYCLOAK_MAIN}.${BASE_FQDN}
  echo ""
  echo "---"
  echo "## Installing keycloak ..."
  ## 1. Config extra secrets
  ##
  cmdWithLoding \
    "kubectl create namespace ${NAMESPACE_FOR_KEYCLOAK}" \
    "Getting Ready keycloak"
  kubectl -n "$NAMESPACE_FOR_KEYCLOAK" create secret generic specific-secrets \
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
  ## 2. Install Keycloak
  ##
  cmdWithLoding \
    "helm -n ${NAMESPACE_FOR_KEYCLOAK} upgrade --install ${HOSTNAME_FOR_KEYCLOAK_MAIN} bitnami/keycloak \
        --wait \
        --timeout 600s \
        --set ingress.hostname=$__fqdn_for_keycloak_main \
        --set ingress.extraTls\[0\].hosts\[0\]=$__fqdn_for_keycloak_main \
        --set ingress.extraTls\[0\].secretName=$HOSTNAME_FOR_KEYCLOAK_MAIN \
        --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
        --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://$__fqdn_for_keycloak_main/auth \
        -f values_for_keycloak-instance.yaml" \
    "Activating keycloak"
  ## 3. Setup TLSContext
  ##
  cmdWithLoding \
    "bash ./values_for_tlscontext.yaml.bash \
        ${NAMESPACE_FOR_KEYCLOAK} \
        ${__fqdn_for_keycloak_main} \
      1> /dev/null" \
    "Activating TLSContext"
      # NOTE
      # Tentative solution to the problem
      # that TLSContext is not generated automatically from Ingress (v2.2.2)
  while ! kubectl -n "$NAMESPACE_FOR_KEYCLOAK" get secret "$HOSTNAME_FOR_KEYCLOAK_MAIN" 2>/dev/null; do
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
    "curl -fs --cacert ${ROOTCA_FILE} https://${__fqdn_for_keycloak_main}/auth/ >/dev/null 2>&1" \
    "Testing keycloak"
  ## 4. Setup preset-entries
  ##
  cmdWithLoding \
    "bash ./create_keycloak-entry.bash ${NAMESPACE_FOR_KEYCLOAK} ${ROOTCA_FILE} 1> /dev/null" \
    "Activating Keycloak-entries"
  return $?
}

## 6. Install Filter
##
installFilter() {
  local __fqdn_for_ambassador_k8ssso=${HOSTNAME_FOR_AMBASSADOR_K8SSSO}.${BASE_FQDN}
    # ambassador-k8ssso.rdbox.172-16-0-110.nip.io
  local __fqdn_for_keycloak_main=${NAMESPACE_FOR_KEYCLOAK}.${BASE_FQDN}
    # keycloak.rdbox.172-16-0-110.nip.io
  local __cluster_name
  __cluster_name=$(getClusterName)
    # rdbox
  local __jwks_uri=http://${HOSTNAME_FOR_KEYCLOAK_MAIN}.${NAMESPACE_FOR_KEYCLOAK}/auth/realms/${__cluster_name}/protocol/openid-connect/certs
    # https://keycloak.rdbox.172-16-0-110.nip.io/auth/realms/rdbox/protocol/openid-connect/certs
  echo ""
  echo "---"
  echo "## Installing filter ..."
  ## 1. Install Filter
  ##
  cmdWithLoding \
    "bash ./values_for_ambassador-k8ssso-filter.yaml.bash \
      ${HOSTNAME_FOR_AMBASSADOR_K8SSSO} \
      ${__fqdn_for_ambassador_k8ssso} \
      ${NAMESPACE_FOR_AMBASSADOR} \
      ${__jwks_uri} \
      " \
    "Activating filter"
  ## 2. Set Context
  ##
  local __ctx_name
  __ctx_name=$(getContextName4Kubectl)
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
  __ctx_name=$(getContextName4Kubectl)
  echo ""
  echo "---"
  echo "## The basic network modules has been installed. Check its status by running:"
  echo "  kubectl -n ${NAMESPACE_FOR_CERTMANAGER} get pod"
  echo "  kubectl -n ${NAMESPACE_FOR_METALLB} get pod"
  echo "  kubectl -n ${NAMESPACE_FOR_AMBASSADOR} get pod"
  echo "  kubectl -n ${NAMESPACE_FOR_KEYCLOAK} get pod"
  echo ""
  echo "---"
  echo "## Trust CA with your browser and operating system. Check its file:"
  echo "  openssl x509 -in ${ROOTCA_FILE} -text"
  echo "  ---"
  echo "  This information is for reference to trust The CA file:"
  echo "    (Windows) https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores"
  echo "    (MacOS  ) https://support.apple.com/guide/keychain-access/kyca2431/mac"
  echo "    (Ubuntu ) https://ubuntu.com/server/docs/security-trust-store"
  # ""
  # ---
  cat ./"${NAMESPACE_FOR_KEYCLOAK}".verifier_command.txt
  # ""
  echo ""
  echo "---"
  echo "## Execute the following command to run kubectl with single sign-on:"
  echo "  # Execute the following command"
  echo "  # This will open your default browser, and execute the login operation"
  echo "  kubectl config use-context ${__ctx_name}"
  echo "  kubectl get node          # whatever is okay, just choose the one you like"
  echo ""
  drawMaxColsSeparator "#" "34"
  return $?
}

main() {
  ## 0. Input Argument Checking
  ##
  checkArgs "$@"
  ## 1. Initializing
  ##
  initializeEssentials "$@"
  ## 2. Install Cert-Manager
  ##
  installCertManager
  ## 3. Install MetalLB
  ##
  installMetalLB
  ## 4. Install Ambassador
  ##
  installAmbassador
  ## 5. Install Keycloak
  ##
  installKeycloak
  ## 6. Install Filter
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