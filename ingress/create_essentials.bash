#!/bin/bash
set -euo pipefail

###############################################################################
## Execute essentials(module) configuration
###############################################################################

## 0. Initializing
##
initializingEssentials() {
  echo ""
  echo "---"
  echo "Initializing essentials ..."
  ## 0-1. Input Argument Checking
  ##
  checkingArgs "$@"
  ## 0-2. Update Helm
  updateHelm
}

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
      "kubectl -n $HOSTNAME_FOR_CERTMANAGER apply -f values_for_cert-manager-caissuer.yaml" \
      "Activating RootCA Issuer"
  if [ "$FLAG_SECRET_OPERATION" = "new-rootca" ]; then
    cmdWithLoding \
      "source ./values_for_cert-manager-rootca.yaml.bash $HOSTNAME_FOR_CERTMANAGER $BASE_FQDN" \
      "Activating RootCA"
    count=1
    while ! kubectl -n "$HOSTNAME_FOR_CERTMANAGER" get secret selfsigned-cacert 2>/dev/null; do
      # NOTE
      # Wait until RootCA is issued
      sleep 1
      echo -ne "\r\033[K"
      seq -s '.' 0 $count | tr -d '0-9'
      count=$((count++))
    done
    mkdir -p "$HISTORY_DIR"
    chmod 0700 "$HISTORY_DIR"
    kubectl -n "$HOSTNAME_FOR_CERTMANAGER" get secrets selfsigned-cacert -o yaml > "$HISTORY_FILE"
    kubectl -n "$HOSTNAME_FOR_CERTMANAGER" get secrets selfsigned-cacert -o json | jq -r '.data["ca.crt"]' | base64 -d > "$ROOTCA_FILE"
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
    "kubectl apply -f values_for_cert-manager-issuer.yaml" \
    "Activating Specific Issuer"
      # NOTE
      # ClusterIssuer is namespace independent
      # However, it depends on **selfsigned-cacert**
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

## 3. Install Ambassador (Step1)
##
installAmbassador() {
  ## 3-1. Install Ambassador's CRD
  ##
  HOSTNAME_FOR_AMBASSADOR=${HOSTNAME_FOR_AMBASSADOR:-ambassador}
  export HOSTNAME_FOR_AMBASSADOR=$HOSTNAME_FOR_AMBASSADOR
  local __aes_app_version
  echo ""
  echo "---"
  echo "Installing ambassador ..."
  __aes_app_version=$(curl -s https://api.github.com/repos/emissary-ingress/emissary/releases/latest | jq -r ".tag_name" | cut -b 2-)
  cmdWithLoding \
    "kubectl apply -f https://app.getambassador.io/yaml/edge-stack/${__aes_app_version}/aes-crds.yaml" \
    "Installing ambassador-CRD"
  cmdWithLoding \
    "kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system" \
    "Activating ambassador-CRD"
  ## 3-2. Install Ambassador Instance
  ##
  cmdWithLoding \
    "helm -n ${HOSTNAME_FOR_AMBASSADOR} upgrade --install ${HOSTNAME_FOR_AMBASSADOR} edge-stack/edge-stack \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f values_for_ambassador.yaml" \
    "Activating ambassador-Instance"
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
        -f values_for_keycloak.yaml" \
    "Activating keycloak"
  ## 4-3. Setup TLSContext
  ##
  cmdWithLoding \
    "source ./values_for_tlscontext.yaml.bash ${HOSTNAME_FOR_KEYCLOAK} ${__fqdn_for_keycloak} 1> /dev/null" \
    "Activating TLSContext"
      # NOTE
      # Tentative solution to the problem
      # that TLSContext is not generated automatically from Ingress (v2.2.2)
  cmdWithLoding \
    "sleep 20" \
    "Waiting TLSContext"
  cmdWithLoding \
    "curl --fail --cacert ${ROOTCA_FILE} https://${__fqdn_for_keycloak}/auth/ >/dev/null 2>&1" \
    "Testing keycloak"
  ## 4-4. Setup preset-entries
  ##
  cmdWithLoding \
    "source ./create_keycloak-entry.bash ${HOSTNAME_FOR_KEYCLOAK} 1> /dev/null" \
    "Activating Keycloak-entries"
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  echo ""
  echo "---"
  echo "The basic network modules has been installed. Check its status by running:"
  echo "  kubectl -n ${HOSTNAME_FOR_CERTMANAGER} get pod"
  echo "  kubectl -n ${HOSTNAME_FOR_METALLB} get pod"
  echo "  kubectl -n ${HOSTNAME_FOR_AMBASSADOR} get pod"
  echo "  kubectl -n ${HOSTNAME_FOR_KEYCLOAK} get pod"
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
  ## 3. Install Ambassador (Step1)
  ##
  installAmbassador
  ## 4. Install Keycloak
  ##
  installKeycloak
  ## 99. Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

source ./create_common.bash
main "$@"
exit $?