#!/bin/bash
set -euo pipefail

###############################################################################
## Execute essentials(module) configuration
###############################################################################
source ./create_common.bash

## 0. Initializing
##
FQDN_THIS_CLUSTER=$(getBaseFQDN)
flag="new-rootca" # or recycle(For Developpers)
if [ $# -eq 1 ]; then
  flag=$1
fi
echo "Mode: $flag"
echo ""
echo "---"
echo "Initializing essentials ..."
cmdWithLoding \
  "helm repo update 1> /dev/null" \
  "Updateing Helm"

## 1. Install Cert-Manager
## 1-1. Install Cert-Manager
##
HOSTNAME_FOR_CERTMANAGER=cert-manager
echo ""
echo "---"
echo "Installing cert-manager ..."
cmdWithLoding \
  "helm -n ${HOSTNAME_FOR_CERTMANAGER} upgrade --install ${HOSTNAME_FOR_CERTMANAGER} jetstack/cert-manager \
    --create-namespace \
    --wait \
    --timeout 180s \
    -f values_for_cert-manager-instance.yaml" \
  "Activating cert-manager"
## 1-2. Setup RootCA (You can recycle a previous RootCA certificates (For Developpers))
##
echo ""
echo "---"
echo "Setup RootCA and Specific Issuer ..."
echo "Mode: $flag"
HISTORY_DIR=${HISTORY_DIR:-.history.${FQDN_THIS_CLUSTER}}
HISTORY_FILE=${HISTORY_FILE:-${HISTORY_DIR}/selfsigned-ca.${FQDN_THIS_CLUSTER}.ca.yaml}
ROOTCA_FILE=${ROOTCA_FILE:-${FQDN_THIS_CLUSTER}.ca.crt}
if [ "$flag" = "new-rootca" ]; then
  cmdWithLoding \
    "source ./values_for_cert-manager-rootca.yaml.bash $HOSTNAME_FOR_CERTMANAGER $FQDN_THIS_CLUSTER" \
    "Activating RootCA"
  echo ""
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
elif [ "$flag" = "recycle" ]; then
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

## 2. Install MetalLB
## 2-1. Config MetalLB with L2 Mode
##
HOSTNAME_FOR_METALLB=metallb
echo ""
echo "---"
echo "Installing metallb ..."
NETWORK_IP=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $1}')
NETWORK_PREFIX=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $2}')
if [ "$NETWORK_PREFIX" -le 16 ]; then
  NETWORK_RANGE=$(echo "$NETWORK_IP" | awk -F. '{printf "%s.%s.%s-%s.%s.%s", $1, $2, "255.200", $1, $2, "255.250"}')
elif [ "$NETWORK_PREFIX" -gt 16 ] && [ "$NETWORK_PREFIX" -le 24 ]; then
  NETWORK_RANGE=$(echo "$NETWORK_IP" | awk -F. '{printf "%s.%s.%s.%s-%s.%s.%s.%s", $1, $2, $3, "200", $1, $2, $3, "250"}')
else
  echo ""
  echo "---"
  echo "WARN: Your Docker network configuration is not expected;"
  echo "- You will need to execute the MetalLB configuration yourself."
  echo "- https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
  exit 1
fi
echo "MetalLB will reserve the following IP address ranges."
echo "- $NETWORK_RANGE"
cmdWithLoding \
  "helm -n ${HOSTNAME_FOR_METALLB} upgrade --install ${HOSTNAME_FOR_METALLB} metallb/metallb \
    --create-namespace \
    --wait \
    --timeout 180s \
    --set configInline.address-pools\[0\].addresses\[0\]=$NETWORK_RANGE \
    -f values_for_metallb.yaml" \
  "Activating metallb"

## 3. Install Ambassador Step1
##
HOSTNAME_FOR_AMBASSADOR=ambassador
echo ""
echo "---"
echo "Installing ambassador ..."
aes_app_version=$(curl -s https://api.github.com/repos/emissary-ingress/emissary/releases/latest | jq -r ".tag_name" | cut -b 2-)
cmdWithLoding \
  "kubectl apply -f https://app.getambassador.io/yaml/edge-stack/${aes_app_version}/aes-crds.yaml" \
  "Installing ambassador-CRD"
cmdWithLoding \
  "kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system" \
  "Activating ambassador-CRD"
cmdWithLoding \
  "helm -n ${HOSTNAME_FOR_AMBASSADOR} upgrade --install ${HOSTNAME_FOR_AMBASSADOR} edge-stack/edge-stack \
    --create-namespace \
    --wait \
    --timeout 300s \
    -f values_for_ambassador.yaml" \
  "Activating ambassador-Instance"

## 4. Install Keycloak
## 4-1. Config extra secrets
##
HOSTNAME_FOR_KEYCLOAK=keycloak
FQDN_FOR_KEYCLOAK=${HOSTNAME_FOR_KEYCLOAK}.${FQDN_THIS_CLUSTER}
echo ""
echo "---"
echo "Installing keycloak ..."
cmdWithLoding \
  "kubectl create namespace ${HOSTNAME_FOR_KEYCLOAK}" \
  "Getting Ready keycloak"
kubectl -n "$HOSTNAME_FOR_KEYCLOAK" create secret generic specific-secrets \
  --from-literal=admin-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=management-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=postgresql-postgres-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=postgresql-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=tls-keystore-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=tls-truestore-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=k8s-default-cluster-admin-password="$(openssl rand -base64 32 | head -c 16)"
    # NOTE
    # The postgresql-postgres-password is password for root user
    # The postgresql-password is password for the unprivileged user
## 4-2. Install Keycloak
##
cmdWithLoding \
  "helm -n ${HOSTNAME_FOR_KEYCLOAK} upgrade --install ${HOSTNAME_FOR_KEYCLOAK} bitnami/keycloak \
    --wait \
    --timeout 300s \
    --set ingress.hostname=$FQDN_FOR_KEYCLOAK \
    --set ingress.extraTls\[0\].hosts\[0\]=$FQDN_FOR_KEYCLOAK \
    --set ingress.extraTls\[0\].secretName=$HOSTNAME_FOR_KEYCLOAK \
    --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
    --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://$FQDN_FOR_KEYCLOAK/auth \
    -f values_for_keycloak.yaml" \
  "Activating keycloak"
## 4-3. Setup TLSContext
##
cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: getambassador.io/v3alpha1
kind: TLSContext
metadata:
  name: ${HOSTNAME_FOR_KEYCLOAK}
  namespace: ${HOSTNAME_FOR_KEYCLOAK}
spec:
  hosts:
    - ${FQDN_FOR_KEYCLOAK}
  secret: ${HOSTNAME_FOR_KEYCLOAK}
EOF
    # NOTE
    # Tentative solution to the problem
    # that TLSContext is not generated automatically from Ingress (v2.2.2)
cmdWithLoding \
  "sleep 20" \
  "Activating keycloak"
cmdWithLoding \
  "curl --fail --cacert ${ROOTCA_FILE} https://${FQDN_FOR_KEYCLOAK}/auth/ >/dev/null 2>&1" \
  "Checking keycloak"

## 5. Notify Verifier-Command
##
echo ""
echo "---"
echo "The basic network modules has been installed. Check its status by running:"
echo "  kubectl -n ${HOSTNAME_FOR_CERTMANAGER} get pod"
echo "  kubectl -n ${HOSTNAME_FOR_METALLB} get pod"
echo "  kubectl -n ${HOSTNAME_FOR_AMBASSADOR} get pod"
echo "  kubectl -n ${HOSTNAME_FOR_KEYCLOAK} get pod"

exit 0