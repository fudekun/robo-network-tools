#!/bin/bash
set -euo pipefail

###############################################################################
## Execute essential network configuration
###############################################################################
source ./create_common.bash

flag="new-rootca" # or recycle(For Developpers)
if [ $# -eq 1 ]; then
  flag=$1
fi
echo "Mode: $flag"

## 1. Cert-Manager Install
## 1-1. Cert-Manager Install
##
echo ""
echo "---"
echo "Installing cert-manager ..."
helm repo update
helm -n cert-manager install cert-manager jetstack/cert-manager  \
  --create-namespace \
  --wait \
  --timeout 180s \
  --set installCRDs=true & showLoading "Activating cert-manager "
## 1-2. Setup RootCA (You can recycle a previous RootCA certificates (For Developpers))
##
echo ""
echo "---"
echo "Setup RootCA and Specific Issuer ..."
FQDN_THIS_CLUSTER=$(getBaseFQDN)
HISTORY_DIR=${HISTORY_DIR:-.history.${FQDN_THIS_CLUSTER}}
HISTORY_FILE=${HISTORY_FILE:-${HISTORY_DIR}/rdbox-selfsigned-ca.${FQDN_THIS_CLUSTER}.ca.yaml}
if [ "$flag" = "new-rootca" ]; then
  kubectl apply -f values_for_cert-manager-rootca.yaml
  # Wait until RootCA is issued
  while ! kubectl -n cert-manager get secret rdbox-selfsigned-ca-cert 2>/dev/null; do sleep 2; done
  # Save the History file and the RootCA
  mkdir -p "$HISTORY_DIR"
  chmod 0700 "$HISTORY_DIR"
  kubectl -n cert-manager get secrets rdbox-selfsigned-ca-cert -o yaml > "$HISTORY_FILE"
  ROOTCA_FILE=${ROOTCA_FILE:-${FQDN_THIS_CLUSTER}.ca.crt}
  kubectl -n cert-manager get secrets rdbox-selfsigned-ca-cert -o json | jq -r '.data["ca.crt"]' | base64 -d > "$ROOTCA_FILE"
elif [ "$flag" = "recycle" ]; then
  if [ -e "$HISTORY_FILE" ]; then
    kubectl -n cert-manager apply -f "$HISTORY_FILE"
  else
    echo "No history file found. Please generate a new RootCA."
    exit 1
  fi
else
  if [ -e "$HISTORY_FILE" ]; then
    kubectl -n cert-manager apply -f "$HISTORY_FILE"
  else
    echo "No history file found. Please generate a new RootCA."
    exit 1
  fi
fi
## 1-3. Setup Specific Issuer
kubectl apply -f values_for_cert-manager-issuer.yaml

## 2. MetalLB Install
## 2-1. Config MetalLB with L2 Mode
##
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
  echo "  You will need to execute the MetalLB configuration yourself."
  echo "  https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
  exit 1
fi
echo ""
echo "---"
echo "MetalLB will reserve the following IP address ranges."
echo "  $NETWORK_RANGE"
## 2-2. MetalLB Install
##
echo ""
echo "---"
echo "Installing MetalLB ..."
# kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/namespace.yaml
# kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey="$(openssl rand -base64 128)"
# kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/metallb.yaml
helm -n metallb-system install metallb metallb/metallb \
  --create-namespace \
  --set configInline.address-pools\[0\].addresses\[0\]="$NETWORK_RANGE" \
  --wait \
  --timeout 180s \
  -f values_for_metallb.yaml & showLoading "Activating MetalLB "

## 3. Ambassador Install
##
echo ""
echo "---"
echo "Installing Ambassador ..."
kubectl apply -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-crds.yaml
#kubectl apply -n ambassador -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-kind.yaml
kubectl apply -n ambassador -f ./ab_op/ambassador-operator-kind.yaml
kubectl wait --timeout=180s -n ambassador --for=condition=deployed ambassadorinstallations/ambassador & showLoading "Activating Ambassador "
kubectl wait --timeout=180s -n ambassador --for=condition=available deployment/ambassador & showLoading "Activating Ambassador "
kubectl wait --timeout=180s -n ambassador --for=condition=available deployment/ambassador-agent & showLoading "Activating Ambassador "
kubectl wait --timeout=180s -n ambassador --for=condition=available deployment/ambassador-operator & showLoading "Activating Ambassador "
kubectl wait --timeout=180s -n ambassador --for=condition=available deployment/ambassador-redis & showLoading "Activating Ambassador "

## 4. Notify Verifier-Command
##
echo ""
echo "---"
echo "The basic network modules has been installed. Check its status by running:"
echo "  kubectl -n cert-manager get pod"
echo "  kubectl -n ambassador get pod"
echo "  kubectl -n metallb-system get pod"

exit 0