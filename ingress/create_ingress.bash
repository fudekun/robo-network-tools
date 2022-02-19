#!/bin/bash
set -euo pipefail

## ./create_ingress.bash rdbox nip.io

sub_domain=$1
dns_service=$2
flag="new-rootca" # or recycle(For Developpers)
if [ $# -eq 3 ]; then
  flag=$3
fi
echo "Mode: $flag"

DEFULT_NIC=$(netstat -rn | grep default | grep -v ":" | awk '{print $4}')
# shellcheck disable=SC2015
IP_DEFAULT_NIC=$( (command -v ip &> /dev/null && ip addr show "$DEFULT_NIC" || ifconfig "$DEFULT_NIC") | \
                  sed -nEe 's/^[[:space:]]+inet[^[:alnum:]]+([0-9.]+).*$/\1/p')
#HOSTNAME_NIPIO_BASED_ON_IP=$(echo "$IP_DEFAULT_NIC" | awk -F. '{printf "%02x", $1}{printf "%02x", $2}{printf "%02x", $3}{printf "%02x", $4}')
HOSTNAME_NIPIO_BASED_ON_IP=${IP_DEFAULT_NIC//\./-}
FQDN_THIS_CLUSTER="$sub_domain"."$HOSTNAME_NIPIO_BASED_ON_IP"."$dns_service"
HISTORY_FILE=rdbox-selfsigned-ca.${FQDN_THIS_CLUSTER}.ca.yaml
ROOTCA_FILE=${FQDN_THIS_CLUSTER}.ca.crt

# Step1 cert-manager Install
echo ""
echo "---"
echo "Installing cert-manager ..."
helm repo update
helm -n cert-manager install cert-manager jetstack/cert-manager  \
  --create-namespace \
  --set installCRDs=true
kubectl wait --timeout=180s -n cert-manager --for=condition=available deployment/cert-manager
kubectl wait --timeout=180s -n cert-manager --for=condition=available deployment/cert-manager-cainjector
kubectl wait --timeout=180s -n cert-manager --for=condition=available deployment/cert-manager-webhook

# Step2 Setup RootCA and specific Issuer
echo ""
echo "---"
echo "Setup RootCA and Specific Issuer ..."
if [ "$flag" = "new-rootca" ]; then
  kubectl apply -f values_for_cert-manager-rootca.yaml
  while ! kubectl -n cert-manager get secret rdbox-selfsigned-ca-cert; do sleep 2; done
  kubectl -n cert-manager get secrets rdbox-selfsigned-ca-cert -o yaml > "$HISTORY_FILE"
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
    kubectl -n cert-manager apply -f $HISTORY_FILE
  else
    echo "No history file found. Please generate a new RootCA."
    exit 1
  fi
fi
kubectl apply -f values_for_cert-manager-issuer.yaml

# Step3 Ambassador Install
echo ""
echo "---"
echo "Installing Ambassador ..."
kubectl apply -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-crds.yaml
#kubectl apply -n ambassador -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-kind.yaml
kubectl apply -n ambassador -f ./ab_op/ambassador-operator-kind.yaml
kubectl wait --timeout=180s -n ambassador --for=condition=deployed ambassadorinstallations/ambassador


# Step4 MetalLB Install
echo ""
echo "---"
echo "Installing MetalLB ..."
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/namespace.yaml
kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey="$(openssl rand -base64 128)"
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/metallb.yaml
kubectl wait --timeout=180s -n metallb-system --for=condition=available deployment/controller

# Step5 Config MetalLB with L2 Mode
#docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":"
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
echo ""
read -r -n1 -p "ok? (y/N): " yn
if [[ $yn = [yY] ]]; then
  # Create multiple YAML objects from stdin
  echo ""
  cat <<EOF | kubectl apply -f -
  apiVersion: v1
  kind: ConfigMap
  metadata:
    namespace: metallb-system
    name: config
  data:
    config: |
      address-pools:
      - name: default
        protocol: layer2
        addresses:
        - $NETWORK_RANGE
EOF
  echo ""
  kubectl -n metallb-system describe configmaps config
else
  echo "abort"
  echo "  You will need to execute the MetalLB configuration yourself."
  echo "  https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
  exit 1
fi

echo ""
echo "---"
echo "The basic network modules has been installed. Check its status by running:"
echo "  kubectl -n cert-manager get pod"
echo "  kubectl -n ambassador get pod"
echo "  kubectl -n metallb-system get pod"

exit 0