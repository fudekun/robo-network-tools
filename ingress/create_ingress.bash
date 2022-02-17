#!/bin/bash
set -euo pipefail

flag="new-rootca" # or recycle(For Developpers)
if [ $# -le 1 ]; then
  flag=$1
fi
echo "Mode: $flag"

HISTORY_FILE=rdbox-selfsigned-ca.rdbox.172-16-0-110.nip.io.ca.yaml
ROOTCA_FILE=rdbox.172-16-0-110.nip.io.ca.crt

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
  kubectl -n cert-manager get secrets rdbox-selfsigned-ca-cert -o yaml > $HISTORY_FILE
  kubectl -n cert-manager get secrets rdbox-selfsigned-ca-cert -o json | jq -r '.data["ca.crt"]' | base64 -d > $ROOTCA_FILE
elif [ "$flag" = "recycle" ]; then
  if [ -e "$HISTORY_FILE" ]; then
    kubectl -n cert-manager apply -f $HISTORY_FILE
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
#docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":"
# Create multiple YAML objects from stdin
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
      - 172.18.255.200-172.18.255.250
EOF

exit 0