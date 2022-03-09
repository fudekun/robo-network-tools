#!/bin/bash
set -euo pipefail

###############################################################################
## Create a minimum KinD to run a ROS2 app on a Kubernetes cluster.
###############################################################################
source ./create_common.bash

## 0. Input Argument Checking
##
if [ $# != 2 ]; then
  echo "\$1 Specify the cluster name (e.g. rdbox)"
  echo "\$2 Specify the Domain name (e.g. Your Domain OR nip.io, sslip.io ...)"
  exit 1
fi
CLUSTER_NAME="$1"
DNS_SERVICE="$2"

## 1. Install KinD
##
kind create cluster --config values_for_kind-cluster.yaml --name "$CLUSTER_NAME"

## 2. SetUp ConfigMap
##
echo ""
echo "---"
echo "Installing cluster-info ..."
cmdWithLoding \
  "kubectl create namespace rdbox-common" \
  "Getting Ready cluster-info"
getNetworkInfo # Get the information needed to fill in the blanks below
FQDN_THIS_CLUSTER="$CLUSTER_NAME"."$HOSTNAME_FOR_WCDNS_BASED_ON_IP"."$DNS_SERVICE"
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-info
  namespace: rdbox-common
data:
  name: ${CLUSTER_NAME}
  domain: ${DNS_SERVICE}
  base_fqdn: ${FQDN_THIS_CLUSTER}
  nic.name: ${NAME_DEFULT_NIC}
  nic.ip_v4: ${IP_DEFAULT_NIC}
  nic.ip_hyphen: ${HOSTNAME_FOR_WCDNS_BASED_ON_IP}
EOF
echo ""
echo "In this cluster, **${FQDN_THIS_CLUSTER}** is used as the FQDN"
echo ""

## 3. Install Weave-Net
##
echo ""
echo "---"
echo "Installing Weave-Net ..."
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
cmdWithLoding \
  "kubectl wait --timeout=180s -n kube-system --for=condition=ready pod -l name=weave-net" \
  "Activating Weave-Net"

## 4. Notify Verifier-Command
##
echo ""
echo "---"
echo "KinD-Cluster and Weave-Net has been installed. Check its status by running:"
echo "  kubectl get node -o wide"

exit 0