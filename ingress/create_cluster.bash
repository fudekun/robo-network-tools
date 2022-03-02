#!/bin/bash
set -euo pipefail

###################
# This script describes the minimum processing required
#  to run a ROS2 app on a Kubernetes cluster.
###################

if [ $# != 1 ]; then
  echo "\$1 Specify the cluster name (e.g. rdbox)"
  exit 1
fi
CLUSTER_NAME="$1"

source ./create_common.bash

# Step1 KinD Install
kind create cluster --config values_for_kind-cluster.yaml --name "$CLUSTER_NAME"

# Step2 ConfigMap SetUp
echo ""
echo "---"
echo "Installing cluster-info ..."
kubectl create namespace rdbox-common & showLoading "Getting Ready cluster-info "
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-info
  namespace: rdbox-common
data:
  name: ${CLUSTER_NAME}
EOF

# Step3 Weave-Net Install
echo ""
echo "---"
echo "Installing Weave-Net ..."
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
kubectl wait --timeout=180s -n kube-system --for=condition=ready pod -l name=weave-net & showLoading "Activating Weave-Net "
echo ""
echo "---"
echo "KinD-Cluster and Weave-Net has been installed. Check its status by running:"
echo "  kubectl get node -o wide"

exit 0