#!/bin/bash
set -euo pipefail

###################
# This script describes the minimum processing required
#  to run a ROS2 app on a Kubernetes cluster.
###################

# Step1 KinD Install
kind create cluster --config kind_cluster.yaml

# Step2 Weave-Net Install
echo ""
echo "---"
echo "Installing Weave-Net ..."
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
kubectl wait --timeout=180s -n kube-system --for=condition=ready pod -l name=weave-net
echo ""
echo "Weave-Net has been installed. Check its status by running:"
echo "  kubectl get node -o wide"