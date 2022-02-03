#!/bin/bash

kind create cluster --config kind_cluster.yaml

echo ""
echo "---"
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
kubectl wait --timeout=180s -n kube-system --for=condition=available daemonSet/weave-net
echo "weave-net has been installed. Check its status by running:"
echo "  kubectl get node -o wide"