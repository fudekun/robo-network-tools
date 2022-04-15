#!/bin/bash
set -euo pipefail

# Create prometheus-stack
echo ""
echo "---"
echo "Installing prometheus-stack ..."

helm repo update
helm install -n rdbox-systems kube-prometheus-stack prometheus-community/kube-prometheus-stack -f values_for_prometheus-stack.yaml

kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kube-prometheus-stack-grafana
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kube-prometheus-stack-kube-state-metrics
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kube-prometheus-stack-operator