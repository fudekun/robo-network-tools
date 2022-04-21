#!/usr/bin/env bash
set -euo pipefail

# Create k8s-Dashboard
echo ""
echo "---"
echo "Installing kubernetes-dashboard ..."

## create namespace (ambassador require a specific namespace.)
kubectl create namespace rdbox-systems
## Add service-account
kubectl -n rdbox-systems apply -f values_for_service-account.yaml

helm repo update
helm -n rdbox-systems install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard -f values_for_k8s-dashboard.yaml

kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kubernetes-dashboard
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kubernetes-dashboard-metrics-server

## On Browser ログインする時に$TOKENが必要だよ
TOKEN=$(kubectl -n rdbox-systems get secrets -o json | jq .items\[\] | jq 'select(.metadata.name | startswith("admin-user-token"))' | jq -r .data.token | base64 -d)

echo ""
echo "TOKEN(Admin)::"
echo "---"
echo "$TOKEN"
echo "---"
echo ""
