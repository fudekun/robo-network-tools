#!/bin/bash
# Dashboard
## create namespace (ambassador require a specific namespace.)
kubectl create namespace rdbox-systems

## Server Cert and key
kubectl -n rdbox-systems create secret tls rdbox-common-tls --key=rdbox_common_certname.key --cert=rdbox_common_certname.crt

## Create Dashboard
## Add service-account
kubectl -n rdbox-systems apply -f service-account.yaml

helm repo update
helm -n rdbox-systems install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard -f values_for_k8s-dashboard.yaml

kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kubernetes-dashboard
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kubernetes-dashboard-metrics-server

## On Browser ログインする時に$TOKENが必要だよ
echo "TOKEN(Admin)::"
TOKEN=$(kubectl -n rdbox-systems get secrets -o json | jq .items\[\] | jq 'select(.metadata.name | startswith("admin-user-token"))' | jq -r .data.token | base64 -d)
echo "$TOKEN"

