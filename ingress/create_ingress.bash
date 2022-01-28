#!/bin/bash
# Ambassador
kubectl apply -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-crds.yaml

kubectl apply -n ambassador -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-kind.yaml

kubectl wait --timeout=180s -n ambassador --for=condition=deployed ambassadorinstallations/ambassador

# Dashboard
## create namespace (ambassador require a specific namespace.)
kubectl create namespace rdbox-systems

## Server Cert and key
kubectl -n rdbox-systems create secret tls rdbox-common-tls --key=rdbox_common_certname.key --cert=rdbox_common_certname.crt

## Create Dashboard
## Add service-account
kubectl -n rdbox-systems apply -f service-account.yaml

helm -n rdbox-systems install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard -f values_for_kind.yaml

kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kubernetes-dashboard
kubectl wait --timeout=180s -n rdbox-systems --for=condition=available deployment/kubernetes-dashboard-metrics-server

## On Browser ログインする時に$TOKENが必要だよ
echo "TOKEN(Admin)::"
TOKEN=$(kubectl -n rdbox-systems get secrets -o json | jq .items\[\] | jq 'select(.metadata.name | startswith("admin-user-token"))' | jq -r .data.token | base64 -d)
echo "$TOKEN"
