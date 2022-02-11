#!/bin/bash
# Ambassador
kubectl apply -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-crds.yaml
kubectl apply -n ambassador -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-kind.yaml
#kubectl apply -n ambassador -f ./ab_op/ambassador-operator-kind.yaml
kubectl wait --timeout=180s -n ambassador --for=condition=deployed ambassadorinstallations/ambassador

## create namespace (ambassador require a specific namespace.)
kubectl create namespace rdbox-systems

## Server Cert and key
kubectl -n rdbox-systems create secret tls rdbox-common-tls --key=rdbox_common_certname.key --cert=rdbox_common_certname.crt

## Create Dashboard
## Add service-account
kubectl -n rdbox-systems apply -f service-account.yaml