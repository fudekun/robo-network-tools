#!/bin/bash
set -euo pipefail

kubectl create namespace keycloak
# The postgresql-postgres-password is password for root user
# The postgresql-password is password for the unprivileged user
kubectl -n keycloak create secret generic keycloak-specific-secrets \
  --from-literal=admin-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=management-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=postgresql-postgres-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=postgresql-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=tls-keystore-password="$(openssl rand -base64 32 | head -c 16)" \
  --from-literal=tls-truestore-password="$(openssl rand -base64 32 | head -c 16)"

helm repo update
helm -n keycloak upgrade --install keycloak bitnami/keycloak \
  --create-namespace \
  -f values_for_keycloak.yaml