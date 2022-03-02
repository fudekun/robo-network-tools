#!/bin/bash
set -euo pipefail

source ./create_common.bash
sub_domain=keycloak
base_fqdn=$(getBaseFQDN)
this_fqdn=$sub_domain.$base_fqdn

echo ""
echo "---"
echo "Installing keycloak ..."
kubectl create namespace keycloak & showLoading "Getting Ready keycloak "
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
  --set ingress.hostname="$this_fqdn" \
  --set ingress.extraTls\[0\].hosts\[0\]="$this_fqdn" \
  --set ingress.extraTls\[0\].secretName=keycloak \
  --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
  --set extraEnvVars\[0\].value="-Dkeycloak.frontendUrl=https://$this_fqdn/auth" \
  -f values_for_keycloak.yaml & showLoading "Activating keycloak "
kubectl -n keycloak wait pods --timeout=180s --for condition=Ready \
  --selector app.kubernetes.io/instance=keycloak & showLoading "Activating keycloak "