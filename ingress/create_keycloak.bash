#!/bin/bash
set -euo pipefail

helm repo update
helm -n keycloak install keycloak bitnami/keycloak \
  --create-namespace \
  -f values_for_keycloak.yaml