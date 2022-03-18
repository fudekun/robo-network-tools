#!/bin/bash
set -euo pipefail

## References
## https://github.com/keycloak/keycloak-documentation/blob/main/server_development/topics/admin-rest-api.adoc
##
##
## 1. Obtain an access token for user in the realm master with username admin and password
## 2. Invoke the API you need by extracting the value of the access_token property
##
__getAccessToken() {
  local base_url=$1
  local username
  local password
  local token_endpoint
  username=$(helm -n keycloak get values keycloak -o json | jq -r '.auth.adminUser')
  password=$(kubectl -n keycloak get secrets "$(helm -n keycloak get values keycloak -o json | jq -r '.auth.existingSecret.name')" -o jsonpath='{.data.admin-password}' | base64 --decode)
  token_endpoint=$(curl -s "$base_url"/auth/realms/master/.well-known/openid-configuration | jq -r '.mtls_endpoint_aliases.token_endpoint')
  curl -fs -X POST "$token_endpoint" \
    -d "client_id=admin-cli" \
    -d "username=$username" \
    -d "password=$password" \
    -d "grant_type=password" \
    | jq -r ".access_token"
}

## References
## https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
##
##
## 1. Create a new Realm and Client
## 2. Make sure that http://localhost:8000 and http://localhost:18000 are valid Redirect URIs
## 3. Set access type to confidential and Save (bearerOnly:false, publicClient:false)
## 4. Go to the Credentials tab and note down the secret
## 5. Go to the user tab and create a user with the first name ????
##
__createEntry() {
  local base_url=$1
  local access_token=$2
  local client_secret=$3
  local cluster_name=$4
  local password
  local preset_group_name
  local operation_endpoint_url
  local cred_hash_array
  local created_date
  local salt
  local hashed_salted_value
  local hash_iterations
  local fullname_array
  password=$(kubectl -n keycloak get secrets "$(helm -n keycloak get values keycloak -o json | jq -r '.auth.existingSecret.name')" -o jsonpath='{.data.k8s-default-cluster-admin-password}' | base64 --decode)
  preset_group_name=$(getPresetGroupName)
  operation_endpoint_url="$base_url/auth/admin/realms"
  created_date=$(python3 -c 'import time; print(int(time.time() * 1000))')
  cred_hash_array=()
  while IFS='' read -r line; do cred_hash_array+=("$line"); done < <(hashPasswordByPbkdf2Sha256 "$password")
  salt=${cred_hash_array[0]}
  hashed_salted_value=${cred_hash_array[1]}
  hash_iterations=${cred_hash_array[2]}
  IFS="-" read -r -a fullname_array <<< "$preset_group_name"
  first_name=${fullname_array[1]}
  last_name=${fullname_array[0]}
  curl -fs -X POST "$operation_endpoint_url" \
      -H "Authorization: bearer $access_token" \
      -H "Content-Type: application/json" \
      -d "$(jq -n -r -f values_for_keycloak-entry-realm.jq.json \
          --arg client_secret "$client_secret" \
          --arg cluster_name "$cluster_name" \
          --arg preset_group_name "$preset_group_name" \
          --arg hash_iterations "$hash_iterations" \
          --arg salt "$salt" \
          --arg hashed_salted_value "$hashed_salted_value" \
          --arg created_date "$created_date" \
          --arg first_name "$first_name" \
          --arg last_name "$last_name" \
      )"
}

main() {
  echo ""
  echo "---"
  echo "Inserting entry to keycloak ..."

  local base_url
  base_url=https://$(helm -n keycloak get values keycloak -o json | jq -r '.ingress.hostname')

  local access_token
  if ! access_token=$(__getAccessToken "${base_url}"); then
    echo "Failed to get token"
    exit 1
  fi

  local client_secret
  local cluster_name
  client_secret="$(openssl rand -base64 64 | head -c 32)"
  cluster_name=$(getClusterName)
  if ! __createEntry "${base_url}" "${access_token}" "${client_secret}" "${cluster_name}"; then
    echo "Failed to create entry"
    exit 1
  fi

  kubectl apply -f values_for_cluster-admin.yaml
}

source ./create_common.bash
main
exit $?