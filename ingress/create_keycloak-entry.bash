#!/bin/bash
set -euox pipefail

## References
## https://github.com/keycloak/keycloak-documentation/blob/main/server_development/topics/admin-rest-api.adoc
##
##
## 1. Obtain an access token for user in the realm master with username admin and password password:
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
## 1. Create a new Realm and Client
## 2. Make sure that http://localhost:8000 and http://localhost:18000 are valid Redirect URIs
## 3. Set access type to confidential and Save (bearerOnly:false, publicClient:false)
## 4. Go to the Credentials tab and note down the secret
## 5. Go to the user tab and create a user with the first name ????
__createEntry() {
  local base_url=$1
  local access_token=$2
  local client_secret=$3
  local cluster_name=$4
  local preset_group_name
  local operation_endpoint
  preset_group_name=$(__getPresetGroupName "${cluster_name}")
  operation_endpoint="$base_url/auth/admin/realms"
  curl -fs -X POST "$operation_endpoint" \
    -H "Authorization: bearer $access_token" \
    -H "Content-Type: application/json" \
    -d @- << EOS
    {
      "id": "$cluster_name",
      "realm": "$cluster_name",
      "displayName": "$cluster_name",
      "enabled": true,
      "sslRequired": "external",
      "registrationAllowed": false,
      "loginWithEmailAllowed": false,
      "duplicateEmailsAllowed": false,
      "resetPasswordAllowed": false,
      "editUsernameAllowed": false,
      "bruteForceProtected": true,
      "internationalizationEnabled": true,
      "supportedLocales": [
        "en",
        "ja"
      ],
      "userManagedAccessAllowed": true,
      "clients": [
        {
          "clientId": "ambassador",
          "enabled": true,
          "redirectUris": [
            "http://localhost:8000",
            "http://localhost:18000"
          ],
          "bearerOnly": false,
          "publicClient": false,
          "secret": "$client_secret",
          "protocolMappers": [
            {
              "name": "roles",
              "protocol": "openid-connect",
              "protocolMapper": "oidc-usermodel-realm-role-mapper",
              "consentRequired": false,
              "config": {
                "multivalued": "true",
                "user.attribute": "foo",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "claim.name": "roles",
                "jsonType.label": "String"
              }
            },
            {
              "name": "groups",
              "protocol": "openid-connect",
              "protocolMapper": "oidc-group-membership-mapper",
              "consentRequired": false,
              "config": {
                "full.path": "false",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
                "claim.name": "groups",
                "jsonType.label": "String"
              }
            }
          ],
          "webOrigins": [
            "*"
          ]
        }
      ],
      "groups": [
        {
          "name": "$preset_group_name"
        }
      ]
    }
EOS
}

__getPresetGroupName() {
  local cluster_name=$1
  echo "$cluster_name"-cluster-admim
}

main() {
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

  local preset_group_name
  preset_group_name=$(__getPresetGroupName "${cluster_name}")
cat <<EOF | kubectl apply -f -
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${preset_group_name}-binding
subjects:
- kind: Group
  name: ${preset_group_name}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
EOF
}

source ./create_common.bash
main

exit 0