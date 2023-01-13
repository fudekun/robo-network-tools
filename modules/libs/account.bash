#!/usr/bin/env bash
set -euo pipefail

###############################################################################
## The collections of a function, which is general purpose
## Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

#######################################
# Handler for deleting temporary directories in function scope
# Globals:
#   NONE
# Arguments:
#   DIR_PATH
# Outputs:
#   NONE
# References:
#   https://unix.stackexchange.com/questions/582922/how-to-pass-local-variable-to-trap-handler-in-bash
#######################################
function exit_handler() {
  local rv="$?"
  local tmp_dir="${1}"
  rm -rf "$tmp_dir"
  return $rv
}

#######################################
# Get a server certificate and save it in a temporary directory.
#   - Only the internal
# Globals:
#   NONE
# Arguments:
#   NONE
# Outputs:
#   DIR_PATH
#######################################
function get_cert() {
  local tmp_dir
  local ca_filepath
  tmp_dir=$(mktemp -d)
  ca_filepath=${tmp_dir}/tls.crt
  kubectl -n cert-manager get secrets "$(getBaseFQDN)" \
    -o jsonpath="{.data.tls\.crt}" \
    | base64 -d > "${ca_filepath}"
  echo "${tmp_dir}"
}

#######################################
# Get a URL of endpoint by realm
# Arguments:
#   realm
# Outputs:
#   URL
#######################################
function get_authorization_url() {
  local realm=$1
  echo -n "https://$(getHostName "keycloak" "main").$(getBaseFQDN)/realms/${realm}"
}

#######################################
# Perse a json string that was obtained from the get_access_token() function
# Globals:
#   NONE
# Arguments:
#   raw_token    A json string include accessToken and refreshToken
#                - https://www.keycloak.org/docs-api/18.0/rest-api/#_accesstoken
#   target       (e.g. access_token or refresh_token)
# Outputs:
#   item
#######################################
function perse_token() {
  local raw_token=$1
  local target=$2
  echo "${raw_token}" | jq -r ".${target}"
  return $?
}

#######################################
# Get a access token
# Globals:
#   NONE
# Arguments:
#   realm          (e.g. rdbox)
#   username       (e.g. cluster-admin)
#   password
#   <optional>totp
# Outputs:
#   A json string include accessToken and refreshToken
#   - https://www.keycloak.org/docs-api/18.0/rest-api/#_accesstoken
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://github.com/keycloak/keycloak-documentation/blob/main/securing_apps/topics/oidc/oidc-generic.adoc#example-using-curl
#######################################
function get_access_token() {
  function __get_access_token() {
    local tmp_dir=$1
    local ca_filepath=${tmp_dir}/tls.crt
    local realm=$2
    local username=$3
    local password=$4
    local totp=${5:-""}
    local keycloak_fqdn
    local token_endpoint
    local resp
    keycloak_fqdn=$(getHostName "keycloak" "main").$(getBaseFQDN)
    token_endpoint=$(curl -fs \
      --cacert "${ca_filepath}" \
      https://"${keycloak_fqdn}"/realms/"${realm}"/.well-known/openid-configuration \
      | jq -r '.mtls_endpoint_aliases.token_endpoint')
      ### NOTE
      ### ex) https://keycloak.rdbox.172-16-0-110.nip.io/realms/mastrer/.well-known/openid-configuration
    if [ -n "$totp" ]; then
      resp=$(curl -fs --cacert "${ca_filepath}" -X POST "$token_endpoint" \
        -d "client_id=admin-cli" \
        -d "grant_type=password" \
        -d "username=$username" \
        -d "password=$password" \
        -d "totp=$totp"
      )
    else
      resp=$(curl -fs --cacert "${ca_filepath}" -X POST "$token_endpoint" \
        -d "client_id=admin-cli" \
        -d "grant_type=password" \
        -d "username=$username" \
        -d "password=$password"
      )
    fi
      ### NOTE
      ### ex) https://keycloak.rdbox.172-16-0-110.nip.io/realms/mastrer/protocol/openid-connect/token
    echo "$resp"
    return 0
  }
  local cert_dir
  cert_dir=$(get_cert)
  # shellcheck disable=SC2064
  trap "exit_handler '${cert_dir}'" EXIT
  __get_access_token "$cert_dir" "$@"
  return $?
}

#######################################
# Get a access token (ServiceAccount)
# Globals:
#   NONE
# Arguments:
#   realm          (e.g. rdbox)
# Outputs:
#   A json string include accessToken and refreshToken
#   - https://www.keycloak.org/docs-api/18.0/rest-api/#_accesstoken
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://github.com/keycloak/keycloak-documentation/blob/main/securing_apps/topics/oidc/oidc-generic.adoc#example-using-curl
#######################################
function get_access_token_of_sa() {
  function __get_access_token_of_sa() {
    local tmp_dir=$1
    local ca_filepath=${tmp_dir}/tls.crt
    local realm=$2
    local keycloak_fqdn
    local token_endpoint
    local resp
    keycloak_fqdn=$(getHostName "keycloak" "main").$(getBaseFQDN)
    token_endpoint=$(curl -fs \
      --cacert "${ca_filepath}" \
      https://"${keycloak_fqdn}"/realms/"${realm}"/.well-known/openid-configuration \
      | jq -r '.mtls_endpoint_aliases.token_endpoint')
      ### NOTE
      ### ex) https://keycloak.rdbox.172-16-0-110.nip.io/realms/mastrer/.well-known/openid-configuration
    local secret b64str
    secret=$(kubectl -n keycloak get secrets "${SPECIFIC_SECRETS}" \
              -o jsonpath='{.data.k8s-default-cluster-cli-secret}' | base64 -d)
    b64str=$(echo -n "admin-cli:${secret}" | base64)
    resp=$(curl -fs --cacert "${ca_filepath}" -X POST "$token_endpoint" \
      -H "Authorization: Basic ${b64str}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials"
    )
      ### NOTE
      ### ex) https://keycloak.rdbox.172-16-0-110.nip.io/realms/mastrer/protocol/openid-connect/token
    echo "$resp"
    return 0
  }
  local cert_dir
  cert_dir=$(get_cert)
  # shellcheck disable=SC2064
  trap "exit_handler '${cert_dir}'" EXIT
  __get_access_token_of_sa "$cert_dir" "$@"
  return $?
}

#######################################
# Revoke a access token
# Globals:
#   NONE
# Arguments:
#   realm    (e.g. rdbox)
#   token    A json string include accessToken and refreshToken
#                - https://www.keycloak.org/docs-api/18.0/rest-api/#_accesstoken
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://github.com/keycloak/keycloak-documentation/blob/main/securing_apps/topics/oidc/oidc-generic.adoc#example-using-curl
#######################################
function revoke_access_token() {
  function __revoke_access_token() {
    local tmp_dir=$1
    local ca_filepath=${tmp_dir}/tls.crt
    local realm=$2
    local token=$3
    local keycloak_fqdn
    local end_session_endpoint
    local refresh_token
    keycloak_fqdn=$(getHostName "keycloak" "main").$(getBaseFQDN)
    end_session_endpoint=$(curl -fs \
                          --cacert "${ca_filepath}" \
                          https://"${keycloak_fqdn}"/realms/"${realm}"/.well-known/openid-configuration \
                          | jq -r '.end_session_endpoint')
      ### NOTE
      ### ex) https://keycloak.rdbox.172-16-0-110.nip.io/realms/mastrer/.well-known/openid-configuration
    refresh_token=$(perse_token "${token}" "refresh_token")
    curl -fs --cacert "${ca_filepath}" -X POST "$end_session_endpoint" \
        -d "client_id=admin-cli" \
        -d "refresh_token=$refresh_token"
      ### NOTE
      ### ex) https://keycloak.rdbox.172-16-0-110.nip.io/realms/mastrer/protocol/openid-connect/logout
    return $?
  }
  local cert_dir
  cert_dir=$(get_cert)
  # shellcheck disable=SC2064
  trap "exit_handler '${cert_dir}'" EXIT
  __revoke_access_token "$cert_dir" "$@"
  return $?
}

#######################################
# Create any entry
# Globals:
#   NONE
# Arguments:
#   realm          (e.g. rdbox)
#   token          a json string was obtained from the get_access_token() function
#   entry_target   (e.g. clients)
#   entry_json
# Outputs:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://www.keycloak.org/docs-api/18.0/rest-api/#_clients_resource
#   https://stackoverflow.com/questions/11027679/capture-stdout-and-stderr-into-different-variables
#######################################
function create_entry() {
  function __create_entry() {
    local tmp_dir=$1
    local ca_filepath=${tmp_dir}/tls.crt
    local realm=$2
    local token=$3
    local entry_target=$4
    local entry_json=$5
    local keycloak_fqdn
    local operation_endpoint_url
    local access_token
    access_token=$(perse_token "${token}" "access_token")
    keycloak_fqdn=$(getHostName "keycloak" "main").$(getBaseFQDN)
    if [ "${realm}" = "__NONE__" ]; then
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms"
    else
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms/${realm}/${entry_target}"
    fi
    local response
    local http_code
    {
        IFS=$'\n' read -r -d '' response;
        IFS=$'\n' read -r -d '' http_code;
    } < <((printf '\0%s\0' "$(curl -s -w '%{http_code}' -o /dev/stderr --cacert "${ca_filepath}" -X POST "${operation_endpoint_url}" \
        -H "Authorization: bearer ${access_token}" \
        -H "Content-Type: application/json" \
        -d "${entry_json}")" 1>&2) 2>&1)
    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 299 ];then
      echo "Success create the new entry(${http_code})"
    elif [ "${http_code}" -eq 409 ]; then
      echo "Already exist the same entry, the HTTP Code is ${http_code}"
      echo "${response}"
      return 0
    else
      echo "the HTTP Code is ${http_code}"
      echo "${response}"
      return 1
    fi
    return $?
  }
  local cert_dir
  cert_dir=$(get_cert)
  # shellcheck disable=SC2064
  trap "exit_handler '${cert_dir}'" EXIT
  __create_entry "$cert_dir" "$@"
  return $?
}

function read_entry() {
  function __read_entry() {
    local tmp_dir=$1
    local ca_filepath=${tmp_dir}/tls.crt
    local realm=$2
    local token=$3
    local entry_target=$4
    local query=${5:-""}
    local keycloak_fqdn
    local operation_endpoint_url
    local access_token
    access_token=$(perse_token "${token}" "access_token")
    keycloak_fqdn=$(getHostName "keycloak" "main").$(getBaseFQDN)
    if [ "${realm}" = "__NONE__" ]; then
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms"
    else
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms/${realm}/${entry_target}"
    fi
    if [ -n "$query" ]; then
      operation_endpoint_url="${operation_endpoint_url}?${query}"
    fi
    local response
    local http_code
    {
        IFS=$'\n' read -r -d '' response;
        IFS=$'\n' read -r -d '' http_code;
    } < <((printf '\0%s\0' "$(curl -s -w '%{http_code}' -o /dev/stderr --cacert "${ca_filepath}" -X GET "${operation_endpoint_url}" \
        -H "Authorization: bearer ${access_token}" \
        -H "Content-Type: application/json")" 1>&2) 2>&1)
    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 299 ];then
      echo "${response}"
      return 0
    else
      echo "the HTTP Code is ${http_code}"
      echo "${response}"
      return 1
    fi
  }
  local cert_dir
  cert_dir=$(get_cert)
  # shellcheck disable=SC2064
  trap "exit_handler '${cert_dir}'" EXIT
  __read_entry "$cert_dir" "$@"
  return $?
}

function update_entry() {
  function __update_entry() {
    local tmp_dir=$1
    local ca_filepath=${tmp_dir}/tls.crt
    local realm=$2
    local token=$3
    local entry_target=$4
    local entry_id=$5
    local entry_json=$6
    local keycloak_fqdn
    local operation_endpoint_url
    local access_token
    access_token=$(perse_token "${token}" "access_token")
    keycloak_fqdn=$(getHostName "keycloak" "main").$(getBaseFQDN)
    if [ "${realm}" = "__NONE__" ]; then
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms"
    else
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms/${realm}/${entry_target}"
    fi
    local response
    local http_code
    {
        IFS=$'\n' read -r -d '' response;
        IFS=$'\n' read -r -d '' http_code;
    } < <((printf '\0%s\0' "$(curl -s -w '%{http_code}' -o /dev/stderr --cacert "${ca_filepath}" -X GET "${operation_endpoint_url}?clientId=${entry_id}&first=0&max=11&search=true" \
        -H "Authorization: bearer ${access_token}" \
        -H "Content-Type: application/json")" 1>&2) 2>&1)
    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 299 ];then
      echo "Success get the new entry(${http_code})"
    else
      echo "the HTTP Code is ${http_code}"
      echo "${response}"
      return 1
    fi
    local id
    id=$(echo "${response}" | jq -r '.[].id')
    local response
    local http_code
    {
        IFS=$'\n' read -r -d '' response;
        IFS=$'\n' read -r -d '' http_code;
    } < <((printf '\0%s\0' "$(curl -s -w '%{http_code}' -o /dev/stderr --cacert "${ca_filepath}" -X PUT "${operation_endpoint_url}/${id}" \
        -H "Authorization: bearer ${access_token}" \
        -H "Content-Type: application/json" \
        -d "${entry_json}")" 1>&2) 2>&1)
    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 299 ];then
      echo "Success get the new entry(${http_code})"
    else
      echo "the HTTP Code is ${http_code}"
      echo "${response}"
      return 1
    fi
  }
  local cert_dir
  cert_dir=$(get_cert)
  # shellcheck disable=SC2064
  trap "exit_handler '${cert_dir}'" EXIT
  __update_entry "$cert_dir" "$@"
  return $?
}

#######################################
# Delete any entry
# Globals:
#   NONE
# Arguments:
#   realm          (e.g. rdbox)
#   token          a json string was obtained from the get_access_token() function
#   entry_target   (e.g. clients)
#   entry_id       (e.g. kubernetes-dashboard)
# Outputs:
#   NONE
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://www.keycloak.org/docs-api/18.0/rest-api/#_clients_resource
#######################################
function delete_entry() {
  function __delete_entry() {
    local tmp_dir=$1
    local ca_filepath=${tmp_dir}/tls.crt
    local realm=$2
    local token=$3
    local entry_target=$4
    local entry_id=$5
    local keycloak_fqdn
    local operation_endpoint_url
    local http_code
    local access_token
    access_token=$(perse_token "${token}" "access_token")
    keycloak_fqdn=$(getHostName "keycloak" "main").$(getBaseFQDN)
    local id
    local response
    local http_code
    if [ "${realm}" = "__NONE__" ]; then
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms"
      id="${entry_id}"
    else
      operation_endpoint_url="https://${keycloak_fqdn}/admin/realms/${realm}/${entry_target}"
      {
          IFS=$'\n' read -r -d '' response;
          IFS=$'\n' read -r -d '' http_code;
      } < <((printf '\0%s\0' "$(curl -fs -w '%{http_code}' -o /dev/stderr --cacert "${ca_filepath}" -G -X GET "${operation_endpoint_url}" \
          -H "Authorization: bearer ${access_token}" \
          -H "Content-Type: application/json" \
          -d "clientId=${entry_id}")" 1>&2) 2>&1)
      if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 299 ];then
        id=$(echo "$response" | jq -r '.[0].id')
      else
        return 1
      fi
    fi
    {
        IFS=$'\n' read -r -d '' response;
        IFS=$'\n' read -r -d '' http_code;
    } < <((printf '\0%s\0' "$(curl -s -w '%{http_code}' -o /dev/stderr --cacert "${ca_filepath}" -X DELETE "${operation_endpoint_url}/${id}" \
        -H "Authorization: bearer ${access_token}")" 1>&2) 2>&1)
    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 299 ];then
      echo "Success delete the old entry(${http_code})"
    else
      echo "the HTTP Code is ${http_code}"
      echo "${response}"
      return 1
    fi
    return $?
  }
  local cert_dir
  cert_dir=$(get_cert)
  # shellcheck disable=SC2064
  trap "exit_handler '${cert_dir}'" EXIT
  __delete_entry "$cert_dir" "$@"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"