#!/bin/bash
set -euo pipefail

showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing filter ..."
  return $?
}

checkArgs() {
  return $?
}

main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "ambassador")"
  return $?
}

showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### Execute the following command to run kubectl with single sign-on:"
  echo "  ### Execute the following command"
  echo "  ### Your default browser will launch and you should perform the login operation"
  echo "    kubectl config use-context $(getContextName4Kubectl)"
  echo "    kubectl get node          # whatever is okay, just choose the one you like"
  return $?
}

__executor() {
  local __base_fqdn
  __base_fqdn=$(getBaseFQDN)
  local __namespace_for_keycloak
  __namespace_for_keycloak=$(getNamespaceName "keycloak")
  local __hostname_for_keycloak_main
  __hostname_for_keycloak_main=$(getHostName "keycloak" "main")
  local __cluster_name
  __cluster_name=$(getClusterName)
    # rdbox
  local __namespace_for_ambassador
    # ambassador
  local __hostname_for_ambassador_k8ssso
    # ambassador-k8ssso
  local __jwks_uri=http://${__hostname_for_keycloak_main}.${__namespace_for_keycloak}/auth/realms/${__cluster_name}/protocol/openid-connect/certs
    # https://keycloak.rdbox.172-16-0-110.nip.io/auth/realms/rdbox/protocol/openid-connect/certs
  __namespace_for_ambassador=$(getNamespaceName "ambassador")
  __hostname_for_ambassador_k8ssso=$(getHostName "ambassador" "k8ssso")
  ## 1. Install Filter
  ##
  echo ""
  echo "### Applying the filter for Impersonate-Group/User ..."
  applyManifestByDI "${__namespace_for_ambassador}" \
                    "${__hostname_for_ambassador_k8ssso}" \
                    "${__RELEASE_ID}" \
                    180s \
                    ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                    ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                    ambassador.dynamics.k8ssso.filter.jwksUri="${__jwks_uri}"
  ## 2. Set Context
  ##
  local __ctx_name
  __ctx_name=$(getContextName4Kubectl)
  echo ""
  echo "### Setting Cluster Context ..."
  if ! kubectl config delete-context "${__ctx_name}" > /dev/null 2>&1; then
    echo "The ClusterContext(context) is Not Found ...ok"
  fi
  kubectl config set-context "${__ctx_name}" \
      --cluster="${__ctx_name}" \
      --user="${__ctx_name}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?