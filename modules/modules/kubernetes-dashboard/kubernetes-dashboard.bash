#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing kubernetes-dashboard ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  local __SPECIFIC_SECRETS="specific-secrets"
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "kubernetes-dashboard")"
  return $?
}

function showVerifierCommand() {
  local namespace
  namespace=$(getNamespaceName "kubernetes-dashboard")
  echo ""
  echo "## USAGE"
  echo "### kubernetes-dashboard has been installed. Check its status by running:"
  echo "    kubectl -n ${namespace} get deployments -o wide"
  return $?
}

function __executor() {
  ## 1. Define the version of kubernetes-dashboard
  ##
  local __helm_version="5.7.0"
  local __app_version
  __app_version=$(curl -s "https://artifacthub.io/api/v1/packages/helm/k8s-dashboard/kubernetes-dashboard/${__helm_version}" \
                | jq -r ".app_version")
  ## 2. Create a namespace
  ##
  local __namespace_for_k8s_dashboard
  echo ""
  echo "### Create a namespace of kubernetes-dashboard ..."
  __namespace_for_k8s_dashboard="$(getNamespaceName "kubernetes-dashboard")"
  if ! kubectl create namespace "${__namespace_for_k8s_dashboard}" 2>/dev/null; then
    echo "already exist the namespace (${__namespace_for_k8s_dashboard}) ...ok"
  else
    kubectl -n "${__namespace_for_k8s_dashboard}" create secret generic "${__SPECIFIC_SECRETS}" \
      --from-literal=client-secret="$(< /dev/urandom tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
  fi
  ## 3. Create a service account with RBAC
  echo ""
  echo "### Create a service account with RBAC(kubernetes.dashboard) ..."
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v"${__app_version}"/aio/deploy/recommended/05_dashboard-rbac.yaml
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v"${__app_version}"/aio/deploy/recommended/01_dashboard-serviceaccount.yaml
  ## 4. Setup a dummy endpoint of kube-apiserver for the kubernetes-dashboard
  ##
  local __base_fqdn
  local __hostname_for_k8s_dashboard
  local __hostname_for_k8ssso
  local __fqdn_for_k8s_dashboard_main
  local __clientTlsContext
  local __clientNamespace
  local __ca_full_path
  __base_fqdn=$(getBaseFQDN)
  __hostname_for_k8s_dashboard=$(getHostName "kubernetes-dashboard" "main")
  echo ""
  echo "### Issueing cert for kubernetes-dashboard ..."
  applyManifestByDI "${__namespace_for_k8s_dashboard}" \
                    "${__hostname_for_k8s_dashboard}" \
                    "${__RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${__base_fqdn}" \
                    kubernetesDashboard.dynamics.main.hostname="${__hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.certificate.create=true
  __fqdn_for_k8s_dashboard_main=${__hostname_for_k8s_dashboard}.${__base_fqdn}
  waitForSuccessOfCommand \
    "kubectl -n ${__namespace_for_k8s_dashboard} get secrets ${__fqdn_for_k8s_dashboard_main}"
    ### NOTE
    ### Wait until cert is issued
  echo ""
  echo "### Activating k8s SSO Endpoint ..."
  __hostname_for_k8ssso=$(getHostName "kubernetes-dashboard" "k8ssso")
  __filterName=$(getHostName "ambassador" "k8ssso")
  __filterNamespace="$(getNamespaceName "ambassador")"
  __clientTlsContext=$(getHostName "ambassador" "k8ssso")
  __clientNamespace="$(getNamespaceName "ambassador")"
    ### NOTE
    ### Use the deployed single sign-on filter "k8ssso.ambassador"
    ### Therefore, a client certificate is specified
    ### This client certificate indicates the user to whom the Impersonate cluster role is bound
  applyManifestByDI "${__namespace_for_k8s_dashboard}" \
                    "${__hostname_for_k8s_dashboard}" \
                    "${__RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${__base_fqdn}" \
                    kubernetesDashboard.dynamics.main.hostname="${__hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.k8ssso.create=true \
                    kubernetesDashboard.dynamics.k8ssso.hostname="${__hostname_for_k8ssso}" \
                    kubernetesDashboard.dynamics.k8ssso.filter.name="${__filterName}" \
                    kubernetesDashboard.dynamics.k8ssso.filter.namespace="${__filterNamespace}" \
                    kubernetesDashboard.dynamics.k8ssso.client.tlsContext="${__clientTlsContext}" \
                    kubernetesDashboard.dynamics.k8ssso.client.namespace="${__clientNamespace}"
  echo ""
  echo "### Testing k8s SSO Endpoint ..."
  __ca_full_path="${TEMP_DIR}"/tls.crt
  kubectl -n "${__namespace_for_k8s_dashboard}" get secrets "${__fqdn_for_k8s_dashboard_main}" \
    -o jsonpath="{.data.tls\.crt}" | base64 -d > "${__ca_full_path}"
  waitForSuccessOfCommand \
    "curl -fs --cacert ${__ca_full_path} \
      https://${__hostname_for_k8ssso}.${__fqdn_for_k8s_dashboard_main}/version \
      | jq > /dev/null 2>&1"
    ### NOTE
    ### Connection test
  if curl -fs --cacert "${__ca_full_path}" https://"${__hostname_for_k8ssso}"."${__fqdn_for_k8s_dashboard_main}"/version; then
    echo ""
    echo "curl https://${__hostname_for_k8ssso}.${__fqdn_for_k8s_dashboard_main}/version ...ok"
  fi
  ## 5. Setup .kube/config
  ##
  local __name_cm_kubeconfig="kubeconfig"
  local __kubeconfig_file_name="values.kubeconfig.yaml"
  echo ""
  echo "### Activating kubeconfig ..."
  if ! kubectl -n "${__namespace_for_k8s_dashboard}" delete cm "${__name_cm_kubeconfig}" 2>/dev/null; then
    echo "The ${__name_cm_kubeconfig}.${__namespace_for_k8s_dashboard} is Not Found ...ok"
  fi
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/kubernetes-dashboard/subs/values.kubeconfig.bash" \
    "${__namespace_for_k8s_dashboard}" \
    "${__hostname_for_k8s_dashboard}" \
    "${__hostname_for_k8ssso}" \
    "${__base_fqdn}" > "${TEMP_DIR}/${__kubeconfig_file_name}"
  kubectl -n "${__namespace_for_k8s_dashboard}" create cm "${__name_cm_kubeconfig}" \
    --from-file "${TEMP_DIR}/${__kubeconfig_file_name}"
  ## 6. Install kubernetes-dashboard
  ##
  echo ""
  echo "### Installing with helm ..."
  local __conf_of_helm
  local __fqdn_for_k8s_dashboard_k8ssso=${__hostname_for_k8ssso}.${__hostname_for_k8s_dashboard}.${__base_fqdn}
  __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_k8s_dashboard}" confs helm)
  helm -n "${__namespace_for_k8s_dashboard}" upgrade --install "${__hostname_for_k8s_dashboard}" kubernetes-dashboard/kubernetes-dashboard \
    --version ${__helm_version} \
    --create-namespace \
    --wait \
    --timeout 600s \
    --set extraArgs\[0\]="--apiserver-host=https://${__fqdn_for_k8s_dashboard_k8ssso}" \
    --set extraArgs\[1\]="--kubeconfig=/original-kubeconfig/${__kubeconfig_file_name}" \
    --set extraVolumes\[0\].secret.secretName="${__hostname_for_k8s_dashboard}.${__base_fqdn}" \
    --set extraVolumes\[1\].configMap.name="${__name_cm_kubeconfig}" \
    -f "${__conf_of_helm}"
  ## 7. Create a Ingress
  ##
  echo ""
  echo "### Activating Ingress ..."
  local __service_port
  __service_port=$(kubectl -n "${__namespace_for_k8s_dashboard}" get service "${__hostname_for_k8s_dashboard}" \
                  -o jsonpath="{.spec.ports[].port}")
  applyManifestByDI "${__namespace_for_k8s_dashboard}" \
                    "${__hostname_for_k8s_dashboard}" \
                    "${__RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${__base_fqdn}" \
                    kubernetesDashboard.dynamics.main.hostname="${__hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.ingress.create=true \
                    kubernetesDashboard.dynamics.ingress.port="${__service_port}"
  ## 8. Create Entry
  ##
  local src_filepath
  local redirectUris
  local secret
  src_filepath="$(getDirNameFor confs)/modules/${__namespace_for_k8s_dashboard}/entry/$(getConfVersion "${__namespace_for_k8s_dashboard}" entry)/client.jq.json"
  redirectUris="https://${__hostname_for_k8s_dashboard}.${__base_fqdn}/.ambassador/oauth2/redirection-endpoint"
  secret=$(kubectl -n "${__namespace_for_k8s_dashboard}" get secrets "${__SPECIFIC_SECRETS}" \
            -o jsonpath='{.data.client-secret}' | base64 -d)
  local user
  local pass
  user=$(helm -n "$(getNamespaceName keycloak)" get values "$(getNamespaceName keycloak)" -o json | jq -r '.auth.adminUser')
  pass=$(kubectl -n "$(getNamespaceName keycloak)" get secrets specific-secrets -o jsonpath='{.data.adminPassword}' | base64 --decode)
  local realm
  local token
  local entry_target
  local entry_json
  token=$(get_access_token "master" "${user}" "${pass}")
  realm=$(getClusterName)
  entry_target="clients"
  entry_json=$(parse_jq_temlate "${src_filepath}" \
                clientId="${__namespace_for_k8s_dashboard}" \
                redirectUris="${redirectUris}" \
                secret="${secret}")
  create_entry "${realm}" "${token}" "${entry_target}" "${entry_json}"
  revoke_access_token "master" "${token}"
  ## 9. Create Filter
  ##
  local authorization_url
  authorization_url=$(get_authorization_url "${realm}")
  applyManifestByDI "${__namespace_for_k8s_dashboard}" \
                    "${__hostname_for_k8s_dashboard}" \
                    "${__RELEASE_ID}" \
                    90s \
                    kubernetesDashboard.dynamics.common.baseFqdn="${__base_fqdn}" \
                    kubernetesDashboard.dynamics.main.hostname="${__hostname_for_k8s_dashboard}" \
                    kubernetesDashboard.dynamics.filter.create=true \
                    kubernetesDashboard.dynamics.filter.authorizationURL="${authorization_url}" \
                    kubernetesDashboard.dynamics.filter.secret="\"${secret}\""
  return $?
}

TEMP_DIR=$(mktemp -d)
trap 'rm -rf $TEMP_DIR' EXIT

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/keycloak.bash"
main "$@"
exit $?
