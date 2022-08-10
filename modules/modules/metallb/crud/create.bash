#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a metallb
# Globals:
#   RDBOX_MODULE_NAME_METALLB
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   CREATES_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing ${MODULE_NAME} ..."
  return $?
}

function checkArgs() {
  return $?
}

function create() {
  showHeaderCommand "$@"
  #######
  update_cluster_info
  #######
  local NAMESPACE
  NAMESPACE="$(getNamespaceName "${MODULE_NAME}")"
  local RELEASE
  RELEASE="$(getReleaseName "${MODULE_NAME}")"
  local BASE_FQDN
  BASE_FQDN=$(getBaseFQDN)
  #######
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### metallb has been installed. Check its status by running:"
  echo "    kubectl -n ${NAMESPACE} get deployments -o wide"
  return $?
}

function __executor() {
  ## 0. Prepare Helm chart
  ##
  local HELM_VERSION_SPECIFIED
  HELM_VERSION_SPECIFIED=$(getHelmPkgVersion "${MODULE_NAME}")
  local HELM_REPO_NAME
  HELM_REPO_NAME=$(getHelmRepoName "${MODULE_NAME}")
  local HELM_PKG_NAME
  HELM_PKG_NAME=$(getHelmPkgName "${MODULE_NAME}")
  local HELM_NAME
  HELM_NAME="${HELM_REPO_NAME}/${HELM_PKG_NAME}"
  local HELM_VERSION
  HELM_VERSION=${HELM_VERSION_SPECIFIED:-$(curl -s https://artifacthub.io/api/v1/packages/helm/"${HELM_NAME}" | jq -r ".version")}
    ### NOTE
    ### If "HELM_VERSION_SPECIFIED" is not specified, the latest version retrieved from the Web is applied.
  prepare_helm_repo
  ## 1. Install MetalLB Instance
  ##
  echo ""
  echo "### Installing with helm ..."
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
      --version "${HELM_VERSION}" \
      --create-namespace \
      --wait \
      --timeout 600s \
      --set controller.podAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set controller.serviceAccount.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set speaker.podAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set speaker.serviceAccount.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  ## 2. Create a CRDs
  ##
  local __hostname_for_metallb_main
  local __docker_network_range
  __hostname_for_metallb_main=$(getHostName "metallb" "main")
  __docker_network_range=$(__getNetworkRangeForVirtualHost)
    ### NOTE
    ### Get ConfigValue MetalLB with L2 Mode
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    metallb.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    metallb.dynamics.main.hostname="${__hostname_for_metallb_main}" \
                    metallb.dynamics.IPAddressPool.create="true" \
                    metallb.dynamics.IPAddressPool.addresses="${__docker_network_range}"
  return $?
}

function __getNetworkRangeForVirtualHost() {
  local __docker_network_ip
  local __docker_network_prefix
  local __docker_network_range
  __docker_network_ip=$(sudo docker network inspect kind \
                        | jq -r ".[].IPAM.Config[].Subnet" \
                        | grep -v ":" | awk -F/ '{print $1}')
  __docker_network_prefix=$(sudo docker network inspect kind \
                        | jq -r ".[].IPAM.Config[].Subnet" \
                        | grep -v ":" \
                        | awk -F/ '{print $2}')
  if [[ "$__docker_network_prefix" -le 16 ]]; then
    __docker_network_range=$(echo "$__docker_network_ip" \
                        | awk -F. '{printf "%s.%s.%s-%s.%s.%s", $1, $2, "255.200", $1, $2, "255.250"}')
  elif [[ "$__docker_network_prefix" -gt 16 ]] && [[ "$__docker_network_prefix" -le 24 ]]; then
    __docker_network_range=$(echo "$__docker_network_ip" \
                        | awk -F. '{printf "%s.%s.%s.%s-%s.%s.%s.%s", $1, $2, $3, "200", $1, $2, $3, "250"}')
  else
    echo "WARN: Your Docker network configuration is not expected;"
    echo "- You will need to execute the MetalLB configuration yourself."
    echo "- https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
    return 1
  fi
  echo -n "$__docker_network_range"
  return 0
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"