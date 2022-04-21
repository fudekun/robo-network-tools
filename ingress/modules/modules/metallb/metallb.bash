#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing metallb ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "metallb")"
  return $?
}

function showVerifierCommand() {
  local namespace
  namespace=$(getNamespaceName "metallb")
  echo ""
  echo "## USAGE"
  echo "### metallb has been installed. Check its status by running:"
  echo "    kubectl -n ${namespace} get deployments -o wide"
  return $?
}

function __executor() {
  local __namespace_for_metallb
  local __hostname_for_metallb_main
  local __docker_network_range
  local __conf_of_helm
  ## 1. Install MetalLB Instance
  ##
  echo ""
  echo "### Installing with helm ..."
  __namespace_for_metallb=$(getNamespaceName "metallb")
  __hostname_for_metallb_main=$(getHostName "metallb" "main")
  __docker_network_range=$(__getNetworkRangeForVirtualHost)
    ### NOTE
    ### Get ConfigValue MetalLB with L2 Mode
  __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_metallb}" confs helm)
  helm -n "${__namespace_for_metallb}" upgrade --install "${__hostname_for_metallb_main}" metallb/metallb \
      --create-namespace \
      --wait \
      --timeout 600s \
      --set configInline.address-pools\[0\].addresses\[0\]="${__docker_network_range}" \
      -f "${__conf_of_helm}"
  return $?
}

function __getNetworkRangeForVirtualHost() {
  local __docker_network_ip
  local __docker_network_prefix
  local __docker_network_range
  __docker_network_ip=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $1}')
  __docker_network_prefix=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $2}')
  if [[ "$__docker_network_prefix" -le 16 ]]; then
    __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s-%s.%s.%s", $1, $2, "255.200", $1, $2, "255.250"}')
  elif [[ "$__docker_network_prefix" -gt 16 ]] && [[ "$__docker_network_prefix" -le 24 ]]; then
    __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s.%s-%s.%s.%s.%s", $1, $2, $3, "200", $1, $2, $3, "250"}')
  else
    echo "WARN: Your Docker network configuration is not expected;"
    echo "- You will need to execute the MetalLB configuration yourself."
    echo "- https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
    return 1
  fi
  echo -n "$__docker_network_range"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?