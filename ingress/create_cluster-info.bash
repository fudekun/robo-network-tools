#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing the cluster-info ..."
  return $?
}

function checkArgs() {
  if isValidClustername "$1"; then
    __RDBOX_CLUSTER_NAME=$(printf %q "$1")
    export __RDBOX_CLUSTER_NAME=$__RDBOX_CLUSTER_NAME
    readonly __RDBOX_CLUSTER_NAME
  else
    return 1
  fi
  if isValidDomainname "$2"; then
    __RDBOX_DOMAIN_NAME=$(printf %q "$2")
    export __RDBOX_DOMAIN_NAME=$__RDBOX_DOMAIN_NAME
    readonly __RDBOX_DOMAIN_NAME
  else
    return 2
  fi
  if [[ $# -eq 3 ]]; then
    if isValidHostname "$3"; then
      __RDBOX_HOST_NAME=$(printf %q "$3")
      export __RDBOX_HOST_NAME=$__RDBOX_HOST_NAME
      readonly __RDBOX_HOST_NAME
    else
      return 3
    fi
  fi
}

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  showVerifierCommand > /dev/null 2>&1
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### Cluster-Info has been installed. Check its status by running:"
  echo "    kubectl -n ${__RDBOX_CLUSTER_INFO_NAMESPACE} get configmap ${__RDBOX_CLUSTER_INFO_NAMENAME} -o yaml"
  return $?
}

function __executor() {
  ## Input Argument Checking
  ##
  checkArgs "$@"
  ## If the Namespace already exists, recreate it
  ##
  if ! bash -c "kubectl delete namespace ${__RDBOX_CLUSTER_INFO_NAMESPACE} >/dev/null 2>&1"; then
    echo "The namespace(${__RDBOX_CLUSTER_INFO_NAMESPACE}) is Not Found ...ok"
  fi
  kubectl create namespace "${__RDBOX_CLUSTER_INFO_NAMESPACE}"
  getNetworkInfo
    ### NOTE
    ### These returning value are passed by EXPORT
  __RDBOX_HOST_NAME=${__RDBOX_HOST_NAME:-$HOSTNAME_FOR_WCDNS_BASED_ON_IP}
    ### NOTE
    ### If no value is declared, WDNS will create a hostname following the general naming conventions.
  local __workbase_dirs
  local __workdir_of_work_base
  local __workdir_of_logs
  local __workdir_of_outputs
  local __workdir_of_tmps
  local __workdir_of_confs
  __workbase_dirs=$(getDirNameListOfWorkbase "${__RDBOX_CLUSTER_NAME}")
  __workdir_of_work_base=$(echo "$__workbase_dirs" | awk -F ' ' '{print $1}')
  __workdir_of_logs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $2}')
  __workdir_of_outputs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $3}')
  __workdir_of_tmps=$(echo "$__workbase_dirs" | awk -F ' ' '{print $4}')
  __workdir_of_confs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $5}')
  cat <<EOF | kubectl apply --timeout 90s --wait -f -
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name:      "${__RDBOX_CLUSTER_INFO_NAMENAME}"
      namespace: "${__RDBOX_CLUSTER_INFO_NAMESPACE}"
    data:
      name: ${__RDBOX_CLUSTER_NAME}
      nic0.name:         "${RDBOX_NAME_DEFULT_NIC}"
      nic0.host:         "${__RDBOX_HOST_NAME}"
      nic0.domain:       "${__RDBOX_DOMAIN_NAME}"
      nic0.base_fqdn:    "${__RDBOX_CLUSTER_NAME}.${__RDBOX_HOST_NAME}.${__RDBOX_DOMAIN_NAME}"
      nic0.ipv4:         "${IPV4_DEFAULT_NIC}"
      nic0.ipv4_hyphen:  "${HOSTNAME_FOR_WCDNS_BASED_ON_IP}"
      nic0.ipv6:         "${IPV6_DEFAULT_NIC}"
      workdir.work_base:   "${__workdir_of_work_base}"
      workdir.logs:        "${__workdir_of_logs}"
      workdir.outputs:     "${__workdir_of_outputs}"
      workdir.tmps:        "${__workdir_of_tmps}"
      workdir.confs:       "${__workdir_of_confs}"
      workdir.scripts:     "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}"
EOF
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?