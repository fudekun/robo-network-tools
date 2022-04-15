#!/bin/bash
set -euo pipefail

###############################################################################
## Create a minimum KinD to run a ROS2 app on a Kubernetes cluster.
###############################################################################

## 0. Input Argument Checking
##
checkArgs() {
  echo ""
  printf "# ARGS:\n%s\n" "$*"
  printf "# ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x //')"
  if [ $# -lt 2 ] || [ "$1" = "help" ]; then
    echo "# Args"
    echo "     \${1} Specify the cluster name  (e.g. rdbox)"
    echo "     \${2} Specify the Domain name   (e.g. Your Domain OR nip.io, sslip.io ...)"
    echo "(opt)\${3} Specify the Host name     (e.g. rdbox-master-00)"
    echo ""
    echo "# EnvironmentVariable"
    echo "  (recommend: Use automatic settings)"
    echo "| Name                          | e.g.                       |"
    echo "| ----------------------------  | -------------------------- |"
    echo "| RDBOX_NAME_DEFULT_NIC         | en0                        |"
    echo "| RDBOX_WORKDIR_OF_WORK_BASE    | HOME/rdbox/#1              |"
    exit 1
  fi
  __RDBOX_CLUSTER_NAME=$(printf %q "$1")
    # EXTRAPOLATION
  export __RDBOX_CLUSTER_NAME=$__RDBOX_CLUSTER_NAME
  __RDBOX_DOMAIN_NAME=$(printf %q "$2")
    # EXTRAPOLATION
  export __RDBOX_DOMAIN_NAME=$__RDBOX_DOMAIN_NAME
  if [ $# = 3 ]; then
    __RDBOX_HOST_NAME=$(printf %q "$3")
      # EXTRAPOLATION
    export __RDBOX_HOST_NAME=$__RDBOX_HOST_NAME
  fi
  return $?
}

## 1. Install KinD
##
installKinD() {
  bash "$(getWorkdirOfScripts)/create_kind.bash" "${__RDBOX_CLUSTER_NAME}"
  return $?
}

## 2. SetUp ConfigMap
##
setupConfigMap() {
  __executor() {
    ## .1 If the Namespace already exists, recreate it
    ##
    if ! bash -c "kubectl delete namespace ${__RDBOX_CLUSTER_INFO_NAMESPACE} >/dev/null 2>&1"; then
      echo "The namespace(${__RDBOX_CLUSTER_INFO_NAMENAME}.${__RDBOX_CLUSTER_INFO_NAMESPACE}) is Not Found ...ok"
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
    kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" patch configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
      --type merge \
      --patch "$(kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" create configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
                  --dry-run=client \
                  --output=json \
                  --from-env-file="${__workdir_of_confs}"/meta-pkgs/essentials.env.properties \
                )"
    return $?
  }
  echo ""
  echo "---"
  echo "## Installing cluster-info ..."
  cmdWithIndent "__executor"
  return $?
}

## 3. Install Weave-Net
##
installWeaveNet() {
  bash "$(getWorkdirOfScripts)/create_weave-net.bash"
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  echo ""
  echo "# USAGE"
  echo "---"
  echo "## K8s Cluster by KinD and Weave-Net has been installed. Check its status by running:"
  echo "    kubectl get node -o wide"
  echo ""
  echo "# SUCCESS"
  echo "[$(getIso8601DayTime)][$(basename "$0")]"
  drawMaxColsSeparator "*" "39"
  return $?
}

main() {
  ## 0. Input Argument Checking
  ##
  checkArgs "$@"
  ## 1. Install KinD
  ##
  cmdWithLoding \
    "installKinD" \
    "Activating K8s Cluster by KinD"
  ## 2. SetUp ConfigMap
  ##
  cmdWithLoding \
    "setupConfigMap" \
    "Activating cluster-info"
  ## 3. Install Weave-Net
  ##
  cmdWithLoding \
    "installWeaveNet" \
    "Activating Weave-Net"
  ## 99. Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

## Set the base directory for RDBOX scripts!!
##
RDBOX_WORKDIR_OF_SCRIPTS_BASE=${RDBOX_WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
RDBOX_WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$RDBOX_WORKDIR_OF_SCRIPTS_BASE")
export RDBOX_WORKDIR_OF_SCRIPTS_BASE=$RDBOX_WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
showHeader
main "$@"
exit $?