#!/bin/bash
set -euo pipefail

###############################################################################
## Create a minimum KinD to run a ROS2 app on a Kubernetes cluster.
###############################################################################

## 0. Input Argument Checking
##
checkArgs() {
  if [ $# -lt 2 ] || [ "$1" = "help" ]; then
    echo "# Args"
    echo "     \${1} Specify the cluster name  (e.g. rdbox)"
    echo "     \${2} Specify the Domain name   (e.g. Your Domain OR nip.io, sslip.io ...)"
    echo "(opt)\${3} Specify the Host name     (e.g. rdbox-master-00)"
    echo ""
    echo "# EnvironmentVariable"
    echo "  (recommend: Use automatic settings)"
    echo "| Name                     | e.g.                        |"
    echo "| :----------------------  | :-------------------------- |"
    echo "| NAME_DEFULT_NIC          | en0                         |"
    echo "| WORKDIR_OF_WORK_BASE     | \${HOME}/rdbox/\${1}          |"
    exit 1
  fi
  CLUSTER_NAME=$(printf %q "$1")
    # EXTRAPOLATION
  export CLUSTER_NAME=$CLUSTER_NAME
  DOMAIN_NAME=$(printf %q "$2")
    # EXTRAPOLATION
  export DOMAIN_NAME=$DOMAIN_NAME
  if [ $# = 3 ]; then
    HOST_NAME=$(printf %q "$3")
      # EXTRAPOLATION
    export HOST_NAME=$HOST_NAME
  fi
  return $?
}

## 1. Install KinD
##
installKinD() {
  __executer() {
    local __exist_cluster
    if ! bash -c "kind get clusters | grep -c ${CLUSTER_NAME}  >/dev/null 2>&1"; then
      kind create cluster --config values_for_kind-cluster.yaml --name "$CLUSTER_NAME"
    else
      echo "already exist for a cluster with the name ${CLUSTER_NAME}"
    fi
    return $?
  }
  echo ""
  echo "---"
  echo "## Creating K8s Cluster by KinD ..."
  cmdWithIndent "__executer"
  return $?
}

## 2. SetUp ConfigMap
##
setupConfigMap() {
  __executer() {
    ## .1 If the Namespace already exists, recreate it
    ##
    if ! bash -c "kubectl delete namespace ${CLUSTER_INFO_NAMESPACE} >/dev/null 2>&1"; then
      echo "The ${CLUSTER_INFO_NAMENAME}.${CLUSTER_INFO_NAMESPACE} is Not Found"
    fi
    kubectl create namespace "${CLUSTER_INFO_NAMESPACE}"
    getNetworkInfo
      # These returning value are passed by EXPORT
    HOST_NAME=${HOST_NAME:-$HOSTNAME_FOR_WCDNS_BASED_ON_IP}
      # If no value is declared, WDNS will create a hostname following the general naming conventions.
    WORKDIR_OF_WORK_BASE=${WORKDIR_OF_WORK_BASE:-${HOME}/rdbox/${CLUSTER_NAME}}
    WORKDIR_OF_WORK_BASE=$(printf %q "$WORKDIR_OF_WORK_BASE")
      # EXTRAPOLATION
    local __workdir_of_logs=${WORKDIR_OF_WORK_BASE}/logs
    local __workdir_of_outputs=${WORKDIR_OF_WORK_BASE}/outputs
    local __workdir_of_tmps=${WORKDIR_OF_WORK_BASE}/tmps
    mkdir -p "${__workdir_of_logs}" "${__workdir_of_outputs}" "${__workdir_of_tmps}"
    cat <<EOF | kubectl apply --timeout 90s --wait -f -
      apiVersion: v1
      kind: ConfigMap
      metadata:
        name:      "${CLUSTER_INFO_NAMENAME}"
        namespace: "${CLUSTER_INFO_NAMESPACE}"
      data:
        name: ${CLUSTER_NAME}
        nic0.name:         "${NAME_DEFULT_NIC}"
        nic0.host:         "${HOST_NAME}"
        nic0.domain:       "${DOMAIN_NAME}"
        nic0.base_fqdn:    "${CLUSTER_NAME}.${HOST_NAME}.${DOMAIN_NAME}"
        nic0.ipv4:         "${IPV4_DEFAULT_NIC}"
        nic0.ipv4_hyphen:  "${HOSTNAME_FOR_WCDNS_BASED_ON_IP}"
        nic0.ipv6:         "${IPV6_DEFAULT_NIC}"
        workdir.work_base:   "${WORKDIR_OF_WORK_BASE}"
        workdir.logs:        "${__workdir_of_logs}"
        workdir.outputs:     "${__workdir_of_outputs}"
        workdir.tmps:        "${__workdir_of_tmps}"
        workdir.scripts:     "${WORKDIR_OF_SCRIPTS_BASE}"

EOF
    return $?
  }
  echo ""
  echo "---"
  echo "## Installing cluster-info ..."
  cmdWithIndent "__executer"
  return $?
}

## 3. Install Weave-Net
##
installWeaveNet() {
  bash "$(getWorkdirOfScripts)/create_weave.bash"
  return $?
}

## xx. Header
##
header() {
  echo "START $(getIso8601String)"
  drawMaxColsSeparator "=" "39"
  echo ""
  echo "---"
  echo "# This is an advanced IT platform for robotics and IoT developers"
  echo "            .___. "
  echo "           /___/| "
  echo "           |   |/ "
  echo "           .---.  "
  echo "           RDBOX  "
  echo "- A Robotics Developers BOX -"
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  echo ""
  echo "---"
  echo "## K8s Cluster by KinD and Weave-Net has been installed. Check its status by running:"
  echo "    kubectl get node -o wide"
  echo ""
  echo "FINISH $(getIso8601String)"
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
    "bash ./create_weave.bash" \
    "Activating Weave-Net"
  ## 99. Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

## Set the base directory for RDBOX scripts!!
##
export WORKDIR_OF_SCRIPTS_BASE=${WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
  # Values can also be inserted externally
source "${WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
# header "$@"
main "$@"
exit $?