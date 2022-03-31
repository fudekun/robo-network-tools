#!/bin/bash
set -euo pipefail

###############################################################################
## Create a minimum KinD to run a ROS2 app on a Kubernetes cluster.
###############################################################################

## 0. Input Argument Checking
##
checkingArgs() {
  header() {
    echo ""
    echo "---"
    echo "# This is an advanced IT platform for robotics and IoT developers ..."
    echo "            .___. "
    echo "           /___/| "
    echo "           |   |/ "
    echo "           .---.  "
    echo "           RDBOX  "
    echo "- A Robotics Developers BOX -"
  }
  if [ $# -lt 2 ]; then
    echo "# Args"
    echo "          \${1} Specify the cluster name  (e.g. rdbox)"
    echo "          \${2} Specify the Domain name   (e.g. Your Domain OR nip.io, sslip.io ...)"
    echo "(optional)\${3} Specify the Host name     (e.g. rdbox-master-00)"
    echo ""
    echo "# EnvironmentVariable"
    echo "(recommend: Use automatic settings)"
    echo "| Name                | e.g.                        |"
    echo "| :------------------ | :-------------------------- |"
    echo "| NAME_DEFULT_NIC     | en0                         |"
    echo "| CLUSTER_WORKDIR     | \${HOME}/rdbox/\${1}        |"
    exit 1
  fi
  CLUSTER_NAME=$(printf %q "$1")
    # ExtrapolationValue
  export CLUSTER_NAME=$CLUSTER_NAME
  DOMAIN_NAME=$(printf %q "$2")
    # ExtrapolationValue
  export DOMAIN_NAME=$DOMAIN_NAME
  if [ $# = 3 ]; then
    HOST_NAME=$(printf %q "$3")
      # ExtrapolationValue
    export HOST_NAME=$HOST_NAME
  fi
  header
  return $?
}

## 1. Install KinD
##
installKinD() {
  echo ""
  echo "---"
  echo "## Creating K8s Cluster by KinD ..."
  kind create cluster --config values_for_kind-cluster.yaml --name "$CLUSTER_NAME"
  return $?
}

## 2. SetUp ConfigMap
##
setupConfigMap() {
  echo ""
  echo "---"
  echo "## Installing cluster-info ..."
  cmdWithLoding \
    "kubectl create namespace cluster-common 1> /dev/null" \
    "Getting Ready cluster-info"
  getNetworkInfo # Get the information needed to fill in the blanks below
  HOST_NAME=${HOST_NAME:-$HOSTNAME_FOR_WCDNS_BASED_ON_IP}
  CLUSTER_WORKDIR=${CLUSTER_WORKDIR:-${HOME}/rdbox/${CLUSTER_NAME}}
  CLUSTER_WORKDIR=$(printf %q "$CLUSTER_WORKDIR")
    # ExtrapolationValue
  local LOGS_DIR=${CLUSTER_WORKDIR}/logs
  local OUTPUTS_DIR=${CLUSTER_WORKDIR}/outputs
  local TMPS_DIR=${CLUSTER_WORKDIR}/tmps
  mkdir -p "${LOGS_DIR}" "${OUTPUTS_DIR}" "${TMPS_DIR}"
cat <<EOF | kubectl apply --timeout 90s --wait -f - 1> /dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${CLUSTER_INFO_NAMENAME}
  namespace: ${CLUSTER_INFO_NAMESPACE}
data:
  name: ${CLUSTER_NAME}
  host: ${HOST_NAME}
  domain: ${DOMAIN_NAME}
  base_fqdn: "${CLUSTER_NAME}.${HOST_NAME}.${DOMAIN_NAME}"
  nic.name: ${NAME_DEFULT_NIC}
  nic.ipv4: ${IP_DEFAULT_NIC}
  nic.ipv4_hyphen: ${HOSTNAME_FOR_WCDNS_BASED_ON_IP}
  workdir.base: ${CLUSTER_WORKDIR}
  workdir.logs: ${LOGS_DIR}
  workdir.outputs: ${OUTPUTS_DIR}
  workdir.tmps: ${TMPS_DIR}
EOF
  local __status=$?
  return ${__status}
}

## 3. Install Weave-Net
##
installWeaveNet() {
  bash ./create_weave.bash
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  echo ""
  echo "---"
  echo "## K8s Cluster by KinD and Weave-Net has been installed. Check its status by running:"
  echo "    kubectl get node -o wide"
  return $?
}

main() {
  ## 0. Input Argument Checking
  ##
  checkingArgs "$@"
  ## 1. Install KinD
  ##
  installKinD
  ## 2. SetUp ConfigMap
  ##
  setupConfigMap
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

source ./create_common.bash
main "$@"
exit $?