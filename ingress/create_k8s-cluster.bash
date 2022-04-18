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
  return $?
}

## 1. Install KinD
##
installKinD() {
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_kind.bash" "$@"
  return $?
}

## 2. SetUp ConfigMap
##
setupConfigMap() {
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_cluster-info.bash" "$@"
  return $?
}

## 3. Install Weave-Net
##
installWeaveNet() {
  bash "$(getWorkdirOfScripts)/create_weave-net.bash" "$@"
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  echo ""
  echo "# USAGE"
  echo "## K8s Cluster by KinD and Weave-Net has been installed. Check its status by running:"
  echo "    kubectl get node -o wide"
  echo ""
  echo "# SUCCESS"
  echo "[$(getIso8601DayTime)][$(basename "$0")]"
  drawMaxColsSeparator "*" "39"
  return $?
}

main() {
  ## Input Argument Checking
  ##
  checkArgs "$@"
  ## Install KinD
  ##
  cmdWithLoding \
    "installKinD $*" \
    "Activating the K8s Cluster by KinD"
  ## SetUp ConfigMap
  ##
  cmdWithLoding \
    "setupConfigMap $*" \
    "Activating the cluster-info"
  ## Install Weave-Net
  ##
  cmdWithLoding \
    "installWeaveNet $*" \
    "Activating the weave-net"
  ## Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?