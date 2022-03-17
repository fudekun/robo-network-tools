#!/bin/bash
set -euo pipefail

###############################################################################
## Create a minimum KinD to run a ROS2 app on a Kubernetes cluster.
###############################################################################

## 0. Input Argument Checking
##
checkingArgs() {
  if [ $# != 2 ]; then
    echo "\$1 Specify the cluster name (e.g. rdbox)"
    echo "\$2 Specify the Domain name (e.g. Your Domain OR nip.io, sslip.io ...)"
    exit 1
  fi
  CLUSTER_NAME="$1"
  export CLUSTER_NAME
  DNS_SERVICE="$2"
  export DNS_SERVICE
  return $?
}

## 1. Install KinD
##
installKinD() {
  kind create cluster --config values_for_kind-cluster.yaml --name "$CLUSTER_NAME"
  return $?
}

## 2. SetUp ConfigMap
##
setupConfigMap() {
  echo ""
  echo "---"
  echo "Installing cluster-info ..."
  cmdWithLoding \
    "kubectl create namespace cluster-common" \
    "Getting Ready cluster-info"
  getNetworkInfo # Get the information needed to fill in the blanks below
cat <<EOF | kubectl apply --timeout 90s --wait -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-info
  namespace: cluster-common
data:
  name: ${CLUSTER_NAME}
  domain: ${DNS_SERVICE}
  base_fqdn: "${CLUSTER_NAME}.${HOSTNAME_FOR_WCDNS_BASED_ON_IP}.${DNS_SERVICE}"
  nic.name: ${NAME_DEFULT_NIC}
  nic.ip_v4: ${IP_DEFAULT_NIC}
  nic.ip_hyphen: ${HOSTNAME_FOR_WCDNS_BASED_ON_IP}
EOF
  local __status=$?
  echo ""
  echo "In this cluster, **$(getBaseFQDN)** is used as the base FQDN"
  echo -e "\033[32mok!\033[m cluster-info"
  return ${__status}
}

## 3. Install Weave-Net
##
installWeaveNet() {
  echo ""
  echo "---"
  echo "Installing Weave-Net ..."
  kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
  cmdWithLoding \
    "kubectl wait --timeout=180s -n kube-system --for=condition=ready pod -l name=weave-net" \
    "Activating Weave-Net"
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  echo ""
  echo "---"
  echo "KinD-Cluster and Weave-Net has been installed. Check its status by running:"
  echo "  kubectl get node -o wide"
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
  installWeaveNet
  ## 99. Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

source ./create_common.bash
main "$@"
exit $?