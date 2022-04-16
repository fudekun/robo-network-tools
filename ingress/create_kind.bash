#!/bin/bash
set -euo pipefail

showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Creating the K8s Cluster by KinD ..."
  return $?
}

main() {
  local __RDBOX_CLUSTER_NAME
  __RDBOX_CLUSTER_NAME=$1
  showHeaderCommand "$__RDBOX_CLUSTER_NAME"
  cmdWithIndent "__executor $__RDBOX_CLUSTER_NAME"
  showVerifierCommand > /dev/null 2>&1
  return $?
}

showVerifierCommand() {
  echo ""
  echo "# USAGE"
  echo "## KinD has been installed. Check its status by running:"
  echo "    kind get nodes --name rdbox"
  return $?
}

checkArgs() {
  ## Define version of the manifest
  ##
  readonly __VERSION_OF_MANIFEST="v1beta1"
  ## Check Args
  ##
  if isValidHostname "$1"; then
    __RDBOX_CLUSTER_NAME=$(printf %q "$1")
    export __RDBOX_CLUSTER_NAME=$__RDBOX_CLUSTER_NAME
    readonly __RDBOX_CLUSTER_NAME
  else
    return 1
  fi
  return $?
}

__executor() {
  ## .0 Check Value
  ##
  checkArgs "$@"
  ## .1 Create the cluster
  ##
  local __workbase_dirs
  local __workdir_of_confs
  local __conffile_path
  __workbase_dirs=$(getDirNameListOfWorkbase "${__RDBOX_CLUSTER_NAME}")
  __workdir_of_confs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $5}')
  __conffile_path=${__workdir_of_confs}/modules/kind/kind/${__VERSION_OF_MANIFEST}/values.yaml
  if ! bash -c "kind get clusters | grep -c ${__RDBOX_CLUSTER_NAME} >/dev/null 2>&1"; then
    kind create cluster --config "${__conffile_path}" --name "${__RDBOX_CLUSTER_NAME}"
  else
    echo "already exist for a cluster with the name ${__RDBOX_CLUSTER_NAME}"
  fi
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?