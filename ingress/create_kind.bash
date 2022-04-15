#!/bin/bash
set -euo pipefail

showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Creating K8s Cluster by KinD ..."
  return $?
}

main() {
  local __cluster_name
  __cluster_name=$1
  showHeaderCommand "$__cluster_name"
  cmdWithIndent "__executor $__cluster_name"
  showVerifierCommand > "$(getFullpathOfVerifyMsgs "kind")"
  return $?
}

showVerifierCommand() {
  echo ""
  echo "---"
  echo "## KinD has been installed. Check its status by running:"
  echo "    kind get nodes --name rdbox"
  return $?
}

__executor() {
  ## Define version of the manifest
  ##
  local __VERSION_OF_MANIFEST
  __VERSION_OF_MANIFEST="v1beta1"
  ## Create the cluster
  ##
  local __cluster_name
  local __workbase_dirs
  local __workdir_of_confs
  local __conffile_path
  if isValidHostname "$1"; then
    __cluster_name=$1
  else
    return 1
  fi
  __workbase_dirs=$(getDirNameListOfWorkbase "${__cluster_name}")
  __workdir_of_confs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $5}')
  __conffile_path=${__workdir_of_confs}/modules/kind/kind/${__VERSION_OF_MANIFEST}/values.yaml
  if ! bash -c "kind get clusters | grep -c ${__cluster_name} >/dev/null 2>&1"; then
    kind create cluster --config "${__conffile_path}" --name "${__cluster_name}"
  else
    echo "already exist for a cluster with the name ${__cluster_name}"
  fi
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?