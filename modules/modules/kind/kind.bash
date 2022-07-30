#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Creating the K8s Cluster by KinD ..."
  return $?
}

function checkArgs() {
  ## Define version of the manifest
  ##
  readonly __VERSION_OF_MANIFEST="v1beta1"
  ## Check Args
  ##
  if isValidClustername "$1"; then
    __RDBOX_CLUSTER_NAME=$(printf %q "$1")
    export __RDBOX_CLUSTER_NAME=$__RDBOX_CLUSTER_NAME
    readonly __RDBOX_CLUSTER_NAME
  else
    return 1
  fi
  return $?
}

function main() {
  showHeaderCommand
  cmdWithIndent "__executor $*"
  showVerifierCommand > /dev/null 2>&1
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### KinD has been installed. Check its status by running:"
  echo "    kind get nodes --name rdbox"
  return $?
}

function __executor() {
  ## .0 Check Value
  ##
  checkArgs "$@"
  ## .1 Create the cluster
  ##
  local __RDBOX_DOMAIN_NAME
  local __workbase_dirs
  local __workdir_of_confs
  local __workdir_of_tmps
  local __conffile_path
  __RDBOX_DOMAIN_NAME=$2
  __RDBOX_HOST_NAME=${3:-""}
  __workbase_dirs=$(getDirNameListOfWorkbase "${__RDBOX_CLUSTER_NAME}")
  __workdir_of_tmps=$(echo "$__workbase_dirs" | awk -F ' ' '{print $4}')
  __workdir_of_confs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $5}')
  __conffile_path=${__workdir_of_confs}/modules/kind/kind/${__VERSION_OF_MANIFEST}/values.yaml
  if ! bash -c "sudo kind get clusters | grep -c ${__RDBOX_CLUSTER_NAME} >/dev/null 2>&1"; then
    sudo kind create cluster --kubeconfig "${KUBECONFIG}" --config "${__conffile_path}" --name "${__RDBOX_CLUSTER_NAME}"
    if [[ $(isRequiredSecurityTunnel) == "true" ]]; then
      __showMsgAboutSecurityTunnel "$(getPortnumberOfkubeapi "${__RDBOX_CLUSTER_NAME}")"
      return 1
    else
      sudo chown "${LOCAL_UID}":"${LOCAL_GID}" "${KUBECONFIG}"
    fi
  else
    echo "already exist for a cluster with the name ${__RDBOX_CLUSTER_NAME}"
  fi
  return $?
}

function __showMsgAboutSecurityTunnel() {
  local port
  port=$1
  echo ""
  echo "## You have successfully built a KinD cluster"
  echo "## But, The following operations are required in your environment (MacOS Container)"
  echo "### First, execute the following command in **HostOS**:"
  echo "    NOTE: the gost is a tunnel module [A simple security tunnel written in Golang](https://github.com/ginuerzh/gost/blob/master/README_en.md)"
  echo "    \`\`\`bash"
  echo "    cd \${A directory where you can download the gost module without problems}"
  echo "    curl -qL -o gost.gz https://github.com/ginuerzh/gost/releases/download/v${__RDBOX_HELPFUL_APPS_OF_GOST_VERSION}/gost-darwin-amd64-${__RDBOX_HELPFUL_APPS_OF_GOST_VERSION}.gz"
  echo "    gzip -d gost.gz"
  echo "    chmod u+x gost"
  echo "    ./gost -L tcp://127.0.0.1:${__RDBOX_HELPFUL_APPS_OF_GOST_PORT}/127.0.0.1:${port}"
  echo "    \`\`\`"
  echo "### Next, execute the same command (rdbox create ...) again!!"
  echo ""
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?