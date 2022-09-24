#!/usr/bin/env bash
set -euo pipefail

###############################################################################
## Create a minimum KinD to run a ROS2 app on a Kubernetes cluster.
###############################################################################

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "# Installing Meta-Package (k8s-cluster) ..."
  return $?
}

## 0. Input Argument Checking
##
function checkArgs() {
  echo ""
  printf "# ARGS:\n%q (%s arg(s))\n" "$*" "$#"
  printf "# ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x //')"
  local opt optarg
  while getopts "${__RDBOX_OPTS_CREATE_MAIN}""${__RDBOX_OPTS_RDBOX_MAIN}"-: opt; do
    optarg="$OPTARG"
    if [[ "$opt" = - ]]; then
      opt="-${OPTARG%%=*}"
      optarg="${OPTARG/${OPTARG%%=*}/}"
      optarg="${optarg#=}"
      if [[ -z "$optarg" ]] && [[ ! "${!OPTIND}" = -* ]]; then
        optarg="${!OPTIND}"
        shift
      fi
    fi
    case "-$opt" in
      -d|--domain) domain_name="$optarg" ;;
      -h|--host) host_name="$optarg" ;;
      -n|--name) cluster_name="$optarg" ;;
      -o|--volume_type) volume_type="$optarg" ;;
      *) ;;
    esac
  done
  shift $((OPTIND - 1))
  return $?
}

function main() {
  showHeaderCommand "$@"
  executor "$@"
  # cmdWithIndent "executor $*"
  showVerifierCommand
  return $?
}

## 99. Notify Verifier-Command
##
function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### K8s Cluster by KinD and Weave-Net has been installed. Check its status by running:"
  echo "    kubectl get node -o wide"
  return $?
}

function executor() {
  ## Input Argument Checking
  ##
  local cluster_name domain_name volume_type host_name
  checkArgs "${@:2}"
  host_name=${host_name:-}
  volume_type=${volume_type:-}
  if [ -z "${volume_type}" ]; then
    echo "You must set (-o|--volume_type [nfs|tmp])"
    return 1
  fi
  ## Install KinD
  ##
  cmdWithLoding \
    "installKinD ${cluster_name} ${domain_name} ${host_name}" \
    "Activating the K8s Cluster by KinD"
  ## SetUp ConfigMap
  ##
  cmdWithLoding \
    "setupConfigMap ${cluster_name} ${domain_name} ${host_name}" \
    "Activating the cluster-info"
  ## Install Weave-Net
  ##
  cmdWithLoding \
    "installWeaveNet" \
    "Activating the weave-net"
  ## Install Volume
  ##
  cmdWithLoding \
    "installVolume ${*:2}" \
    "Activating the volume"
  return $?
}

## 1. Install KinD
##
function installKinD() {
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/kind/kind.bash" "$@"
  return $?
}

## 2. SetUp ConfigMap
##
function setupConfigMap() {
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/cluster-info/cluster-info.bash" "$@"
  return $?
}

## 3. Install Weave-Net
##
function installWeaveNet() {
  bash "$(getWorkdirOfScripts)/modules/modules/weave-net/weave-net.bash"
  return $?
}

## 4. Install Volume
##
function installVolume() {
  bash "$(getWorkdirOfScripts)/modules/modules/volume/volume.bash" "$@"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?