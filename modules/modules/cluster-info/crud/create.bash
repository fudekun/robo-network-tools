#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a std-web
# Globals:
#   RDBOX_MODULE_NAME_KIND
#   MODULE_NAME
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function checkArgs() {
  cmdWithIndent "showParams ${*}"
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
      *) ;;
    esac
  done
  shift $((OPTIND - 1))
  return $?
}

function showParams() {
  local argstr envstr
  argstr=$(printf "# ARGS:\n%q (%s arg(s))\n" "$*" "$#")
  envstr=$(printf "# ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x //')")
  echo "---"
  echo "${argstr}"
  echo "${envstr}"
  echo "---"
  return 0
}

function checkNames() {
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
      ###readonly __RDBOX_HOST_NAME
    else
      return 3
    fi
  fi
}

function create() {
  local cluster_name domain_name host_name
  checkArgs "$@"
  host_name=${host_name:-}
  if cmdWithIndent "executor ${cluster_name} ${domain_name} ${host_name}"; then
    verify_string=$(showVerifierCommand)
    echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
    return 0
  else
    return 1
  fi
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### Cluster-Info has been installed. Check its status by running:"
  echo "    kubectl -n ${__RDBOX_CLUSTER_INFO_NAMESPACE} get configmap ${__RDBOX_CLUSTER_INFO_NAMENAME} -o yaml"
  return 0
}

function executor() {
  if __executor "${@}"; then
    exit 0
  else
    exit 1
  fi
}

function __executor() {
  ## Check value
  ##
  checkNames "$@"
  ## If the Namespace already exists, recreate it
  ##
  if ! bash -c "kubectl delete namespace ${__RDBOX_CLUSTER_INFO_NAMESPACE} >/dev/null 2>&1"; then
    echo "The namespace(${__RDBOX_CLUSTER_INFO_NAMESPACE}) is Not Found ...ok"
  fi
  kubectl create namespace "${__RDBOX_CLUSTER_INFO_NAMESPACE}"
  getNetworkInfo
    ### NOTE
    ### Get a network info and Export ones
    ### RDBOX_NETWORK_DEFULT_NIC_NAME, RDBOX_NETWORK_DEFULT_NIC_IPV4, RDBOX_NETWORK_DEFULT_NIC_IPV6
  __RDBOX_HOST_NAME=${__RDBOX_HOST_NAME:-$__RDBOX_HOSTNAME_FOR_WCDNS_BASED_ON_IP}
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
      nic0.name:         "${RDBOX_NETWORK_DEFULT_NIC_NAME}"
      nic0.host:         "${__RDBOX_HOST_NAME}"
      nic0.domain:       "${__RDBOX_DOMAIN_NAME}"
      nic0.base_fqdn:    "${__RDBOX_CLUSTER_NAME}.${__RDBOX_HOST_NAME}.${__RDBOX_DOMAIN_NAME}"
      nic0.ipv4:         "${RDBOX_NETWORK_DEFULT_NIC_IPV4}"
      nic0.ipv4_hyphen:  "${__RDBOX_HOSTNAME_FOR_WCDNS_BASED_ON_IP}"
      nic0.ipv6:         "${RDBOX_NETWORK_DEFULT_NIC_IPV6}"
      workdir.work_base:   "${__workdir_of_work_base}"
      workdir.logs:        "${__workdir_of_logs}"
      workdir.outputs:     "${__workdir_of_outputs}"
      workdir.tmps:        "${__workdir_of_tmps}"
      workdir.confs:       "${__workdir_of_confs}"
      workdir.scripts:     "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}"
EOF
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"