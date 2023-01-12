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

function checkClustername() {
  if isValidClustername "$1"; then
    __RDBOX_CLUSTER_NAME=$(printf %q "$1")
    export __RDBOX_CLUSTER_NAME=$__RDBOX_CLUSTER_NAME
    readonly __RDBOX_CLUSTER_NAME
    return 0
  else
    return 1
  fi
}

function create() {
  local cluster_name domain_name host_name
  checkArgs "$@"
  host_name=${host_name:-}
  if cmdWithIndent "executor ${cluster_name} ${domain_name} ${host_name}"; then
    return 0
  else
    return 1
  fi
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### KinD has been installed. Check its status by running:"
  echo "    kind get nodes --name rdbox"
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
  ## .0 Check Value
  ##
  checkClustername "$@"
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
    local data_dir=${RDBOX_WORKDIR_OF_DATA_BASE}/${__RDBOX_CLUSTER_NAME}
    sed -i -e "s|__DATA__|${data_dir}|g" "$__conffile_path"
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
  return 0
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"