#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  showHeader
  return $?
}

function main() {
  local ret
  local module_name="" cluster_name=""
  showHeaderCommand
  check_args "${@}"
  if [ "${module_name}" = "all" ] && [ "${cluster_name}" != "" ]; then
    delete_all "$cluster_name"
    ret=$?
  elif [ "${module_name}" != "" ] && [ "${cluster_name}" != "" ]; then
    executor "${module_name}" "${@}"
    ret=$?
  else
    echo "[ERR] Invalid Args"
    ret=1
  fi
  showVerifierCommand "${ret}" "${module_name:-${cluster_name}}"
  return $ret
}

function showVerifierCommand() {
  echo ""
  if [ "$1" = 0 ]; then
    echo "# Succeed, Deleting(${2})"
  else
    echo "# Failed, Deleting(${2})"
  fi
  showFooter "${1}"
  return $?
}

function check_args() {
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
      -m|--module) module_name="$optarg" ;;
      -n|--name) cluster_name="$optarg" ;;
      *) ;;
    esac
  done
  shift $((OPTIND - 1))
  return $?
}

function executor() {
  local module_name
  module_name=${1}
  ## 1. Get Fullpath of a module
  ##
  fullpath_of_script=$(get_fullpath_of_script "${module_name}")
  ## 2. Execute
  ##
  if [[ ${fullpath_of_script} != "" ]]; then
    if [[ "$fullpath_of_script" =~ "meta-pkgs" ]]; then
      bash "${fullpath_of_script}" delete "${@:2}"
    else
      cmdWithLoding \
        "bash ${fullpath_of_script} delete ${*:2}" \
        "- Deleting the ${module_name} ..."
    fi
  else
    echo "Invalid module name (${module_name} dose not exist)"
  fi
  return $?
}

function get_fullpath_of_script() {
  local module_name
  local directories
  local count_of_directories
  module_name=${1}
  directories=$(find "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules" -type d -name "${module_name}")
  count_of_directories=$(find "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules" -type d -name "${module_name}" | wc -l | sed 's/ //g')
  if [[ $count_of_directories -eq 1 ]]; then
    echo -n "${directories}/${module_name}.bash"
  else
    echo -n ""
  fi
  return 0
}

# shellcheck disable=SC2317
function delete_all() {
  # shellcheck disable=SC2317
  function __delete_all() {
    local __cluster_name
    local __ctx_name
    __cluster_name=${1}
    __ctx_name=$(getKubectlContextName4SSO)
    echo "## Deleting Context ..."
    if kubectl config use-context kind-"${__cluster_name}" > /dev/null 2>&1; then
      kubectl config use-context kind-"${__cluster_name}"
    fi
    if kubectl config delete-cluster "${__ctx_name}" > /dev/null 2>&1; then
      kubectl config delete-user "${__ctx_name}"
      kubectl config delete-context "${__ctx_name}"
    fi
    echo "## Deleting essentials ..."
    executor "essentials"
    echo "---"
    echo "## Deleting volume ..."
    if helm -n volume uninstall volume --wait --timeout 180s; then
      echo "OK!"
    fi
    echo "## Deleting Cluster ..."
    sudo kind delete cluster --kubeconfig "${KUBECONFIG}" --name "${__cluster_name}" 2>&1
    return $?
  }
  echo ""
  echo "---"
  echo "# Deleting Cluster ..."
  __delete_all "$@"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?