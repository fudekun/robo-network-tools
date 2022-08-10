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
  if [ "${module_name}" = "" ] && [ "${cluster_name}" != "" ]; then
    cmdWithLoding \
      "delete_all $cluster_name" \
      "- Deleteing $cluster_name ..."
    ret=$?
  elif [ "${module_name}" != "" ] && [ "${cluster_name}" != "" ]; then
    executor "${module_name}" "${@}"
    ret=$?
  else
    ret=1
  fi
  showVerifierCommand "${ret}" "${module_name:-${cluster_name}}"
  return $ret
}

function showVerifierCommand() {
  echo ""
  echo "# Succeed, Deleting(${2})"
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
    cmdWithLoding \
      "bash ${fullpath_of_script} delete ${*:2}" \
      "Deleting the ${module_name}"
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
  return $?
}

function delete_all() {
  function __delete_all() {
    local __cluster_name
    local __ctx_name
    __cluster_name=${1}
    __ctx_name=$(getKubectlContextName4SSO)
    echo "Deleteing Context ..."
    if kubectl config use-context kind-"${__cluster_name}" > /dev/null 2>&1; then
      kubectl config use-context kind-"${__cluster_name}"
    fi
    if kubectl config delete-cluster "${__ctx_name}" > /dev/null 2>&1; then
      kubectl config delete-user "${__ctx_name}"
      kubectl config delete-context "${__ctx_name}"
    fi
    echo "Deleteing Cluster ..."
    sudo kind delete cluster --kubeconfig "${KUBECONFIG}" --name "${__cluster_name}" 2>&1
    return $?
  }
  echo ""
  echo "---"
  echo "# Deleteing Cluster ..."
  cmdWithIndent "__delete_all $*"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?