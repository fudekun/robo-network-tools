#!/bin/bash
set -euo pipefail

function showHeaderCommand() {
  showHeader
  return $?
}

function main() {
  local module_name
  showHeaderCommand
  module_name=$(check_args "${@}")
  executor "${module_name}" "${@}"
  showVerifierCommand $?
}

function showVerifierCommand() {
  showFooter "${1}"
  return $?
}

function check_args() {
  local module_name
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
      *) ;;
    esac
  done
  shift $((OPTIND - 1))
  echo -n "${module_name}"
}

function executor() {
  local module_name
  module_name=${1}
  fullpath_of_script=$(get_fullpath_of_script "${module_name}")
  if [[ ${fullpath_of_script} != "" ]]; then
    bash "${fullpath_of_script}" "${@:2}"
  else
    echo "Invalid module name (${module_name} is not exist)"
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

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?