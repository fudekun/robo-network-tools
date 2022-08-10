#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  showHeader
  return $?
}

function main() {
  local ret
  local module_name
  showHeaderCommand
  module_name=$(check_args "${@}")
  executor "${module_name}" "${@}"
  ret=$?
  showVerifierCommand "${ret}" "${module_name}"
  return $ret
}

function showVerifierCommand() {
  echo ""
  echo "# Succeed, Creating(${2}): CREATES_RELEASE_ID=\"${CREATES_RELEASE_ID}\""
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
  return $?
}

function executor() {
  local module_name
  module_name=${1}
  ## 1. Define ReleaseID
  ##
  local __epoch_ms
  __epoch_ms=$(getEpochMillisec)
  readonly CREATES_RELEASE_ID=${__epoch_ms}
  export CREATES_RELEASE_ID
  echo "CREATES_RELEASE_ID=\"${CREATES_RELEASE_ID}\""
  ## 2. Get Fullpath of a module
  ##
  fullpath_of_script=$(get_fullpath_of_script "${module_name}")
  ## 3. Execute
  ##
  if [[ ${fullpath_of_script} != "" ]]; then
    cmdWithLoding \
      "bash ${fullpath_of_script} create ${*:2}" \
      "Activating the ${module_name}"
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

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?