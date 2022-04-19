#!/bin/bash
set -euo pipefail

function showHeaderCommand() {
  showHeader
  return $?
}

function main() {
  local module_name cluster_name domain_name host_name
  showHeaderCommand
  check_args "${@}"
  executor
  showVerifierCommand $?
}

function showVerifierCommand() {
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
      -d|--domain) domain_name="$optarg" ;;
      -h|--host) host_name="$optarg" ;;
      -m|--module) module_name="$optarg" ;;
      -n|--name) cluster_name="$optarg" ;;
      *) ;;
    esac
  done
  shift $((OPTIND - 1))
}

function executor() {
  bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_${module_name}.bash" \
    "${cluster_name}" \
    "${domain_name}" \
    "${host_name}"
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?