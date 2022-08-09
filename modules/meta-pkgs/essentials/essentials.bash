#!/usr/bin/env bash
set -euo pipefail

###############################################################################
## Execute essentials(Meta-Package) configuration
###############################################################################

showHeaderCommand() {
  echo ""
  echo "---"
  echo "# Installing Meta-Package (essentials) ..."
  return $?
}

## 1. Input Argument Checking
##
checkArgs() {
  return $?
}

main() {
  showHeaderCommand
  checkArgs "$@"
  executor "$@"
  showVerifierCommand
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  local ret
  local modules
  local arg
  local verifier=()
  ret=0
  readarray -t modules < "$(getDirNameFor confs)/meta-pkgs/essentials/create.properties"
  for arg in "${modules[@]}" ; do
    local kv
    IFS="=" read -r -a kv <<< "$arg"
    if [ "${kv[1]}" -gt 0 ]; then
      verifier+=("${kv[1]}=${kv[0]}")
    fi
  done
  echo ""
  echo "---"
  echo "# Succeed, Installing Meta-Package (essentials)"
  local sorted
  readarray -t sorted < <(for a in "${verifier[@]}"; do echo "$a"; done | sort)
  for arg in "${sorted[@]}" ; do
    local kv
    IFS="=" read -r -a kv <<< "$arg"
    cat "$(getFullpathOfVerifyMsgs "$(getNamespaceName "${kv[1]}")")"
    ret=$?
    if [[ "${ret}" -ne 0 ]]; then
      break
    fi
  done
  return "${ret}"
}

executor() {
  local ret
  local modules
  local arg
  ret=0
  readarray -t modules < "$(getDirNameFor confs)/meta-pkgs/essentials/create.properties"
  for arg in "${modules[@]}" ; do
    local kv
    IFS="=" read -r -a kv <<< "$arg"
    bash "$(getWorkdirOfScripts)/modules/modules/${kv[0]}/${kv[0]}.bash" "$@"
    ret=$?
    if [[ "${ret}" -ne 0 ]]; then
      break
    fi
  done
  return "${ret}"
}

## Set the base directory for RDBOX scripts!!
##
RDBOX_WORKDIR_OF_SCRIPTS_BASE=${RDBOX_WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
RDBOX_WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$RDBOX_WORKDIR_OF_SCRIPTS_BASE")
export RDBOX_WORKDIR_OF_SCRIPTS_BASE=$RDBOX_WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?