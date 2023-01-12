#!/usr/bin/env bash
set -euo pipefail

###############################################################################
## Execute essentials(Meta-Package) configuration
###############################################################################

function create() {
  executor "$@"
  showVerifierCommand
}

function executor() {
  local ret
  local modules
  local arg
  ret=0
  readarray -t modules < "$(getWorkdirOfScripts)/modules/meta-pkgs/essentials/create.properties"
  for arg in "${modules[@]}" ; do
    local kv
    IFS="=" read -r -a kv <<< "$arg"
    cmdWithLoding \
      "bash $(getWorkdirOfScripts)/modules/modules/${kv[0]}/${kv[0]}.bash ${*}" \
      "- Activating the ${kv[0]} ..."
    ret=$?
    if [[ "${ret}" -ne 0 ]]; then
      break
    fi
  done
  return "${ret}"
}

function showVerifierCommand() {
  local ret
  local modules
  local arg
  local verifier=()
  ret=0
  readarray -t modules < "$(getWorkdirOfScripts)/modules/meta-pkgs/essentials/create.properties"
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

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"