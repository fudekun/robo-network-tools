#!/usr/bin/env bash
set -euo pipefail

###############################################################################
## Execute essentials(Meta-Package) configuration
###############################################################################

function delete() {
  executor "$@"
}

function executor() {
  local ret
  local modules
  local arg
  ret=0
  readarray -t modules < "$(getWorkdirOfScripts)/modules/meta-pkgs/essentials/create.properties"
  ## Reverse
  ##
  min=0
  max=$(( ${#modules[@]} -1 ))
  while [[ min -lt max ]]
  do
      x="${modules[$min]}"
      modules[min]="${modules[$max]}"
      modules[max]="$x"
        ### MEMO
        ### Swap current first and last elements
      (( min++, max-- ))
        ### MEMO
        ### Move closer
  done
  ##
  for arg in "${modules[@]}" ; do
    local kv
    IFS="=" read -r -a kv <<< "$arg"
    cmdWithLoding \
      "bash $(getWorkdirOfScripts)/modules/modules/${kv[0]}/${kv[0]}.bash ${*}" \
      "- Deleting the ${kv[0]} ..."
    ret=$?
    if [[ "${ret}" -ne 0 ]]; then
      echo "Skip ..."
    fi
  done
  return "${ret}"
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"