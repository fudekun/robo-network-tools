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
  echo ""
  printf "# ARGS:\n%q (%s arg(s))\n" "$*" "$#"
  printf "# ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x //')"
  echo ""
  if [[ $# -eq 1 ]]; then
    if [[ "$1" == "help" ]]; then
      echo "# Args"
      echo "None"
      echo ""
      echo "# EnvironmentVariable"
      echo "  (recommend: Use automatic settings)"
      echo "| Name                               | e.g.                            |"
      echo "| ---------------------------------- | ------------------------------- |"
      echo "| RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT     | (default)new or recycle         |"
      return 1
    fi
  fi
  return $?
}

main() {
  showHeaderCommand
  #executor "$@"
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