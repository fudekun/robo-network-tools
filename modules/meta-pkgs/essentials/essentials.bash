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
  executor "$@"
  # cmdWithIndent "executor $*"
  showVerifierCommand
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  cat "$(getFullpathOfVerifyMsgs "$(getNamespaceName "${RDBOX_MODULE_NAME_CERT_MANAGER}")")"
  cat "$(getFullpathOfVerifyMsgs "$(getNamespaceName "${RDBOX_MODULE_NAME_KEYCLOAK}")")"
  cat "$(getFullpathOfVerifyMsgs "$(getNamespaceName "${RDBOX_MODULE_NAME_AMBASSADOR}")")"
  return $?
}

executor() {
  ## 1. Input Argument Checking
  ##
  checkArgs "$@"
  ## 2. Install Cert-Manager
  ##
  installCertManager "$@"
  ## 3. Install MetalLB
  ##
  installMetalLB "$@"
  ## 4. Install Ambassador
  ##
  installAmbassador "$@"
  ## 5. Install Keycloak
  ##
  installKeycloak "$@"
  ## 6. Install impersonator(k8ssso by Ambassador)
  ##
  installFilter "$@"
  ## 7. Install K8sDashboard
  ##
  installK8sDashboard "$@"
  return $?
}


## 2. Install Cert-Manager
##
installCertManager() {
  bash "$(getWorkdirOfScripts)/modules/modules/cert-manager/cert-manager.bash" "$@"
  return $?
}

## 3. Install MetalLB
##
installMetalLB() {
  bash "$(getWorkdirOfScripts)/modules/modules/metallb/metallb.bash" "$@"
  return $?
}

## 4. Install Ambassador
##
installAmbassador() {
  bash "$(getWorkdirOfScripts)/modules/modules/ambassador/ambassador.bash" "$@"
  return $?
}

## 5. Install Keycloak
##
installKeycloak() {
  bash "$(getWorkdirOfScripts)/modules/modules/keycloak/keycloak.bash" "$@"
  return $?
}

## 6. Install impersonator(k8ssso by Ambassador)
##
installFilter() {
  bash "$(getWorkdirOfScripts)/modules/modules/impersonator/impersonator.bash" "$@"
  return $?
}

## 7. Install K8s-Dashboard
##
installK8sDashboard() {
  bash "$(getWorkdirOfScripts)/modules/modules/kubernetes-dashboard/kubernetes-dashboard.bash" "$@"
  return $?
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