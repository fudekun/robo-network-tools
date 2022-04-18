#!/bin/bash
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

## 0. Input Argument Checking
##
checkArgs() {
  echo ""
  printf "# ARGS:\n%s\n" "$*"
  printf "# ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x /  - /')"
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
      echo "| RDBOX_TYPE_OF_SECRET_OPERATION     | (default)new or recycle         |"
      return 1
    fi
  fi
  local __epoch_ms
  __epoch_ms=$(getEpochMillisec)
  readonly __RELEASE_ID=${__epoch_ms}
  export __RELEASE_ID
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
  local __ctx_name
  local __rootca_file
  local __namespace_for_keycloak
  __ctx_name=$(getContextName4Kubectl)
  __rootca_file=$(getFullpathOfRootCA)
  __namespace_for_keycloak=$(getNamespaceName "keycloak")
  echo ""
  echo "# USAGE"
  echo "## Trust CA with your browser and operating system. Check its file:"
  echo "  openssl x509 -in ${__rootca_file} -text"
  echo "  ---"
  echo "  ### This information is for reference to trust The CA file:"
  echo "    (Windows) https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores"
  echo "    (MacOS  ) https://support.apple.com/guide/keychain-access/kyca2431/mac"
  echo "    (Ubuntu ) https://ubuntu.com/server/docs/security-trust-store"
  # echo ""
  cat "$(getFullpathOfVerifyMsgs "${__namespace_for_keycloak}")"
  # echo ""
  echo ""
  echo "# USAGE"
  echo "## Execute the following command to run kubectl with single sign-on:"
  echo "  ### Execute the following command"
  echo "  ### Your default browser will launch and you should perform the login operation"
  echo "  kubectl config use-context ${__ctx_name}"
  echo "  kubectl get node          # whatever is okay, just choose the one you like"
  echo ""
  echo "# SUCCESS"
  echo "[$(getIso8601DayTime)][$(basename "$0")]"
  drawMaxColsSeparator "*" "39"
  return $?
}

executor() {
  ## 0. Input Argument Checking
  ##
  checkArgs "$@"
  ## 1. Initializing
  ##
  cmdWithLoding \
    "initializeEssentials $*" \
    "Initializing the meta-pkgs of essentials"
  ## 2. Install Cert-Manager
  ##
  cmdWithLoding \
    "installCertManager $*" \
    "Activating the cert-manager"
  ## 3. Install MetalLB
  ##
  cmdWithLoding \
    "installMetalLB $*" \
    "Activating the metallb"
  ## 4. Install Ambassador
  ##
  cmdWithLoding \
    "installAmbassador $*" \
    "Activating the ambassador"
  ## 5. Install Keycloak
  ##
  cmdWithLoding \
    "installKeycloak $*" \
    "Activating the keycloak"
  ## 6. Install Filter
  ##
  cmdWithLoding \
    "installFilter $*" \
    "Activating the filter"
  return $?
}

## 1. Initialize
##
initializeEssentials() {
  __executor() {
    local __workdir_of_confs
    ## 1. Update Helm
    ##
    echo ""
    echo "### Updateing Helm ..."
    helm repo update
    ## 2. Set up a ConfigMap for the meta-pkg of essentials
    ##
    echo ""
    echo "### Setting a ConfigMap for the meta-pkg of essentials ..."
    __workdir_of_confs=$(getDirNameFor confs)
    readonly __workdir_of_confs
    kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" patch configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
      --type merge \
      --patch "$(kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" create configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
                  --dry-run=client \
                  --output=json \
                  --from-env-file="${__workdir_of_confs}"/meta-pkgs/essentials.env.properties \
                )"
    return $?
  }
  echo ""
  echo "---"
  echo "## Initializing essentials ..."
  cmdWithIndent "__executor"
  return $?
}

## 2. Install Cert-Manager
##
installCertManager() {
  bash "$(getWorkdirOfScripts)/create_cert-manager.bash" "$@"
  return $?
}

## 3. Install MetalLB
##
installMetalLB() {
  bash "$(getWorkdirOfScripts)/create_metallb.bash" "$@"
  return $?
}

## 4. Install Ambassador
##
installAmbassador() {
  bash "$(getWorkdirOfScripts)/create_ambassador.bash" "$@"
  return $?
}

## 5. Install Keycloak
##
installKeycloak() {
  bash "$(getWorkdirOfScripts)/create_keycloak.bash" "$@"
  return $?
}

## 6. Install Filter
##
installFilter() {
  bash "$(getWorkdirOfScripts)/create_ambassador-filter.bash" "$@"
  return $?
}

## Set the base directory for RDBOX scripts!!
##
RDBOX_WORKDIR_OF_SCRIPTS_BASE=${RDBOX_WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
RDBOX_WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$RDBOX_WORKDIR_OF_SCRIPTS_BASE")
export RDBOX_WORKDIR_OF_SCRIPTS_BASE=$RDBOX_WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?