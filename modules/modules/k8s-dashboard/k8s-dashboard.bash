#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing ${PACKAGE_NAME} ..."
  return $?
}

function checkArgs() {
  return $?
}

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "k8s-dashboard")"
  return $?
}

function showVerifierCommand() {
  local namespace
  namespace=$(getNamespaceName "k8s-dashboard")
  echo ""
  echo "## USAGE"
  echo "### k8s-dashboard has been installed. Check its status by running:"
  echo "    kubectl -n ${namespace} get deployments -o wide"
  return $?
}

function __executor() {
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?

