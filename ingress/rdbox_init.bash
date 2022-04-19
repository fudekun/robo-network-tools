#!/bin/bash
set -euo pipefail

function showHeaderCommand() {
  showHeader true
  return $?
}

function main() {
  local cluster_name
  local workspace_dir
  cluster_name=${1}
  showHeaderCommand true
  workspace_dir=$(initializeWorkdirOfWorkbase "${cluster_name}")
  showVerifierCommand $? "${workspace_dir}"
}

function showVerifierCommand() {
  local result
  local workspace_dir
  result=${1}
  workspace_dir=${2}
  echo ""
  echo "# Your working directories/files are ready"
  echo "  $workspace_dir"
  showFooter "${result}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?