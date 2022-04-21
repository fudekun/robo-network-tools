#!/usr/bin/env bash
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
  local result workspace_dir conf_dir
  result=${1}
  workspace_dir=${2}
  conf_dir=$(echo "$workspace_dir" | awk -F ' ' '{print $5}')
  echo ""
  echo "# Your working directories/files are ready"
  echo "  $workspace_dir"
  echo ""
  echo "  ## You can customize the configuration files to match your environment"
  echo "  ${conf_dir}"
  showFooter "${result}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?