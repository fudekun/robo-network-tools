#!/bin/bash
set -euo pipefail

main() {
  "${WORKDIR_OF_SCRIPTS_BASE}"/create_kind-cluster.bash "$@"
}

## Set the base directory for RDBOX scripts!!
##
export WORKDIR_OF_SCRIPTS_BASE=${WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
  # Values can also be inserted externally
source "${WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?