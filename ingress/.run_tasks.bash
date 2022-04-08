#!/bin/bash
set -euo pipefail

main() {
  "${WORKDIR_OF_SCRIPTS_BASE}"/create_kind-cluster.bash "$@"
}

## Set the base directory for RDBOX scripts!!
##
WORKDIR_OF_SCRIPTS_BASE=${WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$WORKDIR_OF_SCRIPTS_BASE")
export WORKDIR_OF_SCRIPTS_BASE=$WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?