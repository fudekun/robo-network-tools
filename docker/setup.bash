#!/usr/bin/env bash
set -euox pipefail

function main() {
  docker build \
    --no-cache \
    --build-arg VERSION_KIND="${KIND}" \
    --build-arg VERSION_KUBECTL="${KUBECTL}" \
    --build-arg VERSION_DOCKER_CE="${DOCKER_CE}" \
    --build-arg VERSION_CONTAINERD="${CONTAINERD}" \
    --build-arg VERSION_HELM="${HELM}" \
    --build-arg VERSION_GOST="${GOST}" \
    -t rdbox/docker:"${DOCKER_CE}" "${SCRIPTS_BASE}"
}

SCRIPTS_BASE=${SCRIPTS_BASE:-$(cd "$(dirname "$0")" || exit 1; pwd)}
SCRIPTS_BASE=$(printf %q "$SCRIPTS_BASE")
export SCRIPTS_BASE=$SCRIPTS_BASE

source "${SCRIPTS_BASE}"/app_version_list
main "$@"
exit $?