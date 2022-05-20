#!/usr/bin/env bash
set -euo pipefail

usermod -u "$LOCAL_UID" -o ubuntu > /dev/null 2>&1
groupmod -g "$LOCAL_GID" -o ubuntu > /dev/null 2>&1

exec /usr/sbin/gosu ubuntu "$@"
