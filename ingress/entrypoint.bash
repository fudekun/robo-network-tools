#!/usr/bin/env bash
set -euo pipefail

usermod -u "$LOCAL_UID" -o ubuntu
groupmod -g "$LOCAL_GID" -o ubuntu

exec /usr/sbin/gosu ubuntu "$@"
