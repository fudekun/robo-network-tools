#!/bin/bash
set -euo pipefail

script -q /dev/null ./create_kind-cluster.bash rdbox nip.io | tee >(awk -F'\r' '{print $NF; fflush()}' >rdbox.log)