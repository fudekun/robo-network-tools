#!/usr/bin/env bash
set -euo pipefail

function checkArgs() {
  echo ""
  printf "# ARGS:\n%q (%s arg(s))\n" "$*" "$#"
  printf "# ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x //')"
  local opt optarg
  while getopts "n:o:"-: opt; do
    optarg="$OPTARG"
    if [[ "$opt" = - ]]; then
      opt="-${OPTARG%%=*}"
      optarg="${OPTARG/${OPTARG%%=*}/}"
      optarg="${optarg#=}"
      if [[ -z "$optarg" ]] && [[ ! "${!OPTIND}" = -* ]]; then
        optarg="${!OPTIND}"
        shift
      fi
    fi
    case "-$opt" in
      -n|--name) cluster_name="$optarg" ;;
      -o|--operation) operation="$optarg" ;;
      *) ;;
    esac
  done
  shift $((OPTIND - 1))
  return $?
}

function main() {
  local cluster_name operation
  checkArgs "${@}"
  local item repoTag
  for target in "${cluster_name}-control-plane" "${cluster_name}-worker"; do
    echo "# Save Images to host"
    echo "## ${target}"
    if [ "${operation}" == "save" ] ; then
      docker exec "${cluster_name}-control-plane" crictl images -o json > "./${cluster_name}-control-plane.images.json"
      docker exec "${cluster_name}-worker" crictl images -o json > "./${cluster_name}-worker.images.json"
    fi
    for item in $(jq -c '.images[]' < "${target}.images.json"); do
      repoTag=$(echo "$item" | jq -r '.repoTags[]')
      if [ "${operation}" == "save" ]; then
        docker pull "${repoTag}"
      elif [ "${operation}" == "load" ]; then
        kind load docker-image --name "${cluster_name}" "${repoTag}"
      elif [ "${operation}" == "delete" ]; then
        docker rmi "${repoTag}"
      fi
      echo ""
    done
  done
}

main "${@}"
exit $?