#!/usr/bin/env bash
# shellcheck disable=SC2317
set -euo pipefail

###############################################################################
# Activating a volume
# Globals:
#   RDBOX_MODULE_NAME_VOLUME
#   MODULE_NAME
#   NAMESPACE
#   RELEASE
#   HELM_NAME
#   HELM_REPO_NAME
#   HELM_PKG_NAME
#   HELM_VERSION
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   CREATES_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function checkArgs() {
  local opt optarg
  while getopts "${__RDBOX_OPTS_CREATE_MAIN}""${__RDBOX_OPTS_RDBOX_MAIN}"-: opt; do
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
      -o|--volume_type) volume_type="$optarg" ;;
      -s|--volume_server) volume_server="$optarg" ;;
      -p|--volume_path) volume_path="$optarg" ;;
      -z|--volume_size) volume_size="$optarg" ;;
      *) ;;
    esac
  done
  shift $((OPTIND - 1))
  return $?
}

function create() {
  local volume_type volume_server volume_path volume_size
  checkArgs "$@"
  volume_server=${volume_server:-}
  volume_path=${volume_path:-}
  volume_size=${volume_size:-"40"}
  if cmdWithIndent "executor $*"; then
    verify_string=$(showVerifierCommand)
    echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
    return 0
  else
    return 1
  fi
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### volume has been installed. Check its status by running:"
  echo "    kubectl -n volume get daemonsets volume -o wide"
  return 0
}

function executor() {
  if __executor "${@}"; then
    exit 0
  else
    exit 1
  fi
}

function __executor() {
  ## Input Argument Checking
  ##
  local storage_class storage_mode
  if [ "${volume_type}" = "tmp" ]; then
    storage_class="standard"
    storage_mode="ReadWriteOnce"
    echo "Skip data persistence settings"
    echo "Please use it for operation verification purposes"
  elif [ "${volume_type}" = "nfs" ]; then
    storage_class="nfs-client"
    storage_mode="ReadWriteOnce"
    local cluster_name
    local dirpath_of_nfs_ganesha
    cluster_name=$(getClusterName)
    dirpath_of_nfs_ganesha="${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/helm/k8s-nfs-ganesha"
    if [ -z "${volume_server}" ] && [ -z "${volume_path}" ]; then
      echo "Data persistence using an internal NFS server"
      echo "Please use it for operation verification purposes"
      local nfs_cidrs nfs_port
      nfs_cidrs=$(sudo docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" )
      nfs_port="32049"
        ### MEMO
        ### - nfs_cidrs value is restricted on the KinD network
        ### - nfs_port value must be in the NodePort range
        ###
      volume_path="/mnt/nfs/${cluster_name}"
      volume_server=$(kubectl get nodes -l "storage-ready=true" -o json | jq -r '.items[].status.addresses[] | select(.type=="InternalIP") | .address')
      echo "Createing a VHD(${volume_size}GB) ..."
      if sudo docker exec -t "${cluster_name}-worker" umount "${volume_path}"; then
        sleep 1
      fi
      if sudo docker exec -t "${cluster_name}-worker" ls "/data/nfs/${cluster_name}/ext4.img"; then
        echo "A VHD already exists" 1>&2
        echo "We recommend that you move or delete the VHD (${RDBOX_WORKDIR_OF_DATA_BASE}/${cluster_name}/ext4.img)" 1>&2
        echo "[WARN] Re-use it" 1>&2
        sudo docker exec -t "${cluster_name}-worker" /bin/bash -c "mkdir -p ${volume_path} && \
                mount -t auto -o loop /data/nfs/${cluster_name}/ext4.img ${volume_path}"
      else
        sudo docker exec -t "${cluster_name}-worker" /bin/bash -c "mkdir -p /data/nfs/${cluster_name} && \
                dd if=/dev/zero of=/data/nfs/${cluster_name}/ext4.img bs=1G count=${volume_size} && \
                mkfs -t ext4 /data/nfs/${cluster_name}/ext4.img && \
                mkdir -p ${volume_path} && \
                mount -t auto -o loop /data/nfs/${cluster_name}/ext4.img ${volume_path}"
      fi
      helm -n volume upgrade --install volume "${dirpath_of_nfs_ganesha}" \
          --create-namespace \
          --wait \
          --timeout 600s \
          --set nfsGanesha.enabled="true" \
          --set nfsGanesha.persistence.size="${volume_size}Gi" \
          --set nfsGanesha.persistence.path="${volume_path}" \
          --set nfsGanesha.listenAddress="${nfs_cidrs}\,10.32.0.0/12" \
          --set nfs-subdir-external-provisioner.nfs.path="${volume_path}" \
          --set nfs-subdir-external-provisioner.nfs.server="${volume_server}" \
          --set nfs-subdir-external-provisioner.nfs.mountOptions\[0\]="port=${nfs_port}" \
          --set nfs-subdir-external-provisioner.storageClass.name="${storage_class}" \
          -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
    elif [ -n "${volume_server}" ] && [ -n "${volume_path}" ]; then
      echo "Data persistence using an external NFS server"
      helm -n volume upgrade --install volume "${dirpath_of_nfs_ganesha}" \
          --create-namespace \
          --wait \
          --timeout 600s \
          --set nfsGanesha.enabled="false" \
          --set nfs-subdir-external-provisioner.nfs.path="${volume_path}" \
          --set nfs-subdir-external-provisioner.nfs.server="${volume_server}" \
          --set nfs-subdir-external-provisioner.storageClass.name="${storage_class}" \
          -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
    else
      echo "You must set (-s|--volume_server address)" 1>&2
      echo "You must set (-p|--volume_path path)" 1>&2
      return 1
    fi
  else
    echo "You must set (-o|--volume_type [nfs|tmp])" 1>&2
    return 1
  fi
  kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" patch configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
    --type merge \
    -p "{\"data\":{\"volume.class\":\"${storage_class}\", \"volume.mode\":\"${storage_mode}\", \"volume.size\":\"${volume_size}\"}}"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/account.bash"