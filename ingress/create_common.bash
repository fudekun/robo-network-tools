#!/bin/bash

## FIXED VALUE
##
CLUSTER_INFO_NAMENAME=cluster-info
CLUSTER_INFO_NAMESPACE=cluster-common
NUM_INDENT=4
##
##
__RAW_INDENT=$(for _ in $(eval "echo {1..$NUM_INDENT}"); do echo -ne " "; done)

cleanupShowLoading() {
  tput cnorm
}

showHeader() {
  drawMaxColsSeparator "=" "39"
  echo "[$(getIso8601DayTime)][$(basename "$0")]"
  echo "# START"
  echo ""
  echo "---"
  echo "- This is an advanced IT platform for robotics and IoT developers -"
  echo "           .___. "
  echo "          /___/| "
  echo "          |   |/ "
  echo "          .---.  "
  echo "          RDBOX  "
  echo "- A Robotics Developers BOX -"
}

showLoading() {
  local mypid=$!
  local loadingText=$1
  tput civis
  trap cleanupShowLoading EXIT
  echo -ne "\r"
  sleep 1
  while kill -0 $mypid 2>/dev/null; do
    echo -ne "\r\033[K"
    echo -ne "  $loadingText\r"
    echo -ne "\033[35m-\033[m  $loadingText\r"
    sleep 0.25
    echo -ne "\\  $loadingText\r"
    sleep 0.25
    echo -ne "\033[33m|\033[m  $loadingText\r"
    sleep 0.25
    echo -ne "\033[32m/\033[m  $loadingText\r"
    sleep 0.25
  done
  tput cnorm
    ## For To Get Return Code
  set +euo > /dev/null 2>&1
  wait $mypid
  local exit_status=$?
  if [ ${exit_status} = 0 ]; then
    echo -e "\033[32mok\033[m $loadingText"
  else
    echo -e "\033[31mng\033[m $loadingText"
  fi
  set -euo > /dev/null 2>&1
    ## For To Get Return Code
  return "$exit_status"
}

cmdWithLoding() {
  local commands="$1"
  local message="$2"
  eval "${commands} & showLoading '${message} '"
}

showIndent() {
  sed "s/^/${__RAW_INDENT}/";
}

cmdWithIndent() {
  local commands="$1"
  local mark="${2:-"YES"}" # YES or NO
  if [ "$mark" = "YES" ]; then
    esc=$(printf '\033')
    eval "{ ${commands} 3>&1 1>&2 2>&3 | sed 's/^/${__RAW_INDENT}${esc}[31m[STDERR]&${esc}[0m -> /' ; } 3>&1 1>&2 2>&3 | showIndent"
  else
    eval "${commands} 2>&1 | showIndent"
  fi
}

drawMaxColsSeparator() {
  local char=${1:-#}
  local color=${2:-32}
  local raw_separator
  raw_separator="$(seq -s "${char}" 0 $(($(tput cols)-1)) | tr -d '0-9')"
  printf "\033[${color}m%s\033[m\n" "${raw_separator}"
}

updateHelm() {
  cmdWithLoding \
    "helm repo update 1> /dev/null" \
    "Updateing Helm"
}

watiForSuccessOfCommand() {
  local __cmds="$1"
  local __count=0
  while ! eval "${__cmds} 2>/dev/null"; do
    if [ $__count -gt 300 ]; then
      return 1
    fi
    sleep 1
    __count=$((__count+1))
  done
  echo ""
  return 0
}

initializeWorkdirOfWorkbase() {
  local __cluster_name
  local __workbase_dirs
  local __workdir_of_work_base
  local __workdir_of_logs
  local __workdir_of_outputs
  local __workdir_of_tmps
  local __workdir_of_confs
  __cluster_name="$1"
  __workbase_dirs=$(getDirNameListOfWorkbase "${__cluster_name}")
  __workdir_of_work_base=$(echo "$__workbase_dirs" | awk -F ' ' '{print $1}')
  __workdir_of_logs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $2}')
  __workdir_of_outputs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $3}')
  __workdir_of_tmps=$(echo "$__workbase_dirs" | awk -F ' ' '{print $4}')
  __workdir_of_confs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $5}')
  mkdir -p "${__workdir_of_logs}" "${__workdir_of_outputs}" "${__workdir_of_tmps}" "${__workdir_of_confs}"
  rsync -au "${WORKDIR_OF_SCRIPTS_BASE}"/confs/ "${__workdir_of_confs}"
  echo "${__workdir_of_work_base}" "${__workdir_of_logs}" "${__workdir_of_outputs}" "${__workdir_of_tmps}" "${__workdir_of_confs}"
}

getDirNameListOfWorkbase() {
  local __cluster_name="$1"
  WORKDIR_OF_WORK_BASE=${WORKDIR_OF_WORK_BASE:-${HOME}/crobotics/${__cluster_name}}
  WORKDIR_OF_WORK_BASE=$(printf %q "$WORKDIR_OF_WORK_BASE")
  export WORKDIR_OF_WORK_BASE=${WORKDIR_OF_WORK_BASE}
    ### EXTRAPOLATION
  local __workdir_of_logs=${WORKDIR_OF_WORK_BASE}/logs
  local __workdir_of_outputs=${WORKDIR_OF_WORK_BASE}/outputs
  local __workdir_of_tmps=${WORKDIR_OF_WORK_BASE}/tmps
  local __workdir_of_confs=${WORKDIR_OF_WORK_BASE}/confs
  echo "${WORKDIR_OF_WORK_BASE}" "${__workdir_of_logs}" "${__workdir_of_outputs}" "${__workdir_of_tmps}" "${__workdir_of_confs}"
}

getNetworkInfo() {
  NAME_DEFULT_NIC=${NAME_DEFULT_NIC:-$(netstat -rn | grep default | grep -v "\!" | grep -v ":" | awk '{print $4}')}
  NAME_DEFULT_NIC=$(printf %q "$NAME_DEFULT_NIC")
    # EXTRAPOLATION
  export NAME_DEFULT_NIC
  # shellcheck disable=SC2015
  IPV4_DEFAULT_NIC=$( (command -v ip &> /dev/null && ip addr show "$NAME_DEFULT_NIC" || ifconfig "$NAME_DEFULT_NIC") | \
                    sed -nEe 's/^[[:space:]]+inet[^[:alnum:]]+([0-9.]+).*$/\1/p')
  export IPV4_DEFAULT_NIC
  # shellcheck disable=SC2015
  IPV6_DEFAULT_NIC=$( (command -v ip &> /dev/null && ip addr show "$NAME_DEFULT_NIC" || ifconfig "$NAME_DEFULT_NIC") | \
                    sed -nEe 's/^[[:space:]]+inet6[^[:alnum:]]+([0-9A-Za-z:.]+).*$/\1/p')
  export IPV6_DEFAULT_NIC
  HOSTNAME_FOR_WCDNS_BASED_ON_IP=${IPV4_DEFAULT_NIC//\./-}
  export HOSTNAME_FOR_WCDNS_BASED_ON_IP
}

getContextName4Kubectl() {
  local prefix=${1:-sso}
  local context_name
  context_name=${prefix}-$(getClusterName)
  echo -e "$context_name"
}

__getClusterinfoFromConfigmap() {
  local __item=$1
  kubectl -n ${CLUSTER_INFO_NAMESPACE} get configmaps ${CLUSTER_INFO_NAMENAME} -o json| jq -r "${__item}"
}

getWorkdirOfScripts() {
  __getClusterinfoFromConfigmap ".data[\"workdir.scripts\"]"
}

getClusterName() {
  __getClusterinfoFromConfigmap ".data.name"
}

getBaseFQDN() {
  __getClusterinfoFromConfigmap ".data[\"nic0.base_fqdn\"]"
}

getIPv4 () {
  __getClusterinfoFromConfigmap ".data[\"nic0.ipv4\"]"
}

getNamespaceName() {
  local __namespace=$1
  __getClusterinfoFromConfigmap ".data[\"namespace.${__namespace}\"]"
}

getHostName() {
  local __namespace=$1
  local __host=$2
  __getClusterinfoFromConfigmap ".data[\"${__namespace}.hostname.${__host}\"]"
}

getDirNameFor() {
  local __purpose=$1
  __getClusterinfoFromConfigmap ".data[\"workdir.${__purpose}\"]"
}

getConfVersion() {
  local __namespace=$1
  local __type=$2
  __getClusterinfoFromConfigmap ".data[\"${__namespace}.conf.${__type}.version\"]"
}

getFullpathOfValuesYamlBy() {
  local __namespace=$1
  local __purpose=$2
  local __type=$3
  local __version
  local __workdir_of_purpose
  __version=$(getConfVersion "${__namespace}" "${__type}")
  __workdir_of_purpose=$(getDirNameFor "${__purpose}")
  echo -n "${__workdir_of_purpose}/modules/${__namespace}/${__type}/${__version}/values.yaml"
}

getFullpathOfRootCA() {
  local __dir
  local __base_fqdn
  __dir=$(getDirNameFor outputs)/ca
  __base_fqdn=$(getBaseFQDN)
  mkdir -p "$__dir"
  chmod 0700 "$__dir"
  echo -ne "${__dir}"/"${__base_fqdn}".ca.crt
}

getFullpathOfHistory() {
  local __dir
  local __base_fqdn
  __base_fqdn=$(getBaseFQDN)
  __dir=$(getDirNameFor outputs)/.history.${__base_fqdn}
  mkdir -p "$__dir"
  chmod 0700 "$__dir"
  echo -ne "${__dir}"/selfsigned-ca."${__base_fqdn}".ca.yaml
}

getPresetSuperAdminName() {
  rep_name=$1
  helm -n "${rep_name}" get values "${rep_name}" -o json | jq -r '.auth.adminUser'
}

getPresetClusterAdminName() {
  getPresetGroupName
}

getPresetGroupName() {
  # !! Must be a hyphen-delimited string !!
  # e.g. *cluster-admim*
  echo -n "cluster-admin"
}

getHashedPasswordByPbkdf2Sha256() {
  local __password=$1
  local __hash_iterations=27500
  local __salt
  local __hashed_salted_value
  __salt=$(python3 -c 'import crypt; print(crypt.mksalt(crypt.METHOD_SHA256),end="")')
  __salt=${__salt//[\r\n]\+/ }
  # __salt=$(echo -e "import base64; print(base64.b64encode(b\"${__salt}\").decode(encoding=\"ascii\"),end=\"\")" | python3)
  # __salt=${__salt//[\r\n]\+/ }
  #__hashed_salted_value=$(python3 -c "import hashlib, crypt, base64; print(base64.b64encode(hashlib.pbkdf2_hmac(str('sha512'), byte($__password), byte($__salt), int($__hash_iterations))).decode(encoding='utf-8'))")
  __hashed_salted_value=$(echo -e "import hashlib,crypt,base64; print(base64.b64encode(hashlib.pbkdf2_hmac(\"sha256\", b\"$__password\", b\"$__salt\", int($__hash_iterations), 512//8)).decode(\"ascii\"))" | python3)
  __hashed_salted_value=${__hashed_salted_value//[\r\n]\+/ }
  __salt=$(echo -e "import base64; print(base64.b64encode(b\"${__salt}\").decode(encoding=\"ascii\"),end=\"\")" | python3)
  __salt=${__salt//[\r\n]\+/ }
  echo "$__salt"
  echo "$__hashed_salted_value"
  echo "$__hash_iterations"
}

getEpochMillisec() {
  python3 -c 'import time; print(int(time.time() * 1000))'
}

getIso8601DayTime() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}