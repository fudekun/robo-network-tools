#!/usr/bin/env bash

###############################################################################
## The collections of a function, which is general purpose
## Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

## FIXED VALUE
##
RDBOX_APP_VERSION="v0.0.1"
## MODULE NAME ###############################################
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_KIND="kind"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_CLUSTER_INFO="cluster-info"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_WEAVE_NET="weave-net"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_VOLUME="volume"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_CERT_MANAGER="cert-manager"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_METALLB="metallb"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_AMBASSADOR="ambassador"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_KEYCLOAK="keycloak"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_IMPERSONATOR="impersonator"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_AMBASSADOR_ADMIN="ambassador-admin"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_K8S_DASHBOARD="kubernetes-dashboard"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_PROMETHEUS="prometheus"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_GRAFANA="grafana"
  # shellcheck disable=SC2034
RDBOX_MODULE_NAME_STD_WEB="std-web"
## OTHER #####################################################
__RDBOX_OPTS_CREATE_VOLUME="o:s:p:z:"
__RDBOX_OPTS_CREATE_MAIN="d:m:h:${__RDBOX_OPTS_CREATE_VOLUME}"
__RDBOX_OPTS_RDBOX_MAIN="n:"
__RDBOX_CLUSTER_INFO_NAMESPACE="cluster-common"
__RDBOX_CLUSTER_INFO_NAMENAME="cluster-info"
__RDBOX_SUBCOMMANDS_DIR_RELATIVE_PATH="/subcommands"
__RDBOX_NUM_INDENT=4
__RDBOX_HELPFUL_APPS_OF_GOST_VERSION="2.11.4"
__RDBOX_HELPFUL_APPS_OF_GOST_PORT=59999
## VALUE for internal using
##
__RDBOX_RAW_INDENT=$(for _ in $(eval "echo {1..$__RDBOX_NUM_INDENT}"); do echo -ne " "; done)

#######################################
# Show the Headder message
# Arguments:
#   (optional)is_showing_logo boolean
# Outputs:
#   A message containing the time and the name of the script from which it was run.
#   Optionally include a logo in the message.
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function showHeader() {
  local is_showing_logo=${1:-false}
  drawMaxColsSeparator "=" "39"
  echo "[$(getIso8601DayTime)][$(getEpochSec)][$(basename "$0")]"
  echo "# BEGIN"
  if "${is_showing_logo}"; then
    echo ""
    echo "- This is an advanced IT platform for robotics and IoT developers -"
    echo "           .___. "
    echo "          /___/| "
    echo "          |   |/ "
    echo "          .---.  "
    echo "          RDBOX  "
    echo "- A Robotics Developers BOX -"
  fi
  echo "{'Application': '${RDBOX_APP_VERSION}', 'TemplateEngine': 'v$(getVersionOfTemplateEngine)', 'Template': '$(getApiversionBasedOnSemver)'}"
  return $?
}

#######################################
# Show the Footer message
# Arguments:
#   ReturnCode
# Outputs:
#   A message containing the time and the name of the script from which it was run.
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function showFooter() {
  local result
  local message
  result=${1:-0}
  if [[ "${result}" -eq 0 ]]; then
    message="END (SUCCESS)"
  else
    message="END (FAILED) ${1}"
  fi
  echo ""
  echo "# ${message}"
  echo "[$(getIso8601DayTime)][$(getEpochSec)][$(basename "$0")]"
  drawMaxColsSeparator "*" "39"
  return $?
}

#######################################
# Show the Loading message, until the calling command finishes.
# Arguments:
#   Command (e.g. sudo apt update)
#   Message (string to be displayed while executing the command specified in the argument)
# Outputs:
#   StdOut/StdErr of the specific Command
#   Specific message with the loading icon=>"Repeat 4 letter(- \ | /)"
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function cmdWithLoding() {
  local cmd
  local message
  cmd=$(printf %q "$1" | sed "s/\\\//g")
  message="$2"
  eval "${cmd} & showLoading '${message} '"
  return $?
}

#######################################
# Show and Indent StdOut/StdErr of the specified command
# - When there is output for a file descriptor other than 1 (other than StdOut), mark is given.
# Arguments:
#   Command            (e.g. apt update)
#   (optional)is_showing_mark    boolean
# Outputs:
#   StdOut/StdErr of the specific Command
#   - When there is output for a file descriptor other than 1 (other than StdOut), mark is given.
#   - Only when Yes is specified for "the Mark" argument.
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function cmdWithIndent() {
  local cmd
  local is_showing_mark
  cmd=$(printf %q "$1" | sed "s/\\\//g")
  is_showing_mark="${2:-true}"
  local STATUS
  if "$is_showing_mark"; then
    local esc
    esc=$(printf '\033')
    eval "{ ${cmd} 3>&1 1>&2 2>&3 | sed 's/^/${__RDBOX_RAW_INDENT}${esc}[31m[2]&${esc}[0m -> /' ; } 3>&1 1>&2 2>&3 | showIndent;  STATUS=(\${PIPESTATUS[@]})"
  else
    eval "${cmd} 2>&1 | showIndent;  STATUS=(\${PIPESTATUS[@]})"
  fi
  local code
  if code=$(printf '%s\n' "${STATUS[@]}" | grep -x '[1-9]\|[1-9][0-9]\|1[0-2][0-9]'); then
    return "$code"
  else
    return 0
  fi
}

#######################################
# Show the Loading message, until last command finishes.
# - Based on the PID (get by "$!")
# Arguments:
#   loading_text The string to display with the loading icon
# Outputs:
#   loading_text with the loading icon
#   - the loading icon, Repeat 4 letter(- \ | /), every second.
# Returns:
#   Get a exit code by the caller's pid
#######################################
function showLoading() {
  local last_pid=$!
  local loading_text=$1
  local exit_status
  tput civis                     ## (FROM here) the cursor invisible:
  trap 'tput cnorm' EXIT
  echo -ne "\r"
  sleep 1
  while kill -0 $last_pid 2>/dev/null; do
    echo -ne "\r\033[K"
    echo -ne "  $loading_text\r"
    echo -ne "\033[35m-\033[m  $loading_text\r"
    sleep 0.5
    echo -ne "\\  $loading_text\r"
    sleep 0.5
    echo -ne "\033[33m|\033[m  $loading_text\r"
    sleep 0.5
    echo -ne "\033[32m/\033[m  $loading_text\r"
    sleep 0.5
  done
  tput cnorm                     ## (TO here) the cursor visible again:
  #-------------------
  set +euo > /dev/null 2>&1      ## (FROM here) For To Get Return Code
  wait $last_pid # Get a exit code by the caller's pid
  exit_status=$?
  if [[ ${exit_status} -eq 0 ]]; then
    echo -e "\033[32mok\033[m $loading_text"
  else
    echo -e "\033[31mng\033[m $loading_text"
  fi
  set -euo > /dev/null 2>&1      ## (TO here) For To Get Return Code
  #-------------------
  return "$exit_status"
}

#######################################
# N space characters are added to the beginning of the sentence in the output
# - received by Pipe
# - ${__RDBOX_RAW_INDENT} is a env value
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function showIndent() {
  sed "s/^/${__RDBOX_RAW_INDENT}/"
  return $?
}

#######################################
# Shwo a separator of maximum width according to the terminal in use
# Arguments:
#   (optional) a separator charactor (e.g. #->default)
#              - Anything but one letter.
#   (optional) a color code (e.g. 32->default)
#              - "32" is the code of white
# Outputs:
#   A separator strings (e.g. "###########################")
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function drawMaxColsSeparator() {
  local char=${1:-#}
  local color=${2:-32}
  local raw_separator
  raw_separator="$(seq -s "${char}" 0 $(($(tput cols)-1)) | tr -d '0-9')"
  printf "\033[${color}m%s\033[m\n" "${raw_separator}"
  return $?
}

#######################################
# launch The security tunnel (by the socat) as necessary
# Globals:
#   __RDBOX_HELPFUL_APPS_OF_GOST_PORT
# Arguments:
#   None
# Returns:
#   0 if thing was success, non-zero on error.
#   1 if the k8s cluster was not working.
#   2 if thing was Unable to communicate with security tunnel in HostOS
#######################################
function launchSecurityTunnelAsNecessary() {
  local port_no
  if ! port_no="$(getPortnumberOfkubeapi "${cluster_name}" 2>/dev/null)"; then
    return 1
    ## NOTE
    ## return non-zero, if the k8s cluster is not working
  fi
  if [[ $(isRequiredSecurityTunnel) == "true" ]]; then
    if [[ $(hasWorkingProcess socat) == "false" ]]; then
      echo "Activating a Security Tunnel ..."
      if ! waitForSuccessOfCommand "> /dev/tcp/gateway.docker.internal/${__RDBOX_HELPFUL_APPS_OF_GOST_PORT}" 10 > /dev/null 2>&1; then
        echo "## The following operations are required in your environment (MacOS Container)"
        echo "### Execute the following command in **HostOS**:"
        echo "    $ ./gost -L tcp://127.0.0.1:${__RDBOX_HELPFUL_APPS_OF_GOST_PORT}/127.0.0.1:${port_no}"
        return 2
      fi
      socat tcp-l:"${port_no}",fork,reuseaddr \
        tcp:gateway.docker.internal:"${__RDBOX_HELPFUL_APPS_OF_GOST_PORT}" \
        > /dev/null 2>&1 &
      echo "Activating a Security Tunnel ...ok"
    fi
  fi
  return $?
}

#######################################
# Wait for successful command
#   - The command is executed periodically and continues until the maximum wait time is reached.
# Arguments:
#   Command String
#   Timeout Number (sec)
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function waitForSuccessOfCommand() {
  local cmd
  local count
  local timeout=${2:-300}
  cmd=$(printf %q "${1}" | sed "s/\\\//g")
  count=0
  while ! eval "${cmd} 2>/dev/null"; do
    if [[ ${count} -gt ${timeout} ]]; then
      return 1
    fi
    sleep 1
    count=$((count+1))
  done
  echo ""
  return 0
}

#######################################
# Apply the manifests generated by Dynamics-DI
# Globals:
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
# Arguments:
#   Namespace
#   Hostname
#   ID to uniquely identify user operations
#   Timeout value to be applied by kubectl apply.
#   <variable length arguments> Information required to generate a dynamic configuration file. (e.g. ambassador.dynamics.k8ssso.hostname=ambassador-k8ssso)
# Returns:
#   0 if thing was applyed, non-zero on error.
#######################################
function applyManifestByDI() {
  local __namespace
  local __hostname
  local __release_id
  local __timeout
  local __args_of_raw_set
  local __fullpath_of_generated_dynamics
  local __fullpath_of_generated_manifests
  __namespace=$1
  __hostname=$2
  __release_id=$3
  __timeout=$4
  __args_of_raw_set="${*:5}"
  __fullpath_of_generated_dynamics=$(__generateDynamicsConfigForDI "${__namespace}" "${__hostname}" "${__release_id}" "${__args_of_raw_set}")
  __fullpath_of_generated_manifests=$(__generateManifestForDI "${__namespace}" "${__hostname}" "${__release_id}" "${__fullpath_of_generated_dynamics}")
  if kubectl apply --dry-run=client -f "${__fullpath_of_generated_manifests}" ; then
    echo "---"
    echo "- Successful --dry-run. Apply this manifest."
    echo "   - ${__fullpath_of_generated_manifests}"
    if kubectl apply --timeout "${__timeout}" --wait -f "${__fullpath_of_generated_manifests}" ; then
      echo "- Successful kubectl apply"
      echo "   - ${__fullpath_of_generated_manifests}"
      return 0
    else
      echo "- Failed kubectl apply" >&2
      echo "   - ${__fullpath_of_generated_manifests}" >&2
      return 1
    fi
  else
    echo "---"
    echo "- [ERROR] The format of the manifest is incorrect" >&2
    return 1
  fi
}

function __generateDynamicsValuesForDI() {
  local __namespace
  local __hostname
  local __release_id
  local __type
  local __args_of_eigenvalue
  local __dirpath_of_template_engine
  local __basepath_of_input
  local __version_of_engine
  local __fullpath_of_input_dir
  local __reelativepath_list_of_input
  local __dirpath_of_output
  local __fullpath_of_output_values_yaml
  local __args_of_show_only
  local __cmd
  local __fullpath_of_output_values_latest_yaml
  ## Args
  ##
  __namespace=$1
  __hostname=$2
  __release_id=$3
  __type=$4                # dynamics || manifests
  __args_of_eigenvalue=$5  # Store as a string (Expect a Space Separate Value)
  ## Preparation
  ##
  __dirpath_of_template_engine="${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/helm/template-engine"
  __basepath_of_input=templates/${__namespace}
  __version_of_engine=$(getApiversionBasedOnSemver "$(getVersionOfTemplateEngine)")
  __fullpath_of_input_dir=${__dirpath_of_template_engine}/${__basepath_of_input}
  __reelativepath_list_of_input=$(find "${__fullpath_of_input_dir}" -name "*.yaml" | sed "s|^${__fullpath_of_input_dir}|${__basepath_of_input}|")
  __dirpath_of_output=$(dirname "$(getFullpathOfValuesYamlBy "${__namespace}" outputs "${__type}" "${__version_of_engine}")")
  __fullpath_of_output_values_yaml=${__dirpath_of_output}/values.${__release_id}.$(getEpochMillisec).yaml
  ## Variables actually used
  ##
  __args_of_show_only=$(echo "$__reelativepath_list_of_input" | sed 's/^/--show-only /' | sed  -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g')
  __cmd=$(printf "helm template -n %s --release-name %s %s %s %s" \
          "${__namespace}" \
          "${__hostname}" \
          "${__args_of_show_only}" \
          "${__args_of_eigenvalue}" \
          "${__dirpath_of_template_engine}")
  ## Have an impact on below
  ##
  __fullpath_of_output_values_latest_yaml="${__dirpath_of_output}"/values.latest.yaml
  mkdir -p "$(dirname "${__fullpath_of_output_values_yaml}")"
  if [[ -L "${__fullpath_of_output_values_latest_yaml}" ]]; then
    unlink "${__fullpath_of_output_values_latest_yaml}"
  fi
  eval "${__cmd}" > "${__fullpath_of_output_values_yaml}"
  ## Format the YAML separator (---)
  ##
  sed -i -z 's/##\n---\n#/#/g' "${__fullpath_of_output_values_yaml}"
    ## NOTE
    ## Remove like below (If an empty separator exists at the middle of the file)
    ##
    ## ##
    ## ---
    ## #
  sed -i -z 's/---\n# Source: [A-Za-z0-9 _/.\\-]*yaml\n##\n$//g' "${__fullpath_of_output_values_yaml}"
    ## NOTE
    ## Remove like below (If an empty separator exists at the end of the file)
    ##
    ## ---
    ## # Source: template-engine/templates/cert-manager/manifests/cluster-issuer-ca.yaml
    ## ##
    ## $
  ln -s "${__fullpath_of_output_values_yaml}" "${__fullpath_of_output_values_latest_yaml}"
  echo -n "${__fullpath_of_output_values_yaml}"
  return $?
}

function __generateManifestForDI() {
  local __namespace
  local __hostname
  local __release_id
  local __fullpath_of_generated_dynamics
  local __version_user_conf
  local __fullpath_of_user_conf
  local __args_of_eigenvalue
  __namespace=$1
  __hostname=$2
  __release_id=$3
  __fullpath_of_generated_dynamics=$4
  __version_user_conf=$(getConfVersion "${__namespace}" di)
  __fullpath_of_user_conf="$(getDirNameFor confs)/modules/${__namespace}/di/${__version_user_conf}/values.yaml"
  __args_of_eigenvalue="--set global.manifests=true --values ${__fullpath_of_user_conf} --values ${__fullpath_of_generated_dynamics}"
  __generateDynamicsValuesForDI "${__namespace}" "${__hostname}" "${__release_id}" manifests "${__args_of_eigenvalue}"
  return $?
}

function __generateDynamicsConfigForDI() {
  local __namespace
  local __hostname
  local __release_id
  local __args_of_raw_set
  local __args_of_eigenvalue
  __namespace=$1
  __hostname=$2
  __release_id=$3
  __args_of_raw_set=${*:4} # Store as a string
  __args_of_eigenvalue=$(echo "${__args_of_raw_set}" global.dynamics=true | sed 's/^/ / ; s/ / --set /g')
  __generateDynamicsValuesForDI "${__namespace}" "${__hostname}" "${__release_id}" dynamics "${__args_of_eigenvalue}"
  return $?
}

#######################################
# Initialize based on the specified ClusterName
# - Creates a working directory
# - Synchronize confs directories
# Globals:
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
# Arguments:
#   ClusterName String (e.g. rdbox)
# Outputs:
#   the list of Workdirs by SpaceSeparateString
# Returns:
#   0 if thing was created, non-zero on error.
#######################################
function initializeWorkdirOfWorkbase() {
  local __cluster_name
  local __workbase_dirs
  local __workdir_of_work_base
  local __workdir_of_logs
  local __workdir_of_outputs
  local __workdir_of_tmps
  local __workdir_of_confs
  ## Check Args
  ##
  if isValidClustername "$1"; then
    __cluster_name=$(printf %q "$1")
    readonly __cluster_name
  else
    return 1
  fi
  __workbase_dirs=$(getDirNameListOfWorkbase "${__cluster_name}")
  __workdir_of_work_base=$(echo "$__workbase_dirs" | awk -F ' ' '{print $1}')
  __workdir_of_logs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $2}')
  __workdir_of_outputs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $3}')
  __workdir_of_tmps=$(echo "$__workbase_dirs" | awk -F ' ' '{print $4}')
  __workdir_of_confs=$(echo "$__workbase_dirs" | awk -F ' ' '{print $5}')
  mkdir -p "${__workdir_of_logs}" "${__workdir_of_outputs}" "${__workdir_of_tmps}" "${__workdir_of_confs}"
  rsync -au "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}"/confs/ "${__workdir_of_confs}"
  echo -n "${__workdir_of_work_base}" "${__workdir_of_logs}" "${__workdir_of_outputs}" "${__workdir_of_tmps}" "${__workdir_of_confs}"
  return $?
}

#######################################
# Checks if the argument string is available as a cluster name.
# Arguments:
#   hostname String (e.g. rdbox)
# Returns:
#   0 if thing is valid , non-zero on error.
#######################################
function isValidClustername() {
  local __regex='^[A-Za-z0-9][A-Za-z0-9\-]{1,12}[A-Za-z0-9]$'
  local __clustername
  __clustername=$1
  if [[ "$__clustername" =~ ${__regex} ]]; then
    return 0
  else
    echo "**ERROR**  Invalid Argument (clustername)" >&2
    echo "  - Expect: ${__regex}" >&2
    echo "  - Actual: ${__clustername}" >&2
    return 1
  fi
}

#######################################
# Checks if the argument string is available as a host name.
# Arguments:
#   hostname String (e.g. rdbox-01)
# Returns:
#   0 if thing is valid , non-zero on error.
#######################################
function isValidHostname() {
  local __regex='^[A-Za-z0-9][A-Za-z0-9\-]{1,64}[A-Za-z0-9]$'
  local __hostname
  __hostname=$1
  if [[ "$__hostname" =~ ${__regex} ]]; then
    return 0
  else
    echo "**ERROR**  Invalid Argument (hostname)" >&2
    echo "  - Expect: ${__regex}" >&2
    echo "  - Actual: ${__hostname}" >&2
    return 1
  fi
}

#######################################
# Checks if the argument string is available as a domain.
# Arguments:
#   domainname String (e.g. nip.io)
# Returns:
#   0 if thing is valid , non-zero on error.
#######################################
function isValidDomainname() {
  local __regex='^([A-Za-z]{2,6}|[A-Za-z]{2,6}\.[A-Za-z]{2,6})$'
  local __domainname
  __domainname=$1
  if [[ "$__domainname" =~ ${__regex} ]]; then
    return 0
  else
    echo "**ERROR**  Invalid Argument (domainname)" >&2
    echo "  - Expect: ${__regex}" >&2
    echo "  - Actual: ${__domainname}" >&2
    return 1
  fi
}

#######################################
# Determine if a security tunnel is required
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   true or false (String)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function isRequiredSecurityTunnel() {
  local runtime_name
  local os_name
  runtime_name=$(getRuntimeName)
  os_name=$(getOsNameAtContainer)
  if [[ "${runtime_name}" == "Container" ]] && [[ "${os_name}" == "MacOS" ]]; then
    echo -n "true"
  else
    echo -n "false"
  fi
  return $?
}

#######################################
# Determine if a process with the specified name is running
# Globals:
#   None
# Arguments:
#   A Process Name String (e.g. socat)
# Outputs:
#   true or false (String)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function hasWorkingProcess() {
  local process_name
  process_name="${1}"
  count=$(pgrep -f "${process_name}" | wc -l)
  if [[ ${count} -ge 1 ]]; then
    echo -n "true"
  else
    echo -n "false"
  fi
  return $?
}

#######################################
# Get a Path list of the Directoryes that use for working
# Globals:
#   (optional) RDBOX_WORKDIR_OF_WORK_BASE
# Arguments:
#   ClusterName String (e.g. rdbox)
# Outputs:
#   (a Space Separate Value)
#   1: RDBOX_WORKDIR_OF_WORK_BASE  (e.g. ${HOME}/crobotics/rdbox)
#   2: logs                        (e.g. ${HOME}/crobotics/rdbox/logs)
#   3: outputs                     (e.g. ${HOME}/crobotics/rdbox/outputs)
#   4: tmps                        (e.g. ${HOME}/crobotics/rdbox/tmps)
#   5: confs                       (e.g. ${HOME}/crobotics/rdbox/confs)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getDirNameListOfWorkbase() {
  local __cluster_name="$1"
  RDBOX_WORKDIR_OF_WORK_BASE=${RDBOX_WORKDIR_OF_WORK_BASE:-/tmp/crobotics/${__cluster_name}}
  RDBOX_WORKDIR_OF_WORK_BASE=$(printf %q "$RDBOX_WORKDIR_OF_WORK_BASE")
  export RDBOX_WORKDIR_OF_WORK_BASE=${RDBOX_WORKDIR_OF_WORK_BASE}
    ### EXTRAPOLATION
  local __workdir_of_logs=${RDBOX_WORKDIR_OF_WORK_BASE}/logs
  local __workdir_of_outputs=${RDBOX_WORKDIR_OF_WORK_BASE}/outputs
  local __workdir_of_tmps=${RDBOX_WORKDIR_OF_WORK_BASE}/tmps
  local __workdir_of_confs=${RDBOX_WORKDIR_OF_WORK_BASE}/confs
  echo "${RDBOX_WORKDIR_OF_WORK_BASE}" "${__workdir_of_logs}" "${__workdir_of_outputs}" "${__workdir_of_tmps}" "${__workdir_of_confs}"
  return $?
}

#######################################
# Get a network info and Export ones
# Globals:
#   (optional) RDBOX_NETWORK_DEFULT_NIC_NAME
#   (optional) RDBOX_NETWORK_DEFULT_NIC_IPV4
#   (optional) RDBOX_NETWORK_DEFULT_NIC_IPV6
# Arguments:
#   None
# Outputs:
#   (export)
#   RDBOX_NETWORK_DEFULT_NIC_NAME (e.g. en0)
#   RDBOX_NETWORK_DEFULT_NIC_IPV4 (e.g. 172.16.0.110)
#   RDBOX_NETWORK_DEFULT_NIC_IPV6 (e.g. fe80::455:ebb3:3575:4f90)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getNetworkInfo() {
  local runtime_name
  local os_name
  runtime_name=$(getRuntimeName)
  os_name=$(getOsNameAtHost)
  if [[ "${runtime_name}" == "Host" ]] && [[ "${os_name}" == "MacOS" ]]; then
    RDBOX_NETWORK_DEFULT_NIC_NAME=${RDBOX_NETWORK_DEFULT_NIC_NAME:-$(netstat -rn | grep default | grep -v "\!" | grep -v ":" | awk '{print $4}')}
  else
    RDBOX_NETWORK_DEFULT_NIC_NAME=${RDBOX_NETWORK_DEFULT_NIC_NAME:-$(netstat -rn | grep ^0.0.0.0 | grep -v ":" | awk '{print $8}')}
  fi
  RDBOX_NETWORK_DEFULT_NIC_NAME=$(printf %q "$RDBOX_NETWORK_DEFULT_NIC_NAME")
    # EXTRAPOLATION
  export RDBOX_NETWORK_DEFULT_NIC_NAME=${RDBOX_NETWORK_DEFULT_NIC_NAME}
  # shellcheck disable=SC2015
  RDBOX_NETWORK_DEFULT_NIC_IPV4=${RDBOX_NETWORK_DEFULT_NIC_IPV4:-$( (command -v ip &> /dev/null && ip addr show "$RDBOX_NETWORK_DEFULT_NIC_NAME" || ifconfig "$RDBOX_NETWORK_DEFULT_NIC_NAME") | \
                    sed -nEe 's/^[[:space:]]+inet[^[:alnum:]]+([0-9.]+).*$/\1/p')}
  export RDBOX_NETWORK_DEFULT_NIC_IPV4=${RDBOX_NETWORK_DEFULT_NIC_IPV4}
  # shellcheck disable=SC2015
  RDBOX_NETWORK_DEFULT_NIC_IPV6=${RDBOX_NETWORK_DEFULT_NIC_IPV6:-$( (command -v ip &> /dev/null && ip addr show "$RDBOX_NETWORK_DEFULT_NIC_NAME" || ifconfig "$RDBOX_NETWORK_DEFULT_NIC_NAME") | \
                    sed -nEe 's/^[[:space:]]+inet6[^[:alnum:]]+([0-9A-Za-z:.]+).*$/\1/p')}
  export RDBOX_NETWORK_DEFULT_NIC_IPV6=${RDBOX_NETWORK_DEFULT_NIC_IPV6}
  __RDBOX_HOSTNAME_FOR_WCDNS_BASED_ON_IP=${RDBOX_NETWORK_DEFULT_NIC_IPV4//\./-}
  export __RDBOX_HOSTNAME_FOR_WCDNS_BASED_ON_IP=${__RDBOX_HOSTNAME_FOR_WCDNS_BASED_ON_IP}
}

#######################################
# Get the kubectl's context name for SSO
# - oidc-login by krew
# Arguments:
#   (optional) prefix (e.g. sso)
# Outputs:
#   The context name of regulation (e.g. sso-k8s-cluster)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getKubectlContextName4SSO() {
  local prefix=${1:-"sso"}
  local context_name
  context_name=${prefix}-$(getClusterName)
  echo -n "$context_name"
}

#######################################
# Get the values from cluster-info.cluster-common
# - Frequently used items are functioned
# Arguments:
#   a search condition by a jq format (e.g. ".data[\"nic0.ipv4\"]")
# Outputs:
#   The value of cluster (e.g. sso-k8s-cluster)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getClusterinfoFromConfigmap() {
  local __item=$1
  kubectl -n ${__RDBOX_CLUSTER_INFO_NAMESPACE} get configmaps ${__RDBOX_CLUSTER_INFO_NAMENAME} -o json| jq -r "${__item}"
}
function getWorkdirOfScripts() {
  getClusterinfoFromConfigmap ".data[\"workdir.scripts\"]"
}
function getClusterName() {
  getClusterinfoFromConfigmap ".data.name"
}
function getBaseFQDN() {
  getClusterinfoFromConfigmap ".data[\"nic0.base_fqdn\"]"
}
function getIPv4 () {
  getClusterinfoFromConfigmap ".data[\"nic0.ipv4\"]"
}
function getVolumeClass () {
  getClusterinfoFromConfigmap ".data[\"volume.class\"]"
}
function getVolumeMode () {
  getClusterinfoFromConfigmap ".data[\"volume.mode\"]"
}
function getVolumeSize () {
  getClusterinfoFromConfigmap ".data[\"volume.size\"]"
}
function getNamespaceName() {
  local __namespace=$1
  getClusterinfoFromConfigmap ".data[\"namespace.${__namespace}\"]"
}
function getReleaseName() {
  local __namespace=$1
  getClusterinfoFromConfigmap ".data[\"${__namespace}.release\"]"
}
function getHelmRepoName() {
  local __namespace=$1
  getClusterinfoFromConfigmap ".data[\"${__namespace}.helm.repo.name\"]"
}
function getHelmPkgName() {
  local __namespace=$1
  getClusterinfoFromConfigmap ".data[\"${__namespace}.helm.pkg.name\"]"
}
function getHelmPkgVersion() {
  local __namespace=$1
  getClusterinfoFromConfigmap ".data[\"${__namespace}.helm.pkg.version\"]"
}
function getHostName() {
  local __namespace=$1
  local __host=$2
  getClusterinfoFromConfigmap ".data[\"${__namespace}.hostname.${__host}\"]"
}
function getDirNameFor() {
  local __purpose=$1
  getClusterinfoFromConfigmap ".data[\"workdir.${__purpose}\"]"
}
function getConfVersion() {
  local __namespace=$1
  local __type=$2
  getClusterinfoFromConfigmap ".data[\"${__namespace}.conf.${__type}.version\"]"
}

#######################################
# Get the full path of the directory for the specified terms in WORK_DIR.
# Arguments:
#   namespace
#   purpose            (e.g. confs, logs outputs, tmps ....)
#   type               (e.g. di,helms,  dynamics,manifests....)
#   (optional)version  (e.g. v1beta1)
# Outputs:
#   the full path of the directory (e.g. /crobotics/rdbox/outputs/modules/metallb/manifests/v1beta1/subs)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getFullpathOfOnesBy() {
  local __namespace
  local __purpose
  local __type
  local __version
  local __workdir_of_purpose
  __namespace=$1
  __purpose=$2
  __type=$3
  __version=${4:-$(getConfVersion "${__namespace}" "${__type}")}
  __workdir_of_purpose=$(getDirNameFor "${__purpose}")
  echo -n "${__workdir_of_purpose}/modules/${__namespace}/${__type}/${__version}"
  return $?
}

#######################################
# Get the full path of the directory for the specified terms in WORK_DIR.
#    - WITH the filename of **values.yaml***
# Arguments:
#   namespace
#   purpose            (e.g. confs, logs outputs, tmps ....)
#   type               (e.g. di,helms,  dynamics,manifests....)
#   (optional)version  (e.g. v1beta1)
# Outputs:
#   the full path of the file (e.g. /crobotics/rdbox/outputs/modules/metallb/manifests/v1beta1/values.yaml)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getFullpathOfValuesYamlBy() {
  local dirpath
  dirpath=$(getFullpathOfOnesBy "${@}")
  echo -n "${dirpath}/values.yaml"
  return $?
}

#######################################
# Get the full path of the RootCA
# Outputs:
#   the full path of the file (e.g. /crobotics/rdbox/outputs/ca/rdbox.172-16-0-110.nip.io.ca.crt)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getFullpathOfRootCA() {
  local __dir
  local __base_fqdn
  __dir=$(getDirNameFor outputs)/ca
  __base_fqdn=$(getBaseFQDN)
  mkdir -p "$__dir"
  chmod 0700 "$__dir"
  echo -ne "${__dir}"/"${__base_fqdn}".ca.crt
  return $?
}

#######################################
# Get the full path of a history file for the cert-manager
#    - **Only cert-manager**
# Outputs:
#   the full path of the file (e.g. /crobotics/rdbox/outputs/.history.rdbox.172-16-0-110.nip.io/selfsigned-ca.rdbox.172-16-0-110.nip.io.ca.yaml)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getFullpathOfHistory() {
  local __dir
  local __base_fqdn
  __base_fqdn=$(getBaseFQDN)
  __dir=$(getDirNameFor outputs)/.history.${__base_fqdn}
  mkdir -p "$__dir"
  chmod 0700 "$__dir"
  echo -ne "${__dir}"/selfsigned-ca."${__base_fqdn}".ca.yaml
  return $?
}

#######################################
# Get the full path of a VerifyMsgs text file
#    - This file contains the information to be communicated to the user.
# Outputs:
#   the full path of the file (e.g. /crobotics/rdbox/outputs/verify_msgs/keycloak.verifier_command.txt)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getFullpathOfVerifyMsgs() {
  local __namespace
  local __dir
  __namespace="$1"
  __dir=$(getDirNameFor outputs)/verify_msgs
  mkdir -p "${__dir}"
  echo -n "${__dir}"/"${__namespace}".verifier_command.txt
  return $?
}

#######################################
# Get the keycloak super admin user name
#    - This user manages all realms of the keycloak.
#    - Only Keycloak (not manage k8s cluster)
# Outputs:
#   super-admin
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getPresetKeycloakSuperAdminName() {
  local rep_name
  rep_name=$1
  helm -n "${rep_name}" get values "${rep_name}" -o json | jq -r '.auth.adminUser'
  return $?
}

#######################################
# Get the cluster-admin user name
#    - This user manages a specific K8s cluster.
# Outputs:
#   cluster-admin
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getPresetClusterAdminUserName() {
  # !! Must be a hyphen-delimited string !!
  # e.g. *cluster-admim*
  echo -n "cluster-admin"
  return $?
}

#######################################
# Get the cluster-admin group name
#    - This user manages a specific K8s cluster.
# Outputs:
#   cluster-admin
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getPresetClusterAdminGroupName() {
  # !! Must be a hyphen-delimited string !!
  # e.g. *cluster-admim*
  echo -n "/cluster/cluster-admin"
  return $?
}

#######################################
# Get the guest group name
#    - This user is used for test and tutorial
# Outputs:
#   /guest/admin
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getPresetNamespaceGuestGroupName() {
  # !! Must be a hyphen-delimited string !!
  # e.g. *cluster-admim*
  echo -n "/guest/admin"
  return $?
}

#######################################
# Get the salted password by Pbkdf2Sha256
# Globals:
#   None
# Arguments:
#   Password
# Outputs:
#   A salt (e.g. "$5$nvUwza0i9nHktSZq" It is generated by python3 crypt.mksalt module)
#   A hash salted password (e.g. jsVGyrRcqvbvVbVAp6A502PsmG7HuXcFZ0SQmi++FgcPGuXRUvUygqcQ6Vbk4ez9A+v6reS8z74rOwJwa5vBGg==)
#   A count of iterations(27500)
# References:
#   https://docs.python.org/ja/3/library/hashlib.html?highlight=pbkdf2#hashlib.pbkdf2_hmac
#######################################
function getHashedPasswordByPbkdf2Sha256() {
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
  #__hashed_salted_value=${__hashed_salted_value//[\r\n]\+/ }
  __salt=$(echo -e "import base64; print(base64.b64encode(b\"${__salt}\").decode(encoding=\"ascii\"),end=\"\")" | python3)
  #__salt=${__salt//[\r\n]\+/ }
  echo "$__salt"
  echo "$__hashed_salted_value"
  echo "$__hash_iterations"
}

#######################################
# Get a Epoch sec
# - The decimal point is in 100ns units.
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   A Epoch sec (e.g. 1650430272.1467361)
#######################################
function getEpochSec() {
  local __sec
  local __ret
  __sec=$(python3 -c 'import time; print(time.time())')
  __ret=$?
  echo -n "${__sec}"
  return ${__ret}
}

#######################################
# Get a Epoch milli sec
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   A Epoch milli sec (e.g. 1650430272146)
#######################################
function getEpochMillisec() {
  local __ms
  local __ret
  __ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
  __ret=$?
  echo -n "$__ms"
  return ${__ret}
}

#######################################
# Get a DateTime string (ISO8601 compliance)
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   A DateTime string (e.g. 2022-04-20T13:51:12+0900)
#######################################
function getIso8601DayTime() {
  local __dt
  local __ret
  __dt=$(date '+%Y-%m-%dT%H:%M:%S%z')
  __ret=$?
  echo -n "${__dt}"
  return ${__ret}
}

#######################################
# Get the version string of TemplateEngine
# Globals:
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
# Arguments:
#   None
# Outputs:
#   A TemplateEngine Version String (e.g. 0.1.0)
#######################################
function getVersionOfTemplateEngine() {
  local __dirpath_of_template_engine
  local __version_of_engine
  local __ret
  __dirpath_of_template_engine="${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/helm/template-engine"
  __version_of_engine=$(helm show chart "${__dirpath_of_template_engine}" | yq '.version')
  __ret=$?
  echo -n "${__version_of_engine}"
  return ${__ret}
}

#######################################
# Get a APIVersion based on the SemVer
# - Samples
#    - v1alpha1 = v0.0.1
#    - v1alpha2 = v0.0.2
#    - v1beta1  = v0.1.0
#    - v1       = v1.0.0
#    - v2alpha1 = v1.0.1
#    - v2beta1  = v1.1.0
#    - v2       = v2.0.0
# Globals:
#   None
# Arguments:
#   SemVer String (e.g. v1beta1)
# Outputs:
#   A APIVersion String (e.g. v0.1.0)
#######################################
function getApiversionBasedOnSemver() {
  local __raw_version
  local __major
  local __minor
  local __build
  local __api_version
  __raw_version=${1:-"$(getVersionOfTemplateEngine)"}
  __major=$(echo "${__raw_version}" | awk -F'.' '{ print $1 }')
  __minor=$(echo "${__raw_version}" | awk -F'.' '{ print $2 }')
  __build=$(echo "${__raw_version}" | awk -F'.' '{ print $3 }')
  __major=$((__major+1))
  __minor=$((__minor+0))
  __build=$((__build+0))
  if [[ ${__minor} -gt 0 ]]; then
    __api_version=$(printf "v%dbeta%d" "${__major}" "${__minor}")
  else
    __api_version=$(printf "v%dalpha%d" "${__major}" "${__build}")
  fi
  echo -n "${__api_version}"
  return $?
}

#######################################
# Get a Runtime Name
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   A Runtime Name (Container or Host)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getRuntimeName() {
  if host "gateway.docker.internal" > /dev/null 2>&1; then
    echo -n "Container"
  else
    echo -n "Host"
  fi
  return $?
}

#######################################
# Get a OS Name at the container
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   A OS Name (MacOS or Windows or Linux)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getOsNameAtContainer() {
  if host "docker.for.mac.host.internal" > /dev/null 2>&1; then
    echo -n "MacOS"
  elif host "docker.for.win.host.internal" > /dev/null 2>&1; then
    echo -n "Windows"
  else
    echo -n "Linux"
  fi
  return $?
}

#######################################
# Get a OS Name at the Host
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   A OS Name (MacOS or Windows or Linux)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getOsNameAtHost() {
  local os_name
  if [[ "$(uname)" == 'Darwin' ]]; then
    os_name='MacOS'
    echo -n ${os_name}
    return 0
  fi
  local uname_str
  uname_str=$(uname -s)
  if [[ "${uname_str:0:5}" == 'Linux' ]]; then
    os_name='Linux'
  elif [[ "${uname_str:0:10}" == 'MINGW32_NT' ]]; then
    os_name='Windows'
  else
    echo "Your platform ($(uname -a)) is not supported."
    return 1
  fi
  echo -n ${os_name}
  return 0
}

#######################################
# Get a Port Number of the kubeapi-server
# Globals:
#   None
# Arguments:
#   ClusterName String (e.g. rdbox)
# Outputs:
#   A Port Number of the kubeapi-server (e.g. 35762)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function getPortnumberOfkubeapi() {
  local cluster_name
  local port
  local inspect_json
  cluster_name="${1}"
  inspect_json=$(sudo docker inspect "${cluster_name}"-control-plane)
  port=$(echo "${inspect_json}" | jq -r '.[].NetworkSettings.Ports."6443/tcp"[].HostPort')
  if [[ "$port" =~ ^[0-9]+$ ]]; then
    echo -n "${port}"
  else
    return 1
  fi
  return $?
}

#######################################
# Perse a json file with jq args
# Globals:
#   None
# Arguments:
#   src_filepath String (the file is formated by jq arg)
#   <variable length arguments> joined by " " (e.g. "clientId user0001" "password BHIee2")
# Outputs:
#   parsed json string
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
# References:
#   https://public-constructor.com/shel-jq-variable/
#######################################
function parse_jq_temlate() {
  local src_filepath=$1
  local args=()
  for arg in "${@:2}" ; do
    local key
    local value
    IFS=" " read -r key value <<< "$arg"
    args+=("--arg" "${key}" "${value}")
  done
  jq -n -c -r -f "$src_filepath" "${args[@]}"
  return $?
}

#######################################
# kubectl compatible commands
#   - First, the command specified by the argument is manifested.
#      - The manifest is stored in outputs/modules/${MODULE}/manifests/.
#      - The symbolic link "values.latest.yaml" is also updated.
#   - Then, the manifest created above is applied to the cluster with the Apply subcommand.
# Globals:
#   NAMESPACE
#   CREATES_RELEASE_ID
# Arguments:
#   command                Typical kubectl command ((kubectl_r) create namespace jpg)
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function kubectl_r() {
  local cmd
  cmd=$(printf %q "$*" | sed "s/\\\ / /g")
  local version_of_engine
  local dirpath_of_output
  version_of_engine=$(getApiversionBasedOnSemver "$(getVersionOfTemplateEngine)")
  dirpath_of_output=$(dirname "$(getFullpathOfValuesYamlBy "${NAMESPACE}" outputs "manifests" "${version_of_engine}")")
  fullpath_of_output_values_yaml=${dirpath_of_output}/values.${CREATES_RELEASE_ID}.$(getEpochMillisec).yaml
  fullpath_of_output_values_latest_yaml="${dirpath_of_output}"/values.latest.yaml
  mkdir -p "$(dirname "${fullpath_of_output_values_yaml}")"
  if [[ "${cmd}" =~ (^| )create($| ) ]]; then
    # shellcheck disable=SC2086
    kubectl ${cmd} --save-config --dry-run=client -o yaml > "${fullpath_of_output_values_yaml}"
  else
    # shellcheck disable=SC2086
    kubectl ${cmd} --dry-run=client -o yaml > "${fullpath_of_output_values_yaml}"
  fi
  if output=$(kubectl apply --timeout 180s --wait -f "${fullpath_of_output_values_yaml}" 2>&1); then
    if [[ -L "${fullpath_of_output_values_latest_yaml}" ]]; then
      unlink "${fullpath_of_output_values_latest_yaml}" > /dev/null 2>&1
    fi
    ln -s "${fullpath_of_output_values_yaml}" "${fullpath_of_output_values_latest_yaml}" > /dev/null 2>&1
    echo "${output}"
    return 0
  else
    echo "${output}"
    return 1
  fi
}

#######################################
# Prepare a Helm repo's info
# Globals:
#   HELM_NAME              (e.g. datawire/edge-stack)
#   HELM_REPO_NAME         (e.g. datawire)
#   -   HELM_PKG_NAME      (e.g. edge-stack)
# Arguments:
#   NONE
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function prepare_helm_repo() {
  local HELM_REPO_URL
  HELM_REPO_URL=$(curl -s https://artifacthub.io/api/v1/packages/helm/"${HELM_NAME}" | jq -r ".repository.url")
  helm repo add "${HELM_REPO_NAME}" "${HELM_REPO_URL}" > /dev/null 2>&1
  helm repo update "${HELM_REPO_NAME}" > /dev/null 2>&1
  return $?
}

#######################################
# Handler for deleting temporary directories in function scope
# Globals:
#   NONE
# Arguments:
#   DIR_PATH
# Outputs:
#   NONE
# References:
#   https://unix.stackexchange.com/questions/582922/how-to-pass-local-variable-to-trap-handler-in-bash
#######################################
function exit_handler() {
  local rv="$?"
  local tmp_dir="${1}"
  rm -rf "$tmp_dir"
  return "$rv"
}

#######################################
# Update the cluseter-info by the **env.properties** of $MODULE_NAME
# - a configmap of cluster-common(Namespace)
# Globals:
#   MODULE_NAME                            (e.g. keycloak)
#   __RDBOX_CLUSTER_INFO_NAMESPACE         (e.g. cluster-common)
#   __RDBOX_CLUSTER_INFO_NAMENAME          (e.g. cluseter-info)
# Arguments:
#   NONE
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function update_cluster_info() {
  function __update_cluster_info() {
    local tmp_dir=$1
    local env_prop
    env_prop="$(getWorkdirOfScripts)/modules/modules/${MODULE_NAME}/env.properties"
    local cm_filepath="${tmp_dir}"/cm.json
    kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" create configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
      --dry-run=client \
      --output=json \
      --from-env-file="${env_prop}" \
    | jq -r -c > "${cm_filepath}"
    local NAMESPACE
    NAMESPACE="${__RDBOX_CLUSTER_INFO_NAMESPACE}"
    kubectl_r -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" patch configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
      --type merge \
      --patch-file "${cm_filepath}"  > /dev/null 2>&1
    return $?
  }
  local tmp_dir
  tmp_dir=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "exit_handler '${tmp_dir}'" EXIT
  __update_cluster_info "$tmp_dir" "$@"
  return $?
}

#######################################
# Purge $MODULE_NAME items from the cluseter-info
# - a configmap of cluster-common(Namespace)
# Globals:
#   MODULE_NAME                            (e.g. keycloak)
#   __RDBOX_CLUSTER_INFO_NAMESPACE         (e.g. cluster-common)
#   __RDBOX_CLUSTER_INFO_NAMENAME          (e.g. cluseter-info)
# Arguments:
#   NONE
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function purge_cluster_info() {
  function __purge_cluster_info() {
    local tmp_dir=$1
    local cm_filepath="${tmp_dir}"/cm.yaml
    kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" get configmaps "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
      --output yaml \
    | yq "del(.data.${MODULE_NAME}*, \
              .data.\"namespace.${MODULE_NAME}\", \
              .metadata.uid, \
              .metadata.creationTimestamp, \
              .metadata.resourceVersion, \
              .metadata.managedFields)" > "${cm_filepath}"
    local NAMESPACE
    local CREATES_RELEASE_ID
    NAMESPACE="${__RDBOX_CLUSTER_INFO_NAMESPACE}"
    CREATES_RELEASE_ID=$(getEpochMillisec)
    kubectl_r replace -f "${cm_filepath}"
    return $?
  }
  local tmp_dir
  tmp_dir=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "exit_handler '${tmp_dir}'" EXIT
  __purge_cluster_info "$tmp_dir" "$@"
  return $?
}

#######################################
# Get a id of latest release
# Globals:
#   MODULE_NAME                          (e.g. keycloak)
# Outputs:
#   ID                                   (e.g. 1659418304268)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function get_latest_release() {
  local __version_of_engine __dirpath_of_output __fullpath_latest_values_yaml
  local __latest_values_yaml __latest_values_array
  __version_of_engine=$(getApiversionBasedOnSemver "$(getVersionOfTemplateEngine)")
  __dirpath_of_output=$(dirname "$(getFullpathOfValuesYamlBy "${MODULE_NAME}" outputs "manifests" "${__version_of_engine}")")
  __fullpath_latest_values_yaml=${__dirpath_of_output}/values.latest.yaml
  __latest_values_yaml=$(basename "$(readlink "${__fullpath_latest_values_yaml}")")
  IFS="." read -r -a __latest_values_array <<< "$__latest_values_yaml"
  echo -n "${__latest_values_array[1]}"
  return $?
}

#######################################
# Get a manifests of latest release
# Globals:
#   MODULE_NAME                          (e.g. keycloak)
# Outputs:
#   ID                                   (e.g. 1659418304268)
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function get_latest_manifests() {
  local __version_of_engine __dirpath_of_output __fullpath_latest_values_yaml
  local __latest_values_yaml __latest_values_array
  __version_of_engine=$(getApiversionBasedOnSemver "$(getVersionOfTemplateEngine)")
  __dirpath_of_output=$(dirname "$(getFullpathOfValuesYamlBy "${MODULE_NAME}" outputs "manifests" "${__version_of_engine}")")
  __fullpath_latest_values_yaml=${__dirpath_of_output}/values.latest.yaml
  __latest_values_yaml=$(basename "$(readlink "${__fullpath_latest_values_yaml}")")
  IFS="." read -r -a __latest_values_array <<< "$__latest_values_yaml"
  echo -n "${__dirpath_of_output}/${__latest_values_array[0]}.${__latest_values_array[1]}.*.yaml"
  return $?
}

#######################################
# Get a result of to execute ls command
# - that is formated SSV(Space Separated Value) with be escaped
# Arguments:
#   path                          (e.g. /path/to/hoge.*.yaml)
# Outputs:
#   paths                         (e.g. "/path/to/hoge.1.yaml /path/to/hoge.2.yaml /path/to/hoge.3.yaml")
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function get_escaped_ssv_by_ls() {
  local path=$1
  fullpath_file_list=$(bash -c "ls ${path}")
  echo "${fullpath_file_list}" | sed "s/\\$//g" | sed "s/'//g" | tr '\n' ' '
  return $?
}

#######################################
# Get args of files for kubectl_delete
# - that is formated SSV(Space Separated Value) with be escaped
# - Sample USAGE
#  ```bash
#  local args
#  IFS=' ' read -r -a args <<< "$(get_args_of_files_for_kubectl_delete)"
#  kubectl delete "${args[@]}"
#  ```
# Globals:
#   MODULE_NAME       (e.g. keycloak)
# Arguments:
#   None
# Outputs:
#   args              (e.g. "-f /path/to/hoge.1.yaml -f /path/to/hoge.2.yaml")
# Returns:
#   0 if thing was gived assurance output, non-zero on error.
#######################################
function get_args_of_files_for_kubectl_delete() {
  local fullpath_latest_manifests_as_regex
  fullpath_latest_manifests_as_regex=$(get_latest_manifests)
    ### NOTE
    ### e.g.)
    ### /tmp/crobotics/rdbox/outputs/modules/kubernetes-dashboard/manifests/v1beta1/values.1660031982882.*.yaml
  local latest_values_array
  IFS=" " read -r -a latest_values_array <<< "$(get_escaped_ssv_by_ls "${fullpath_latest_manifests_as_regex}")"
  local args=()
  for arg in "${latest_values_array[@]}" ; do
    args+=("-f" "${arg}")
  done
  echo -n "${args[@]}"
    ### NOTE
    ### e.g.)
    ### "-f /path/to/hoge.1.yaml -f /path/to/hoge.2.yaml"
  return $?
}