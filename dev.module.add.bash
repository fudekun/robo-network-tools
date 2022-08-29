#!/usr/bin/env bash
set -euo pipefail

###############################################################################
## [For developers] Use when adding a new module.
## Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

#######################################
# [For developers] Use when adding a new module.
# - Create files/dirs
#   - main-script
#   - conf
#   - template-engine
# Arguments:
#   module_name (e.g. keycloak)
#   version     (e.g. v1beta1)
# Returns:
#   0 if thing was success, non-zero on error.
#######################################
function main() {
  local module_name=$1
  local version=$2
  local module_dir="${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/${module_name}"
  local conf_dir="${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/confs/modules/${module_name}"
  local template_dir="${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/helm/template-engine/templates/${module_name}"
  # main-script
  mkdir -p "${module_dir}" "${module_dir}/crud"
  create_main "${module_name}" > "${module_dir}/${module_name}.bash"
  create_script "${module_name}" > "${module_dir}/crud/create.bash"
  touch "${module_dir}/crud/delete.bash"
  # conf
  mkdir -p "${conf_dir}/di/${version}" "${conf_dir}/helm/${version}" "${conf_dir}/entry/${version}"
  touch "${conf_dir}/di/${version}/values.yaml"
  touch "${conf_dir}/helm/${version}/values.yaml"
  conf_env_properties "${module_name}" "${version}" > "${module_dir}/env.properties"
  # template-engine
  mkdir -p "${template_dir}/dynamics" "${template_dir}/manifests"
  dynamics_values_yaml "${module_name}" > "${template_dir}/dynamics/values.yaml"
  printf "##\n" > "${template_dir}/manifests/values.yaml"
  local under_module_name=${module_name/-/_}
  echo "OK!!"
  echo "
  1. Check and Modify created files
    - ${module_dir}/${module_name}.bash
    - ${conf_dir}/di/${version}/values.yaml
    - ${conf_dir}/helm/${version}/values.yaml
    - ${module_dir}/env.properties
    - ${template_dir}/dynamics/values.yaml
    - ${template_dir}/manifests/values.yaml
  2. Add to \"${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/confs/meta-pkgs/essentials/create.properties\" if necessary.
    - e.g.) ${module_name}=4
      - the number that is order of showing Verifier Text
      - If you specific 0, the Verifier Text is hidden.
      - The smaller the number specified, the higher the number displayed first.
  3. Define a RDBOX_MODULE_NAME_ in the modules/libs/common.bash
    - RDBOX_MODULE_NAME_${under_module_name^^}=\"${module_name}\"
  "
  return $?
}

function create_main() {
  local module_name=$1
  local under_module_name=${module_name/-/_}
echo "#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Operating a ${module_name}
# Globals:
#   RDBOX_MODULE_NAME_${under_module_name^^}
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   CREATES_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function showHeaderCommand() {
  local operating=\${1^}
  echo \"\"
  echo \"---\"
  echo \"## \${operating} \${MODULE_NAME} ...\"
  cmdWithIndent \"showParams \$*\"
  return \$?
}

function showParams() {
  echo \"---\"
  echo \"\"
  echo CLUSTER_NAME=\"\${CLUSTER_NAME}\"
  echo NAMESPACE=\"\${NAMESPACE}\"
  echo RELEASE=\"\${RELEASE}\"
  echo BASE_FQDN=\"\${BASE_FQDN}\"
  echo \"---\"
  return \$?
}

function main() {
  local operation=\${1}
  #######################################################
  local MODULE_NAME
  MODULE_NAME=\"\${RDBOX_MODULE_NAME_${under_module_name^^}}\"
  if [ \"\${operation}\" = \"create\" ]; then
    update_cluster_info
  fi
  ############################
  local CLUSTER_NAME
  CLUSTER_NAME=\$(getClusterName)
  local NAMESPACE
  NAMESPACE=\"\$(getNamespaceName \"\${MODULE_NAME}\")\"
  local RELEASE
  RELEASE=\"\$(getReleaseName \"\${MODULE_NAME}\")\"
  local BASE_FQDN
  BASE_FQDN=\$(getBaseFQDN)
  #######################################################
  showHeaderCommand \"\${@}\"
  if [ \"\${operation}\" = \"create\" ]; then
    source \"\$(dirname \"\${0}\")/crud/create.bash\"
    create \"\${*:2}\"
  elif [ \"\${operation}\" = \"delete\" ]; then
    source \"\$(dirname \"\${0}\")/crud/delete.bash\"
    delete \"\${*:2}\"
  elif [ \"\${operation}\" = \"update\" ]; then
    source \"\$(dirname \"\${0}\")/crud/update.bash\"
    update \"\${*:2}\"
  else
    echo \"Operation Not found\"
    return 1
  fi
  return \$?
}

source \"\${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash\"
main \"\$@\"
exit \$?
"
}

function create_script() {
  local module_name=$1
  local under_module_name=${module_name/-/_}
echo "#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a ${module_name}
# Globals:
#   RDBOX_MODULE_NAME_${under_module_name^^}
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
  return \$?
}

function create() {
  checkArgs \"\$@\"
  if cmdWithIndent \"executor \$*\"; then
    verify_string=\$(showVerifierCommand)
    echo \"\${verify_string}\" > \"\$(getFullpathOfVerifyMsgs \"\${MODULE_NAME}\")\"
    return 0
  else
    return 1
  fi
  return \$?
}

function showVerifierCommand() {
  echo \"\"
  echo \"## USAGE\"
  echo \"### \${MODULE_NAME} has been installed. Check its status by running:\"
  echo \"    kubectl -n \${NAMESPACE} get deployments -o wide\"
  return \$?
}

function executor() {
  if __executor \"\${@}\"; then
    exit 0
  else
    exit 1
  fi
}

function __executor() {
  return \$?
}

source \"\${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash\"
"
}

function conf_env_properties() {
  local module_name=$1
  local version=$2
echo "## namespaces
namespace.${module_name}=${module_name}

## ${module_name}
${module_name}.helm.repo.name=
${module_name}.helm.pkg.name=
${module_name}.helm.pkg.version=
${module_name}.release=${module_name}
${module_name}.hostname.main=${module_name}
${module_name}.conf.di.version=${version}
${module_name}.conf.helm.version=${version}
${module_name}.conf.entry.version=${version}
"
}

function dynamics_values_yaml() {
  local module_name
  module_name=$(spinal_to_upper "${1}")
echo "##
{{- if .Values.${module_name} }}
{{- if and .Values.global.dynamics (hasKey .Values.global \"dynamics\")}}
${module_name}:
  dynamics:
    common:
      baseFqdn: {{ .Values.${module_name}.dynamics.common.baseFqdn }}
    main:
      hostname: {{ .Values.${module_name}.dynamics.main.hostname }}
{{- end }}
{{- end }}"
}

function spinal_to_upper() {
  local ans
  IFS=- read -ra str <<<"$1"
  for ((i = 0; i < ${#str[@]}; i++))
  do
    if [ "${i}" -eq 0 ]; then
      ans+="${str[$i]}"
    else
      ans+="${str[$i]^}"
    fi
  done
  echo -n "${ans}"
}

## Set the base directory for RDBOX scripts!!
##
RDBOX_WORKDIR_OF_SCRIPTS_BASE=${RDBOX_WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
RDBOX_WORKDIR_OF_SCRIPTS_BASE=$(printf %q "$RDBOX_WORKDIR_OF_SCRIPTS_BASE")
export RDBOX_WORKDIR_OF_SCRIPTS_BASE=$RDBOX_WORKDIR_OF_SCRIPTS_BASE
  ### EXTRAPOLATION
source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?