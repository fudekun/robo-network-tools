#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a ambassador
# Globals:
#   MODULE_NAME
#   NAMESPACE
#   RELEASE
#   HELM_NAME
#   HELM_VERSION
#   RDBOX_WORKDIR_OF_SCRIPTS_BASE
#   CREATES_RELEASE_ID
#
# Style: https://google.github.io/styleguide/shellguide.html
###############################################################################

function checkArgs() {
  return $?
}

function create() {
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### ambassador has been installed. Check its status by running:"
  echo "    kubectl -n ${NAMESPACE} get deployments  -o wide"
  return $?
}

function __executor() {
  ## 0. Prepare Helm chart
  ##
  prepare_helm_repo
  ## 1. Install ambassador
  ##
  echo ""
  echo "### Create a ambassador ..."
  create_main
  return $?
}

function create_main() {
  ## 1. Define the app version
  ##
  local __app_version
  __app_version=$(curl -s "https://artifacthub.io/api/v1/packages/helm/${HELM_NAME}/${HELM_VERSION}" \
                | jq -r ".app_version")
  ## 2. Preparation
  ##
  ### .1 cert
  ###
  echo ""
  echo "### ((Because of to install Self-Signed Cert)) Pre-Build the image of ambassador ..."
  sudo docker build \
      --build-arg IMAGE_VERSION="${__app_version}" \
      --build-arg FILENAME_ROOT_CA="${BASE_FQDN}.ca.crt" \
      -t docker.io/datawire/aes:"${__app_version}" \
      -f "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/modules/${MODULE_NAME}/subs/docker/Dockerfile" \
      "$(getDirNameFor outputs)"/ca > /dev/null 2>&1
  sudo kind load docker-image docker.io/datawire/aes:"${__app_version}" \
      --name "$(getClusterName)" > /dev/null 2>&1
  ### .2 CRDs
  ###
  echo ""
  echo "### Activating a CRD of the ambassador ..."
  kubectl_r apply -f https://app.getambassador.io/yaml/edge-stack/"${__app_version}"/aes-crds.yaml
  kubectl wait --timeout=180s --for=condition=available deployment emissary-apiext -n emissary-system
  ## 3. Install Ambassador Instance
  ##
  echo ""
  echo "### Installing with helm ..."
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
      --version "${HELM_VERSION}" \
      --create-namespace \
      --wait \
      --timeout 600s \
      --description "CREATES_RELEASE_ID=r${CREATES_RELEASE_ID}" \
      --set emissary-ingress.service.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set emissary-ingress.adminService.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set emissary-ingress.podAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set emissary-ingress.deploymentAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set emissary-ingress.service.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set emissary-ingress.adminService.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set redis.annotations.deployment."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set redis.annotations.service."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"