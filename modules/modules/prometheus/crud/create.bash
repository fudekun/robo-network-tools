#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a prometheus
# Globals:
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
  return $?
}

function create() {
  checkArgs "$@"
  if cmdWithIndent "executor $*"; then
    verify_string=$(showVerifierCommand)
    echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "${MODULE_NAME}")"
    return 0
  else
    return 1
  fi
  return $?
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### ${MODULE_NAME} has been installed. Check its status by running:"
  echo "    kubectl -n ${NAMESPACE} get deployments -o wide"
  return $?
}

function executor() {
  if __executor "${@}"; then
    exit 0
  else
    exit 1
  fi
}

function __executor() {
  ## 0. Prepare Helm chart
  ##
  prepare_helm_repo
  ## 1. Create a namespace
  ##
  echo ""
  echo "### Create a namespace of prometheus ..."
  kubectl_r create namespace "${NAMESPACE}"
  ## 2. Install Prometheus
  ##
  echo ""
  echo "### Installing with helm ..."
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
      --version "${HELM_VERSION}" \
      --create-namespace \
      --wait \
      --timeout 600s \
      --description "CREATES_RELEASE_ID=r${CREATES_RELEASE_ID}" \
      --set commonAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set alertmanager.alertmanagerSpec.storage.volumeClaimTemplate.spec.storageClassName="$(getVolumeClass)" \
      --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.storageClassName="$(getVolumeClass)" \
      -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  ## 3. Setup Ingress and TLSContext
  ##
  echo ""
  echo "### Activating the Ingress and TLS ..."
  local hostname port service
  hostname=$(getHostName "${MODULE_NAME}" "main")
  port=$(kubectl -n "${NAMESPACE}" get service "${RELEASE}-kube-prometheus-prometheus" -o json \
    | jq -r '.spec.ports[] | select (.name=="http-web") | .port')
      ### NOTE
      ### {{- define "kube-prometheus-stack.fullname" -}}
      ### {{- $name := default .Chart.Name .Values.nameOverride -}}
      ### {{- printf "%s-%s" .Release.Name $name | trunc 26 | trimSuffix "-" -}}
  service="http://${RELEASE}-kube-prometheus-prometheus.${NAMESPACE}.svc:${port}"
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    180s \
                    prometheus.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    prometheus.dynamics.main.hostname="${hostname}" \
                    prometheus.dynamics.certificate.create="true" \
                    prometheus.dynamics.ingress.create="true" \
                    prometheus.dynamics.ingress.service="${service}"
      ### NOTE
      ### Tentative solution to the problem
      ### that TLSContext is not generated automatically from Ingress (v2.2.2)
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"

