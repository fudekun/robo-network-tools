#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Activating a cert-manager
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
  RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT=${RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT:-"new"}
  if [[ "${RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT}" == "new" || "${RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT}" == "recycle" ]]; then
    readonly RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT=$RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT
  else
    echo "**ERROR**  Invalid Environment Variable (RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT)" >&2
    echo "  - Expect: new|recycle" >&2
    echo "  - Actual: ${RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT}" >&2
    return 1
  fi
  if [[ "${RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT}" == "recycle" ]]; then
    if [ ! -e "$(getFullpathOfHistory)" ]; then
      echo "**ERROR**  No history file found. Please generate a new RootCA." >&2
      echo "  - Expect: Unset Environment Variable (RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT)" >&2
      return 1
    fi
  fi
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
}

function showVerifierCommand() {
  echo ""
  echo "## USAGE"
  echo "### Trust CA with your browser and operating system. Check its file:"
  echo "    openssl x509 -in $(getFullpathOfRootCA) -text"
  echo "  ### This information is for reference to trust The CA file:"
  echo "    (Windows) https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores"
  echo "    (MacOS  ) https://support.apple.com/guide/keychain-access/kyca2431/mac"
  echo "    (Ubuntu ) https://ubuntu.com/server/docs/security-trust-store"
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
  ## 1. Install Cert-Manager
  ##
  echo ""
  echo "### Installing with helm ..."
  helm -n "${NAMESPACE}" upgrade --install "${RELEASE}" "${HELM_NAME}" \
      --version "${HELM_VERSION}" \
      --create-namespace \
      --wait \
      --timeout 600s \
      --description "CREATES_RELEASE_ID=r${CREATES_RELEASE_ID}" \
      --set serviceAccount.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set podAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set deploymentAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set serviceAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set webhook.podAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set webhook.deploymentAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set webhook.serviceAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set webhook.serviceAccount.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set cainjector.podAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set cainjector.deploymentAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set cainjector.serviceAccount.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set startupapicheck.jobAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set startupapicheck.podAnnotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      --set startupapicheck.serviceAccount.annotations."rdbox\.local/release"="r${CREATES_RELEASE_ID}" \
      -f "$(getFullpathOfValuesYamlBy "${NAMESPACE}" confs helm)"
  ## 2. Setup RootCA (You can recycle a previous RootCA certificates (For Developpers))
  ##
  echo ""
  echo "### Setting CA ..."
  if [[ "$RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT" == "new" ]]; then
    __issueNewSecrets
  elif [[ "$RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT" == "recycle" ]]; then
    __issueSecretsUsingExistingHistory
  else
    echo "Please generate a new RootCA."
    exit 1
  fi
    ### NOTE
    ### Use the environment variable "RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT" to switch
    ### between issuing a new certificate or using a past certificate.
  return $?
}

function __issueNewSecrets() {
  local __rootca_file
  local __history_file
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    certManager.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    certManager.dynamics.isSelfsigned.create="true" \
                    certManager.dynamics.isCa.create="true"
    ### NOTE
    ### Can be changed to authenticated secret
  waitForSuccessOfCommand \
    "kubectl -n ${NAMESPACE} get secrets ${BASE_FQDN}"
    ### NOTE
    ### Wait until RootCA is issued
  __history_file=$(getFullpathOfHistory)
  readonly __history_file
  kubectl -n "${NAMESPACE}" get secrets "${BASE_FQDN}" -o yaml --show-managed-fields \
    | yq 'del(.metadata.uid, .metadata.creationTimestamp, .metadata.resourceVersion, .metadata.managedFields)' \
    > "${__history_file}"
    ### NOTE
    ### Save the History file
  __rootca_file=$(getFullpathOfRootCA)
  readonly __rootca_file
  kubectl -n "${NAMESPACE}" get secrets "${BASE_FQDN}" -o json \
    | jq -r '.data["ca.crt"]' \
    | base64 -d \
    > "${__rootca_file}"
    ### NOTE
    ### Save the RootCA (e.g. outputs/ca/rdbox.172-16-0-110.nip.io.ca.crt)
  return $?
}

function __issueSecretsUsingExistingHistory() {
  local __history_file
  __history_file=$(getFullpathOfHistory)
  readonly __history_file
  kubectl -n "${NAMESPACE}" apply --timeout 90s --wait -f "${__history_file}"
  applyManifestByDI "${NAMESPACE}" \
                    "${RELEASE}" \
                    "${CREATES_RELEASE_ID}" \
                    90s \
                    certManager.dynamics.common.baseFqdn="${BASE_FQDN}" \
                    certManager.dynamics.isCa.create="true"
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"