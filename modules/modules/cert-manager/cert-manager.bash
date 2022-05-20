#!/usr/bin/env bash
set -euo pipefail

function showHeaderCommand() {
  echo ""
  echo "---"
  echo "## Installing cert-manager ..."
  return $?
}

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

function main() {
  showHeaderCommand "$@"
  cmdWithIndent "__executor $*"
  verify_string=$(showVerifierCommand)
  echo "${verify_string}" > "$(getFullpathOfVerifyMsgs "cert-manager")"
  return $?
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

function __executor() {
  local __namespace_for_certmanager
  local __hostname_for_certmanager_main
  local __base_fqdn
  local __conf_of_helm
  ## 0. Check Values
  ##
  checkArgs "$@"
  ## 1. Install Cert-Manager
  ##
  echo ""
  echo "### Installing with helm ..."
  __namespace_for_certmanager=$(getNamespaceName "cert-manager")
  readonly __namespace_for_certmanager
  __hostname_for_certmanager_main=$(getHostName "cert-manager" "main")
  readonly __hostname_for_certmanager_main
  __base_fqdn=$(getBaseFQDN)
  readonly __base_fqdn
  __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_certmanager}" confs helm)
  readonly __conf_of_helm
  helm -n "${__namespace_for_certmanager}" upgrade --install "${__hostname_for_certmanager_main}" jetstack/cert-manager \
      --version 1.8.0 \
      --create-namespace \
      --wait \
      --timeout 600s \
      -f "${__conf_of_helm}"
  ## 2. Setup RootCA (You can recycle a previous RootCA certificates (For Developpers))
  ##
  echo ""
  echo "### Setting CA ..."
  __setupSecrets "${__namespace_for_certmanager}" "${__hostname_for_certmanager_main}" "${__base_fqdn}"
    ### NOTE
    ### Use the environment variable "RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT" to switch
    ### between issuing a new certificate or using a past certificate.
  return $?
}

function __setupSecrets() {
  local __namespace_for_certmanager
  local __hostname_for_certmanager_main
  local __base_fqdn
  local __history_file
  readonly __namespace_for_certmanager="${1}"
  readonly __hostname_for_certmanager_main="${2}"
  readonly __base_fqdn="$3"
  __history_file=$(getFullpathOfHistory)
  readonly __history_file
  if [[ "$RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT" == "new" ]]; then
    __issueNewSecrets "${__namespace_for_certmanager}" "${__hostname_for_certmanager_main}" "${__history_file}" "${__base_fqdn}"
  elif [[ "$RDBOX_ESSENTIALS_A_POLICY_TO_ISSUE_CERT" == "recycle" ]]; then
    __issueSecretsUsingExistingHistory "${__namespace_for_certmanager}" "${__hostname_for_certmanager_main}" "${__history_file}"
  else
    echo "Please generate a new RootCA."
    exit 1
  fi
    ### NOTE
    ### ClusterIssuer is namespace independent
    ### However, it depends on selfsigned-cacert
    ###                        -> (Name of $__base_fqdn, like rdbox.rdbox.172-16-0-110.nip.io)
  return $?
}

function __issueNewSecrets() {
  local __namespace_for_certmanager
  local __hostname_for_certmanager_main
  local __history_file
  local __base_fqdn
  local __rootca_file
  readonly __namespace_for_certmanager="${1}"
  readonly __hostname_for_certmanager_main="${2}"
  readonly __history_file="${3}"
  readonly __base_fqdn="${4}"
  applyManifestByDI "${__namespace_for_certmanager}" \
                    "${__hostname_for_certmanager_main}" \
                    "${__RELEASE_ID}" \
                    90s \
                    certManager.dynamics.common.baseFqdn="${__base_fqdn}" \
                    certManager.dynamics.common.isSelfsigned=true \
                    certManager.dynamics.common.isCa=true
    ### NOTE
    ### Can be changed to authenticated secret
  waitForSuccessOfCommand \
    "kubectl -n ${__namespace_for_certmanager} get secrets ${__base_fqdn}"
    ### NOTE
    ### Wait until RootCA is issued
  kubectl -n "${__namespace_for_certmanager}" get secrets "${__base_fqdn}" -o yaml --show-managed-fields \
    | yq 'del(.metadata.uid, .metadata.creationTimestamp, .metadata.resourceVersion, .metadata.managedFields)' \
    > "${__history_file}"
    ### NOTE
    ### Save the History file
  __rootca_file=$(getFullpathOfRootCA)
  readonly __rootca_file
  kubectl -n "${__namespace_for_certmanager}" get secrets "${__base_fqdn}" -o json \
    | jq -r '.data["ca.crt"]' \
    | base64 -d \
    > "${__rootca_file}"
    ### NOTE
    ### Save the RootCA (e.g. outputs/ca/rdbox.172-16-0-110.nip.io.ca.crt)
  return $?
}

function __issueSecretsUsingExistingHistory() {
  local __namespace_for_certmanager
  local __hostname_for_certmanager_main
  local __history_file
  readonly __namespace_for_certmanager="${1}"
  readonly __hostname_for_certmanager_main="${2}"
  readonly __history_file="${3}"
  kubectl -n "${__namespace_for_certmanager}" apply --timeout 90s --wait -f "${__history_file}"
  applyManifestByDI "${__namespace_for_certmanager}" \
                    "${__hostname_for_certmanager_main}" \
                    "${__RELEASE_ID}" \
                    90s \
                    certManager.dynamics.common.baseFqdn="${__base_fqdn}" \
                    certManager.dynamics.common.isCa=true
  return $?
}

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/modules/libs/common.bash"
main "$@"
exit $?