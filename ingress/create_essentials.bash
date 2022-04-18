#!/bin/bash
set -euo pipefail

###############################################################################
## Execute essentials(module) configuration
###############################################################################

## 0. Input Argument Checking
##
checkArgs() {
  echo ""
  printf "# ARGS:\n%s\n" "$*"
  printf "# ENVS:\n%s\n" "$(export | grep RDBOX | sed 's/^declare -x /  - /')"
  echo ""
  if [[ $# -eq 1 ]]; then
    if [[ "$1" == "help" ]]; then
      echo "# Args"
      echo "None"
      echo ""
      echo "# EnvironmentVariable"
      echo "  (recommend: Use automatic settings)"
      echo "| Name                               | e.g.                            |"
      echo "| ---------------------------------- | ------------------------------- |"
      echo "| RDBOX_TYPE_OF_SECRET_OPERATION     | (default)new or recycle         |"
      return 1
    fi
  fi
  local __epoch_ms
  __epoch_ms=$(getEpochMillisec)
  readonly __RELEASE_ID=${__epoch_ms}
  return $?
}

## 1. Initialize
##
initializeEssentials() {
  __executor() {
    local __workdir_of_confs
    ## 1. Update Helm
    ##
    echo ""
    echo "### Updateing Helm ..."
    helm repo update
    ## 2. Set up a ConfigMap for the meta-pkg of essentials
    ##
    echo ""
    echo "### Setting a ConfigMap for the meta-pkg of essentials ..."
    __workdir_of_confs=$(getDirNameFor confs)
    readonly __workdir_of_confs
    kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" patch configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
      --type merge \
      --patch "$(kubectl -n "${__RDBOX_CLUSTER_INFO_NAMESPACE}" create configmap "${__RDBOX_CLUSTER_INFO_NAMENAME}" \
                  --dry-run=client \
                  --output=json \
                  --from-env-file="${__workdir_of_confs}"/meta-pkgs/essentials.env.properties \
                )"
    return $?
  }
  echo ""
  echo "---"
  echo "## Initializing essentials ..."
  cmdWithIndent "__executor"
  return $?
}

## 2. Install Cert-Manager
##
installCertManager() {
  __issueNewSecrets() {
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
  __issueSecretsUsingExistingHistory() {
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
  __setupSecrets() {
    local __namespace_for_certmanager
    local __hostname_for_certmanager_main
    local __base_fqdn
    local __history_file
    readonly __namespace_for_certmanager="${1}"
    readonly __hostname_for_certmanager_main="${2}"
    readonly __base_fqdn="$3"
    __history_file=$(getFullpathOfHistory)
    readonly __history_file
    if [[ "$RDBOX_TYPE_OF_SECRET_OPERATION" == "new" ]]; then
      __issueNewSecrets "${__namespace_for_certmanager}" "${__hostname_for_certmanager_main}" "${__history_file}" "${__base_fqdn}"
    elif [[ "$RDBOX_TYPE_OF_SECRET_OPERATION" == "recycle" ]]; then
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
  checkArgs() {
    RDBOX_TYPE_OF_SECRET_OPERATION=${RDBOX_TYPE_OF_SECRET_OPERATION:-"new"}
    if [[ "${RDBOX_TYPE_OF_SECRET_OPERATION}" == "new" || "${RDBOX_TYPE_OF_SECRET_OPERATION}" == "recycle" ]]; then
      readonly RDBOX_TYPE_OF_SECRET_OPERATION=$RDBOX_TYPE_OF_SECRET_OPERATION
    else
      echo "**ERROR**  Invalid Environment Variable (RDBOX_TYPE_OF_SECRET_OPERATION)" >&2
      echo "  - Expect: new|recycle" >&2
      echo "  - Actual: ${RDBOX_TYPE_OF_SECRET_OPERATION}" >&2
      return 1
    fi
    if [[ "${RDBOX_TYPE_OF_SECRET_OPERATION}" == "recycle" ]]; then
      if [ ! -e "$(getFullpathOfHistory)" ]; then
        echo "**ERROR**  No history file found. Please generate a new RootCA." >&2
        echo "  - Expect: Unset Environment Variable (RDBOX_TYPE_OF_SECRET_OPERATION)" >&2
        return 1
      fi
    fi
  }
  __executor() {
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
      ### Use the environment variable "RDBOX_TYPE_OF_SECRET_OPERATION" to switch
      ### between issuing a new certificate or using a past certificate.
    return $?
  }
  echo ""
  echo "---"
  echo "## Installing cert-manager ..."
  cmdWithIndent "__executor"
  return $?
}

## 3. Install MetalLB
##
installMetalLB() {
  __getNetworkRangeForVirtualHost() {
    local __docker_network_ip
    local __docker_network_prefix
    local __docker_network_range
    __docker_network_ip=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $1}')
    __docker_network_prefix=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $2}')
    if [[ "$__docker_network_prefix" -le 16 ]]; then
      __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s-%s.%s.%s", $1, $2, "255.200", $1, $2, "255.250"}')
    elif [[ "$__docker_network_prefix" -gt 16 ]] && [[ "$__docker_network_prefix" -le 24 ]]; then
      __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s.%s-%s.%s.%s.%s", $1, $2, $3, "200", $1, $2, $3, "250"}')
    else
      echo "WARN: Your Docker network configuration is not expected;"
      echo "- You will need to execute the MetalLB configuration yourself."
      echo "- https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
      return 1
    fi
    echo -n "$__docker_network_range"
    return $?
  }
  __executor() {
    local __namespace_for_metallb
    local __hostname_for_metallb_main
    local __docker_network_range
    local __conf_of_helm
    ## 1. Install MetalLB Instance
    ##
    echo ""
    echo "### Installing with helm ..."
    __namespace_for_metallb=$(getNamespaceName "metallb")
    __hostname_for_metallb_main=$(getHostName "metallb" "main")
    __docker_network_range=$(__getNetworkRangeForVirtualHost)
      ### NOTE
      ### Get ConfigValue MetalLB with L2 Mode
    __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_metallb}" confs helm)
    helm -n "${__namespace_for_metallb}" upgrade --install "${__hostname_for_metallb_main}" metallb/metallb \
        --create-namespace \
        --wait \
        --timeout 600s \
        --set configInline.address-pools\[0\].addresses\[0\]="${__docker_network_range}" \
        -f "${__conf_of_helm}"
    return $?
  }
  echo ""
  echo "---"
  echo "## Installing metallb ..."
  cmdWithIndent "__executor"
  return $?
}

## 4. Install Ambassador
##
installAmbassador() {
  __executor() {
    local __aes_app_version
    local __namespace_for_ambassador
    local __hostname_for_ambassador_main
    local __conf_of_helm
    ## 1. Install Ambassador's CRD
    ##
    echo ""
    echo "### Activating a CRD of the ambassador ..."
    __aes_app_version=$(curl -s https://api.github.com/repos/emissary-ingress/emissary/releases/latest \
                      | jq -r ".tag_name" \
                      | cut -b 2-)
    kubectl apply -f https://app.getambassador.io/yaml/edge-stack/"${__aes_app_version}"/aes-crds.yaml
    kubectl wait --timeout=180s --for=condition=available deployment emissary-apiext -n emissary-system
    ## 2. Install Ambassador Instance
    ##
    echo ""
    echo "### Installing with helm ..."
    __namespace_for_ambassador=$(getNamespaceName "ambassador")
    __hostname_for_ambassador_main=$(getHostName "ambassador" "main")
    __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_ambassador}" confs helm)
    helm -n "${__namespace_for_ambassador}" upgrade --install "${__hostname_for_ambassador_main}" edge-stack/edge-stack \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f "${__conf_of_helm}"
    ## 3. Authenticate Ambassador Edge Stack with Kubernetes API
    ##
    ## References
    ## https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
    ##
    ##
    ## 1. Delete the openapi mapping from the Ambassador namespace
    ##
    if ! kubectl delete -n "${__namespace_for_ambassador}" ambassador-devportal-api 2>/dev/null; then
      echo "The openapi-mapping(ambassador-devportal-api) is Not Found ...ok"
    fi
    ## 2. private key using root key of this clsters.
    ##
    local __base_fqdn
    local __hostname_for_ambassador_k8ssso
    local __fqdn_for_ambassador_k8ssso
    local __private_key_file
    local __server_cert_file
    __base_fqdn=$(getBaseFQDN)
    __hostname_for_ambassador_k8ssso=$(getHostName "ambassador" "k8ssso")
    __fqdn_for_ambassador_k8ssso=${__hostname_for_ambassador_k8ssso}.${__base_fqdn}
    __private_key_file=${TEMP_DIR}/${__hostname_for_ambassador_k8ssso}.key
    __server_cert_file=${TEMP_DIR}/${__hostname_for_ambassador_k8ssso}.crt
    echo ""
    echo "### Issueing Private Key for ambassador ..."
    applyManifestByDI "${__namespace_for_ambassador}" \
                      "${__hostname_for_ambassador_k8ssso}" \
                      "${__RELEASE_ID}" \
                      90s \
                      ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                      ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                      ambassador.dynamics.k8ssso.certificate.useCa=true
    waitForSuccessOfCommand \
      "kubectl -n ${__namespace_for_ambassador} get secrets ${__fqdn_for_ambassador_k8ssso}"
      ### NOTE
      ### Wait until SubCA is issued
    kubectl -n "${__namespace_for_ambassador}" get secrets "${__fqdn_for_ambassador_k8ssso}" -o json \
        | jq -r '.data["tls.key"]' \
        | base64 -d \
        > "${__private_key_file}"
      ### NOTE
      ### As a temporary file to issue CSRs
    ## 3. Create a file a CNF and a certificate signing request with the CNF file.
    ## 4. Same as above
    ##
    echo ""
    echo "### Activating CertificateSigningRequest ..."
    local __csr
    __csr=$(bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_ambassador-k8ssso-csr.cnf.bash" \
        "${__hostname_for_ambassador_k8ssso}" \
        "${__fqdn_for_ambassador_k8ssso}" \
        "${__private_key_file}" | base64)
    ## 5. Create and apply the following YAML for a CertificateSigningRequest.
    ##
    applyManifestByDI "${__namespace_for_ambassador}" \
                      "${__hostname_for_ambassador_k8ssso}" \
                      "${__RELEASE_ID}" \
                      180s \
                      ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                      ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                      ambassador.dynamics.k8ssso.certificateSigningRequest.request="${__csr}"
    ## 6. Confirmation
    ##
    echo ""
    echo "### Approving CertificateSigningRequest ..."
    kubectl certificate approve "${__hostname_for_ambassador_k8ssso}"
    ## 7. Get the resulting certificate
    ##
    echo ""
    echo "### Exporting TLS Secret ..."
    kubectl get csr "${__hostname_for_ambassador_k8ssso}" -o jsonpath="{.status.certificate}" \
        | base64 -d \
        > "${__server_cert_file}"
    ## 8. Create a TLS Secret using our private key and public certificate.
    ##
    if ! kubectl -n "${__namespace_for_ambassador}" delete secret "${__hostname_for_ambassador_k8ssso}" 2>/dev/null; then
      echo "The secret(${__hostname_for_ambassador_k8ssso}.${__namespace_for_ambassador}) is Not Found ...ok"
    fi
    kubectl -n "${__namespace_for_ambassador}" create secret tls "${__hostname_for_ambassador_k8ssso}" \
        --cert "${__server_cert_file}" \
        --key "${__private_key_file}"
    ## 9. Create a Mapping and TLSContext and RBAC for the Kube API.
    ## 10. Same as above
    ##
    echo ""
    echo "### Activating k8s SSO Endpoint ..."
    applyManifestByDI "${__namespace_for_ambassador}" \
                      "${__hostname_for_ambassador_k8ssso}" \
                      "${__RELEASE_ID}" \
                      180s \
                      ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                      ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                      ambassador.dynamics.k8ssso.endpoint.rbac.create=true
    ## 11. As a quick check
    ##
    if kubectl -n "${__namespace_for_ambassador}" get filters "${__hostname_for_ambassador_k8ssso}" 2>/dev/null; then
      echo "already exist the filters (${__hostname_for_ambassador_k8ssso}.${__namespace_for_ambassador}) ...ok"
      echo "skip a quick check ...ok"
    else
      echo "The filters(${__hostname_for_ambassador_k8ssso}.${__namespace_for_ambassador}) is Not Found ...ok"
      waitForSuccessOfCommand \
        "curl -fs --cacert ${__server_cert_file} https://${__fqdn_for_ambassador_k8ssso}/api | jq"
    fi
      ### NOTE
      ### Wait until to startup the Host
    ## 12. Set Context
    echo ""
    echo "### Setting Cluster Context ..."
    local __ctx_name
    __ctx_name=$(getContextName4Kubectl)
    if ! kubectl config delete-cluster "${__ctx_name}" 2>/dev/null; then
      echo "The ClusterContext(cluster) is Not Found ...ok"
    fi
    kubectl config set-cluster "${__ctx_name}" \
        --server=https://"${__fqdn_for_ambassador_k8ssso}" \
        --certificate-authority="${__server_cert_file}" \
        --embed-certs
    return $?
  }
  echo ""
  echo "---"
  echo "## Installing ambassador ..."
  cmdWithIndent "__executor"
  return $?
}

## 5. Install Keycloak
##
installKeycloak() {
  __executor() {
    local __SPECIFIC_SECRETS="specific-secrets"
    local __namespace_for_keycloak
    local __base_fqdn
    local __hostname_for_keycloak_main
    local __fqdn_for_keycloak_main
    local __cluster_issuer
    local __conf_of_helm
    local __rootca_file
    local __http_code
    ## 1. Config extra secrets
    ##
    echo ""
    echo "### Setting Config of keycloak ..."
    __namespace_for_keycloak=$(getNamespaceName "keycloak")
    if ! kubectl create namespace "${__namespace_for_keycloak}" 2>/dev/null; then
      echo "already exist the namespace (${__namespace_for_keycloak}) ...ok"
    fi
    if kubectl -n "${__namespace_for_keycloak}" get secret "${__SPECIFIC_SECRETS}"; then
      echo "already exist the secrets (${__SPECIFIC_SECRETS}.${__namespace_for_keycloak}) ...ok"
    else
      kubectl -n "${__namespace_for_keycloak}" create secret generic "${__SPECIFIC_SECRETS}" \
        --from-literal=admin-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
        --from-literal=management-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
        --from-literal=postgresql-postgres-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
        --from-literal=postgresql-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
        --from-literal=tls-keystore-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
        --from-literal=tls-truestore-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
        --from-literal=k8s-default-cluster-admin-password="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')" \
        --from-literal=k8s-default-cluster-sso-aes-secret="$(openssl rand -base64 32 | sed -e 's/\+/\@/g')"
          ### NOTE
          ### The postgresql-postgres-password is password for root user
          ### The postgresql-password is password for the unprivileged user
          ### The k8s-default-cluster-sso-aes-secret is used for K8s SSO via ambassador
    fi
    ## 2. Install Keycloak
    ##
    echo ""
    echo "### Installing with helm ..."
    __base_fqdn=$(getBaseFQDN)
    __hostname_for_keycloak_main=$(getHostName "keycloak" "main")
    __fqdn_for_keycloak_main=${__hostname_for_keycloak_main}.${__base_fqdn}
    __cluster_issuer=cluster-issuer-ca."${__base_fqdn}"
    __conf_of_helm=$(getFullpathOfValuesYamlBy "${__namespace_for_keycloak}" confs helm)
    helm -n "${__namespace_for_keycloak}" upgrade --install "${__hostname_for_keycloak_main}" bitnami/keycloak \
      --create-namespace \
      --wait \
      --timeout 600s \
      --set ingress.hostname="${__fqdn_for_keycloak_main}" \
      --set ingress.extraTls\[0\].hosts\[0\]="${__fqdn_for_keycloak_main}" \
      --set ingress.annotations."cert-manager\.io/cluster-issuer"="${__cluster_issuer}" \
      --set ingress.extraTls\[0\].secretName="${__hostname_for_keycloak_main}" \
      --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
      --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://"${__fqdn_for_keycloak_main}/auth" \
      -f "${__conf_of_helm}"
    ## 3. Setup TLSContext
    ##
    echo ""
    echo "### Activating the TLSContext ..."
    applyManifestByDI "${__namespace_for_keycloak}" \
                      "${__hostname_for_keycloak_main}" \
                      "${__RELEASE_ID}" \
                      180s \
                      keycloak.dynamics.common.baseFqdn="${__base_fqdn}" \
                      keycloak.dynamics.main.hostname="${__hostname_for_keycloak_main}" \
                      keycloak.dynamics.main.tlsContext.create=true
        ### NOTE
        ### Tentative solution to the problem
        ### that TLSContext is not generated automatically from Ingress (v2.2.2)
    waitForSuccessOfCommand \
      "kubectl -n ${__namespace_for_keycloak} get secrets ${__hostname_for_keycloak_main}"
        ### NOTE
        ### Wait until SubCA is issued
    echo ""
    echo "### Testing to access the endpoint ..."
    __rootca_file=$(getFullpathOfRootCA)
    __http_code=$(waitForSuccessOfCommand \
                "curl -fs -w '%{http_code}' -o /dev/null --cacert ${__rootca_file} https://${__fqdn_for_keycloak_main}/auth/")
    echo "The HTTP Status is ${__http_code} ...ok"
      ### NOTE
      ### Use the RootCA (e.g. outputs/ca/rdbox.172-16-0-110.nip.io.ca.crt)
    ## 4. Setup preset-entries
    ##
    echo ""
    echo "### Activating essential entries of the keycloak ..."
    bash "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_keycloak-entry.bash" \
      "${__namespace_for_keycloak}" \
      "${__rootca_file}"
    ## 5. Setup Authz
    ##
    echo ""
    echo "### Setup the sample RBAC ..."
    applyManifestByDI "${__namespace_for_keycloak}" \
                      "${__hostname_for_keycloak_main}" \
                      "${__RELEASE_ID}" \
                      180s \
                      keycloak.dynamics.common.baseFqdn="${__base_fqdn}" \
                      keycloak.dynamics.main.hostname="${__hostname_for_keycloak_main}" \
                      keycloak.dynamics.main.rbac.create=true
    return $?
  }
  echo ""
  echo "---"
  echo "## Installing keycloak ..."
  cmdWithIndent "__executor"
  return $?
}

## 6. Install Filter
##
installFilter() {
  __executor() {
    local __base_fqdn
    __base_fqdn=$(getBaseFQDN)
    local __namespace_for_keycloak
    __namespace_for_keycloak=$(getNamespaceName "keycloak")
    local __hostname_for_keycloak_main
    __hostname_for_keycloak_main=$(getHostName "keycloak" "main")
    local __cluster_name
    __cluster_name=$(getClusterName)
      # rdbox
    local __namespace_for_ambassador
      # ambassador
    local __hostname_for_ambassador_k8ssso
      # ambassador-k8ssso
    local __fqdn_for_ambassador_k8ssso=${__hostname_for_ambassador_k8ssso}.${__base_fqdn}
      # ambassador-k8ssso.rdbox.172-16-0-110.nip.io
    local __fqdn_for_keycloak_main=${__namespace_for_keycloak}.${__base_fqdn}
      # keycloak.rdbox.172-16-0-110.nip.io
    local __jwks_uri=http://${__hostname_for_keycloak_main}.${__namespace_for_keycloak}/auth/realms/${__cluster_name}/protocol/openid-connect/certs
      # https://keycloak.rdbox.172-16-0-110.nip.io/auth/realms/rdbox/protocol/openid-connect/certs
    __namespace_for_ambassador=$(getNamespaceName "ambassador")
    __hostname_for_ambassador_k8ssso=$(getHostName "ambassador" "k8ssso")
    ## 1. Install Filter
    ##
    echo ""
    echo "### Applying the filter for Impersonate-Group/User ..."
    applyManifestByDI "${__namespace_for_ambassador}" \
                      "${__hostname_for_ambassador_k8ssso}" \
                      "${__RELEASE_ID}" \
                      180s \
                      ambassador.dynamics.common.baseFqdn="${__base_fqdn}" \
                      ambassador.dynamics.k8ssso.hostname="${__hostname_for_ambassador_k8ssso}" \
                      ambassador.dynamics.k8ssso.filter.jwksUri="${__jwks_uri}"
    ## 2. Set Context
    ##
    local __ctx_name
    __ctx_name=$(getContextName4Kubectl)
    echo ""
    echo "### Setting Cluster Context ..."
    if ! kubectl config delete-context "${__ctx_name}"; then
      echo "The ClusterContext(context) is Not Found ...ok"
    fi
    kubectl config set-context "${__ctx_name}" \
        --cluster="${__ctx_name}" \
        --user="${__ctx_name}"
    return $?
  }
  echo ""
  echo "---"
  echo "## Installing filter ..."
  cmdWithIndent "__executor"
  return $?
}

## 99. Notify Verifier-Command
##
showVerifierCommand() {
  local __ctx_name
  local __rootca_file
  local __namespace_for_keycloak
  __ctx_name=$(getContextName4Kubectl)
  __rootca_file=$(getFullpathOfRootCA)
  __namespace_for_keycloak=$(getNamespaceName "keycloak")
  echo ""
  echo "# USAGE"
  echo "## Trust CA with your browser and operating system. Check its file:"
  echo "  openssl x509 -in ${__rootca_file} -text"
  echo "  ---"
  echo "  ### This information is for reference to trust The CA file:"
  echo "    (Windows) https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores"
  echo "    (MacOS  ) https://support.apple.com/guide/keychain-access/kyca2431/mac"
  echo "    (Ubuntu ) https://ubuntu.com/server/docs/security-trust-store"
  # echo ""
  cat "$(getFullpathOfVerifyMsgs "${__namespace_for_keycloak}")"
  # echo ""
  echo ""
  echo "# USAGE"
  echo "## Execute the following command to run kubectl with single sign-on:"
  echo "  ### Execute the following command"
  echo "  ### Your default browser will launch and you should perform the login operation"
  echo "  kubectl config use-context ${__ctx_name}"
  echo "  kubectl get node          # whatever is okay, just choose the one you like"
  echo ""
  echo "# SUCCESS"
  echo "[$(getIso8601DayTime)][$(basename "$0")]"
  drawMaxColsSeparator "*" "39"
  return $?
}

main() {
  ## 0. Input Argument Checking
  ##
  checkArgs "$@"
  ## 1. Initializing
  ##
  cmdWithLoding \
    "initializeEssentials" \
    "Initializing the meta-pkgs of essentials"
  ## 2. Install Cert-Manager
  ##
  cmdWithLoding \
    "installCertManager" \
    "Activating the cert-manager"
  ## 3. Install MetalLB
  ##
  cmdWithLoding \
    "installMetalLB" \
    "Activating the metallb"
  ## 4. Install Ambassador
  ##
  cmdWithLoding \
    "installAmbassador" \
    "Activating the ambassador"
  ## 5. Install Keycloak
  ##
  cmdWithLoding \
    "installKeycloak" \
    "Activating the keycloak"
  ## 6. Install Filter
  ##
  cmdWithLoding \
    "installFilter" \
    "Activating the filter"
  ## 99. Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

TEMP_DIR=$(mktemp -d)
trap 'rm -rf $TEMP_DIR' EXIT

source "${RDBOX_WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
main "$@"
exit $?