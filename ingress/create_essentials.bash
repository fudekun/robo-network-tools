#!/bin/bash
set -euo pipefail

###############################################################################
## Execute essentials(module) configuration
###############################################################################

## 0. Input Argument Checking
##
checkArgs() {
  printf "Args: %s\n" "$*"
  if [ $# -eq 1 ]; then
    if [ "$1" = "help" ]; then
      echo "# Args"
      echo "None"
      echo ""
      echo "# EnvironmentVariable"
      echo "  (recommend: Use automatic settings)"
      echo "| Name                         | e.g.                            |"
      echo "| ---------------------------- | ------------------------------- |"
      echo "| TYPE_OF_SECRET_OPERATION     | (default)new-rootca or recycle  |"
      exit 1
    else
      __flag_secret_operation=$1
    fi
  fi
  local __base_fqdn
  __base_fqdn=$(getBaseFQDN)
  export BASE_FQDN=$__base_fqdn
  return $?
}

## 1. Initialize
##
initializeEssentials() {
  echo ""
  echo "---"
  echo "## Initializing essentials ..."
  ## 1. Update Helm
  updateHelm
}

## 2. Install Cert-Manager
##
installCertManager() {
  __executor() {
    __issueNewSecrets() {
      local __namespace_for_certmanager="$1"
      local __base_fqdn="$2"
      local __rootca_file
      __rootca_file=$(getFullpathOfRootCA)
      bash ./values_for_cert-manager-rootca.yaml.bash "$__namespace_for_certmanager" "$__base_fqdn"
        ### NOTE
        ### Can be changed to authenticated secret
      watiForSuccessOfCommand \
        "kubectl -n $__namespace_for_certmanager get secrets $__base_fqdn"
        ### NOTE
        ### Wait until RootCA is issued
      kubectl -n "$__namespace_for_certmanager" get secrets "$__base_fqdn" -o yaml > "$__history_file"
        ### NOTE
        ### Save the History file
      kubectl -n "$__namespace_for_certmanager" get secrets "$__base_fqdn" -o json | \
        jq -r '.data["ca.crt"]' | \
        base64 -d > "$__rootca_file"
        ### NOTE
        ### Save the RootCA
      return $?
    }
    __issueSecrets() {
      local __namespace_for_certmanager="$1"
      local __base_fqdn="$2"
      local __history_file
      __history_file=$(getFullpathOfHistory)
      kubectl apply -f values_for_cert-manager-issuer-rootca.yaml
      TYPE_OF_SECRET_OPERATION=${TYPE_OF_SECRET_OPERATION:-"new-rootca"}
      if [ "$TYPE_OF_SECRET_OPERATION" = "new-rootca" ]; then
        __issueNewSecrets "${__namespace_for_certmanager}" "${__base_fqdn}"
      elif [ "$TYPE_OF_SECRET_OPERATION" = "recycle" ]; then
        if [ -e "$__history_file" ]; then
          kubectl -n "$__namespace_for_certmanager" apply -f "$__history_file"
        else
          echo "No history file found. Please generate a new RootCA."
          exit 1
        fi
      else
        echo "Please generate a new RootCA."
        exit 1
      fi
      return $?
    }
    local __namespace_for_certmanager
    local __hostname_for_certmanager_main
    local __base_fqdn
    ## 1. Install Cert-Manager
    ##
    __namespace_for_certmanager=$(getNamespaceName "cert_manager")
    __hostname_for_certmanager_main=$(getHostName "cert_manager" "main")
    __base_fqdn=$(getBaseFQDN)
    echo ""
    echo "### Installing with helm ..."
    helm -n "${__namespace_for_certmanager}" upgrade --install "${__hostname_for_certmanager_main}" jetstack/cert-manager \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f values_for_cert-manager-instance.yaml
    ## 2. Setup RootCA (You can recycle a previous RootCA certificates (For Developpers))
    ##
    echo ""
    echo "### Setting RootCA ..."
    __issueSecrets "${__namespace_for_certmanager}" "${__base_fqdn}"
      ### NOTE
      ### Use the environment variable "TYPE_OF_SECRET_OPERATION" to switch
      ### between issuing a new certificate or using a past certificate.
    ## 3. Setup Specific Issuer
    ##
    echo ""
    echo "### Setting Specific Issuer ..."
    bash ./values_for_cert-manager-issuer-subca.yaml.bash "${__namespace_for_certmanager}" "${__base_fqdn}"
      ### NOTE
      ### ClusterIssuer is namespace independent
      ### However, it depends on selfsigned-cacert
      ###                        -> (Name of $__base_fqdn, like rdbox.rdbox.172-16-0-110.nip.io)
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
  __executor() {
    __getNetworkRangeForVirtualHost() {
      local __docker_network_ip
      local __docker_network_prefix
      local __docker_network_range
      __docker_network_ip=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $1}')
      __docker_network_prefix=$(docker network inspect kind | jq -r ".[].IPAM.Config[].Subnet" | grep -v ":" | awk -F/ '{print $2}')
      if [ "$__docker_network_prefix" -le 16 ]; then
        __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s-%s.%s.%s", $1, $2, "255.200", $1, $2, "255.250"}')
      elif [ "$__docker_network_prefix" -gt 16 ] && [ "$__docker_network_prefix" -le 24 ]; then
        __docker_network_range=$(echo "$__docker_network_ip" | awk -F. '{printf "%s.%s.%s.%s-%s.%s.%s.%s", $1, $2, $3, "200", $1, $2, $3, "250"}')
      else
        echo "WARN: Your Docker network configuration is not expected;"
        echo "- You will need to execute the MetalLB configuration yourself."
        echo "- https://kind.sigs.k8s.io/docs/user/loadbalancer/#setup-address-pool-used-by-loadbalancers"
        exit 1
      fi
      echo -ne "$__docker_network_range"
      return $?
    }
    local __namespace_for_metallb
    local __docker_network_range
    ## 1. Get ConfigValue MetalLB with L2 Mode
    ##
    echo ""
    echo "### Calculating ConfigValue ..."
    __docker_network_range=$(__getNetworkRangeForVirtualHost)
    ## 2. Install MetalLB Instance
    ##
    echo ""
    echo "### Installing with helm ..."
    __namespace_for_metallb=$(getNamespaceName "metallb")
    __hostname_for_metallb_main=$(getHostName "metallb" "main")
    helm -n "${__namespace_for_metallb}" upgrade --install "${__hostname_for_metallb_main}" metallb/metallb \
        --create-namespace \
        --wait \
        --timeout 600s \
        --set configInline.address-pools\[0\].addresses\[0\]="$__docker_network_range" \
        -f values_for_metallb.yaml
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
    local __namespace_for_ambassador
    local __hostname_for_ambassador_main
    local __aes_app_version
    ## 1. Install Ambassador's CRD
    ##
    __namespace_for_ambassador=$(getNamespaceName "ambassador")
    __hostname_for_ambassador_main=$(getHostName "ambassador" "main")
    __aes_app_version=$(curl -s https://api.github.com/repos/emissary-ingress/emissary/releases/latest | jq -r ".tag_name" | cut -b 2-)
    echo ""
    echo "### Activating a CRD of the ambassador ..."
    kubectl apply -f https://app.getambassador.io/yaml/edge-stack/"${__aes_app_version}"/aes-crds.yaml
    kubectl wait --timeout=180s --for=condition=available deployment emissary-apiext -n emissary-system
    ## 2. Install Ambassador Instance
    ##
    echo ""
    echo "### Installing with helm ..."
    helm -n "${__namespace_for_ambassador}" upgrade --install "${__hostname_for_ambassador_main}" edge-stack/edge-stack \
        --create-namespace \
        --wait \
        --timeout 600s \
        -f values_for_ambassador-instance.yaml
    ## 3. Authenticate Ambassador Edge Stack with Kubernetes API
    ##
    ## References
    ## https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
    ##
    ##
    ## 1. Delete the openapi mapping from the Ambassador namespace
    ##
    # if ! bash -c "kubectl delete -n ${__namespace_for_ambassador} ambassador-devportal-api"; then
    #   echo "CRD(ambassador-devportal-api) is Not Found ...ok"
    # fi
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
    bash ./values_for_ambassador-k8ssso-subca.yaml.bash \
        "${__namespace_for_ambassador}" \
        "${__fqdn_for_ambassador_k8ssso}"
    watiForSuccessOfCommand \
      "kubectl -n ${__namespace_for_ambassador} get secrets ${__fqdn_for_ambassador_k8ssso}"
      ### NOTE
      ### Wait until SubCA is issued
    kubectl -n "${__namespace_for_ambassador}" get secrets "${__fqdn_for_ambassador_k8ssso}" -o json | \
        jq -r '.data["tls.key"]' | \
        base64 -d > "${__private_key_file}"
      ### NOTE
      ### As a temporary file to issue CSRs
    ## 3. Create a file a CNF and a certificate signing request with the CNF file.
    ## 4. Same as above
    ##
    echo ""
    echo "### Activating CertificateSigningRequest ..."
    local __csr
    __csr=$(bash ./values_for_ambassador-k8ssso-csr.cnf.bash \
        "${__hostname_for_ambassador_k8ssso}" \
        "${__fqdn_for_ambassador_k8ssso}" \
        "${__private_key_file}" | base64)
    ## 5. Create and apply the following YAML for a CertificateSigningRequest.
    ##
    bash ./values_for_ambassador-k8ssso-csr.yaml.bash \
        "${__hostname_for_ambassador_k8ssso}" \
        "${__csr}"
    ## 6. Confirmation
    ##
    echo ""
    echo "### Approving CertificateSigningRequest ..."
    kubectl certificate approve "${__hostname_for_ambassador_k8ssso}"
    ## 7. Get the resulting certificate
    ##
    echo ""
    echo "### Exporting TLS Secret ..."
    kubectl get csr "${__hostname_for_ambassador_k8ssso}" -o jsonpath="{.status.certificate}" | \
        base64 -d > "${__server_cert_file}"
    ## 8. Create a TLS Secret using our private key and public certificate.
    ##
    kubectl -n "${__namespace_for_ambassador}" create secret tls "${__hostname_for_ambassador_k8ssso}" \
        --cert "${__server_cert_file}" \
        --key "${__private_key_file}"
    ## 9. Create a Mapping and TLSContext and RBAC for the Kube API.
    ## 10. Same as above
    ##
    echo ""
    echo "### Activating k8s SSO Endpoint ..."
    bash ./values_for_ambassador-k8ssso-endpoint.yaml.bash \
        "${__hostname_for_ambassador_k8ssso}" \
        "${__fqdn_for_ambassador_k8ssso}" \
        "${__namespace_for_ambassador}"
    ## 11. As a quick check
    ##
    watiForSuccessOfCommand \
      "curl -fs --cacert ${__server_cert_file} https://${__fqdn_for_ambassador_k8ssso}/api | jq"
      ### NOTE
      ### Wait until to startup the Host
    ## 12. Set Context
    echo ""
    echo "### Setting Cluster Context ..."
    kubectl config set-cluster "$(getContextName4Kubectl)" \
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
    local __base_fqdn
    local __namespace_for_keycloak
    local __hostname_for_keycloak_main
    local __fqdn_for_keycloak_main
    __base_fqdn=$(getBaseFQDN)
    __namespace_for_keycloak=$(getNamespaceName "keycloak")
    __hostname_for_keycloak_main=$(getHostName "keycloak" "main")
    __fqdn_for_keycloak_main=${__hostname_for_keycloak_main}.${__base_fqdn}
    ## 1. Config extra secrets
    ##
    echo ""
    echo "### Setting Config of keycloak ..."
    kubectl create namespace "${__namespace_for_keycloak}"
    kubectl -n "${__namespace_for_keycloak}" create secret generic specific-secrets \
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
    ## 2. Install Keycloak
    ##
    echo ""
    echo "### Installing with helm ..."
    helm -n "${__namespace_for_keycloak}" upgrade --install "${__hostname_for_keycloak_main}" bitnami/keycloak \
      --wait \
      --timeout 600s \
      --set ingress.hostname="${__fqdn_for_keycloak_main}" \
      --set ingress.extraTls\[0\].hosts\[0\]="${__fqdn_for_keycloak_main}" \
      --set ingress.extraTls\[0\].secretName="${__hostname_for_keycloak_main}" \
      --set extraEnvVars\[0\].name=KEYCLOAK_EXTRA_ARGS \
      --set extraEnvVars\[0\].value=-Dkeycloak.frontendUrl=https://"${__fqdn_for_keycloak_main}/auth" \
      -f values_for_keycloak-instance.yaml
    ## 3. Setup TLSContext
    ##
    echo ""
    echo "### Activating the TLSContext ..."
    bash ./values_for_tlscontext.yaml.bash \
      "${__namespace_for_keycloak}" \
      "${__fqdn_for_keycloak_main}"
        ### NOTE
        ### Tentative solution to the problem
        ### that TLSContext is not generated automatically from Ingress (v2.2.2)
    watiForSuccessOfCommand \
      "kubectl -n ${__namespace_for_keycloak} get secrets ${__hostname_for_keycloak_main}"
        ### NOTE
        ### Wait until SubCA is issued
    local __rootca_file
    __rootca_file=$(getFullpathOfRootCA)
    echo ""
    echo "### Testing to access the endpoint ..."
    watiForSuccessOfCommand \
      "curl -fs --cacert ${__rootca_file} https://${__fqdn_for_keycloak_main}/auth/ >/dev/null 2>&1"
    ## 4. Setup preset-entries
    ##
    echo ""
    echo "### Activating essential entries of the keycloak ..."
    bash ./create_keycloak-entry.bash "${__namespace_for_keycloak}" "${__rootca_file}"
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
    bash ./values_for_ambassador-k8ssso-filter.yaml.bash \
        "${__hostname_for_ambassador_k8ssso}" \
        "${__fqdn_for_ambassador_k8ssso}" \
        "${__namespace_for_ambassador}" \
        "${__jwks_uri}"
    ## 2. Set Context
    ##
    local __ctx_name
    __ctx_name=$(getContextName4Kubectl)
    echo "Setting Cluster Context ..."
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
  drawMaxColsSeparator "#" "32"
  echo -e "\033[32mSUCCESS Termination\033[m"
  echo -e "\033[32mUsage:\033[m"
  echo ""
  echo "---"
  echo "## Trust CA with your browser and operating system. Check its file:"
  echo "  openssl x509 -in ${__rootca_file} -text"
  echo "  ---"
  echo "  ### This information is for reference to trust The CA file:"
  echo "    (Windows) https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores"
  echo "    (MacOS  ) https://support.apple.com/guide/keychain-access/kyca2431/mac"
  echo "    (Ubuntu ) https://ubuntu.com/server/docs/security-trust-store"
  # echo ""
  # echo "---""
  cat ./"${__namespace_for_keycloak}".verifier_command.txt
  # echo ""
  echo ""
  echo "---"
  echo "## Execute the following command to run kubectl with single sign-on:"
  echo "  ### Execute the following command"
  echo "  ### This will open your default browser, and execute the login operation"
  echo "  kubectl config use-context ${__ctx_name}"
  echo "  kubectl get node          # whatever is okay, just choose the one you like"
  echo ""
  drawMaxColsSeparator "#" "32"
  return $?
}

main() {
  ## 0. Input Argument Checking
  ##
  checkArgs "$@"
  ## 1. Initializing
  ##
  initializeEssentials "$@"
  ## 2. Install Cert-Manager
  ##
  cmdWithLoding \
    "installCertManager" \
    "Activating cert-manager"
  ## 3. Install MetalLB
  ##
  cmdWithLoding \
    "installMetalLB" \
    "Activating metallb"
  ## 4. Install Ambassador
  ##
  cmdWithLoding \
    "installAmbassador" \
    "Activating ambassador"
  ## 5. Install Keycloak
  ##
  cmdWithLoding \
    "installKeycloak" \
    "Activating keycloak"
  ## 6. Install Filter
  ##
  cmdWithLoding \
    "installFilter" \
    "Activating filter"
  ## 99. Notify Verifier-Command
  ##
  showVerifierCommand
  return $?
}

TEMP_DIR=$(mktemp -d)
trap 'rm -rf $TEMP_DIR' EXIT

## Set the base directory for RDBOX scripts!!
##
export WORKDIR_OF_SCRIPTS_BASE=${WORKDIR_OF_SCRIPTS_BASE:-$(cd "$(dirname "$0")"; pwd)}
  # Values can also be inserted externally
source "${WORKDIR_OF_SCRIPTS_BASE}/create_common.bash"
showHeader
main "$@"
exit $?