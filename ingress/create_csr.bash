#!/bin/bash
set -euo pipefail

key_dir=$(mktemp -d)
trap 'rm -rf $key_dir' EXIT

source ./create_common.bash
base_fqdn=$(getBaseFQDN)
this_fqdn=ambassador-kubeapi.$base_fqdn

# Temporarily store the private key (Safety)
crt_file=$this_fqdn.crt
private_key_file=$key_dir/.$this_fqdn.key
csr_file=$key_dir/.$this_fqdn.csr


## References
## https://www.getambassador.io/docs/edge-stack/1.14/howtos/auth-kubectl-keycloak/
##
##
echo ""
echo "---"
echo "Setting UP Authenticate ambassador with Kubernetes API ..."
## 1. Delete the openapi mapping from the Ambassador namespace
##
#kubectl delete -n ambassador ambassador-devportal-api
## 2. private key using root key of this clsters.
##
kubectl -n cert-manager get secrets rdbox-selfsigned-ca-cert -o json | jq -r '.data["tls.key"]' | base64 -d > "$private_key_file"
## 3. Create a file a CNF and a certificate signing request with the CNF file.
## 4. Same as above
##
cat <<EOF | openssl req -new -key "$private_key_file" -nodes -out "$csr_file" -config /dev/stdin
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = $this_fqdn
[ dn ]
CN = ambassador-kubeapi
[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:FALSE
keyUsage=keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names
EOF
## 5. Create and apply the following YAML for a CertificateSigningRequest.
##
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: aes-csr
spec:
  groups:
  - system:authenticated
  request: $(< "$csr_file" base64)
  usages:
  - digital signature
  - key encipherment
  - server auth
  - client auth
EOF
## 6. Confirmation
##
kubectl certificate approve aes-csr
## 7. Get the resulting certificate
##
kubectl get csr aes-csr -o jsonpath='{.status.certificate}' | base64 -d > "$crt_file"
## 8. Create a TLS Secret using our private key and public certificate.
##
kubectl create secret tls -n ambassador aes-kubeapi --cert "$crt_file" --key "$private_key_file"
## 9~10. Create a Mapping and TLSContext and RBAC for the Kube API.
##
< values_for_csr.yaml sed "s/{{YOUR_HOST_NAME}}/$this_fqdn/g" | kubectl apply -f -
## 11. As a quick check
##
sleep 15 & showLoading "During the verification of the RBAC "
if ! curl --cacert "$crt_file" https://"$this_fqdn"/api;
then
  exit 1
fi

exit 0