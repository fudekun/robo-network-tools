#!/bin/bash
set -euo pipefail

key_dir=$(mktemp -d)
echo "$key_dir"
trap 'rm -rf $key_dir' EXIT
key_file=$key_dir/.source.key

kubectl -n cert-manager get secrets rdbox-selfsigned-ca-cert -o json | jq -r '.data["tls.key"]' | base64 -d > "$key_file"
cat <<EOF | openssl req -new -key "$key_file" -nodes -out kube-api.rdbox.172-16-0-110.nip.io.csr -config /dev/stdin
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = kube-api.rdbox.172-16-0-110.nip.io

[ dn ]
CN = ambassador-kubeapi
C = JP
ST = Tokyo
L = Koto
O = "INTEC Inc."
OU = ATI

[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:FALSE
keyUsage=keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names
EOF

