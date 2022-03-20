#!/bin/bash
set -euo pipefail

__hostname_for_this=$1
__fqdn_this_cluster=$2
__private_key_file=$3

cat <<EOF | openssl req -new -key "$__private_key_file" -nodes -config /dev/stdin
[ req ]
default_bits = 4096
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[ alt_names ]
DNS.1 = $__fqdn_this_cluster
[ req_ext ]
subjectAltName = @alt_names
[ dn ]
CN = $__hostname_for_this
[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:FALSE
keyUsage=keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names
EOF