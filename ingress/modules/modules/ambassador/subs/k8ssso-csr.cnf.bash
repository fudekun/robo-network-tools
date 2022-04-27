#!/usr/bin/env bash
set -euo pipefail

#######################################
# Create a CSR in a format accepted by the openssl command
# - CSR=Certificate Signing Request
# Globals:
#   None
# Arguments:
#   hostname (Use as CN: e.g. ambassador-sso)
#   fqdn (Included hostname: e.g. ambassador-sso.rdbox.172-16-0-110.nip.io)
#   fullpath_private_key_file (Your Secret Key: e.g. /hoge/fuge/private.key)
# Outputs:
#   A CSR String (Start with -----BEGIN CERTIFICATE REQUEST-----)
# Returns:
#   0 if thing was created, non-zero on error.
# References:
#   https://www.digicert.com/kb/ssl-support/openssl-quick-reference-guide.htm
#######################################
function main() {
  local hostname fqdn fullpath_private_key_file
  hostname=$1
  fqdn=$2
  fullpath_private_key_file=$3

  cat <<EOF | openssl req -new -key "$fullpath_private_key_file" -nodes -config /dev/stdin
  [ req ]
  default_bits = 2048
  prompt = no
  default_md = sha256
  req_extensions = req_ext
  distinguished_name = dn
  [ req_ext ]
  subjectAltName = @alt_names
  [ alt_names ]
  DNS.1 = "$fqdn"
  [ dn ]
  CN = "$hostname"
  [ v3_ext ]
  authorityKeyIdentifier=keyid,issuer:always
  basicConstraints=CA:FALSE
  keyUsage=keyEncipherment,dataEncipherment
  extendedKeyUsage=clientAuth
  subjectAltName=@alt_names
EOF
  return $?
}

main "${@}"
exit $?