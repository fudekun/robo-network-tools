#!/bin/bash

NAME_DEFULT_NIC=$(netstat -rn | grep default | grep -v ":" | awk '{print $4}')
export NAME_DEFULT_NIC
# shellcheck disable=SC2015
IP_DEFAULT_NIC=$( (command -v ip &> /dev/null && ip addr show "$NAME_DEFULT_NIC" || ifconfig "$NAME_DEFULT_NIC") | \
                  sed -nEe 's/^[[:space:]]+inet[^[:alnum:]]+([0-9.]+).*$/\1/p')
export IP_DEFAULT_NIC
#HOSTNAME_FOR_WCDNS_BASED_ON_IP=$(echo "$IP_DEFAULT_NIC" | awk -F. '{printf "%02x", $1}{printf "%02x", $2}{printf "%02x", $3}{printf "%02x", $4}')
HOSTNAME_FOR_WCDNS_BASED_ON_IP=${IP_DEFAULT_NIC//\./-}
export HOSTNAME_FOR_WCDNS_BASED_ON_IP