#!/bin/bash

showLoading() {
  mypid=$!
  loadingText=$1

  echo -ne "$loadingText\r"

  while kill -0 $mypid 2>/dev/null; do
    echo -ne "$loadingText.\r"
    sleep 0.5
    echo -ne "$loadingText..\r"
    sleep 0.5
    echo -ne "$loadingText...\r"
    sleep 0.5
    echo -ne "\r\033[K"
    echo -ne "$loadingText\r"
    sleep 0.5
  done
  wait $mypid
  st=$?
  echo "$loadingText...FINISHED"
  return "$st"
}

getNetworkInfo() {
  NAME_DEFULT_NIC=$(netstat -rn | grep default | grep -v ":" | awk '{print $4}')
  export NAME_DEFULT_NIC
  # shellcheck disable=SC2015
  IP_DEFAULT_NIC=$( (command -v ip &> /dev/null && ip addr show "$NAME_DEFULT_NIC" || ifconfig "$NAME_DEFULT_NIC") | \
                    sed -nEe 's/^[[:space:]]+inet[^[:alnum:]]+([0-9.]+).*$/\1/p')
  export IP_DEFAULT_NIC
  #HOSTNAME_FOR_WCDNS_BASED_ON_IP=$(echo "$IP_DEFAULT_NIC" | awk -F. '{printf "%02x", $1}{printf "%02x", $2}{printf "%02x", $3}{printf "%02x", $4}')
  HOSTNAME_FOR_WCDNS_BASED_ON_IP=${IP_DEFAULT_NIC//\./-}
  export HOSTNAME_FOR_WCDNS_BASED_ON_IP
}

getClusterName() {
  kubectl -n rdbox-common get configmaps cluster-info -o json| jq -r ".data.name"
}

getBaseFQDN() {
  kubectl -n rdbox-common get configmaps cluster-info -o json| jq -r ".data.base_fqdn"
}