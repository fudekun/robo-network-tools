#!/bin/bash

showLoading() {
  local mypid=$!
  local loadingText=$1

  echo -ne "    $loadingText\r"

  while kill -0 $mypid 2>/dev/null; do
    echo -ne ".   $loadingText\r"
    sleep 0.5
    echo -ne "..  $loadingText\r"
    sleep 0.5
    echo -ne "... $loadingText\r"
    sleep 0.5
    echo -ne "\r\033[K"
    echo -ne "    $loadingText\r"
    sleep 0.5
  done
  wait $mypid
  local exit_status=$?
  echo -e "\033[32mok!\033[m $loadingText"
  return "$exit_status"
}

cmdWithLoding() {
  local commands=$1
  local message=$2
  eval "${commands} & showLoading '${message} '"
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

updateHelm() {
  cmdWithLoding \
    "helm repo update 1> /dev/null" \
    "Updateing Helm"
}

getClusterName() {
  kubectl -n cluster-common get configmaps cluster-info -o json| jq -r ".data.name"
}

getBaseFQDN() {
  kubectl -n cluster-common get configmaps cluster-info -o json| jq -r ".data.base_fqdn"
}

getPresetGroupName() {
  echo cluster-admim
}