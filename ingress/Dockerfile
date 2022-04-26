FROM ubuntu:22.04

## Setup the docker-ce
## References: https://docs.docker.com/engine/install/ubuntu/
##
### Update the apt package index and install packages to allow apt to use a repository over HTTPS:
RUN apt-get update \
    && apt-get install -y \
        ca-certificates \
        curl \
        gnupg2 \
        lsb-release
### Add Docker’s official GPG key:
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
### Use the following command to set up the stable repository. To add the nightly or test repository, add the word nightly or test (or both) after the word stable in the commands below. Learn about nightly and test channels.
RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
### Update the apt package index, and install the latest version of Docker Engine and containerd, or go to the next step to install a specific version:
RUN apt-get update \
    && apt-get install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io

## Setup kubectl
RUN curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg \
    | apt-key add - \
    && echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" \
      | tee -a /etc/apt/sources.list.d/kubernetes.list
RUN apt-get update \
    && apt-get install -y \
        kubectl

## Setup the helm
## References: https://helm.sh/ja/docs/intro/install/
### From Apt (Debian/Ubuntu)
### Members of the Helm community have contributed a Helm package for Apt. This package is generally up to date.
RUN curl https://helm.baltorepo.com/organization/signing.asc \
    | apt-key add - \
    && echo "deb https://baltocdn.com/helm/stable/debian/ all main" \
      | tee /etc/apt/sources.list.d/helm-stable-debian.list
RUN apt-get update \
    && apt-get install -y \
        helm
### Setup the repos that RDBOX depends on
### Commands for confirmation: `helm repo list`
### NOTES:
### - datawire => edge-stack
### - jetstack => cert-manager
RUN helm repo add datawire https://getambassador.io/ \
    && helm repo add metallb https://metallb.github.io/metallb \
    && helm repo add jetstack https://charts.jetstack.io \
    && helm repo add bitnami https://charts.bitnami.com/bitnami

## Setup the kind
RUN curl -L -o /usr/local/bin/kind https://github.com/kubernetes-sigs/kind/releases/latest/download/kind-linux-amd64 \
    && chmod u+x /usr/local/bin/kind

## Setup the yq
RUN curl -L -o /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 \
    && chmod u+x /usr/local/bin/yq

## Setup the gost
RUN curl -L -o /tmp/gost.gz https://github.com/ginuerzh/gost/releases/download/v2.11.2/gost-linux-amd64-2.11.2.gz \
    && gunzip -c /tmp/gost.gz > /usr/local/bin/gost \
    && chmod u+x /usr/local/bin/gost

## Setup the others
RUN apt-get update \
    && apt-get install -y \
        jq \
        iproute2 \
        iputils-ping \
        net-tools \
        dnsutils \
        rsync \
        socat