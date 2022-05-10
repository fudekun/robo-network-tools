FROM ubuntu:22.04

ARG VERSION_KIND
ARG VERSION_KUBECTL
ARG VERSION_DOCKER_CE
ARG VERSION_CONTAINERD
ARG VERSION_HELM
ARG VERSION_GOST

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
        docker-ce=5:${VERSION_DOCKER_CE}.* \
        docker-ce-cli=5:${VERSION_DOCKER_CE}.* \
        containerd.io=${VERSION_CONTAINERD}.* \
    && apt-mark hold \
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
        kubectl=${VERSION_KUBECTL}-00 \
    && apt-mark hold \
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
        helm=${VERSION_HELM}.* \
    && apt-mark hold \
        helm

## Setup the yq
RUN curl -L -o /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 \
    && chmod +x /usr/local/bin/yq

## Setup the kind
RUN curl -L -o /usr/local/bin/kind https://github.com/kubernetes-sigs/kind/releases/v${VERSION_KIND}/download/kind-linux-amd64 \
    && chmod +x /usr/local/bin/kind

## Setup the gost
RUN curl -L -o /tmp/gost.gz https://github.com/ginuerzh/gost/releases/download/v${VERSION_GOST}/gost-linux-amd64-${VERSION_GOST}.gz \
    && gunzip -c /tmp/gost.gz > /usr/local/bin/gost \
    && chmod +x /usr/local/bin/gost

## Setup the others
RUN apt-get update \
    && apt-get install -y \
        jq \
        iproute2 \
        iputils-ping \
        net-tools \
        dnsutils \
        rsync \
        socat \
        vim \
        sudo \
        gosu \
        git

## Setup User and Group
## References: https://qiita.com/Spritaro/items/602118d946a4383bd2bb
## References: https://qiita.com/yohm/items/047b2e68d008ebb0f001
ARG USERNAME=ubuntu
ARG GROUPNAME=ubuntu
ARG UID=1000
ARG GID=1000
ARG PASSWORD=password
RUN groupadd -g $GID $GROUPNAME && \
    useradd -m -s /bin/bash -u $UID -g $GID -G sudo $USERNAME && \
    echo $USERNAME:$PASSWORD | chpasswd && \
    echo "$USERNAME   ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
COPY ./files/entrypoint.bash /usr/local/bin/entrypoint.bash
RUN chmod +x /usr/local/bin/entrypoint.bash
ENTRYPOINT ["/usr/local/bin/entrypoint.bash"]
WORKDIR /home/$USERNAME/

## Setup krew (Plug-In manager for kubectl)
## References: https://krew.sigs.k8s.io/docs/user-guide/quickstart/
RUN cd "$(gosu ubuntu mktemp -d)" \
    && OS="$(uname | tr '[:upper:]' '[:lower:]')" \
    && ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" \
    && KREW="krew-${OS}_${ARCH}" \
    && gosu ubuntu curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" \
    && gosu ubuntu tar zxvf "${KREW}.tar.gz" \
    && gosu ubuntu ./"${KREW}" install krew \
    && echo 'export PATH="${KREW_ROOT:-/home/ubuntu/.krew}/bin:$PATH"' >> /home/ubuntu/.bashrc

## Setup oidc-login (krew's Plug-In)
## References: https://github.com/int128/kubelogin
RUN PATH="${KREW_ROOT:-/home/ubuntu/.krew}/bin:$PATH" \
    && gosu ubuntu kubectl krew update \
    && gosu ubuntu kubectl krew install oidc-login