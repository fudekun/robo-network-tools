# Ingressの試験をやる

## クラスタを構築する

```bash
kind create cluster --config cluster.yaml

kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
```

## Ambassador

### オレオレ証明書を発行する

```bash
# for Mac(Because Chrome requires a SAN value. The default openssl command is outdated and unsupported.)
/usr/local/opt/openssl/bin/openssl  req -newkey rsa:4096 -nodes -sha256 -keyout rdbox_common_certname.key -x509 -days 365 -out rdbox_common_certname.crt -subj "/C=JP/ST=Tokyo/L=Tokyo/CN=rdbox.127-0-0-1.nip.io" -addext "subjectAltName=DNS:rdbox.127-0-0-1.nip.io"
```

### ｏｐｅｒａｔｏｒ版（v1.14という古いのが入る）

```bash
kubectl apply -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-crds.yaml

kubectl apply -n ambassador -f https://github.com/datawire/ambassador-operator/releases/latest/download/ambassador-operator-kind.yaml

kubectl wait --timeout=180s -n ambassador --for=condition=deployed ambassadorinstallations/ambassador

# create namespace (ambassador require a specific namespace.)
kubectl create namespace rdbox-systems

# Server Cert and key
kubectl -n rdbox-systems create secret tls rdbox-common-tls --key=rdbox_common_certname.key --cert=rdbox_common_certname.crt

# Create Dashboard
## Add service-account
kubectl -n rdbox-systems apply -f service-account.yaml

helm -n rdbox-systems install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard -f values_for_kind.yaml

curl https://rdbox.127-0-0-1.nip.io -vvvv -k

## On Browser ログインする時に$TOKENが必要だよ
TOKEN=$(kubectl -n rdbox-systems get secrets -o json | jq .items\[\] | jq 'select(.metadata.name | startswith("admin-user-token"))' | jq -r .data.token | base64 -d)
echo $TOKEN
```

### Helm版（v2.1で最新っぽいけど上手くいかない）

```bash
# Add the Repo:
helm repo add datawire https://app.getambassador.io
helm repo update

# Create Namespace and Install:
kubectl create namespace ambassador && \
kubectl apply -f https://app.getambassador.io/yaml/edge-stack/latest/aes-crds.yaml && \
kubectl wait --timeout=90s --for=condition=available deployment emissary-apiext -n emissary-system

helm install edge-stack --namespace ambassador datawire/edge-stack --set emissary-ingress.service.type=NodePort  && \
kubectl -n ambassador wait --for condition=available --timeout=90s deploy -lproduct=aes
```

### 動作確認

```bash
kubectl apply -n ambassador -f ambassador_usage.yaml
```

## metalLB

```bash
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/namespace.yaml

kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey="$(openssl rand -base64 128)"

kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/metallb.yaml
```

```bash
kubectl apply -f metallb_config.yaml
```

## クラスタを消す

```bash
kind delete cluster --name rdbox-hakoniwa
```
