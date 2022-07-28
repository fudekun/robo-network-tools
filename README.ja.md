# [RDBOX(Robotics Developers BOX)](https://github.com/rdbox-intec/rdbox): embodies the ideal of a cloud robotics

This repository is developing the next generation of **the RDBOX** (Please call me "ði άːrdíː bäks")

This RDBOX built with a single node. Using [KinD (Kubernetes in Docker)](https://kind.sigs.k8s.io/)  
Faster and easier than [previously RDBOX](https://github.com/rdbox-intec/rdbox)

## ROS2アプリとの連携例

1. [SROS2 with OIDC(OpenID Connect) :ロボットが人を認証・認可するための技術〜](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc)
    ![SROS2_with_OIDC](/docs/imgs/SROS2_with_OIDC.jpeg)

※ ROS2アプリとの連携を実施する前に、以下に記載する「RDBOX-Next環境構築手順」に従って基礎的な環境を構築して下さい

## RDBOX-Next環境構築手順

### 新旧RDBOXの差

構築しただけのKubernetesクラスタは何の役目も果たすことはできません。入れ物です。  
この入れ物に対して、様々なワークロードの集合体（アプリケーション）を追加していくことで利用者は利便性を享受することができます。  
これは従来のRDBOXでもおこなってきたことです。  

次世代ROBOXでは、ただやみくもにワークロードを追加していくのではありません。  
開発チームでは、クラウドロボティクス技術を安全かつ便利に使うために必要な**3つの要素**を定義しました。

  1. 通信の制御
  2. 通信の暗号化
  3. リクエストの認証・認可
     - ユーザやデバイスを、グループもしくは個別に管理

「**3つの要素** を充足したワークロードが、簡単に追加できるインフラ」を目指して、開発が絶賛進行中です。

### システム構成

KinDを使ってKubernetesのComponent（**Control Plane** / **Node**）を1つのDockerコンテナ内に構築します。  
※ Kubernetesの構築方法はKinDを使う以外にも、本番環境での利用を想定した方法も準備中です。

3つの要素の実態として `「essentials」メタパッケージ` がワークロード内に初期構築されます。  
これらは、以下の図のようなシステム構成を採ります。  

![Component_of_RDBOX-NX.png](/docs/imgs/Component_of_RDBOX-NX.png)

- 通信の制御
  - [metallb](https://metallb.universe.tf) や [ambassador](https://www.getambassador.io/products/edge-stack/) 等で実現
- 通信の暗号化
  - [cert-manager](https://cert-manager.io) で実現
- リクエストの認証・認可（ユーザやデバイスをグループもしくは個別に管理）
  - [keycloak](https://www.keycloak.org) で実現

Node内の緑色のボックスは「ワークロード」の集合体として捉えて下さい。  
このあとに追加されていくクラウドロボティクスの為の各種アプリケーションは、初期構築した `「essentials」メタパッケージ` を使って、  
**3つの要素** を満たしたワークロードとして使い始めることが可能です。
(図のdashboardとprometheus。そして、これはほんの一例に過ぎません。)

### テスト状況

本手順は、以下の環境でのテストを実施しました（2022-05-13）。  
いずれも**amd64** 環境です。

- Ubuntu 20.04.4
  - 5.13.0-41-generic
  - Docker-CE （20.10.16）
- MacOSX Monterey 12.3.1
  - Docker Desktop 4.6.1
- Windows11 21H2（WSL2）
  - Ubuntu20.04.4
    - 5.10.16.3-microsoft-standard-WSL2
  - Docker-CE （20.10.14）

### 注意(品質について)

KinD (Kubernetes in Docker) は、ローカルの開発やCIに使用することを想定したKubernetesクラスタです。  
本番環境での使用は想定していませんのでご注意下さい。  

`built with a single node`なRDBOXは、KinDで作った環境でクラウドロボティクスの利点を確認して頂くために開発しました。  
そのようなユーザに対して、本番環境での利用を想定した構成への移行をスムーズに行うための「仕組み」も準備中です。  
詳細はロードマップをご覧ください。

### 事前準備

#### Dockerのセットアップ

Docker環境を用意する。以下の公式ドキュメントに従ってください。

- Ubuntu/Windows11(WSL2)：[Install Docker Engine on Ubuntu \| Docker Documentation](https://docs.docker.com/engine/install/ubuntu/)
- Mac：[Install Docker Desktop on Mac \| Docker Documentation](https://docs.docker.com/desktop/mac/install/)

##### 【注意】dockerコマンドはsudoなしで実行できるようにしておいて下さい

```bash
$ sudo gpasswd -a $USER docker

# 1. You need to logout.

# 2. Please login again.

$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAME
```

#### その他必要なモジュールを追加

```bash
sudo apt-get update
sudo apt-get install -y \
    git
```

### ソースコードのダウンロード

ブランチに注意して下さい。

```bash
git clone -b insiders https://github.com/rdbox-intec/rdbox.git
cd rdbox
```

`insiders`ブランチになっていることを確認します。

```bash
$ git branch
  develop
* insiders
  master
```

### Dockerイメージを作る

次のスクリプトを実行すると、RDBOX-NextのDockerイメージが作成されます。

```bash
bash docker/setup.bash
```

```bash
~ omit ~

Removing intermediate container 6defb90ca35d
 ---> 4a9760a195e9
Successfully built 4a9760a195e9
Successfully tagged rdbox/docker:20.10
+ exit 0
```

### 初期設定コマンドの実施

構築には本リポジトリの`rdboxコマンドラインツール`を使用します。サブコマンド並びに引数を組み合わせて、ユーザ環境に最適なクラウドロボティクス環境を提供します。

`rdboxコマンドラインツール`を使って順に環境構築をしていきます。  
`rdbox init`コマンド：

- クラスタの名前を決定する
- 作業ディレクトリの作成
- 設定ファイルの取得

以下の通り、`--name rdbox`ではクラスター名をrdboxとして設定しています。

```bash
./rdbox init --name rdbox
```

```bash
~ omit ~

# END (SUCCESS)
[2022-05-12T23:56:07+0000][1652399767.0702667][init.bash]
*********************************************************
```

### 【取り扱い注意】上級者向け

`init`サブコマンドを実行すると、ホームディレクトリ上`~/crobotics`に作業ディレクトリ、設定ファイルが配置されます。必要に応じて各設定を変更することもできます。

- 各設定内容の説明は準備中
`~/crobotics`はデフォルト値です。

```bash
~/crobotics
└── rdbox
    ├── confs
    │   ├── meta-pkgs
    │   │   └── essentials.env.properties
    │   └── modules
    │       ├── ambassador
    │       │   ├── di
    │       │   │   └── v1beta1
    │       │   │       └── values.yaml
    │       │   └── helm
    │       │       └── v1beta1
    │       │           └── values.yaml
    │       ├── cert-manager
    │       │   ├── di
    │       │   │   └── v1beta1
    │       │   │       └── values.yaml
    │       │   └── helm
    │       │       └── v1beta1
    │       │           └── values.yaml
    │       ├── keycloak
    │       │   ├── di
    │       │   │   └── v1beta1
    │       │   │       └── values.yaml
    │       │   ├── entry
    │       │   │   └── v1beta1
    │       │   │       ├── client.jq.json
    │       │   │       ├── client_scope.jq.json
    │       │   │       └── values.jq.json
    │       │   └── helm
    │       │       └── v1beta1
    │       │           └── values.yaml
    │       ├── kind
    │       │   └── kind
    │       │       └── v1beta1
    │       │           └── values.yaml
    │       └── metallb
    │           └── helm
    │               └── v1beta1
    │                   └── values.yaml
    ├── logs
    │   └── init.1652399767094.rdbox.log
    ├── outputs
    └── tmps
```

### Kubernetesクラスターの構築

まず、Kubernetesクラスターを構築。次に、このクラスタに対してコンテナネットワークをインプリメントします。

具体的には、私達は以下のKubernetesリソースを使用します。

- [KinD](https://kind.sigs.k8s.io)
  - Kubernetes in Dockerの略。
  - Dockerコンテナ内にKubernetesクラスターを作る。自分の環境をほぼ汚染せずにKubernetesの検証が可能
- [Weave-Net](https://www.weave.works/docs/net/latest/kubernetes/kube-addon/)
  - Kubernetes用のコンテナネットワークの選択肢の一つ。
  - UDPマルチキャストなどもサポートし、ROS2におけるDDS通信との相性が良い。

上記のリソースを導入するために、`rdbox create`コマンドを使います。

- `--name rdbox`は`init`で指定したクラスターの名称を指定。
- `--module k8s-cluster`では今回構築するモジュールの種別を指定。
- `--domain nip.io`には名前解決可能なローカルドメインを指定する必要があります。
  - 存在しない場合は`nip.io`などの**ワイルドカードDNSサービス**を指定して下さい。

```bash
./rdbox create --name rdbox --module k8s-cluster --domain nip.io
```

```bash
~ omit ~

## USAGE
### K8s Cluster by KinD and Weave-Net has been installed. Check its status by running:
    kubectl get node -o wide

# END (SUCCESS)
[2022-05-13T00:08:59+0000][1652400539.5034535][create.bash]
***************************************************************
```

注意：オプションで `--host ${YOUR_HOST_NAME}`が指定できます。これは名前解決可能なローカルドメインが存在する場合にだけ指定してください。何も入力しない場合はワイルドカードDNSサービスがサポートする書式`デフォルトNICのIPv4アドレスをハイフン区切りとしたもの(e.g. 192-168-22-222)`が自動的に利用されます。

これでkubernetesクラスタとして動作する最小限の構成が完成しています。ホスト上に`kubectl`がインストールされている場合は`kubectl get node -o wide`コマンドをホスト上のターミナルで実行するとノードの動きを確認できます。

- [Install Tools \| Kubernetes](https://kubernetes.io/docs/tasks/tools/#kubectl)

```bash
# kubectlがホストマシンにインストールされている場合のみ実行可能
NAME                  STATUS   ROLES                  AGE    VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE       KERNEL-VERSION      CONTAINER-RUNTIME
rdbox-control-plane   Ready    control-plane,master   111s   v1.23.4   172.18.0.3    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
rdbox-worker          Ready    <none>                 75s    v1.23.4   172.18.0.2    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
```

また、`docker ps` コマンドでKinDによってDockerコンテナのみでクラスターが構築されている様子が伺えます。

```bash
CONTAINER ID   IMAGE                  COMMAND                  CREATED         STATUS         PORTS                                                                NAMES
6072b4d58771   kindest/node:v1.23.4   "/usr/local/bin/entr…"   2 minutes ago   Up 2 minutes   0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp, 0.0.0.0:32022->32022/tcp   rdbox-worker
03c5e5c00750   kindest/node:v1.23.4   "/usr/local/bin/entr…"   2 minutes ago   Up 2 minutes   127.0.0.1:44251->6443/tcp                                            rdbox-control-plane
```

### essentialのインストール

KubernetesをROS2と一緒に使う上で必要となる最も基礎的なモジュールをインストール、セットアップします。

以下のKubernetesリソースをインストール・セットアップします。

- [cert-manger](https://cert-manager.io)
  - 各種証明書の管理
- [MetalLB](https://metallb.universe.tf)
  - KubernetesリソースであるIngress機能を提供
- [Ambassador Edge Stack](https://www.getambassador.io/products/edge-stack/api-gateway/)
  - `kubectl`（kubernetesのコマンドラインツール）に対するSSO（シングル・サインオン）を提供。権限に応じたクラスター操作を実現。
- [KeyCloak](https://www.keycloak.org)
  - ユーザやグループの認証・認可基盤

先程と同様に`rdbox create`コマンドで各種リソースのインストール・セットアップを実施します。

- `--name rdbox`は`init`で指定したクラスターの名称を指定。
- `--module k8s-essentials`では今回構築するモジュールの種別を指定。

（このセットアップは、マシンスペックにもよりますが10分程度かかる場合があります。）

```bash
./rdbox create --name rdbox --module essentials
```

```bash
~ omit ~

## USAGE
### Trust CA with your browser and operating system. Check its file:
    openssl x509 -in *******.ca.crt -text
  ### This information is for reference to trust The CA file:
    (Windows) https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores
    (MacOS  ) https://support.apple.com/guide/keychain-access/kyca2431/mac
    (Ubuntu ) https://ubuntu.com/server/docs/security-trust-store

## USAGE
### The basic keycloak entry has been inserted. Check its status by running:
  ### For all realms
  https://*******/admin
    echo Username: $(helm -n keycloak get values keycloak -o json | jq -r '.auth.adminUser')
    echo Password: $(kubectl -n keycloak get secrets specific-secrets -o jsonpath='{.data.adminPassword}' | base64 --decode)
  ### For this k8s cluster only (ClusterName: rdbox)
  https://*******/realms/rdbox/protocol/openid-connect/auth?client_id=security-admin-console
    echo Username: cluster-admin
    echo Password: $(kubectl -n keycloak get secrets specific-secrets -o jsonpath='{.data.k8s-default-cluster-admin-password}' | base64 --decode)

## USAGE
### **ContainerOS** Execute the following command to run kubectl with single sign-on:
  ### **ContainerOS**
  ### Access the URL included in the command execution result using a web browser of the host OS (e.g., Chrome)
      And you should perform the login operation
      - (If the message **Success SSO Login** is printed, the login was successful.)
      - (It does not matter if negative wording such as Forbidden is included.)
    rdbox login --name rdbox

~ omit ~

# END (SUCCESS)
[2022-05-13T01:02:16+0000][1652403736.657805][create.bash]
***************************************************************
# Finalizing logger ...(Please Max 10s wait)
```

#### 注意 - 必ず標準出力を記録してください

上記のように、出力の末尾にユーザ管理基盤（Keycloak）にに必要なアカウントの情報が**USAGE**として表示されます。失念しないようにどこかにコピペしておくことを推奨します。

## ユーザ管理基盤（Keycloak）の設定

メモしたユーザ管理基盤用のアカウント情報を使って設定する。

### CA証明書を信頼する

ホストOSの作業ディレクトリ`~/crobotics/${CLUSTER_NAME}/outputs/ca`に保存されているCA証明書を確認します。

```bash
openssl x509 -in ~/crobotics/rdbox/outputs/ca/rdbox.172-16-0-132.nip.io.ca.crt -text
```

このCA証明書をOSやブラウザに信頼できる証明書として登録します。以下に参考リンクを記載します。

#### OS

- [Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores)
- [MacOS](https://support.apple.com/guide/keychain-access/kyca2431/mac)
- [Ubuntu](https://ubuntu.com/server/docs/security-trust-store)
  - `sudo cp ~/crobotics/${CLUSTER_NAME}/outputs/ca/*****.ca.crt /usr/local/share/ca-certificates/`
  - `sudo update-ca-certificates`

#### ブラウザ

- [Set up an HTTPS certificate authority \- Chrome Enterprise and Education Help](https://support.google.com/chrome/a/answer/6342302?hl=en)
- [Setting Up Certificate Authorities \(CAs\) in Firefox](https://support.mozilla.org/kb/setting-certificate-authorities-firefox)

### ユーザ管理基盤（Keycloak）に限定的な管理アカウントでログインしてみる

ここでは、主にkubernetesクラスターを管理するためにRDBOXが自動作成した「限定的な管理者（レルム管理者）」として、Keycloakにログインします。  
なお、ユーザ管理基盤全体（全てのレルム）を管理するアカウント（super-admin）のログインも同様に実施可能です。

#### 初期ログイン情報を取得

メモの記載通りにアカウント情報を取得する。（以下のコマンドは一例です。実際のメモを確認して下さい。）

```bash
echo Username: cluster-admin
echo Password: $(kubectl -n keycloak get secrets specific-secrets -o jsonpath='{.data.k8s-default-cluster-admin-password}' | base64 --decode)
```

#### 指定のURLにアクセスしてログイン

WebブラウザのインジケータによってCAのインポートに成功して、暗号化されていることを確認できます。その後、前章で取得した初期ログイン情報を入力して下さい。

![keycloak_signin.jpg](/docs/imgs/keycloak_signin.jpg)

#### 二要素認証のセットアップ

管理アカウントであるため2要素認証をセットアップします。

![2FA_setup.jpg](/docs/imgs/2FA_setup.jpg)

### Keycloak画面を操作する

Keycloakの機能は多岐に渡ります。詳しくは[公式ドキュメント](https://www.keycloak.org/documentation.html)を確認して下さい。  
ここでは、GroupsやUsersといったユーザー管理にまつわる項目を覗いてみましょう。

#### Groups

チュートリアルのための、Groupsには2つのグループが作成されています。

- cluster-admin
  - ここに所属するユーザはkuberntestのRBAC（Role-based access control）におけるcluster-adminがバインドされます。
    - クラスター内およびすべてのNamespace内のすべてのリソースを完全に制御できます。
- guest
  - ここに所属するユーザは特定のnamespace内（今回はguest）のみに限られた権限がRBACでバインドされています。
  - このグループに所属するユーザは、管理者用のコンソールページ（今操作しているページ）にはログインすることができません。
    - ユーザ個人の為のページにて、パスワードの変更や、セッション状況の確認及び切断することは可能です。後述します。

![groups.jpg](/docs/imgs/groups.jpg)

#### Users

チュートリアルのために、Groupsに紐付いたユーザが予め登録されている。

![users.jpg](/docs/imgs/users.jpg)

#### Clients Account-console

`cluster-admin`グループに所属していないユーザが、自身で「パスワードの変更や、セッション状況の確認や切断」を実施するためには、以下の設定が必要です。

1. 左ペインからClientsを選択。リスト内からAccount-consoleを選択。
2. Enabledという項目をONに設定する。
3. Web Originsという項目に`*`を追加する。
4. Saveボタンをクリックして内容を保存する。

#### 個人ページ

パスワードの変更や、セッション状況の確認や切断が可能。

URL：`https://${KeycloakのFQDN}/realms/${クラスター名}/account/`
![accountpage.jpg](:/96a6a042c1694cef85355e634104efa6)

## SSOでKubernetesを使ってみる

Keycloakに登録されているユーザーとして認証・認可された結果に基づき`kubectl`を実行する。

- 前章で確認したグループ（cluster-adminとguest）で許可されている操作が異なることを確認する。
- `kubectl`がホストマシンにインストールされていない場合でも確認することが可能です。

### 初期設定

#### セットアップに使用したコンテナ内部にログイン

このコマンドを実行した後の操作は、コンテナ内部から実行したこととなります。

```bash
./rdbox bash --name rdbox
```

#### ログイン操作(cluster-admin)

コンテナ内部に入ったら以下のコマンドを実施。コンテナ内部はPATHが通っているので rdbox コマンドをそのまま実行可能。

```bash
rdbox login --name rdbox
```

```bash
error: could not open the browser: exec: "xdg-open,x-www-browser,www-browser": executable file not found in $PATH

Please visit the following URL in your browser manually: http://localhost:8000
```

上記のように、  
`Please visit the following URL in your browser manually: http://localhost:8000`  
というメッセージに従ってブラウザで[http://localhost:8000](http://localhost:8000)にアクセスする。  
するとKeycloakのログイン画面にリダイレクトされるので先程確認したアカウント`cluster-admin`でログインする。先程設定した二要素認証も確認されます。

![login_cluster-admin.jpg](/docs/imgs/login_cluster-admin.jpg)

![2FA_setuped.jpg](/docs/imgs/2FA_setuped.jpg)

認証に成功すると、コマンドを実行したターミナルでは、ログインが成功した旨のメッセージが表示されます。

```bash
~ omit ~

Success SSO Login
```

## Testing RBAC

このチュートリアルでは、以下の2つのユーザを使ってKeycloakとRBACによる認証・認可基盤の働きについて確認します。

- **cluster-adminグループに所属する、cluster-adminユーザ**
- **guestグループに所属する、guestユーザ**

前述の通り、チュートリアルのための、Groupsには2つのグループは以下の特性を有します。

- cluster-admin
  - ここに所属するユーザはkuberntestのRBAC（Role-based access control）におけるcluster-adminがバインドされます。
    - クラスター内およびすべてのNamespace内のすべてのリソースを完全に制御できます。
- guest
  - ここに所属するユーザは特定のnamespace内（今回はguest）のみに限られた権限がRBACでバインドされています。
  - このグループに所属するユーザは、管理者用のコンソールページ（今操作しているページ）にはログインすることができません。
    - ユーザ個人の為のページにて、パスワードの変更や、セッション状況の確認及び切断することは可能です。後述します。

### kubectlコマンドを試す(cluster-admin)

#### get node

まず`cluster-admin`の操作を試してみます。  
`kubectl get node`といったクラスター全体に渡る権限に関わる操作が可能です。

```bash
$ kubectl get node -o wide
NAME                  STATUS   ROLES                  AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE       KERNEL-VERSION      CONTAINER-RUNTIME
rdbox-control-plane   Ready    control-plane,master   86m   v1.23.4   172.18.0.2    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
rdbox-worker          Ready    <none>                 86m   v1.23.4   172.18.0.3    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
```

#### create namespac

新しくnamespaceを作ることが可能です。

```bash
$ kubectl create namespace test-rdbox
namespace/test-rdbox created
```

#### apply

作成したnamespaceに対し、Nginxのサンプルプログラム用のマニフェストを適用する。getコマンドを使うことで実際にdeploymentが作成されていることが確認できます。  
そして、`kubectl port-forward -n test-rdbox deploy/nginx-deployment 8888:80`によってポート転送を設定すると、ブラウザで実際に動作している様子を確認することもできます。

```bash
# apply（≒インストール）
$ kubectl apply -n test-rdbox -f https://k8s.io/examples/application/deployment.yaml
deployment.apps/nginx-deployment created

# get（確認）
$ kubectl -n test-rdbox get deployments      
NAME               READY   UP-TO-DATE   AVAILABLE   AGE
nginx-deployment   2/2     2            2           91s

# 通信路の確保
# これによって、http://localhost:8888 にアクセスするとnginxのデモページに転送がかかる
$ kubectl port-forward -n test-rdbox deploy/nginx-deployment 8888:80
```

### kubectlコマンドを試す(guest)

同じターミナルを使って今度は、guestグループのguestユーザでログインしてみます。（これは権限の違いを確認しましょう）

#### logout from cluster-admin

```bash
rdbox logout --name rdbox
```

```bash
~ omit ~
Success SSO Logout
```

また、ブラウザでもログアウトを実施して下さい。

URL：`https://${KeycloakのFQDN}/realms/${クラスター名}/account/`

![accountpage_signout.jpg](/docs/imgs/accountpage_signout.jpg)

#### ログイン操作（guest）

今度は、guestユーザでログインします。
Username： `guest`
Password： `password`

```bash
rdbox login --name rdbox
```

```bash
error: could not open the browser: exec: "xdg-open,x-www-browser,www-browser": executable file not found in $PATH

Please visit the following URL in your browser manually: http://localhost:8000
```

上記のように、  
`Please visit the following URL in your browser manually: http://localhost:8000`  
というメッセージに従ってブラウザで[http://localhost:8000](http://localhost:8000)にアクセスする。  
するとKeycloakのログイン画面にリダイレクトされるので先程確認したアカウント`guest`でログインする。

認証に成功すると、コマンドを実行したターミナルでは、ログインが成功した旨のメッセージが表示されます。

```bash
~ omit ~

Success SSO Login
```

#### get node(guest)

`cluste-admin`と同様のことを `guest`の操作で試してみます。

`kubectl get node`といったクラスター全体に渡る操作はできません。`nodes is forbidden`として権限が無い旨のメッセージが表示されます。

```bash
$ kubectl get node -o wide
Error from server (Forbidden): nodes is forbidden: User "guest" cannot list resource "nodes" in API group "" at the cluster scope
```

#### create namespac(guest)

namespaceも新規に作ることはできません。

```bash
$ kubectl create namespace test-rdbox
Error from server (Forbidden): namespaces is forbidden: User "guest" cannot create resource "namespaces" in API group "" at the cluster scope
```

#### apply(guest)

getコマンドを使っても、先程Applyしたdeploymentの状態を確認する権限はありません。

```bash
# get（確認）
$ kubectl -n test-rdbox get deployments
Error from server (Forbidden): deployments.apps is forbidden: User "guest" cannot list resource "deployments" in API group "apps" in the namespace "test-rdbox"
```

では、guestユーザに権限が与えられている、`guest`namespaceに対してapplyしてみます。すると成功することがわかります。

ポート転送を設定すると、ブラウザで実際に動作している様子を確認することもできます。

```bash
# apply（≒インストール）
$ kubectl apply -n guest -f https://k8s.io/examples/application/deployment.yaml
deployment.apps/nginx-deployment created

# 通信路の確保
# これによって、http://localhost:8888 にアクセスするとnginxのデモページに転送がかかる
$ kubectl port-forward -n guest deploy/nginx-deployment 8888:80
```

### チュートリアルのまとめ

2つのユーザを使って、操作権限の差について確認することができました。keycloak並びにRBAC（Kubernetes）を組み合わせることで、かなり自由度の高い認証や権限管理が可能になります。ぜひ、カスタマイズして使ってみて下さい。

#### チュートリアル後に読みたい文献

- [Documentation \- Keycloak](https://www.keycloak.org/documentation)
- [Using RBAC Authorization \| Kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

## 環境の削除

不要になった環境を削除したい場合は、ホストマシンで以下のコマンドを実行して下さい

```bash
cd ${ソースコードをクローンした場所}
./rdbox logout --name rdbox
./rdbox delete --name rdbox
```

```bash
=====================
[2022-05-13T03:22:29+0000][1652412149.3937433][delete.bash]
# BEGIN
{'Application': 'v0.0.1', 'TemplateEngine': 'v0.1.0', 'Template': 'v1beta1'}

---
# Deleteing Cluster ...
    Deleteing Context ...
    Switched to context "kind-rdbox".
    Deleteing Cluster ...
    Deleting cluster "rdbox" ...
ok Deleteing Cluster 

# END (SUCCESS)
[2022-05-13T03:22:31+0000][1652412151.4958436][delete.bash]
*****************
# Finalizing logger ...(Please Max 10s wait)
```

dockerコマンドの結果から、環境が削除されていることがわかります。

```bash
$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

## Licence

Licensed under the [MIT](/LICENSE) license.
