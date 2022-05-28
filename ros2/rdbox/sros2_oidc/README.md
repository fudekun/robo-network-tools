# SROS2 with OIDC(OpenID Connect) - Technology for robots to authenticate and authorize a human

[Japanese README](/ros2/rdbox/sros2_oidc/README.ja.md)

## Video

<!-- markdownlint-disable MD034 -->
https://user-images.githubusercontent.com/40556102/170811723-17f9c6eb-4f3b-41bd-8b64-799535ce5009.mp4

## Concepts

協働型ロボットとして、人と綿密に関わって動くロボットが増えている。その中で「誰が何を命令したか？」「誰にどのようなサービスを提供可能か？」等、「管理・監査・証跡」もしくは「個人に最適化した役務提供」等を目的に、個人を認識（≒認証・認可）する必要性が発生している。利用者の属性（氏名・権限・位置情報等）や認証（顔・指紋等）に基づき、役務提供する場合、個人情報保護が課題となる。しかし現状、多くの現場でそれらの個人情報をロボット上PCに保存して運用していないだろうか。研究段階や利用者の人数が少ないうちは顕在化しないが、社会システムとしてロボット活用が一般化した時には問題となる可能性が高い。

この課題に対して、我々は「sros2_oidc」というパッケージを開発・公開した。本パッケージのアプローチでは、認証規約として[OIDC(OpenID Connect)](https://openid.net/connect/)を採用し、SROS2と組み合わせてロボット終端まで利用者情報を安全な経路で伝送するという方式を採る。

![system architecture.jpeg](/ros2/rdbox/sros2_oidc/docs/imgs/EN_system%20architecture.jpeg)

OIDCはWebサービスではスタンダードな認証規約の一つである。ロボットに対してはユーザから同意が得られた最小限の情報だけ（例えば位置情報のみ）を連携することや、遠隔から利用権限を即時停止するなどその用途は多岐に渡る。また、OIDCで取り扱いに注意が必要な「アクセスToken」を、セキュリティを確保した上で「Relaying Party（OIDCとROS2の橋渡しを行う）」から、「Resource Server（実際に情報を受け取って命令を実行するロボット）」へ受け渡しするために「SROS2」を利用している（図2）。「PKI(公開鍵基盤)/セキュリティ規則を記述したXML」に基づくアクセス制御を行うSROS2は、固定されたノード間の通信において強みを発揮する。一方で、鍵の管理コストが、利用者が増えるたび増大するといった問題点もある。本パッケージのような橋渡しのための仕組みは、管理コストの低減に役立つことが期待できる。

![OIDC_Flow.png](/ros2/rdbox/sros2_oidc/docs/imgs/OIDC_Flow.png)

## Environment Building Steps

### Setup of SROS2

まず、SROS2が動くROS2 Foxy環境を準備します。

手順は、我々が記載した["SROS2をセットアップしてみよう"](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/jp/SROS2_setup.md)も参考になります。

### Setup of OpenID Provider (OP)

次に、OpenID Provider（OP）をセットアップする。OPとしてKeycloakを使用する。  
Keycloakは、RDBOXの初期セットアップでインストールする`essentials meta-package`で既にセットアップ済みです。  
Keycloakに対して、`sros2_oidc用のレルム`、`Relaying Prty`、`ユーザ`等を順に追加していく。

手順は、["SROS2_OIDC（Keycloak操作）"](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/jp/keycloak.md)をご確認下さい。

### Copy the sros2_oidc directory to the ROS2 working directory

クローンしたrdboxリポジトリ（insidersブランチ）の中に、`sros2_oidc`のソースコードを含むディレクトリがあります。  
`sros2_oidc`ディレクトリをあなたのROS2用作業ディレクトリにコピーしてください。

```bash
git clone -b insiders https://github.com/rdbox-intec/rdbox
cp -rf ./rdbox/ros2/rdbox ${YOUR_ROS2_WS}/src
```

### Set up a specific value for each user's environment

[OpenID Providr構築時に再確認が必要とした各項目](https://github.com/rdbox-intec/rdbox/blob/insiders/ros2/rdbox/sros2_oidc/docs/jp/keycloak.md#credentials%E3%82%BF%E3%83%96)は、ユーザによって異なるものであるため環境変数として設定する必要がある。

- server_url
- realm_name
- client_id
- client_secret_key
- redirect_url
  - 以下を設定したが、アクセス元に合わせて`localhost` or `ユーザ環境に合わせたFQDN`を選択する。
    - `http://localhost:8080/gettoken`
    - `http://${ユーザ環境に合わせたFQDN}:8080/gettoken`
      - e.g. `http://rdbox.172.16-0-132.nip.io:8080/gettoken`

サンプル： `SROS2_OIDC_OP_`プレフィックスを除いた文字列が、Keycloakでの設定値と対応している。

```bash
export SROS2_OIDC_OP_SERVER_URL=https://keycloak.rdbox.172-16-0-132.nip.io/auth/
export SROS2_OIDC_OP_REALM_NAME=ros2_oidc
export SROS2_OIDC_OP_CLIENT_ID=amcl
export SROS2_OIDC_OP_CLIENT_SECRET_KEY=fkRX4Vb2DdUa1A6tWttQFQawnfv8teNF
export SROS2_OIDC_OP_REDIRECT_URL=http://rdbox.172-16-0-132.nip.io:8080/gettoken
```

### Build the source code

  ```bash
  cd ${YOUR_ROS2_WS}
  sudo pip3 install -r ${YOUR_ROS2_WS}/src/rdbox/sros2_oidc/requirements.txt
  colcon build --packages-select sros2_oidc talker_goal_pose
  ```

## SROS2（for sros2_oidc）

### Generate keystore, keys, certificates

#### Generate a keystore

```bash
$ mkdir ~/sros2_demo
$ cd ~/sros2_demo
$ ros2 security create_keystore demo_keystore
creating keystore: demo_keystore
creating new CA key/cert pair
creating governance file: demo_keystore/enclaves/governance.xml
creating signed governance file: demo_keystore/enclaves/governance.p7s
all done! enjoy your keystore in demo_keystore
cheers!
```

#### Generate keys and certificates for the Talker node

```bash
$ ros2 security create_key demo_keystore /sros2_oidc/jwt_talker
creating key for identity: '/sros2_oidc/jwt_talker'
creating cert and key
creating permission
```

#### Generate keys and certificates for the Listener node

```bash
$ ros2 security create_key demo_keystore /sros2_oidc/jwt_listener
creating key for identity: '/sros2_oidc/jwt_listener'
creating cert and key
creating permission
```

### Define environment variables

必要に応じて`.bashrc`等に追記しておくとよい。

```bash
export ROS_SECURITY_KEYSTORE=~/sros2_demo/demo_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
```

## Let's try sros2_oidc

### Prerequisites

本チュートリアルでは、[Robotis社のTurtleBot3](https://emanual.robotis.com/docs/en/platform/turtlebot3/overview/)を題材として使用させて頂きます。まずはTurtleBot3に関する環境の設定を行います。

- Turtlebot3環境をインストール
  - [TurtleBot3 Quick Start Guide](https://emanual.robotis.com/docs/en/platform/turtlebot3/quick-start/)
  - [TurtleBot3 Simulation](https://emanual.robotis.com/docs/en/platform/turtlebot3/simulation/#gazebo-simulation)

### Launch the simulator

```bash
export TURTLEBOT3_MODEL=burger
ros2 launch turtlebot3_gazebo turtlebot3_world.launch.py
```

### Launch the navigation

```bash
export TURTLEBOT3_MODEL=burger
ros2 launch turtlebot3_navigation2 navigation2.launch.py use_sim_time:=True map:=$HOME/map.yaml
```

### Set initial position with rviz

「2D Pose Estimate」ボタンをクリックして、ロボットの初期位置を入力する。

### Launch the sros2_oidc

#### Relaying Party (RP)

```bash
$ ros2 run sros2_oidc rp --ros-args --remap use_sim_time:=True --enclave /sros2_oidc/jwt_talker
~ omit ~
[INFO] [1653024071.293409261] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/sros2_oidc/jwt_talker
```

#### Resource Server

```bash
$ ros2 run sros2_oidc resource --ros-args -p package_name:='talker_goal_pose' -p executable_name:='goal_pose' --remap use_sim_time:=True --enclave /sros2_oidc/jwt_listener
~ omit ~
[INFO] [1653024090.440248408] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/sros2_oidc/jwt_listener
```

### Access `sros2_oidc's WebUI` from a browser

アクセス元に合わせて`localhost` or `ユーザ環境に合わせたFQDN`を選択し、ブラウザからアクセスする。

- `http://localhost:8080/`
- `http://${ユーザ環境に合わせたFQDN}:8080/`
  - e.g. `http://rdbox.172.16-0-132.nip.io:8080/`

以下のような画面が表示されるので、「ログイン」する。

  ![UI_Home.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_Home.jpg)

ログインでは、Keycloakの作成したrealmが用意したログイン画面にリダイレクトされるため、必要な情報を入力し、ログイン操作を実施する。

  ![UI_Keycloak_login.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_Keycloak_login.jpg)

sros2_oidcのRPに初回ログインした時には、連携する情報について同意を求める画面が表示されます（今回はlocation）。続けるためには同意が必要です。

  ![GrantPage.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/GrantPage.jpg)

ログイン及び、同意が取れた場合は、ユーザに許可されたサービスが表示されます。「Come to me!!」ボタンをクリックすると[冒頭の動画](https://user-images.githubusercontent.com/40556102/169439356-1eccb2bc-7004-42bd-8611-8813a87c739b.mp4)のように、ロボットを移動させることができます。

  ![UI_ServiceList.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_ServiceList.jpg)

この時、`Resource Server`はユーザ属性内容を解釈し、以下のように位置情報を取り出せていることがわかります。

  ```bash
  $ ros2 run sros2_oidc resource --ros-args --remap use_sim_time:=True --enclave /sros2_oidc/jwt_listener
  ~ omit ~
  [INFO] [1653024090.440248408] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/sros2_oidc/jwt_listener
  ~ omit ~
  [INFO] [1653028094.165181655] [jwt_listener]: Accept: [3.0,2.3]
  ```

## Technology

Comming Soon!!

## Roadmap

- [x] 各設定をコード直書きから、環境変数 or 設定ファイルで実施できるようにする
- [x] JWTをString.msgで受け取ってから、任意のROS Message形式に変換できるようにする
- [ ] 高速なレスポンスが欲しい場合のオプションを用意する（トークンイントロスペクションではなく、ローカルで検証する方法の実装）
- [ ] 全経路の完全な暗号化

## Licence

Licensed under the [MIT](https://github.com/rdbox-intec/rdbox/blob/insiders/LICENSE) license.
