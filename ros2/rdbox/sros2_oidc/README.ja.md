# SROS2 with OIDC(OpenID Connect) ：ロボットが安全に人を識別するための技術

[English README](/ros2/rdbox/sros2_oidc/README.md)

## Video

<!-- markdownlint-disable MD034 -->
https://user-images.githubusercontent.com/40556102/169439356-1eccb2bc-7004-42bd-8611-8813a87c739b.mp4

## System component

下図は、「ユーザー属性（位置のみ）」に基づいて移動ロボットを動かすことを想定しています。

![system architecture.png](/ros2/rdbox/sros2_oidc/docs/imgs/JP_system_architecture.jpeg)

ROSエンジニアに関連するエンティティを中心に、情報の流れを整理する。

### Entities

- Terminal
  - Webブラウザ (PC / Phone / on a robot)
- Relaying Party
  - HTTPサーバー
    - 既にOPに登録されている
  - ROSノード
    - OIDCアクセストークンをPublishする
- Resource Server
  - ROSノード
    - OIDCアクセストークンをSubscribeする
- OIDC Access Token
  - ユーザー属性にアクセスするための権限
  - ごく短時間のみ有効
  - JWT format: ヘッダー、ペイロード、シグネチャはそれぞれBase64urlエンコーディングで別々にエンコードされ、ピリオドで連結される

### Flow of information

1. Terminal: ユーザーを認証します。次に、ユーザーの認証を確認します。
   - （管理者からの）許可
   - （本人からの）同意 (by the agreement page)
2. Relaying Party: OIDCアクセストークン(JWT形式)を受け取り、SROS2トピック(msgs.String)として公開する
3. Resource Server: OIDCアクセストークンを受け取り、OPに問い合わせることで検証する。
4. Resource Server: (位置)情報を取り出す。そして、"ユーザー属性（位置）"に基づいて移動ロボットを動かす
   -(位置)情報を取得する方法: トークンに含める / OPに問い合わせる

### Authorization Code Flow

OIDC Authorization Code Flowは、一般的に難しい解説がされています。  
したがって、下図はROSエンティティを用いてアレンジした。

![OIDC_Flow.png](/ros2/rdbox/sros2_oidc/docs/imgs/OIDC_Flow.png)

特筆すべきは、ROSノードが個人情報を受信することはない点である。

- ごく短時間のトークンしか受け取らない
- httpリダイレクトを駆使して認証・認可を委譲する
- ユーザー端末にアクセストークンを渡すこともしない

## 構築手順

### SROS2のセットアップ

SROS2が動くROS2 Foxy環境を準備します。

手順は、我々が記載した["SROS2をセットアップしてみよう"](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/jp/SROS2_setup.md)も参考になります。  
最新の手順及び、技術的な詳細は、[ros2/sros2: GitHub](https://github.com/ros2/sros2)をご確認下さい。

### OpenID Provider（OP, Keycloakを使用）のセットアップ

次に、OpenID Provider(OP)を設定します。OPとしてKeycloakを使用します。  
Keycloakは、[RDBOXの初期セットアップ](https://github.com/rdbox-intec/rdbox/tree/insiders)にてインストールする`essentials meta-package`で既にセットアップ済みです。  
（このチュートリアルは、[RDBOXの初期セットアップ](https://github.com/rdbox-intec/rdbox/tree/insiders)が完了している前提で記載してあります。）  
このチュートリアルでは、Keycloakに対して、`sros2_oidc用のレルム`、`Relaying Party`、`ユーザ`等を順に追加していく。

手順は、["SROS2_OIDC（Keycloak操作）"](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/jp/keycloak.md)をご確認下さい。

### ソースコード

#### コピーしてください

クローンした`sros2_oidc`のソースコードを含むrdboxディレクトリを、あなたのROS2用作業ディレクトリにコピーしてください。

```bash
git clone --recursive -b insiders https://github.com/rdbox-intec/rdbox
cp -rf ./rdbox/ros2/rdbox ${YOUR_ROS2_WS}/src
```

### 環境固有設定

[OpenID Providr構築時に再確認が必要とした各項目](https://github.com/rdbox-intec/rdbox/blob/insiders/ros2/rdbox/sros2_oidc/docs/jp/keycloak.md#credentials%E3%82%BF%E3%83%96)は、内容がユーザによって異なる。そのため環境変数として設定する必要がある。

- server_url
- realm_name
- client_id
- client_secret_key
- redirect_url
  - 以下を設定したが、アクセス元に合わせて`localhost` or `ユーザ環境に合わせたFQDN`を選択する。
    - `http://localhost:8080/gettoken`
    - `http://${ユーザ環境に合わせたFQDN}:8080/gettoken`
      - e.g. `http://rdbox.172.16-0-132.nip.io:8080/gettoken`

```bash
export SROS2_OIDC_OP_SERVER_URL=https://keycloak.rdbox.172-16-0-132.nip.io/
export SROS2_OIDC_OP_REALM_NAME=ros2_oidc
export SROS2_OIDC_OP_CLIENT_ID=amcl
export SROS2_OIDC_OP_CLIENT_SECRET_KEY=fkRX4Vb2DdUa1A6tWttQFQawnfv8teNF
export SROS2_OIDC_OP_REDIRECT_URL=http://rdbox.172-16-0-132.nip.io:8080/gettoken
```

### ビルド

  ```bash
  cd ${YOUR_ROS2_WS}
  colcon build --packages-select sros2_oidc talker_goal_pose
  ```

## SROS2（for sros2_oidc）

### このデモで必要なファイル用のフォルダを作成

これから、このデモに必要なすべてのファイルを格納するフォルダを作成します。

```bash
mkdir ~/sros2_demo
```

### キーストア、鍵、証明書の生成

#### Generate a keystore

```bash
$ cd ~/sros2_demo
$ ros2 security create_keystore demo_keystore
creating keystore: demo_keystore
creating new CA key/cert pair
creating governance file: demo_keystore/enclaves/governance.xml
creating signed governance file: demo_keystore/enclaves/governance.p7s
all done! enjoy your keystore in demo_keystore
cheers!
```

#### TalkerとListenerのノードの鍵や証明書を生成

※FoxyはReadme.mdが違うので注意。絶対にBranchを確認すること

```bash
$ ros2 security create_key demo_keystore /sros2_oidc/jwt_talker
creating key for identity: '/sros2_oidc/jwt_talker'
creating cert and key
creating permission
```

```bash
$ ros2 security create_key demo_keystore /sros2_oidc/jwt_listener
creating key for identity: '/sros2_oidc/jwt_listener'
creating cert and key
creating permission
```

### 環境変数定義

```bash
export ROS_SECURITY_KEYSTORE=~/sros2_demo/demo_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
```

## sros2_oidcのデモ

### 事前準備

本チュートリアルでは、[Robotis社のTurtleBot3](https://emanual.robotis.com/docs/en/platform/turtlebot3/overview/)を題材として使用させて頂きます。まずはTurtleBot3に関する環境の設定を行います。

- Turtlebot3環境をインストール
  - [TurtleBot3 Quick Start Guide](https://emanual.robotis.com/docs/en/platform/turtlebot3/quick-start/)
  - [TurtleBot3 Simulation](https://emanual.robotis.com/docs/en/platform/turtlebot3/simulation/#gazebo-simulation)

### シミュレータを起動

```bash
export TURTLEBOT3_MODEL=burger
ros2 launch turtlebot3_gazebo turtlebot3_world.launch.py
```

### ナビゲーションを起動

```bash
export TURTLEBOT3_MODEL=burger
ros2 launch turtlebot3_navigation2 navigation2.launch.py use_sim_time:=True map:=$HOME/map.yaml
```

### rvizで初期位置を設定

「2D Pose Estimate」ボタンをクリックして、ロボットの初期位置を入力する。

### sros2_oidcを起動

#### RP

```bash
$ ros2 run sros2_oidc rp --ros-args --remap use_sim_time:=True --enclave /sros2_oidc/jwt_talker
~ omit ~
[INFO] [1653024071.293409261] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/sros2_oidc/jwt_talker
```

#### ResourceServer

```bash
$ ros2 run sros2_oidc resource --ros-args -p package_name:='talker_goal_pose' -p executable_name:='goal_pose' --remap use_sim_time:=True --enclave /sros2_oidc/jwt_listener
~ omit ~
[INFO] [1653024090.440248408] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/sros2_oidc/jwt_listener
```

### ブラウザから`sros2_oidcのWebUI`にアクセスする

アクセス元に合わせて`localhost` or `ユーザ環境に合わせたFQDN`を選択し、ブラウザからアクセスする。

- `http://localhost:8080/`
- `http://${ユーザ環境に合わせたFQDN}:8080/`
  - e.g. `http://rdbox.172.16-0-132.nip.io:8080/`

以下のような画面が表示されるので、「ログイン」する。

  ![UI_Home.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_Home.jpg)

「ログイン」リンクをクリックすると、Keycloakの作成したrealmが用意したログイン画面にリダイレクトされます。  
必要な情報を入力し、ログイン操作を実施する。

  ![UI_Keycloak_login.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_Keycloak_login.jpg)

sros2_oidcのRPに初回ログインした時には、連携する情報について同意を求める画面が表示されます（今回はlocation）。  
学習を続けるため、アクセス許可を与えます。

  ![GrantPage.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/GrantPage.jpg)

ログイン及び、同意が取れた場合は、ユーザに許可されたサービスが表示されます。「Come to me!!」リンクをクリックすると[冒頭の動画](https://user-images.githubusercontent.com/40556102/169439356-1eccb2bc-7004-42bd-8611-8813a87c739b.mp4)のように、ロボットを移動させることができます。

  ![UI_ServiceList.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_ServiceList.jpg)

この時、`Resource Server`はユーザ属性内容を解釈し、以下のように位置情報を取り出せていることがわかります。

  ```bash
  $ ros2 run sros2_oidc resource --ros-args --remap use_sim_time:=True --enclave /sros2_oidc/jwt_listener
  ~ omit ~
  [INFO] [1653024090.440248408] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/sros2_oidc/jwt_listener
  ~ omit ~
  [INFO] [1653028094.165181655] [jwt_listener]: Accept: [3.0,2.3]
  ```

## 技術解説

Comming Soon!!

## ロードマップ

- [x] 各設定をコード直書きから、環境変数 or 設定ファイルで実施できるようにする
- [x] JWTをString.msgで受け取ってから、任意のROS Message形式に変換できるようにする
- [ ] 高速なレスポンスが欲しい場合のオプションを用意する（トークンイントロスペクションではなく、ローカルで検証する方法の実装）
- [ ] 全経路の完全な暗号化

## Licence

Licensed under the [MIT](https://github.com/rdbox-intec/rdbox/blob/insiders/LICENSE) license.
