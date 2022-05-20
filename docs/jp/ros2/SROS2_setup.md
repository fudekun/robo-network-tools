# SROS2をセットアップしてみよう

## 参考とした一次資料

本記事では、公式ドキュメントを参照しながら環境構築した際に、感じた過不足やそもそもの誤りを補記したものとなっている。

- [ros2/sros2: tools to generate and distribute keys for SROS 2](https://github.com/ros2/sros2)
- [Building ROS 2 on Ubuntu Linux — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/Ubuntu-Development-Setup.html)
- [Working with eProsima Fast DDS — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/DDS-Implementations/Working-with-eProsima-Fast-DDS.html)

また、本手順は、以下の環境でのテストを実施しました（2022-05-12）。  
いずれも**amd64** 環境です。

- Ubuntu 20.04.4
  - 5.13.0-41-generic
  - ROS2 Foxy
  - FastDDS

## ROS2の公式手順に則り環境構築

### DebianパッケージでFoxyをインストール

- [Installing ROS 2 via Debian Packages — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/Ubuntu-Install-Debians.html)
- 気をつけなければ行けないのがGPGキーのURLが古いママになっているので最新のやつを使うように。
  - [ROS Discourse](https://discourse.ros.org/t/ros-gpg-key/20671)

  ```bash
  sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key -o /usr/share/keyrings/ros-archive-keyring.gpg
  ```

- rosdepをセットアップ

  ```bash
  sudo apt install python3-rosdep2
  rosdep update
  ```

- colconをセットアップ
  - colcon は ROS ビルドツール `catkin_make`, `catkin_make_isolated`, `catkin_tools` および `ament_tools` のイテレーションです。colconの設計の詳細については、[このドキュメント](https://design.ros2.org/articles/build_tool.html)を参照してください。

  ```bash
  sudo apt install python3-colcon-common-extensions
  ```

### ワークスペースを作る

[Creating a workspace — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Tutorials/Workspace/Creating-A-Workspace.html)

```bash
cd ~
mkdir -p ~/ros2_ws/src
cd ~/ros2_ws/src
# なにかソースコードがあればsrcに保存する
cd ..
colcon build
```

### Foxyソースコードをビルドできるようにする

[Building ROS 2 on Ubuntu Linux — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/Ubuntu-Development-Setup.html)

#### Install development tools and ROS tools

```bash
sudo apt update && sudo apt install -y \
  build-essential \
  cmake \
  git \
  libbullet-dev \
  python3-colcon-common-extensions \
  python3-flake8 \
  python3-pip \
  python3-pytest-cov \
  python3-rosdep \
  python3-setuptools \
  python3-vcstool \
  wget
# install some pip packages needed for testing
python3 -m pip install -U \
  argcomplete \
  flake8-blind-except \
  flake8-builtins \
  flake8-class-newline \
  flake8-comprehensions \
  flake8-deprecated \
  flake8-docstrings \
  flake8-import-order \
  flake8-quotes \
  pytest-repeat \
  pytest-rerunfailures \
  pytest
 # install Fast-RTPS dependencies
sudo apt install --no-install-recommends -y \
  libasio-dev \
  libtinyxml2-dev
# install Cyclone DDS dependencies
sudo apt install --no-install-recommends -y \
  libcunit1-dev
```

#### ROSコード取得

```bash
mkdir -p ~/ros2_ws/src
cd ~/ros2_ws
wget https://raw.githubusercontent.com/ros2/ros2/foxy/ros2.repos
vcs import src < ros2.repos
```

#### rosdepを使った依存関係のインストール

```bash
sudo rosdep init
rosdep update
rosdep install --from-paths src --ignore-src -y --skip-keys "fastcdr rti-connext-dds-5.3.1 urdfdom_headers"
```

注意: (Linux Mint のような) Ubuntu ベースのディストリビューションを使っ ていて、そのディストリビューションであることが分からない場合、`Unsupported OS [mint]`  のようなエラーメッセージが表示されます。この場合、上記のコマンドに  `--os=ubuntu:focal` を追加してください。

#### 追加DDS実装のインストール

デフォルトのeProsimaのFast RTPS以外のDDSまたはRTPSベンダーを使用したい場合は、[こちら](https://docs.ros.org/en/foxy/Installation/DDS-Implementations.html)で手順を確認できます。

**※注意1**  
ROS 2 を別の方法で既にインストールしている場合 (Debians またはバイナリ配布)、`colcon build --symlink-install`を他のインストールをソースとしない新しい環境で実行することを確認してください。

- **.bashrc に source `/opt/ros/${ROS_DISTRO}/setup.bash` がないことを確認してください**
- **ROS 2がソースになっていないことは、printenv | grep -i ROSというコマンドで確認することができます。出力は空であるべきです。**

**※注意2**  
すべてのサンプルのコンパイルに問題があり、そのためにビルドが成功しない場合、[CATKIN_IGNORE](https://github.com/ros-infrastructure/rep/blob/master/rep-0128.rst) と同じ方法で `COLCON_IGNORE` を使用してサブツリーを無視したり、ワークスペースからフォルダーを削除したりすることが可能です。例えば、大きなOpenCVライブラリのインストールを避けたい場合です。例えば、大きな OpenCV ライブラリのインストールを避けたい場合、`cam2image` デモ・ディレクトリで `touch COLCON_IGNORE` を実行し、ビルド・プロセスからそれを除外するだけです。

#### 追加DDSとして、FastDDSを「Securityモード」でインストールする

- 参考1：[Working with eProsima Fast DDS — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/DDS-Implementations/Working-with-eProsima-Fast-DDS.html)
  - 今回は特に「Build from source codeを参照」
- 参考2：[8\. Security — Fast DDS 2\.6\.0 documentation](https://fast-dds.docs.eprosima.com/en/latest/fastdds/security/security.html)
  > デフォルトでは、Fast DDS はセキュリティサポートを一切コンパイルしませんが、CMake の設定ステップで -DSECURITY=ON を追加して有効にすることができます。Fast DDS のコンパイルに関する詳細は、「ソースからの Linux インストール」および「ソースからの Windows インストール」を参照してください。

rosdep指定以外の依存パッケージをインストール・設定する

```bash
sudo apt install cmake g++ python3-pip wget git
sudo apt install libasio-dev libtinyxml2-dev \
  libp11-dev libengine-pkcs11-openssl \
  softhsm2 \
  libengine-pkcs11-openssl

sudo usermod -a -G softhsm $USER
p11-kit list-modules
openssl engine pkcs11 -t
```

最後に、colcon buildを実行します。

```bash
colcon build --symlink-install --parallel-workers 4 --cmake-args -DSECURITY=ON
```

## デモを動かしてみる

[sros2/SROS2\_Linux\.md at master · ros2/sros2](https://github.com/ros2/sros2/blob/master/SROS2_Linux.md)

### このデモで必要なファイル用のフォルダを作成します

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

Keystore作成後のディレクトリ構成は以下の通りとなる。

```bash
$ tree
.
└── demo_keystore
    ├── enclaves
    │   ├── governance.p7s
    │   └── governance.xml
    ├── private
    │   ├── ca.key.pem
    │   ├── identity_ca.key.pem -> ca.key.pem
    │   └── permissions_ca.key.pem -> ca.key.pem
    └── public
        ├── ca.cert.pem
        ├── identity_ca.cert.pem -> ca.cert.pem
        └── permissions_ca.cert.pem -> ca.cert.pem

4 directories, 8 files
```

#### TalkerとListenerのノードの鍵や証明書を生成する

※FoxyはReadme.mdが違うので注意。絶対にBranchを確認すること

```bash
$ ros2 security create_key demo_keystore /talker_listener/talker
creating key for identity: '/talker_listener/talker'
creating cert and key
creating permission
```

```bash
$ tree
.
└── demo_keystore
    ├── enclaves
    │   ├── governance.p7s
    │   ├── governance.xml
    │   └── talker_listener
    │       └── talker
    │           ├── cert.pem
    │           ├── governance.p7s -> ../../governance.p7s
    │           ├── identity_ca.cert.pem -> ../../../public/identity_ca.cert.pem
    │           ├── key.pem
    │           ├── permissions_ca.cert.pem -> ../../../public/permissions_ca.cert.pem
    │           ├── permissions.p7s
    │           └── permissions.xml
    ├── private
    │   ├── ca.key.pem
    │   ├── identity_ca.key.pem -> ca.key.pem
    │   └── permissions_ca.key.pem -> ca.key.pem
    └── public
        ├── ca.cert.pem
        ├── identity_ca.cert.pem -> ca.cert.pem
        └── permissions_ca.cert.pem -> ca.cert.pem

6 directories, 15 files
```

```bash
$ ros2 security create_key demo_keystore /talker_listener/listener
creating key for identity: '/talker_listener/listener'
creating cert and key
creating permission
```

```bash
$ tree
.
└── demo_keystore
    ├── enclaves
    │   ├── governance.p7s
    │   ├── governance.xml
    │   └── talker_listener
    │       ├── listener
    │       │   ├── cert.pem
    │       │   ├── governance.p7s -> ../../governance.p7s
    │       │   ├── identity_ca.cert.pem -> ../../../public/identity_ca.cert.pem
    │       │   ├── key.pem
    │       │   ├── permissions_ca.cert.pem -> ../../../public/permissions_ca.cert.pem
    │       │   ├── permissions.p7s
    │       │   └── permissions.xml
    │       └── talker
    │           ├── cert.pem
    │           ├── governance.p7s -> ../../governance.p7s
    │           ├── identity_ca.cert.pem -> ../../../public/identity_ca.cert.pem
    │           ├── key.pem
    │           ├── permissions_ca.cert.pem -> ../../../public/permissions_ca.cert.pem
    │           ├── permissions.p7s
    │           └── permissions.xml
    ├── private
    │   ├── ca.key.pem
    │   ├── identity_ca.key.pem -> ca.key.pem
    │   └── permissions_ca.key.pem -> ca.key.pem
    └── public
        ├── ca.cert.pem
        ├── identity_ca.cert.pem -> ca.cert.pem
        └── permissions_ca.cert.pem -> ca.cert.pem

7 directories, 22 files
```

### 環境変数定義

```bash
export ROS_SECURITY_KEYSTORE=~/sros2_demo/demo_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
```

### 動かしてみよう

#### Talker

コマンドのはじめにセキュリティ・ディレクトリがあることが報告される。

```bash
$ ros2 run demo_nodes_cpp talker --ros-args --enclave /talker_listener/talker
[INFO] [1652340512.392429650] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/talker_listener/talker
[INFO] [1652340513.450340516] [talker]: Publishing: 'Hello World: 1'
[INFO] [1652340514.449367459] [talker]: Publishing: 'Hello World: 2'
[INFO] [1652340515.449664188] [talker]: Publishing: 'Hello World: 3'
```

#### Listener

```bash
ros2 run demo_nodes_py listener --ros-args --enclave /talker_listener/listener
[INFO] [1652340696.157994402] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/talker_listener/listener
[INFO] [1652340696.461833794] [listener]: I heard: [Hello World: 184]
[INFO] [1652340697.444044110] [listener]: I heard: [Hello World: 185]
[INFO] [1652340698.445647789] [listener]: I heard: [Hello World: 186]
```

#### その他雑感

- Topic Listには何も出ない（隠匿されている）
- データサイズが大きくなる（3倍ぐらい）306 -> 916
