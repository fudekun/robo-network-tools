# Let's Set Up the SROS2

## Reference

This article is a supplement to the excesses and errors felt in the official tutorial.

- [ros2/sros2: tools to generate and distribute keys for SROS 2](https://github.com/ros2/sros2)
- [Building ROS 2 on Ubuntu Linux — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/Ubuntu-Development-Setup.html)
- [Working with eProsima Fast DDS — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/DDS-Implementations/Working-with-eProsima-Fast-DDS.html)

We tested in the following environments (May 12, 2022)  
Both are **amd64** environments.

- Ubuntu 20.04.4
  - 5.13.0-41-generic
  - ROS2 Foxy
  - FastDDS

## Environment Building Steps

### Install Foxy with Debian package

1. [Installing ROS 2 via Debian Packages — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/Ubuntu-Install-Debians.html)
   - NOTE - The URL for the GPG key described in the official documentation is out of date. Please change it to use the latest one.
      > [ROS Discourse](https://discourse.ros.org/t/ros-gpg-key/20671)

      ```bash
      sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key -o /usr/share/keyrings/ros-archive-keyring.gpg
      ```

2. Setup rosdep
   - Note - rosdep is a command-line tool for installing system dependencies.
     > [ros\-infrastructure/rosdep: rosdep multi\-package manager system dependency tool](https://github.com/ros-infrastructure/rosdep)

   ```bash
   sudo apt install python3-rosdep2
   rosdep update
   ```

3. Setup colcon
   - NOTE - colcon is an iteration of the ROS build tools `catkin_make`, `catkin_make_isolated`, `catkin_tools` and `ament_tools`.
      > [design.ros2.org](https://design.ros2.org/articles/build_tool.html)

      ```bash
      sudo apt install python3-colcon-common-extensions
      ```

### Creating a workspace

[Creating a workspace — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Tutorials/Workspace/Creating-A-Workspace.html)

```bash
cd ~
mkdir -p ~/ros2_ws/src
cd ~/ros2_ws
colcon build
```

### Build Foxy source code

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

#### Get the source code

```bash
mkdir -p ~/ros2_ws/src
cd ~/ros2_ws
wget https://raw.githubusercontent.com/ros2/ros2/foxy/ros2.repos
vcs import src < ros2.repos
```

#### Install dependencies using rosdep

```bash
sudo rosdep init
rosdep update
rosdep install --from-paths src --ignore-src -y --skip-keys "fastcdr rti-connext-dds-5.3.1 urdfdom_headers"
```

#### Install a DDS Implementation

If you want to use a DDS or RTPS vendor other than the default eProsima Fast RTPS, you can find instructions [here](https://docs.ros.org/en/foxy/Installation/DDS-Implementations.html).

**Important NOTE**  
The `colcon build --symlink-install` command should be run in a new environment that does not source other installations.

- **Make sure your `.bashrc` does not include `source /opt/ros/${ROS_DISTRO}/setup.bash`**
- **You can verify that the installed ROS2 is not the source with the command `printenv | grep -i ROS`**
  - The output should be empty

#### Install FastDDS in Security Mode

- [Working with eProsima Fast DDS — ROS 2 Documentation: Foxy documentation](https://docs.ros.org/en/foxy/Installation/DDS-Implementations/Working-with-eProsima-Fast-DDS.html)
  - Please read "Build from source code" in this study.
- [8\. Security — Fast DDS 2\.6\.0 documentation](https://fast-dds.docs.eprosima.com/en/latest/fastdds/security/security.html)
  > By default, Fast DDS does not compile any security support, but it can be activated adding `-DSECURITY=ON` at CMake configuration step. For more information about Fast DDS compilation, see [Linux installation from sources](https://fast-dds.docs.eprosima.com/en/latest/installation/sources/sources_linux.html#linux-sources) and [Windows installation from sources](https://fast-dds.docs.eprosima.com/en/latest/installation/sources/sources_windows.html#windows-sources).

##### Install and configure dependent packages

Resolves dependencies that rosdep cannot resolve.

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

Finally, execute `colcon build`.

```bash
colcon build --symlink-install --cmake-args -DSECURITY=ON
```

## Running samples

[sros2/SROS2\_Linux\.md at master · ros2/sros2](https://github.com/ros2/sros2/blob/master/SROS2_Linux.md)

### Create a folder for the files needed for this demo

Create a directory to store key files, etc.

```bash
mkdir ~/sros2_demo
```

### Keystore, key, and certificate generation

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

The directory structure after keystore creation will be as follows.

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

#### Generate keys and certificates for Talker and Listener nodes

The contents of Foxy's README.md have been substantially revised from the contents of master's README.md.  
Check the Branch when referring to official documentation.

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

### Environment Variables

```bash
export ROS_SECURITY_KEYSTORE=~/sros2_demo/demo_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
```

### Let's try it

#### Talker

The output to stdout reports that a security directory has been detected.
> [rcl]: Found security directory:

```bash
$ ros2 run demo_nodes_cpp talker --ros-args --enclave /talker_listener/talker
[INFO] [1652340512.392429650] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/talker_listener/talker
[INFO] [1652340513.450340516] [talker]: Publishing: 'Hello World: 1'
[INFO] [1652340514.449367459] [talker]: Publishing: 'Hello World: 2'
[INFO] [1652340515.449664188] [talker]: Publishing: 'Hello World: 3'
```

#### Listener

The output to stdout reports that a security directory has been detected.
> [rcl]: Found security directory:

```bash
ros2 run demo_nodes_py listener --ros-args --enclave /talker_listener/listener
[INFO] [1652340696.157994402] [rcl]: Found security directory: /home/ubuntu/sros2_demo/demo_keystore/enclaves/talker_listener/listener
[INFO] [1652340696.461833794] [listener]: I heard: [Hello World: 184]
[INFO] [1652340697.444044110] [listener]: I heard: [Hello World: 185]
[INFO] [1652340698.445647789] [listener]: I heard: [Hello World: 186]
```
