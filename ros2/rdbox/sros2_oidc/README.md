# SROS2 with OIDC(OpenID Connect) - Technology for robots to authenticate and authorize a human

[Japanese README](/ros2/rdbox/sros2_oidc/README.ja.md)

## Video

<!-- markdownlint-disable MD034 -->
https://user-images.githubusercontent.com/40556102/170811723-17f9c6eb-4f3b-41bd-8b64-799535ce5009.mp4

## System component

The following figure is assumed to move a mobile robot based on "user attributes (only the location)".

![system architecture.jpeg](/ros2/rdbox/sros2_oidc/docs/imgs/EN_system_architecture.jpeg)

Organize the flow of information, focusing on entities that are associated with ROS engineers.

### Entities

- Terminal
  - Web browser (PC / Phone / on a robot)
- Relaying Party
  - A http server
    - Registered in the OP
  - A node of the ROS
    - Publish a OIDC access token
- Resource Server
  - A node of the ROS
    - Subscribe a OIDC access token
- OIDC Access Token
  - Authority to access user attributes
  - Effective only for a very short time
  - JWT format: Header, Payload, Signature are encoded separately using Base64url Encoding, and concatenated using periods

### Flow of information

1. Terminal: Authenticate the user. Then check user's Authorization.
   - Permission
   - Grant (by the agreement page)
2. Relaying Party: Receive a OIDC access token (JWT format) and publish it as a SROS2 topic (msgs.String)
3. Resource Server: Receive a OIDC access token and verify it by querying the OP.
4. Resource Server: Retrieve (location) information. Then move a mobile robot based on "user attribute (location)”
   - Retrieve a (location) information from: including in a token / querying the OP

### Authorization Code Flow

The OIDC Authorization Code Flow is typically explained difficult commentary.  
Therefore, the figure below was arranged using ROS entities.

![OIDC_Flow.png](/ros2/rdbox/sros2_oidc/docs/imgs/OIDC_Flow.png)

It is noteworthy that no personal information is received to the ROS node.

- Receive only very short time tokens
- Delegate authn/authz by full use of the http redirects
- Not even passing a access token to user's terminal

## Environment Building Steps

### Setup of SROS2

Prepare a "ROS2 Foxy" environment in which SROS2 runs.

You can also refer to our article ["Let's Set Up the SROS2"](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/en/SROS2_setup.md) for instructions.

Please check [ros2/sros2: GitHub](https://github.com/ros2/sros2) for the latest instructions and technical details.

### Setup of OpenID Provider (OP)

Next, set up an OpenID Provider (OP). Use Keycloak as OP.  
Keycloak is already set up in the `essentials meta-package` installed with the [initial setup of RDBOX](https://github.com/rdbox-intec/rdbox/tree/insiders).  
（This tutorial assumes that the [initial setup of RDBOX](https://github.com/rdbox-intec/rdbox/tree/insiders) has been completed.）  
In this tutorial, `Realm` for sros2_oidc, `Relaying Party`, `User`, etc. will be added to the Keycloak.

Please check [SROS2_OIDC (Keycloak operation)](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/en/keycloak.md) for the instructions.

### Copy the sros2_oidc directory to the ROS2 working directory

In the rdbox repository (insiders branch) that you cloned, you will find a directory containing the source code for `sros2_oidc`.  
Copy the `sros2_oidc` directory to your working directory for ROS2.

```bash
git clone -b insiders https://github.com/rdbox-intec/rdbox
cp -rf ./rdbox/ros2/rdbox ${YOUR_ROS2_WS}/src
```

### Set up a specific value for each user's environment

[Each item reconfirmed at the time of OpenID Providr construction](https://github.com/rdbox-intec/rdbox/blob/insiders/ros2/rdbox/sros2_oidc/docs/en/keycloak.md#credentials%20tab), the contents will vary from user to user. Therefore, they need to be set as environment variables.

- server_url
- realm_name
- client_id
- client_secret_key
- redirect_url
  - Select `localhost` or `FQDNs for user environments` as appropriate for the access source.
    - `http://localhost:8080/gettoken`
    - `http://${FQDNs for user environments}:8080/gettoken`
      - e.g. `http://rdbox.172.16-0-132.nip.io:8080/gettoken`

```bash
export SROS2_OIDC_OP_SERVER_URL=https://keycloak.rdbox.172-16-0-132.nip.io/
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

```bash
export ROS_SECURITY_KEYSTORE=~/sros2_demo/demo_keystore
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
```

## Let's try sros2_oidc

### Prerequisites

In this tutorial, we will use [Robotis' TurtleBot3](https://emanual.robotis.com/docs/en/platform/turtlebot3/overview/) as our subject matter. overwhelming gratitude!!  
First, we will set up the environment for TurtleBot3.

- Official Documentations
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

Click the "2D Pose Estimate" button to input the initial position of the robot.

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

Access from a browser.  
Select `localhost` or `FQDNs for user environments` as appropriate for the access source.

- `http://localhost:8080/`
- `http://${FQDNs for user environments}:8080/`
  - e.g. `http://rdbox.172.16-0-132.nip.io:8080/`

The following screen will be displayed, so log in.

  ![UI_Home.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_Home.jpg)

Clicking the `Login link` will redirect you to the `Login screen` provided by the Keycloak-created realm.  
Enter the required information and conduct the login operation.

  ![UI_Keycloak_login.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_Keycloak_login.jpg)

When you log in to sros2_oidc's RP for the first time, you will be asked to grant permission for the information to be linked (in this case, location).  
Grant access to continue learning.

  ![GrantPage.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/GrantPage.jpg)

If agreement is obtained from the user, the services authorized to the user will be displayed.  
Clicking on the "Come to me!" link to move the robot, as shown in the [video](https://user-images.githubusercontent.com/40556102/169439356-1eccb2bc-7004-42bd-8611-8813a87c739b.mp4) at the beginning of this article.

  ![UI_ServiceList.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/UI_ServiceList.jpg)

At this time, the `Resource Server` is retrieved as user attributes (location information).  
(as in the stdout shown in the example)

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

- [x] Enable each setting to be implemented in environment variables or configuration files instead of writing directly in code
- [x] To be able to receive JWT in String.msg and then convert it to any ROS Message format
- [ ] Provide an option if a fast response is desired (implement a local verification method instead of token introspection)
- [ ] Full encryption of all routes

## Licence

Licensed under the [MIT](https://github.com/rdbox-intec/rdbox/blob/insiders/LICENSE) license.
