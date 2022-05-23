<!-- markdownlint-disable MD033 -->
<h1><img alt="RDBOX(A Robotics Developers BOX)" title="RDBOX(A Robotics Developers BOX)" src="./images/logo-rdbox.png" align="right" width=125px></img></h1>

# RDBOX (A Robotics Developers BOX)

**[The insider preview is now available (in the "insiders" branch)](https://github.com/rdbox-intec/rdbox/tree/insiders)**

RDBOX is an advanced IT platform for robotics and IoT developers that highly integrates cloud-native and edge computing technologies.  

[![CircleCI](https://circleci.com/gh/rdbox-intec/image-builder-rpi.svg?style=svg)](https://circleci.com/gh/rdbox-intec/image-builder-rpi)
[![RDBOX App Market](https://github.com/rdbox-intec/script_for_rdbox_app_market/workflows/RDBOX%20App%20Market/badge.svg)](https://github.com/rdbox-intec/script_for_rdbox_app_market/actions?query=workflow%3A%22RDBOX+App+Market%22)
[![RDBOX Middleware Build and Deploy](https://github.com/rdbox-intec/rdbox-middleware/workflows/RDBOX%20Middleware%20Build%20and%20Deploy/badge.svg)](https://github.com/rdbox-intec/rdbox-middleware/actions?query=workflow%3A%22RDBOX+Middleware+Build+and+Deploy%22)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/287bfe44a78d46c6aaecd1a31ca407c0)](https://www.codacy.com/gh/rdbox-intec/rdbox-middleware/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=rdbox-intec/rdbox-middleware&amp;utm_campaign=Badge_Grade)
[![Github Release](https://img.shields.io/github/release/rdbox-intec/rdbox.svg)](https://github.com/rdbox-intec/rdbox/releases)
[![JFrog](https://img.shields.io/badge/JFrog-ready-green)](https://rdbox0intec.jfrog.io/ui/packages?name=rdbox&type=packages)

RDBOX makes "cloud-native technologies and ideas" more accessible by encompassing "the base fundamental technologies".  
<img src="./images/RDBOX_OverViews.jpg" title="./images/you_can_easily_make_by_rdbox.png" width=600px></img>

To get started, Please prepare [RaspberryPi](https://www.raspberrypi.org/) and [AWS](https://github.com/rdbox-intec/rdbox/wiki/tutorials-en#aws) or [Azure](https://github.com/rdbox-intec/rdbox/wiki/tutorials-en#azure) or [Google Cloud Platform](https://github.com/rdbox-intec/rdbox/wiki/tutorials-en#google-cloud-platform-gcp) or [Laptop(With Vagrant)](https://github.com/rdbox-intec/rdbox/wiki/tutorials-en#virutalbox).  
Don’t be surprised, there IT infrastructure is **built automatically** and **maintained automatically**.  
[(DETAIL: Effect on you)](#Effect-on-you)  
And that is got Effect with only **Run the scripts** and **Burn the SDCARD.**  
[(DETAIL: What you do)](#What-you-do)  
<img src="./images/RDBOX_NetworkOverViews.jpg" title="./images/L1-L7.png" width=600px></img>

Please do not worry. You can create an SD card easily by app. (Now offering Windows10 and MacOS version. Linux versions will be released soon.)  
:arrow_down: [Download Windows10](https://github.com/rdbox-intec/rdboxGARIBAN/releases/download/v0.1.7/rdboxGARIBAN-Setup-0.1.7.exe) | :arrow_down: [Download MacOS](https://github.com/rdbox-intec/rdboxGARIBAN/releases/download/v0.1.7/rdboxGARIBAN-0.1.7.dmg) | :arrow_down: Download Linux  
<img src="./images/GARIBAN_PV_Short.gif" width=600px></img>  
[Click here for details.](https://github.com/rdbox-intec/rdboxGARIBAN)

This is just an example of RDBOX functionality.  
You can start using the useful features right away **with a click**. The [RDBOX App Market](https://github.com/rdbox-intec/rdbox_app_market) is a platform to easily add [highly integrates cloud-native and edge computing technologies applications](https://github.com/rdbox-intec/rdbox_app_market/tree/master/bot-gen) to your RDBOX environment to help you develop service robots and IoT devices.  
e.g. [Jenkins](https://www.jenkins.io/), [Harbor](https://goharbor.io/), [Gogs](https://gogs.io/), [elasticsearch, kibana, logstash](https://www.elastic.co/)  
<img src="https://raw.githubusercontent.com/rdbox-intec/rdbox_app_market/master/docs/images/overviews_rdbox_app_market.png" width=600px></img>  
[Click here for details.](https://github.com/rdbox-intec/rdbox_app_market)

In addition, you can easily control robots at multiple locations.  
Many other functions are available in RDBOX.  
<img src="./images/rdbox-multi-sites.png" width=600px></img>

---

# Table of Contents

- [How to use](#how-to-use)
- [Effect on you](#effect-on-you)
- [What you do??(Materials you'll need to prepare)](#what-you-do)
- [Features](#Features)
  - [1. Orchestrate all resources running "ROS robots"](#1-orchestrate-all-resources-running-"ros-robots")
  - [2. Make It yourself](#2-make-it-yourself)
  - [3. NETWORK CONNECT](#3-network-connect)
- [Compared with other robotics platforms.](#compared-with-other-robotics-platforms.)
  - [1. The RDBOX Provides ALL layers (L1 to L7) of the OSI reference model.](#1-the-rdbox-provides-all-layers-l1-to-l7-of-the-osi-reference-model)
  - [2. The RDBOX can be made with general equipment.](#2-the-rdbox-can-be-made-with-general-equipment)
  - [3. The RDBOX take in the good points of other companies' robot development platforms.](#3-the-rdbox-take-in-the-good-points-of-other-companies-robot-development-platforms)
- [Components](#components)
- [Our Mission](#our-mission)
  - [Solve: Short of talented engineers (48,000 people in Japan in 2020)](#solve-short-of-talented-engineers-48000-people-in-japan-in-2020)
  - [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Support & Contacts](#support-&-contacts)
- [Licence](#licence)

# How to use

Auto-build Kubernetes cluster(Use Docker as a containerd.) & Secure-Scalable Physical-network optimized for ROS robots.

<img src="./images/prepare_by_you_of_rdbox.png" title="../images/prepare_by_you_of_rdbox.png" width=600px>

1. Prepare RaspberryPi and AWS or Azure or Google Cloud Platform or PC. (Please see the [wiki](../../wiki) for details.)
2. Please also refer to [the latest release notes.](https://github.com/rdbox-intec/rdbox/releases)
3. **[If you just want to try RDBOX out, check out the Our Wiki page to give it a whirl](../../wiki). （←英語/日本語の二ヶ国語のマニュアルが用意されています。）**

## Supplementary information

- [One of our utilities, flashRDBOX,](https://github.com/rdbox-intec/flashRDBOX) allows interactive dependency injection (DI) to RaspberryPi. There is no need for difficult operations.
- If you own [TurtleBot3](http://emanual.robotis.com/docs/en/platform/turtlebot3/overview/), you can also experience the deployment of ROS applications.
- Otherwise, you can learn the procedure for building development environment with RDBOX.

# Effect on you

```bash
RDBOX based on HypriotOS (Debian GNU/Linux 10)

             .___.
            /___/|
            |   |/
            .---.
            RDBOX
 - A Robotics Developers BOX -
```

- You can get your only IT infrastructure.
  - **Provides ALL layers (L1 to L7)** of the OSI reference model.
  - **Mesh Wi-Fi network-covered space** by [Raspberry Pi](https://www.raspberrypi.org/)
  - **Strict security**
  - **Compute power provided** by [Kubernetes computer clusters](https://kubernetes.io/)
  - **Deploy and update ROS APPs** by [Kubernetes computer clusters](https://kubernetes.io/)
- Full support for your robot working in on-site.
  - It is easy to separate part of the existing Enterprise network.
    - [SoftEtherVPN_Stable](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable)
    - [go-transproxy](https://github.com/rdbox-intec/go-transproxy)
  - Other Robot Development Platform not enough support on-site.

# What you do

- Run the Script on your Virtual machine ([VirtualBox](https://www.virtualbox.org/) or [AWS](https://aws.amazon.com/) or [Azure](https://azure.microsoft.com/) or [Google Cloud Platform](https://cloud.google.com/)).
- Burn the SDCARD Image for your [Raspberry Pi](https://www.raspberrypi.org/).

# Features

Make your job easy with **3 features**.

## **1. Orchestrate all resources** running "ROS robots/IoT Devices"

- You will get a simpler and creative development experience than [deploying with traditional roslaunch](http://wiki.ros.org/roslaunch). Furthermore, it becomes easy to control a lot of groups of robots.
- Orchestrate ROS nodes on robots and conputer resources by [Kubernetes](https://kubernetes.io/).
  - **Allow mixing of x86 and ARM architecture CPU.**
  - k8s master will run on AWS EC2 or Azure VirtualMachine or Google Cloud Platform ComputeEngine or VirtualBox on your PC.
- Connect with the robots and others by [Mesh Wi-Fi Network](https://www.open-mesh.org/projects/open-mesh/wiki).
- Connect with the Clouds/On-Premise by [VPN Network](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable).  
![RDBOX_SHOW.gif](./images/RDBOX_SHOW.gif "show")

## **2. Make It yourself!!**

- The RDBOX Edge devices builds with Raspberry Pi 3B/3B+/4B.
- There is no worry that the back port will be installed. (All source code and hardware are disclosed.)
- Raspberry Pi provides you edge computing and Wi-Fi network and environmental sensors and more.
- Provide assembly procedure and original SD card image.  
![parts_of_edge.jpeg](./images/parts_of_edge.jpeg "parts")

## **3. NETWORK CONNECT**

- Easily set up a dedicated local area network for robots.
  - Simply connect RDBOX in between the internet and your service robot. In one simple step, you can build a local area network and development environment. No knowledge of internet or networking is necessary.
- Many network applications, including NTP, are offered with the product. Automate your network robot management.
- All you need is a power source. Cover the whole movable range of mobile robots with a Wi-Fi network.  
![RDBOX_FETURES.gif](./images/rdbox_fetures.png "fetures")

# Compared with other robotics platforms

**3 Advantages** compared to competitor's "robot development platform".

## 1. The RDBOX Provides ALL layers (L1 to L7) of the OSI reference model

- Competitor's "robot development platform" does not support it. You may need to pay a great deal of money to a specialist for consultation.
  - Providing access points via mesh Wi-Fi. The robot just connects to the access point.
  - It is possible to get security measures such as VPN and firewall andmore..., and convenient functions such as network application.

## 2. The RDBOX can be made with general equipment

- You can start using it with the "laptop" and "Raspberry Pi3B / 3B + / 4B" you may already have.

## 3. The RDBOX take in the good points of other companies' robot development platforms

- It can be used by combining "simulator linkage" and "existing API service" that other companies are good at.
  - Object Detection API
  - Reinforcement learning by Gazebo.
  - and more..

# Components

## Our Components

- [RDBOX App Market](https://github.com/rdbox-intec/rdbox_app_market)
  - The RDBOX App Market is a platform to easily add highly integrates cloud-native and edge computing technologies applications to your RDBOX environment to help you develop service robots and IoT devices.
- [rdboxGARIBAN](https://github.com/rdbox-intec/rdboxGARIBAN)
  - Create an SD card for RDBOX using an easy-to-understand GUI.
- [go-transproxy](https://github.com/rdbox-intec/go-transproxy)
  - Transparent proxy servers for HTTP, HTTPS, DNS and TCP.
- [rdbox-middleware](https://github.com/rdbox-intec/rdbox-middleware)
  - Middleware for RDBOX
- [image-builder-rpi](https://github.com/rdbox-intec/image-builder-rpi)
  - SD card image for Raspberry Pi with Docker: HypriotOS

## Third Components

- [hostapd](https://salsa.debian.org/debian/wpa)
  - hostapd is an IEEE 802.11 AP and IEEE 802.1X/WPA/WPA2/EAP/RADIUS Authenticator.
  - We are applying and applying [our patch.](https://github.com/rdbox-intec/softether-patches)
- [SoftEtherVPN_Stable](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable)
  - Open Cross-platform Multi-protocol VPN Software.
  - We are applying and applying [our patch.](https://github.com/rdbox-intec/wpa-patches)
- [bridge-utils](https://git.kernel.org/pub/scm/linux/kernel/git/shemminger/bridge-utils.git/)
  - Utilities for configuring the Linux Ethernet bridge.
- [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html)
  - network services for small networks.
- [nfs](http://nfs.sourceforge.net/)
  - support for NFS kernel server.
- etc.....

# Our Mission

<img src="./images/rdbox_logo_containers.png" width=180px></img>
<img src="./images/rdbox_logo_tools.png" width=180px></img>

## Solve: Short of talented engineers (48,000 people in Japan in 2020)

- Robotics is a complex technology.
- Therefore, the backbone of the engineer is different. Naturally, IT skills of each engineer are not constant.
- The use of IT technology is essential to build a robot system that links various types of service robots and IoT devices.

## RDBOX (a IT infrastructure for ROS robots.) Boosts the productivity of engineers with various backbones

- for Engineer with various backbones.
  - Create opportunities to experience "Advanced IT technologies".
- for Advanced IT Engineer
  - Provides easy customization and high affinity to existing modules. (like a ToolBOX)
- for Robotics beginners
  - Master the standard development process.(high productivity.)

## Roadmap

- [x] Portable version
- [x] Multipoint connection
- [ ] Improved fault tolerance (multiple sites version)
- [x] App Market
- [x] Multi-OS GUI SDWriter
- [ ] aws and nvidia, cooperation
- [x] Azure
- [x] Google Cloud Platform
- [ ] Create dedicated H/W
- [ ] Docker File Generator
- [ ] k8s. yaml file Generator
- [ ] elastic plug-in

# Contributing

The following is a set of guidelines for contributing to RDBOX.  

These are mostly guidelines, not rules.  

Use your best judgment, and feel free to propose changes to this document in a pull request.

- Contributions to our components that make up RDBOX apply similar rules.
  - [RDBOX App Market](https://github.com/rdbox-intec/rdbox_app_market)
  - [rdboxGARIBAN](https://github.com/rdbox-intec/rdboxGARIBAN)
  - [go-transproxy](https://github.com/rdbox-intec/go-transproxy)
  - [rdbox-middleware](https://github.com/rdbox-intec/rdbox-middleware)
  - [image-builder-rpi](https://github.com/rdbox-intec/image-builder-rpi)

1. Fork this repository.
2. Create a branch from `master` branch.
3. Write code.
4. Send a PR from the branch.

# Support & Contacts

For help and feedback, please feel free to contact us.

ask Stack Overflow questions with [#rdbox](https://stackoverflow.com/questions/tagged/rdbox).

or E-mail consultant is also available.
RDBOX Project (info-rdbox@intec.co.jp)

**If you are favorite to RDBOX, please follow my GitHub account.**

# Licence

Licensed under the [MIT](/LICENSE) license.
<!-- markdownlint-enable MD033 -->
