# [RDBOX(Robotics Developers BOX)](https://github.com/rdbox-intec/rdbox): embodies the ideal of a cloud robotics

[Japanese README](/README.ja.md)

This repository is developing the next generation of **the RDBOX** (Please call me "ði άːrdíː bäks")

This RDBOX built with a single node. Using [KinD (Kubernetes in Docker)](https://kind.sigs.k8s.io/)  
Faster and easier than [previously RDBOX](https://github.com/rdbox-intec/rdbox)

## Examples of working with ROS2 application

NOTE - Before implementing the working with ROS2 application, please build a basic environment according to the ["RDBOX-Next Environment Building Steps"](#rdbox-next-environment-building-steps) described below.

1. [SROS2 with OIDC(OpenID Connect) - Technology for robots to authenticate and authorize a human](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc)
    ![SROS2_with_OIDC](/docs/imgs/SROS2_with_OIDC.jpeg)

## RDBOX-Next Environment Building Steps

### Previous vs New

A just-built Kubernetes cluster cannot serve any purpose. It is an empty box, so to speak.  
In Kubernetes, users can benefit from the convenience of easy adding a collection of various workloads to this empty box.  
This benefit is also available in the previous RDBOX.

In the next generation ROBOX, we are not just to add workloads blindly.  
Therefore, our development team has defined **three elements** that are essential for safe and convenient use of cloud robotics.

  1. Control of communications
  2. Encryption of communications
  3. Authentication and authorization of requests
     - Users and devices can be managed as a group or individually

Development is underway with the goal of creating "an infrastructure to which workloads that satisfy the **Three Elements**" can be easily added.

### System overview

Build Kubernetes Components (**Control Plane** / **Node**) in a single Docker container using KinD  
NOTE - In addition to using KinD, we are preparing a method for building Kubernetes for use in a production environment.

The `"essentials" meta-package` is initially built in the workload as the instances of the three elements.  
These systems are set up as shown in the figure.  

![Component_of_RDBOX-NX.png](/docs/imgs/Component_of_RDBOX-NX.png)

- Control of communications
  - Use [metallb](https://metallb.universe.tf), [ambassador](https://www.getambassador.io/products/edge-stack/), etc.
- Encryption of communications
  - Use [cert-manager](https://cert-manager.io), etc.
- Authentication and authorization of requests
  - Use [keycloak](https://www.keycloak.org), etc.

The green boxed paragraph in the Node should be viewed as a collection of "workloads".  
Various applications for cloud robotics that you can add at yourself.  
(The dashboard and prometheus in the figure. And, this is but one small example.)
**These applications can be started as workloads that satisfy the three elements**.

### the state of test

This procedure was tested in the following environment (May 13, 2022)  
Additionally, We tested in an **amd64** CPU architecture environment.

- Ubuntu 20.04.4
  - 5.13.0-41-generic
  - Docker-CE （20.10.16）
- MacOSX Monterey 12.3.1
  - Docker Desktop 4.6.1
- Windows11 21H2（WSL2）
  - Ubuntu20.04.4
    - 5.10.16.3-microsoft-standard-WSL2
  - Docker-CE （20.10.14）

### What is it used for?

KinD is a Kubernetes cluster designed to be used for local development and CI. Please note that this is not designed for use in a production environment.  
> [kind was primarily designed for testing Kubernetes itself, but may be used for local development or CI](https://kind.sigs.k8s.io)

The `built with a single node` RDBOX was developed to let you experience the benefits of cloud robotics, and the environment created with KinD gives us a good experience with very simple steps.  
We are also developing **a mechanism** for users who have a good experience with the `built with a single node` RDBOX to carry over your `cloud native robots` to the production environment.  
Please refer to the roadmap for details.

### Prerequisites

#### Setting up Docker

Prepare a Docker environment. Follow the official documentation below.

- Ubuntu/Windows11(WSL2)：[Install Docker Engine on Ubuntu \| Docker Documentation](https://docs.docker.com/engine/install/ubuntu/)
- Mac：[Install Docker Desktop on Mac \| Docker Documentation](https://docs.docker.com/desktop/mac/install/)

##### NOTE - Please make sure that docker commands can be run without sudo

```bash
$ sudo gpasswd -a $USER docker

# 1. You need to logout.

# 2. Please login again.

$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAME
```

#### Add dependent modules

```bash
sudo apt-get update
sudo apt-get install -y \
    git
```

### Download Source Code

Note the branch name. (`insiders` branch)

```bash
git clone --recursive -b insiders https://github.com/rdbox-intec/rdbox.git
cd rdbox
```

Make sure you are in the `insiders` branch.

```bash
$ git branch
  develop
* insiders
  master
```

### Building a Docker image

Running the following script will build a Docker image for RDBOX-Next.

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

### Execute the initialization command

Use the `rdbox command line tool` of this repository to build the RDBOX. Provides the best cloud robotics environment for the user's environment.

We will build the environment in order using `rdbox command line tool`.  
Use the `rdbox init` command to:

- determine the name of the cluster
- create a working directory
- retrieve configuration files

The following command uses the `--name rdbox` argument to set the cluster name as rdbox.

```bash
./rdbox init --name rdbox
```

```bash
~ omit ~

# END (SUCCESS)
[2022-05-12T23:56:07+0000][1652399767.0702667][init.bash]
*********************************************************
```

### For advanced users

The `init` subcommand creates a working directory and configuration files in `~/crobotics`. Each configuration file can be changed as needed.

- The explanation of each setting is under preparation.
- `~/crobotics` is the default value.

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

### Building a Kubernetes Cluster

First, a Kubernetes cluster is built. Next, implement a container network for this cluster.

Specifically, we use the following Kubernetes resources

- [KinD](https://kind.sigs.k8s.io)
  - `KinD` is an abbreviation for "Kubernetes in Docker".
  - Create a Kubernetes cluster inside a Docker container. This makes it possible to examine Kubernetes without tainting one's environment.
- [Weave-Net](https://www.weave.works/docs/net/latest/kubernetes/kube-addon/)
  - One of the container network options for Kubernetes.
  - It supports UDP multicast, etc., making it a good match for DDS communication in ROS2.

Use the `rdbox create` command to deploy the above resources.

- `--name rdbox`: Specify the name of the cluster specified in the `subcommand init`.
- `--module k8s-cluster`: Specify the name of module (k8s-cluster)
- `--domain nip.io`: You must specify a name-resolvable local domain.
  - If it does not exist, specify a **wildcard DNS service** such as `nip.io`.
- `--volume_type tmp` specifies the data storage format.
  - tmp: Data is deleted when the cluster is deleted. Storage for testing purposes.
  - nfs: A simple NFS server is built in a cluster and data is stored in the server. Data is not lost even if the cluster is deleted. (Trial)
    - `--volume_size 40` Specifies the amount of data storage space, in GB. 40 GB or more is recommended.

```bash
./rdbox create --name rdbox --module k8s-cluster --domain nip.io --volume_type tmp
```

```bash
./rdbox create -n rdbox -m k8s-cluster -d nip.io --volume_type nfs --volume_size 40
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

NOTE - You can optionally specify `--host ${YOUR_HOST_NAME}`. This can only be specified if a name-resolvable local domain exists. If nothing is entered, the format supported by the wildcard DNS service, `the IPv4 address of the default NIC, separated by hyphens (e.g. 192-168-22-222)`, is automatically used.

With the above work, the minimum configuration to operate as a Kubernetes cluster is completed. If `kubectl` is installed on the host, you can run the command `kubectl get node -o wide` on the host terminal to check the node activity.

- [Install Tools \| Kubernetes](https://kubernetes.io/docs/tasks/tools/#kubectl)

```bash
# This is only possible if kubectl is installed on the host machine.
NAME                  STATUS   ROLES                  AGE    VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE       KERNEL-VERSION      CONTAINER-RUNTIME
rdbox-control-plane   Ready    control-plane,master   111s   v1.23.4   172.18.0.3    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
rdbox-worker          Ready    <none>                 75s    v1.23.4   172.18.0.2    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
```

Also, if you run the `docker ps` command on the host, you can see that the cluster is built only with Docker containers.

```bash
CONTAINER ID   IMAGE                  COMMAND                  CREATED         STATUS         PORTS                                                                NAMES
6072b4d58771   kindest/node:v1.23.4   "/usr/local/bin/entr…"   2 minutes ago   Up 2 minutes   0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp, 0.0.0.0:32022->32022/tcp   rdbox-worker
03c5e5c00750   kindest/node:v1.23.4   "/usr/local/bin/entr…"   2 minutes ago   Up 2 minutes   127.0.0.1:44251->6443/tcp                                            rdbox-control-plane
```

### The meta-package of essentials

Install/Setup the most basic group of modules required to use ROS2 on Kubernetes.

Specifically, we use the following Kubernetes resources

- [cert-manger](https://cert-manager.io)
  - Management of various certificates
- [MetalLB](https://metallb.universe.tf)
  - Provides Ingress functionality as one of the Kubernetes resources
- [Ambassador Edge Stack](https://www.getambassador.io/products/edge-stack/api-gateway/)
  - Provides SSO (single sign-on) to `kubectl` (kubernetes command line tool). Provides cluster operations based on authority.
- [KeyCloak](https://www.keycloak.org)
  - Infrastructure of User/group authentication and authorization

Use the `rdbox create` command to deploy the above resources.

- `--name rdbox`: Specify the name of the cluster specified in the `subcommand init`.
- `--module k8s-essentials`: Specify the name of module (k8s-cluster)

(This setup may take up to 10 minutes or so.)

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

#### NOTE - Be sure to make a note

As shown above, the account information required for the user management infrastructure (Keycloak) is displayed as **USAGE** at the end of the stdout. It is recommended that you make a note of this information so that you do not lose it.

## Configuration of user management infrastructure (Keycloak)

Set up using the account information for the user management infrastructure that you wrote down.

### Trust a CA certificate

Check the CA certificate stored in the host OS working directory `~/crobotics/${CLUSTER_NAME}/outputs/ca`.

```bash
openssl x509 -in ~/crobotics/rdbox/outputs/ca/rdbox.172-16-0-132.nip.io.ca.crt -text
```

Register this CA certificate as a trusted certificate with your OS and browser. The following links are provided for your reference.

#### OS

- [Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores)
- [MacOS](https://support.apple.com/guide/keychain-access/kyca2431/mac)
- [Ubuntu](https://ubuntu.com/server/docs/security-trust-store)
  - `sudo cp ~/crobotics/${CLUSTER_NAME}/outputs/ca/*****.ca.crt /usr/local/share/ca-certificates/`
  - `sudo update-ca-certificates`

#### Web browser

- [Set up an HTTPS certificate authority \- Chrome Enterprise and Education Help](https://support.google.com/chrome/a/answer/6342302?hl=en)
- [Setting Up Certificate Authorities \(CAs\) in Firefox](https://support.mozilla.org/kb/setting-certificate-authorities-firefox)

### Log in to the user management infrastructure with a limited administrator account

You login to Keycloak as a "limited administrator" (realm administrator) automatically created by RDBOX for the purpose of managing the kubernetes cluster.  
The login for the account (super-admin) that manages the entire Keycloak (all realms) can be executed in the same way.

#### Obtain initial account information

Obtain account information as described in the memo. (The following command is an example. Check the actual memo.)

```bash
echo Username: cluster-admin
echo Password: $(kubectl -n keycloak get secrets specific-secrets -o jsonpath='{.data.k8s-default-cluster-admin-password}' | base64 --decode)
```

#### Access the specified URL and login there

An indicator in the web browser confirms that the CA was successfully imported and the communication is encrypted. Then enter the initial login information obtained in the previous chapter. Finally, click the `Sign In` button.

![keycloak_signin.jpg](/docs/imgs/keycloak_signin.jpg)

#### Setting up two-factor authentication

Set up two-factor authentication to protect the administration account.

![2FA_setup.jpg](/docs/imgs/2FA_setup.jpg)

### Operating Keycloak

Keycloak has a wide range of functions. Please check the [official documentation](https://www.keycloak.org/documentation.html) for more information.  
Let's take a look at the items related to user management, such as Groups and Users.

#### Groups

For the tutorial, two groups are created in Groups.

- cluster-admin
  - Users in this group are binding `cluster-admin` in kuberntest's RBAC (Role-based access control)
    - It gives full control over every resource in the cluster and in all namespaces.
- guest
  - Users in this group are binding to have limited privileges only within a specific namespace (in this case, guest) in kuberntest's RBAC (Role-based access control).
  - Users in this group cannot login to the console page for administrators (the page you are currently working on).
    - It is possible to change the password, check the session status, and disconnect from the user's personal page. See below.

![groups.jpg](/docs/imgs/groups.jpg)

#### Users

For the tutorial, users linked to Groups are registered in advance.

![users.jpg](/docs/imgs/users.jpg)

#### Clients Account-console

Users who do not member of the `cluster-admin` group need the following settings in order to "change passwords, check session status, and disconnect" by themselves.

1. Click on `Clients` from the left pane. Select `Account-console` from the list.
2. Set the item `Enabled` to ON.
3. Add `*` to the field named `Web Origins`.
4. Click the `Save` button to save the contents.

#### Personal page

Users execute "change passwords, check session status, and disconnect" by themselves.

URL：`https://${the FQDNs of the keycloak}/realms/${the name of the cluster}/account/`
![accountpage.jpg](/docs/imgs/accountpage.jpg)

## Control Kubernetes with SSO

Execute `kubectl` based on the results of authentication and authorization as a registered user in Keycloak.

- You will experience that each group (`cluster-admin` and `guest`) checked in the previous chapter has a different permitted operation.
- This can be tested even if `kubectl` is not installed on the host machine.

### initialization

#### Login inside the container used for setup

Any operations after executing this command will have been performed from inside the container.

```bash
./rdbox bash --name rdbox
```

#### Login operation (cluster-admin)

Execute the following commands inside the container.  PATH is passed inside the container, so rdbox commands can be executed as is

```bash
rdbox login --name rdbox
```

```bash
error: could not open the browser: exec: "xdg-open,x-www-browser,www-browser": executable file not found in $PATH

Please visit the following URL in your browser manually: http://localhost:8000
```

As above, Follow the message:  
`Please visit the following URL in your browser manually: http://localhost:8000`  
and access [http://localhost:8000](http://localhost:8000) in your browser.  
You will then be redirected to Keycloak's login page and login using the account `cluster-admin` that you have just checked. The two-factor authentication you have just set up will also be checked.

![login_cluster-admin.jpg](/docs/imgs/login_cluster-admin.jpg)

![2FA_setuped.jpg](/docs/imgs/2FA_setuped.jpg)

Upon successful authentication, the terminal where the command was executed will show a message of successful login.

```bash
~ omit ~

Success SSO Login
```

## Testing RBAC

In this tutorial, we will examine how Keycloak and RBAC authentication and authorization infrastructure works with the following two users

- **cluster-admin user** who is a member of the **cluster-admin group**
- **guest user** who is a member of the **guest group**

For the tutorial, the two groups in Groups have the following features:

- cluster-admin
  - Users in this group are binding `cluster-admin` in kuberntest's RBAC (Role-based access control)
    - It gives full control over every resource in the cluster and in all namespaces.
- guest
  - Users in this group are binding to have limited privileges only within a specific namespace (in this case, guest) in kuberntest's RBAC (Role-based access control).
  - Users in this group cannot login to the console page for administrators (the page you are currently working on).
    - It is possible to change the password, check the session status, and disconnect from the user's personal page. See below.

### Try kubectl command (by the cluster-admin)

#### get node

First try the `cluster-admin` operation.  
Operations involving cluster-wide permissions, such as `kubectl get node`, can be executed.

```bash
$ kubectl get node -o wide
NAME                  STATUS   ROLES                  AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE       KERNEL-VERSION      CONTAINER-RUNTIME
rdbox-control-plane   Ready    control-plane,master   86m   v1.23.4   172.18.0.2    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
rdbox-worker          Ready    <none>                 86m   v1.23.4   172.18.0.3    <none>        Ubuntu 21.10   5.13.0-41-generic   containerd://1.5.10
```

#### create namespac

It is possible to create a new namespace.

```bash
$ kubectl create namespace test-rdbox
namespace/test-rdbox created
```

#### apply

Let's apply the manifest for the Nginx sample program to the namespace we just created. By using the get command, you can check that the deployment has actually been created.  
And if you set up port forwarding by running the `kubectl port-forward -n test-rdbox deploy/nginx-deployment 8888:80` command, you can also see it in your web browser.

```bash
# apply（≒install）
$ kubectl apply -n test-rdbox -f https://k8s.io/examples/application/deployment.yaml
deployment.apps/nginx-deployment created

# get（check）
$ kubectl -n test-rdbox get deployments      
NAME               READY   UP-TO-DATE   AVAILABLE   AGE
nginx-deployment   2/2     2            2           91s

# To secure communication paths
# you can also see it in your web browser
$ kubectl port-forward -n test-rdbox deploy/nginx-deployment 8888:80
```

### Try kubectl command (by the guest)

Now try login as the guest user in the guest group. (Let's check the difference in privileges)

#### logout from cluster-admin

```bash
rdbox logout --name rdbox
```

```bash
~ omit ~
Success SSO Logout
```

Also, please logout of your browser.

URL：`https://${the FQDNs of the keycloak}/realms/${the name of the cluster}/account/`

![accountpage_signout.jpg](/docs/imgs/accountpage_signout.jpg)

#### Login operation (by the guest)

Now login as the guest user.
Username： `guest`
Password： `password`

```bash
rdbox login --name rdbox
```

```bash
error: could not open the browser: exec: "xdg-open,x-www-browser,www-browser": executable file not found in $PATH

Please visit the following URL in your browser manually: http://localhost:8000
```

As above, Follow the message:  
`Please visit the following URL in your browser manually: http://localhost:8000`  
and access [http://localhost:8000](http://localhost:8000) in your browser.  
You will then be redirected to Keycloak's login page and login using the account `guest` that you have just checked.

Upon successful authentication, the terminal where the command was executed will show a message of successful login.

```bash
~ omit ~

Success SSO Login
```

#### get node(guest)

Try something similar to `cluste-admin` by the `guest` operation.

Cluster-wide operations such as `kubectl get node` are not allowed. You will get a message `nodes is forbidden` showing that you do not have permission.

```bash
$ kubectl get node -o wide
Error from server (Forbidden): nodes is forbidden: User "guest" cannot list resource "nodes" in API group "" at the cluster scope
```

#### create namespac(guest)

You cannot create a new namespace either.

```bash
$ kubectl create namespace test-rdbox
Error from server (Forbidden): namespaces is forbidden: User "guest" cannot create resource "namespaces" in API group "" at the cluster scope
```

#### apply(guest)

The get command does not give you the authority to check the status of the deployment `cluster-admin` just applied.

```bash
# get（check）
$ kubectl -n test-rdbox get deployments
Error from server (Forbidden): deployments.apps is forbidden: User "guest" cannot list resource "deployments" in API group "apps" in the namespace "test-rdbox"
```

Now, let's try to apply to the `guest` namespace, where the guest user has been granted permission. You will see that the command is successfully executed.

And if you set up port forwarding by running the `kubectl port-forward` command, you can also see it in your web browser.

```bash
# apply（≒install）
$ kubectl apply -n guest -f https://k8s.io/examples/application/deployment.yaml
deployment.apps/nginx-deployment created

# To secure communication paths
# you can also see it in your web browser
$ kubectl port-forward -n guest deploy/nginx-deployment 8888:80
```

### Conclusion of the Tutorial

Using the two users, we were able to check the difference in operating privileges. The combination of keycloak and RBAC (Kubernetes) makes it possible to manage authentication and authorization with a lot of flexibility. We encourage you to customize and use it yourself.

#### References to read after the tutorial

- [Documentation \- Keycloak](https://www.keycloak.org/documentation)
- [Using RBAC Authorization \| Kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

## Deleting the Environment

If you wish to remove an environment that is no longer needed after the examination, execute the following command on the host machine.

```bash
cd rdbox
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

The results of the docker command show that the environment has been deleted.

```bash
$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

## Licence

Licensed under the [MIT](/LICENSE) license.
