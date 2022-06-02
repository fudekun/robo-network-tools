# SROS2_OIDC (Keycloak operation)

The goal of this tutorial： Add `location information` as a user attribute in keycloak.

## Realm

1. Login as a Super-Administrator  
NOTE - The login information for the Super-Administrator account is output to the console, when the `essential meta-packages` of `RDBOX` was setuped by you.

2. Create a new "realm". Click on a `Add realm` button  
NOTE - Mouse over area where the realm name (Master, or the name of the cluster you have set up) is displayed, and a button will appear.

  ![Add_realm_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_realm_button.jpg)

### Add realm screen

1. Enter any name and click the `Create` button. (In this case, we will use `ros2_oidc`)

  ![Add_realm_page.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_realm_page.jpg)

### Advanced settings for realm

1. Click the `Create` button, the page moves to the individual setting for the realm (ros2_oidc).  
2. After the page moves to the next screen, the following settings are to be implemented.  
NOTE - Be sure to click the `Save` button after changing the settings. (To ensure that your changes are applied.)

- Click the `General` tab and turn on the `User-Managed Access` check.
  - Required when testing the operation of the `Manage account` screen by a normal user.
- Click the `Login` tab and turn off the `Login with email` check.

  ![Realm_Settings_general.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Realm_Settings_general.jpg)

## User（Add realm administrator）

Using Super Administrators more than necessary is not recommended in the use of Keycloak.  
Therefore, create a Realm-specific administrator (User) that you have just created.

1. Click on "Users" in the left pane. Click the `Add User` button on the Users page. (You will be moved to the `Add user` page.)  

- Each item is set as optional.
  - More advanced authentication can be supported by setting `Required User Actions`.（Two-factor authentication by OTP, etc.）

NOTE - Be sure to click the `Save` button after changing the settings. (To ensure that your changes are applied.)

  ![Add_user_page.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_user_page.jpg)

### Advanced Settings for Administrator User

After clicking the `Save` button, You will be moved to the `Individual settings` page for a created user (any name).

#### Setting Credentials

1. Click on the `Credentials` tab and set the initial password.  
2. Fill in each text box in the "Set Password" area and click the `Set Password` button to save the contents.  
NOTE - If `Temporary` is turned on, it will required to reset your password when you log in for the first time.

  ![User_Credentials.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/User_Credentials.jpg)

#### Setting Client Roles

1. Click on the `Role Mappings` tab and set Client Roles.  
NOTE - Grant authority to conduct responsible for as a Realm Administrator. (Access the administration page to create users, add ROS2 clients, etc.)

- Select "account" from the `Client Roles` select box
  - Add the following to `Assigned Roles`
    - manage-account
- Select "realm-management" from the `Client Roles` select box
  - Add the following to `Assigned Roles`
    - Everything

  ![User_RoleMapping_ClientRole_Account.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/User_RoleMapping_ClientRole_Account.jpg)

### Switching accounts

#### Logout of the Super-Administrator

1. Mouse over the account name field in the upper right corner, and the `Sign Out` link will appear. Click on it to sign out from the Super-Administrator.

  ![SignOut.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/SignOut.jpg)

#### Login as the Realm administrator you created

1. Login to the management page for the Realm you created; the URL is as follows

  ```bash
  https://${FQDNs for user environments}/auth/realms/${The name of realm you created}/protocol/openid-connect/auth?client_id=security-admin-console
  ```

- At first login: You may be prompted to update your password and/or set up 2FA.
- Make sure the left pane looks like this:
  - If permissions are correctly granted, all items will be displayed.

  ![Keycloak_Admin_Console-ros2_oidc_leftpain.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Keycloak_Admin_Console-ros2_oidc_leftpain.jpg)

#### Add a normal user

1. Add normal users as needed for testing. (Up to here chapters becomes a great reference)

## User (Setting a location information)

1. Click on the `Users` link in the left pane.
2. Click the `View all users` button to display the user list and select any user.
  ![Keycloak_many_users.jpeg](/ros2/rdbox/sros2_oidc/docs/imgs/Keycloak_many_users.jpeg)
3. Click the `Attributes` tab on the individual settings page for the relevant user.（On this screen, various attribute information can be assigned.）
4. In this tutorial, user-specific location information will be set as follows
   - key：location
   - value：3.0,2.3
     - Comma-separated user-specific location information（X-coordinate,Y-coordinate）
     - Each value should be specified with an any Float value.
  ![Add_attribute.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_attribute.jpg)
5. NOTE - Be sure to click the `Save` button after changing the settings. (To ensure that your changes are applied.)

## Client Scopes

User attributes managed by KeyCloak can be linked to OIDC ID tokens, access tokens, and UserInfo responses. Keycloak calls this linkage system "Protocol Mapper".

In this section, a new "Client Scope" is created. This is used to manage "Protocol Mapper" as a group.

1. Click on the `Client Scopes` link in the left pane. A Page moves to the list of Client Scopes.
2. Click on the `Create` button to create new "Client Scopes".

  ![client_scopes_create_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_scopes_create_button.jpg)

### Create new "Client Scopes"

1. Enter the following three items and click the "Save" button.
   - Name：location
   - Description：location(x,y)
   - Consent Screen Text ：location(x,y)
  ![Add_client_scope.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_client_scope.jpg)

### Set up a location mapper

1. Return to the Client Scopes list page. Click on the item (location) you have just created.
2. A page moves to the advanced settings. Click on the `Mappers` tab.
3. Click the `Create` button to create a new Mapper.
  ![location_mappers_create_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/location_mappers_create_button.jpg)
4. On the "Create Protocol Mapper" page, set the following five items.
   - Name ：　location
   - Mapper Type ： Select "User Attribute" from the drop box
   - User Attribute：location (Displayed after selecting Mapper Type)
   - Token Claim Name ：location (Displayed after selecting Mapper Type)
   - Claim JSON Type ：String (Displayed after selecting Mapper Type)
  ![create_protocol_mapper.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/create_protocol_mapper.jpg)
5. NOTE - Be sure to click the `Save` button after changing the settings. (To ensure that your changes are applied.)

## Client

1. Click on the `Clients` link in the left pane. A Page moves to the list of Clients.
2. Click on the `Create` button in the upper right corner to create a new Client.

  ![client_list.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_list.jpg)

### Add Client

1. Type "amcl" in the `Client ID` text box and click the `Save` button.

  ![Add_client.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_client.jpg)

### Settings tab

Configure detailed settings for a Client(Client for sros2_oidc service).

1. Click on the `Settings` tab.
2. Set each item as below.
   - Consent Required ：ON
   - Access Type：confidential
   - Valid Redirect URIs
     - `http://localhost:8080/gettoken`
     - `http://${FQDNs for user environments}:8080/gettoken`
       - e.g. `http://rdbox.172.16-0-132.nip.io:8080/gettoken`
   - Web Origins
     - \*
       - （asterisk）
3. NOTE - Be sure to click the `Save` button after changing the settings. (To ensure that your changes are applied.)

### Client Scopes tab

Set the **Client Scopes** required by the client(Client for sros2_oidc service).

1. Click on the `Client Scopes` tab.
2. Operate the `Remove` and `Add` buttons in the `Assigned Default Client Scopes` box in `Default Client Scopes` area so that `location` (the **Client Scopes** you just added) and `web-origins` remain.

  ![client_client_scope.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_client_scope.jpg)

### Credentials tab

1. Click on the `Credentials` tab.
2. Note the Secret. This is the information needed to set up the sros2_oidc program.

List the information needed to set up the ros2_oidc program; it is advisable to check it again on the Clients page.

- server_url
- realm_name
- client_id
- client_secret_ke
- redirect_url
