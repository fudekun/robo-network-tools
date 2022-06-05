# SROS2_OIDC（Keycloak操作）

このチュートリアルのゴール： keycloakにてユーザ属性として、位置情報を追加する。

## Realm

1. Super管理者でログインします。
NOTE - Super管理者アカウントのログイン情報は、 RDBOXの`essentials meta-packages`セットアップ時にコンソール出力されています。

2. 新しい「レルム」を作成します。"Add realm"をクリックして下さい。
NOTE - レルム名（Master、または設定したクラスタ名）が表示されている部分にマウスオーバーすると、ボタンが表示されます。

  ![Add_realm_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_realm_button.jpg)

### Add realm画面

任意の名前を入力して、「Create」ボタンをクリック。（ここでは、`ros2_oidc`とする。）

  ![Add_realm_page.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_realm_page.jpg)

### realmの詳細設定

Createボタンクリック後は、作成したレルム（ros2_oidc）に関する個別設定画面に遷移する。  
画面遷移後に、以下の設定を実施する。

NOTE - 変更後は必ず「Save」ボタンをクリックして変更内容が確実に反映されるように気をつける。

- Generalタブを選択して、User-Managed AccessチェックをONにする。
  - 一般ユーザによるアカウント設定画面の動作検証を実施する場合に必要。
- Loginタブを選択して、 Login with emailチェックをOFFにする。

  ![Realm_Settings_general.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Realm_Settings_general.jpg)

## User（レルム管理者を追加する）

必要以上にSuper管理者を使い続けることはKeycloakの利用において推奨されていない。  
ゆえに、今作成したレルムに特化した管理者（User）を作成する。

左ペインの「Users」をクリック。Users画面（Lookupタブ）の「Add User」ボタンをクリックし、「Add user」画面に遷移する。

- 各項目を任意に設定。
  - Required User Actionsに「Configure OTP」などを設定するとOTPによる二要素認証をサポートできる。
- 「Save」ボタンをクリックして、内容を保存する。

  ![Add_user_page.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_user_page.jpg)

### 管理ユーザの詳細設定

Createボタンクリック後は、作成したユーザ（任意の名前）に関する個別設定画面に遷移する。

#### Credentials設定

Credentialsタブをクリックして、初期パスワードを設定する。  
「Set Password」エリアを入力し、「Set Password」ボタンをクリックして内容を保存する。  
（TemporaryがONになっている場合は次回ログイン操作時にパスワードの再設定が求められるようにしてくれます。）

  ![User_Credentials.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/User_Credentials.jpg)

#### Client Roles設定

Role Mappingsタブをクリックして、Client Rolesを設定する。  
NOTE - Realm管理者として、業務を行うための権限を付与する。(管理画面にアクセスして、ユーザ作成やROS2クライアントの追加等を実施する)

- Client Rolesのセレクトボックスから「account」を選択
  - Assigned Rolesに以下を追加
    - manage-account
- Client Rolesのセレクトボックスから「realm-management」を選択
  - Assigned Rolesに以下を追加
    - 全て

  ![User_RoleMapping_ClientRole_Account.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/User_RoleMapping_ClientRole_Account.jpg)

### アカウント切り替え

#### Super管理者をログアウト

右上のアカウント名表示部にマウスオーバーすると、「Sign Out」という選択が出てくるのでクリックする。

  ![SignOut.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/SignOut.jpg)

#### 作成したRealm管理者としてログイン

- 作成したRealmに対応した管理画面にログインする

  ```bash
  https://${ユーザ環境に合わせたFQDN}/realms/${任意のRealm名}/protocol/openid-connect/auth?client_id=security-admin-console
  ```

- 新規ログインの場合、パスワードの更新要求や2FAのセットアップが求められるかもしれないが従う。
- 左ペインにが以下の通りになっていることを確認する。
  - 権限が正しく付与されていれば、全ての項目が表示される。

  ![Keycloak_Admin_Console-ros2_oidc_leftpain.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Keycloak_Admin_Console-ros2_oidc_leftpain.jpg)

#### （オプション）一般ユーザを追加する

検証の必要に応じて、一般ユーザを追加する。（手順はここまでの記述が参考となる、User個別設定画面のRole Mappingsタブでの設定内容には気をつけること。）

## User（位置情報を設定）

1. 左ペインの `Users` リンクをクリックします。
2. `View all users`ボタンをクリックすると、ユーザーリストが表示され、任意のユーザーを選択することができます。
  ![Keycloak_many_users.jpeg](/ros2/rdbox/sros2_oidc/docs/imgs/Keycloak_many_users.jpeg)
3. 該当ユーザの個別設定画面で「Attributes」タブをクリックする。ここの画面では様々な属性情報を付与することができる。
4. 今回のチュートリアルでは、ユーザ固有の位置情報を以下の通りに設定する。
   - key：location
   - value：3.0,2.3
     - ユーザ固有の位置情報（X,Y、カンマ区切り）
     - 各値は任意の Float 値で指定する。
  ![Add_attribute.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_attribute.jpg)
5. 入力後は必ず「Save」ボタンをクリックして、確実に内容を保存すること。

## Client Scopes

KeyCloakが管理するユーザー属性は、OIDCのIDトークン、アクセストークン、UserInfoレスポンスと連携させることができます。KeyCloakはこの連携システムを "Protocol Mapper "と呼んでいます。

ここでは、「クライアントスコープ」を新規に作成します。これは、「Protocol Mapper」をグループとして管理するために使用されます。

1. 左ペインの[Client Scopes]リンクをクリックします。クライアントスコープの一覧にページが移動します。
2. 新しいクライアントスコープを作成するには、Createボタンをクリックします。

  ![client_scopes_create_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_scopes_create_button.jpg)

### 新しい "クライアントスコープ "を作成する

1. 以下の3項目を入力し、「Save」ボタンをクリックする。
   - Name：location
   - Description：location(x,y)
   - Consent Screen Text ：location(x,y)
  ![Add_client_scope.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_client_scope.jpg)

### locationのMapperを設定する

1. クライアントスコープの一覧ページに戻ります。先ほど作成した項目（場所）をクリックします。
2. 詳細設定にページが移動するので、そこで"Mappers"タブをクリックします。
3. "Create"ボタンをクリックして、新しいMapperを作成します。
  ![location_mappers_create_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/location_mappers_create_button.jpg)
4. 「Create Protocol Mapper」画面で、以下の5項目を設定し、「Save」ボタンをクリックする。
   - 名前 ： 場所
   - Mapper Type ： ドロップボックスから「User Attribute」を選択します。
   - User Attribute：位置（Mapper Type選択後に表示される）
   - Token Claim Name ：location (Mapper Type選択後に表示されます)
   - Claim JSON Type ：String(MapperType選択後に表示)
  ![create_protocol_mapper.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/create_protocol_mapper.jpg)
5. 注意 - 設定を変更した後は、必ず`Save`ボタンをクリックしてください。(変更内容を確実に反映させるため)

## Client

1. 左側のペインの `Clients` リンクをクリックします。クライアントリストにページが移動します。
2. 右上の `Create` ボタンをクリックすると、新しいクライアントが作成されます。

  ![client_list.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_list.jpg)

### Add Client画面でClientを追加

ここでは「Client ID」テキストボックスに「amcl」と入力し、「Save」ボタンをクリックする。

  ![Add_client.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_client.jpg)

### Settingsタブで各種設定

Client(sros2_oidcサービスのためのClient)の詳細設定を実施する。

1. `Settings`タブをクリックします。
2. 各項目を以下のように設定します。
   - Consent Required ：ON
   - Access Type：confidential
   - Valid Redirect URIs
     - `http://localhost:8080/gettoken`
     - `http://${ユーザ環境に合わせたFQDN}:8080/gettoken`
       - e.g. `http://rdbox.172.16-0-132.nip.io:8080/gettoken`
   - Web Origins
     - \*
       - （アスタリスク）
3. 注意 - 設定を変更した後は、必ず`Save`ボタンをクリックしてください。(変更内容を確実に反映させるため)

### Client Scopesタブで各種設定

該当Clientが要求するClient Scopesを設定する

1. `Client Scopes`タブをクリックします。
2. Default Client Scopes の「Assigned Default Client Scopes」ボックスが「location」（先程追加したClient Scopes）と「web-origins」が残るように「Remove」「Add」ボタンを操作する。

  ![client_client_scope.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_client_scope.jpg)

### Credentialsタブ

1. `Credentials`タブをクリックします。
2. Secretを記録しておく。これはsros2_oidcのプログラムの設定に必要となる情報となる。

sros2_oidcのプログラムの設定に必要となる情報を列挙する、Clients画面で再度確認ておくのが望ましい。

- server_url
- realm_name
- client_id
- client_secret_ke
- redirect_url
