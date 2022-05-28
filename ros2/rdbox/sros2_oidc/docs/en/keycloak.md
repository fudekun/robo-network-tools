# SROS2_OIDC（Keycloak操作）

keycloakにてユーザ属性として、位置情報を追加する。

## Realm

まず、Super管理者でログインして、新規に「レルム」を作成する。

※ アカウント設定は、Kubernetesクラスタ構築時のコンソール出力内容を参考に取得して下さい。

レルム名が表示されている（Masterやrdboxコマンドで設定したクラスタの名称になっている）エリアにマウスオーバーすると、「Add realm」ボタンが表示されるのでクリックする。

  ![Add_realm_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_realm_button.jpg)

### Add realm画面

任意の名前を入力して、「Create」ボタンをクリック。（ここでは、ros2_oidcとする。）

  ![Add_realm_page.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_realm_page.jpg)

### realmの詳細設定

Createボタンクリック後は、作成したレルム（ros2_oidc）に関する個別設定画面に遷移する。以下のような設定を実施する。

タブの移動前に「Save」ボタンをクリックして変更内容が確実に反映されるように気をつける。

- Generalタブを選択して、User-Managed AccessチェックをONにする。
  - 一般ユーザによるアカウント設定画面を検証する場合に必要。
- Loginタブを選択して、 Login with emailチェックをOFFにする。

  ![Realm_Settings_general.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Realm_Settings_general.jpg)

## User（管理ユーザ追加）

Super管理者を使い続けることはKeycloakの利用において推奨できないため、今作成したRealmの管理者（User）を作成する。

左ペインの「Users」をクリック。Users画面（Lookupタブ）の「Add User」ボタンをクリックし、「Add user」画面に遷移する。

- 各項目を任意に設定。
  - Required User Actionsに「Configure OTP」などを設定するとOTPによる二要素認証をサポートできる。
- 「Save」ボタンをクリックして、内容を保存する。

  ![Add_user_page.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_user_page.jpg)

### 管理ユーザの詳細設定

Createボタンクリック後は、作成したユーザ（任意の名前）に関する個別設定画面に遷移する。

#### Credentials設定

Credentialsタブをクリックして、初期パスワードを設定する。「Set Password」エリアを入力し、「Set Password」ボタンをクリックして内容を保存する。

（TemporaryがONになっている場合は次回ログイン操作時にパスワードの再設定が求められるようにしてくれます。）

  ![User_Credentials.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/User_Credentials.jpg)

#### Client Roles設定

- Role Mappingsタブをクリックして、Client Rolesを設定する。管理者として、管理画面にアクセスしユーザ作成、ROS2クライアントの追加という業務を行うための権限を付与する。
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

- 作成したRealmに対応した管理画面にログインする。※アカウント設定は、Kubernetesクラスタ構築時のコンソール出力内容を参考に取得して下さい。

  ```bash
  https://${ユーザ環境に合わせたFQDN}/auth/realms/${任意のRealm名}/protocol/openid-connect/auth?client_id=security-admin-console
  ```

- 新規ログインの場合、パスワードの更新要求や2FAのセットアップが求められるかもしれないが従う。
- ログインができており、左ペインにが以下の通りになっていることを確認する。（権限が正しく付与されていれば全て表示されている。）

  ![Keycloak_Admin_Console-ros2_oidc_leftpain.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Keycloak_Admin_Console-ros2_oidc_leftpain.jpg)

#### アカウント切り替え（その他）

検証の必要に応じて、一般ユーザを追加する。（手順はここまでの記述が参考となる、User個別設定画面のRole Mappingsタブでの設定内容には気をつけること。）

## User（位置情報を設定）

左ペインの「Users」をクリック。「View all users」でユーザリストを表示し、任意のユーザを選らぶ。

  ![Keycloak_many_users.jpeg](/ros2/rdbox/sros2_oidc/docs/imgs/Keycloak_many_users.jpeg)

該当ユーザの個別設定画面で「Attributes」タブをクリックする。ここの画面では様々な属性情報を付与することができる。

今回のチュートリアルでは、ユーザ固有の位置情報を取得するため以下の通りとする。

- key：location
- value：1.2,5.9
  - ユーザ固有の位置情報（X,Y、カンマ区切り）
入力後は必ず「Save」ボタンをクリックして、確実に内容を保存すること。

  ![Add_attribute.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_attribute.jpg)

## Client Scopes

Keycloakでは、OIDCのIDトークン、アクセストークン、UserInfoレスポンスにKeyCloakで管理している情報を連携することができる。この連携の仕組みは「Protocol Mapper」と呼ばれている。

ここでは、Protocol Mapperを一つのグループとしてまとめて管理するために便利なClient Scopeを新規に生成する。左ペインの「Client Scopes」をクリック。「Create」ボタンを押して、新規にClient Scopesを作る。

  ![client_scopes_create_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_scopes_create_button.jpg)

### 名前や同意画面で表示する確認メッセージなどを設定

以下の3項目を入力し、「Save」ボタンをクリックする。

- Name：location
- Description：location(x,y)
- Consent Screen Text ：location(x,y)

  ![Add_client_scope.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_client_scope.jpg)

### Client Scopesのリストの中から今作ったものを選択

Client Scopesの一覧画面に戻るので、今作ったもの（location）を選択する。

Setteings画面が表示される。そこで「Mappers」タブをクリック。Mapperを新規に作成するため、「Create」ボタンをクリックする。

  ![location_mappers_create_button.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/location_mappers_create_button.jpg)

### locationのMapperを設定する

「Create Protocol Mapper」画面で、以下の5項目を設定し、「Save」ボタンをクリックする。

- Name ：　location
- Mapper Type ： ドロップボックスより「User Attribute」選択

以下は、Mapper Typeを選択した後に表示される

- User Attribute：location
- Token Claim Name ：location
- Claim JSON Type ：String

  ![create_protocol_mapper.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/create_protocol_mapper.jpg)

## Client

左ペインの「Clients」をクリック。「Clients」画面に遷移するので、右上の「Create」ボタンを押して、新規にClientを作る。

  ![client_list.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_list.jpg)

### Add Client画面でClientを追加

ここでは「Client ID」テキストボックスに「amcl」と入力し、「Save」ボタンをクリックする。

  ![Add_client.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/Add_client.jpg)

### Settingsタブで各種設定

ros2_oidcに合わせ、該当Clientの詳細設定を実施する。

画面遷移で「Settings」タブが選択されていることを確認する。入力が終わったら保存するために画面下方の「Save」ボタンをクリックする。

- Consent Required ：ON
- Access Type：confidential
- Valid Redirect URIs
  - `http://localhost:8080/gettoken`
  - `http://${ユーザ環境に合わせたFQDN}:8080/gettoken`
    - e.g. `http://rdbox.172.16-0-132.nip.io:8080/gettoken`
- Web Origins
  - \*
    - （アスタリスク）

### Client Scopesタブで各種設定

該当Clientが要求するClient Scopesを設定する

Default Client Scopes の「Assigned Default Client Scopes」ボックスが「location」（先程追加したClient Scopes）と「web-origins」が残るように「Remove」「Add」ボタンを操作する。

  ![client_client_scope.jpg](/ros2/rdbox/sros2_oidc/docs/imgs/client_client_scope.jpg)

### Credentialsタブ

Secretを記録しておく。これはros2_oidcのプログラムの設定に必要となる情報となる。

ros2_oidcのプログラムの設定に必要となる情報を列挙する、Clients画面で再度確認ておくのが望ましい。

- server_url
- realm_name
- client_id
- client_secret_ke
- redirect_url
