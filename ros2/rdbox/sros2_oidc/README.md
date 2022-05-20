# SROS2 with OIDC(OpenID Connect) ：ロボットが安全に人を識別するための技術

## Video

<!-- markdownlint-disable MD034 -->
https://user-images.githubusercontent.com/40556102/169439356-1eccb2bc-7004-42bd-8611-8813a87c739b.mp4

## Concepts

協働型ロボットとして、人と綿密に関わって動くロボットが増えている。その中で「誰が何を命令したか？」「誰にどのようなサービスを提供可能か？」等、「管理・監査・証跡」もしくは「個人に最適化した役務提供」等を目的に、個人を認識（≒認証・認可）する必要性が発生している。利用者の属性（氏名・権限・位置情報等）や認証（顔・指紋等）に基づき、役務提供する場合、個人情報保護が課題となる。しかし現状、多くの現場でそれらの個人情報をロボット上PCに保存して運用していないだろうか。研究段階や利用者の人数が少ないうちは顕在化しないが、社会システムとしてロボット活用が一般化した時には問題となる可能性が高い。

この課題に対して、我々は「sros2_oidc」というパッケージを開発・公開した。本パッケージのアプローチでは、認証規約として[OIDC(OpenID Connect)](https://openid.net/connect/)を採用し、SROS2と組み合わせてロボット終端まで利用者情報を安全な経路で伝送するという方式を採る。

![system architecture.png](/ros2/rdbox/sros2_oidc/docs/imgs/JP_system%20architecture.png)

OIDCはWebサービスではスタンダードな認証規約の一つである。ロボットに対してはユーザから同意が得られた最小限の情報だけ（例えば位置情報のみ）を連携することや、遠隔から利用権限を即時停止するなどその用途は多岐に渡る。また、OIDCで取り扱いに注意が必要な「アクセスToken」を、セキュリティを確保した上で「Relaying Party（OIDCとROS2の橋渡しを行う）」から、「Resource Server（実際に情報を受け取って命令を実行するロボット）」へ受け渡しするために「SROS2」を利用している（図2）。「PKI(公開鍵基盤)/セキュリティ規則を記述したXML」に基づくアクセス制御を行うSROS2は、固定されたノード間の通信において強みを発揮する。一方で、鍵の管理コストが、利用者が増えるたび増大するといった問題点もある。本パッケージのような橋渡しのための仕組みは、管理コストの低減に役立つことが期待できる。

![OIDC_Flow.png](/ros2/rdbox/sros2_oidc/docs/imgs/OIDC_Flow.png)

## 構築手順

### SROS2のセットアップ

まず、SROS2が動くROS2 Foxy環境を準備します。

手順は、我々が記載した["SROS2をセットアップしてみよう"](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/jp/SROS2_setup.md)も参考になります。

### OpenID Provider（OP, Keycloakを使用）のセットアップ

次に、OpenID Provider（OP, Keycloakを使用）に対して、`sros2_oidc用のレルム`、`Relaying Prty`、`ユーザ`等を順に追加していきます。

手順は、別ページ["SROS2_OIDC（Keycloak操作）"](https://github.com/rdbox-intec/rdbox/tree/insiders/ros2/rdbox/sros2_oidc/docs/jp/keycloak.md)をご確認下さい。

### sros2_oidcのデモ
