# Weekend Productivity Challenge: Event Publisher on AWS

> Tags: #productivity

WordPress で記事を「公開」した瞬間に、要約・SNS投稿文・翻訳・タグ付けといった"公開後の定型作業"をAIが肩代わりしてくれたら——。そんな面倒くさがりのための仕組みを、週末のあいだに AWS 上で組み立てました。この記事では、その中核になる WordPress プラグイン **Event Publisher on AWS** を紹介します。

## 1. Vision & What the App Does（ビジョンとアプリの概要）

ブログを運営していると、記事本体を書き終えたあとに"それ以外の作業"が地味に多いことに気づきます。要約文を書き、X（旧Twitter）用の投稿文を考え、英語圏向けに翻訳し、関連するカテゴリやタグを整理する……。書くこと自体より、この**公開後のルーティンワーク**のほうに時間を溶かしている、という人は少なくないはずです。

**Event Publisher on AWS** は、この「公開後の定型作業」を丸ごと自動化するための"トリガー基盤"です。やっていることはシンプルで、WordPress で投稿が **公開・更新・予約・削除** されたタイミングを検知し、そのイベントを **Amazon EventBridge** に発行します。あとは EventBridge の先に AI 処理（Amazon Bedrock / Nova）をつないでおくだけで、記事を公開した瞬間に：

- 記事本文からの**自動要約**の生成
- **SNS投稿文**の下書き生成
- 英語など**多言語への翻訳**ドラフト
- 内容に基づく**タグ・カテゴリの提案**

といった作業が、人手を介さずバックグラウンドで走り出します。

ユーザー体験としては驚くほど地味で、**「いつも通り WordPress の"公開"ボタンを押すだけ」**。設定画面で AWS リージョンとイベントバス名を入れておけば、あとはプラグインが裏側でイベントを流し続けます。書き手は執筆に集中でき、公開後の雑務はイベント駆動のAIパイプラインが引き受ける——これがこのツールが解決したい生産性の問題です。

## 2. How You Built It（開発プロセス）

技術的な肝は、**「WordPress から、余計な依存ライブラリなしで、安全に EventBridge を叩く」**という一点に尽きます。

WordPress プラグインは配布時に `vendor/` を同梱したくない（＝AWS SDK for PHP を丸ごと積みたくない）という事情があります。そこで **AWS SDK に頼らず、EventBridge の `PutEvents` API を SigV4 署名から手書きで実装**しました。`hash_hmac` で署名キーを導出し、Canonical Request を組み立てて `Authorization` ヘッダを作る——という一連の処理をプラグイン内に閉じ込め、**本番動作に必要な外部依存ゼロ**（Composer の依存はテスト用の `require-dev` のみ）を実現しています。

認証情報の扱いも工夫したポイントです。EC2 上で動かすケースを想定し、**IMDSv2**（トークン方式のインスタンスメタデータ）経由でインスタンスロールの一時認証情報を取得できるようにしました。トークン取得 → 認証情報取得の流れをキャッシュ（transient）でラップし、EC2 以外の環境では無駄なリクエストを飛ばさないよう失敗結果もキャッシュしています。

苦労したのは主に3点です：

1. **署名の一致問題** — SigV4 は署名対象のヘッダやペイロードのハッシュが1バイトでもズレると `403` になります。`x-amz-security-token` を含む/含まないケース（一時認証情報の有無）で Canonical Headers を出し分ける必要があり、ここのデバッグに時間を使いました。
2. **公開フローをブロックしない** — 公開のたびに同期でAPIを叩くと、失敗時に投稿画面が固まります。そこで `wp_schedule_single_event` を使った**非同期送信モード**をデフォルトにし、EventBridge 側が不調でも執筆体験を止めないようにしました（同期モードも選択可）。
3. **イベント形式の標準化** — 当初は素朴なJSONを送っていましたが、下流のトレーサビリティを考え、**Envelope 形式**（`event_id` / `correlation_id` / `event_timestamp` / `source_system` / `data`）に統一（v2.0.0）。イベントIDと相関IDで、どの記事のどのアクションがどのAI処理につながったかを追跡できるようにしました。

品質面では **PHPUnit + Brain Monkey** でWordPress関数をモックした単体テストを整備し、**CircleCI で PHPUnit と Semgrep（SAST）** を回しています。

## 3. AWS Services Used & Architecture Overview（利用AWSサービスと構成）

**AWS Services Used:**

- **Amazon EventBridge** — 公開イベントを受け取るイベントバス。ルールでイベントを振り分け、AI処理のトリガーにする中心的存在。
- **AWS Lambda** — EventBridge ルールのターゲット。イベントを受けて Bedrock を呼び出す"自動化ロジック"の実行層。
- **Amazon Bedrock（Nova モデル）** — 要約・SNS文生成・翻訳・タグ提案といったAI処理を担うLLMオーケストレーション層。
- **Amazon EC2 + IMDSv2** — WordPress を稼働させるホスト。インスタンスロールで安全に認証情報を供給。
- **Amazon DynamoDB / S3（任意）** — 生成物（要約・翻訳）の保存やべき等制御のための状態管理。

**Architecture Overview:**

```
[WordPress 投稿公開]
      │  transition_post_status / before_delete_post フック
      ▼
[Event Publisher プラグイン]
      │  SigV4署名付き PutEvents（Envelope形式・非同期）
      ▼
[Amazon EventBridge]  event: post.published / post.updated / post.deleted
      │  Rule でマッチング
      ▼
[AWS Lambda]  ── invoke ──▶ [Amazon Bedrock / Nova]
      │                          要約・SNS文・翻訳・タグ生成
      ▼
[DynamoDB / S3 に保存 → WordPress へ書き戻し or 通知]
```

データの流れは一方向でシンプルです。書き手のアクション（公開）がイベントになり、EventBridge が"神経系"として各AI処理へ配線し、Bedrock が実際の知的作業をこなす。プラグインはこの入口＝**イベントの発生源**に徹しています。

## 4. What You Learned（学び）

いちばんの学びは、**「AIの生産性ツールは、必ずしもAIをアプリに直接埋め込む必要はない」**ということでした。イベント駆動アーキテクチャで"公開"という業務イベントを疎結合に切り出しておけば、AI処理はあとから EventBridge の先にいくらでも足せます。プラグイン本体はAIを一切知らないのに、システム全体としてはAIパイプラインとして機能する——この**関心の分離**の気持ちよさを体感できました。

技術面では、**SDKに頼らずSigV4署名を手実装した**ことで、AWSの署名の仕組みとIMDSv2の認証フローを"腹落ち"レベルで理解できました。普段ブラックボックスにしていた部分を自分で書くと、エラーの原因が推測できるようになります。

そして**非同期化の重要性**。外部API連携をユーザー操作の同期パスに置かない、という当たり前の設計判断が、そのままUX（執筆体験）の品質に直結することを再確認しました。

## 5. Link to App or Repo（リンク）

- **GitHub Repository:** https://github.com/hideokamoto/event-publisher-on-aws
- **Live Demo:** WordPress 管理画面にプラグインを導入し、リージョン／イベントバス名を設定 →「接続テスト」ボタンでEventBridgeへの疎通を確認できます（スクリーンショット添付予定）。

いつも通り"公開"を押すだけで、公開後の雑務がAIに片付いていく。週末の小さな仕組みですが、毎回の運用コストを確実に削ってくれる相棒になりました。 #productivity
