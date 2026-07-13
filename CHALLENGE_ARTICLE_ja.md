# Weekend Productivity Challenge: Event Publisher on AWS

> Tags: #productivity

10年で1,000本以上、いまも週2ペースで年100記事を更新しています。しんどいのは「書くこと」ではなく、**公開したあとに毎回ついてくる定型作業**のほう。要約を書き、タグを整理し、SNSに拡散し、アクセス解析を眺め、サーバーとCMSを保守する——。この「記事を書く以外」の作業に追われると、書きたいときに書きたいことが書けなくなります。

そこで、これらの雑務をAIエージェント群にオフロードするための"神経系"として作ったのが、WordPress プラグイン **Event Publisher on AWS** です。この記事では、このプラグインを起点に実際に本番稼働している、イベント駆動のAIコンテンツ運用自動化パイプラインを紹介します。

## 1. Vision & What the App Does（ビジョンとアプリの概要）

解決したい生産性の問題はシンプルです。**「記事を書く」以外のルーティンワークを、書き手の手から完全に切り離す。**

具体的には、公開後に発生する以下の作業を自動化します：

- **要約の自動生成**（Bedrock / Claude が本文から抜粋を作り、WordPress に書き戻す）
- **タグの自動抽出**（同じく Claude が内容からタグを提案し、WordPress に反映）
- **ベクトルインデックス化**（Nova Embeddings で埋め込みを作り S3 Vectors に格納）
- **SNS（X / Twitter）への自動投稿**（公開直後の告知＋過去記事の掘り起こし拡散）
- **パフォーマンス分析レポート**（GA4 × Search Console × Claude で週次レポートを Slack へ）
- **インフラ運用**（Bedrock Agent + SSM Runbook で WP/サーバー保守を Slack から）

**Event Publisher on AWS** そのものの役割は、この一連の自動化の**入口＝トリガー**です。WordPress で投稿が **公開・更新・予約・削除** された瞬間を検知し、その業務イベントを Amazon EventBridge に発行します。

ユーザー体験は拍子抜けするほど地味で、書き手がやることは**「いつも通り"公開"ボタンを押す」だけ**。押した瞬間、要約・タグ付け・インデックス化・SNS告知がバックグラウンドで走り出します。書き手は執筆だけに集中でき、公開後の雑務はイベント駆動のAIパイプラインが黙って片付ける——これが目指した状態です。

## 2. How You Built It（開発プロセス）

このプラグインの技術的な肝は、**「WordPress から、余計な依存ライブラリなしで、安全に EventBridge を叩く」**という一点です。

WordPress プラグインは配布時に `vendor/` を同梱したくない（AWS SDK for PHP を丸ごと積みたくない）という事情があります。そこで **AWS SDK に頼らず、EventBridge の `PutEvents` API を SigV4 署名から手書きで実装**しました。`hash_hmac` で署名キーを導出し、Canonical Request を組み立てて `Authorization` ヘッダを作る一連の処理をプラグイン内に閉じ込め、**本番動作に必要な外部依存ゼロ**（Composer の依存はテスト用の `require-dev` のみ）を実現しています。

認証情報は、WordPress を載せている EC2 のインスタンスロールを **IMDSv2**（トークン方式のメタデータ）経由で取得。トークン取得と認証情報取得を transient でキャッシュし、EC2 以外の環境では失敗結果もキャッシュして無駄なリクエストを抑えています。

苦労したのは主に3点です：

1. **SigV4 署名の一致** — 署名対象のヘッダやペイロードハッシュが1バイトでもズレると即 `403`。一時認証情報の有無で `x-amz-security-token` を含む/含まないケースの Canonical Headers を出し分ける必要があり、ここのデバッグに時間を使いました。
2. **公開フローをブロックしない** — 公開のたびに同期でAPIを叩くと、失敗時に投稿画面が固まります。`wp_schedule_single_event` を使った**非同期送信モード**をデフォルトにし、AWS 側が不調でも執筆体験を止めないようにしました（同期モードも選択可）。
3. **イベント形式の契約化** — 下流のトレーサビリティのため、**Envelope 形式**（`event_id` / `correlation_id` / `event_timestamp` / `source_system` / `data`）にv2.0.0で統一。イベントIDと相関IDで「どの記事のどのアクションがどのAI処理につながったか」を追跡できます。

システム全体は **モノレポのマイクロサービス分割**として構成し、各リポジトリを独立してデプロイ・テスト可能にしました。**EventBridge / SNS のメッセージ形式（JSONスキーマ）だけが暗黙の契約（Contract）**という疎結合設計です。元は巨大なモノリシック Lambda 関数だったものを、AIの力を借りてモダン化していった結果、自然と EDA（イベント駆動アーキテクチャ）に行き着きました。開発は **Kiro による Spec駆動開発（requirements → design → tasks → 実装/検証）** と Steering Docs（コーディング規約）を併用しています。品質面ではプラグインを **PHPUnit + Brain Monkey** でテストし、**CircleCI で PHPUnit と Semgrep（SAST）** を回しています。

## 3. AWS Services Used & Architecture Overview（利用AWSサービスと構成）

**AWS Services Used:**

- **Amazon EventBridge** — 公開イベントを受けるカスタムバス（`wp-kyoto`）＋日次スケジューラ。パイプライン全体の"神経系"。
- **AWS Lambda** — `content-enrichment` / `x-post-bot` / `blog-marketing-automation` / `ga-reporter` など各自動化ロジックの実行層。
- **Amazon Bedrock** — 要約・タグ抽出・SNS投稿文生成に **Claude**、週次レポートに **Claude Sonnet**、埋め込みに **Nova Embeddings**、インフラ運用に **Bedrock Agent** を利用するAIオーケストレーション層。
- **Amazon SNS** — Topic `post-to-x` を使った Fan-out。複数の発行元から購読者へ疎結合に配信。
- **Amazon SQS** — SNS→SQS→Bot の配信バッファ、および投稿失敗時の **DLQ** フォールバック。
- **Amazon S3 Vectors** — 記事の埋め込みベクトルの保存先。
- **AWS Secrets Manager** — X（Twitter）の OAuth2 トークン管理（自動更新）。
- **Amazon EC2 + IMDSv2** — WordPress の稼働ホストと安全な認証情報供給。
- **AWS Systems Manager** — インフラ運用エージェントの SSM Runbook 実行。

**Architecture Overview:**

```
[WordPress 投稿公開 (EC2)]
      │  transition_post_status / before_delete_post フック
      ▼
[Event Publisher プラグイン]  ← 本応募の中核
      │  SigV4署名付き PutEvents（PHP直接・AWS SDK不要・非同期・Envelope形式）
      ▼
[Amazon EventBridge  Bus: wp-kyoto]
      │  detail-type フィルタ: post.published / updated / deleted / scheduled
      ▼
[content-enrichment Lambda]
      ├─ PostExcerptTask   Bedrock Claude → 要約 → WordPressへ書き戻し
      ├─ PostTagTask       Bedrock Claude → タグ抽出 → WordPressへ書き戻し
      ├─ PostIndexingTask  Nova Embeddings → S3 Vectors
      └─ PostSnsPublishTask → SNS Topic: post-to-x に発行
                                   │  Fan-out
                                   ▼
                          [x-post-bot Lambda + Secrets Manager]
                             → X(Twitter) 投稿（スレッド対応 / OAuth2自動更新 / DLQ:SQS）

（別ライン）
[EventBridge スケジュール 毎日9:00 JST]
   → 3サイト横断で過去記事をランダム抽出（WP API）
   → Claude で投稿文生成（280字以内・絵文字禁止・3回リトライ+指数バックオフ）
   → SNS: post-to-x → x-post-bot で自動拡散

[ga-reporter]     GA4 × Search Console × WP API → Claude Sonnet → Slack（週次レポート）
[aws-wp-manager]  Bedrock Agent + SSM Runbook → Slack（インフラ運用）
```

データの流れは一方向でシンプルです。書き手のアクション（公開）が業務イベントになり、EventBridge が神経系として各AI処理へ配線し、Bedrock が実際の知的作業をこなす。**プラグインはこの入口＝イベントの発生源に徹し、重い処理はすべて AWS 側にオフロード**することで、WordPress 本体をシンプルに保ち、運用コストを抑えています。

## 4. What You Learned（学び）

いちばんの学びは、**「AIの生産性ツールは、AIをアプリ本体に埋め込む必要はない」**ということでした。EDAで"公開"という業務イベントを疎結合に切り出しておけば、AI処理はあとから EventBridge / SNS の先にいくらでも足せます。プラグイン本体はAIを一切知らないのに、システム全体としては強力なAIパイプラインとして機能する——この**関心の分離**の効きの良さを実感しました。EventBridge と SNS の**メッセージ形式だけを契約**にすると、各サービスを独立してデプロイ・テストでき、機能追加が"新しい購読者を足すだけ"になります。

技術面では、**SDKに頼らずSigV4署名を手実装した**ことで、AWSの署名の仕組みとIMDSv2の認証フローを腹落ちレベルで理解できました。普段ブラックボックスにしていた部分を自分で書くと、`403` の原因が推測できるようになります。

もうひとつは、**「やらないことを決めたら、あとはAWSで自動化する」**という発想の転換。元は1つの巨大なモノリシック Lambda だったものを、AIの支援（Kiro での Spec駆動開発）でマイクロサービスへ分割・モダン化していった過程そのものが、開発サイクルの学びでした。まず多少手を動かしてから設計すると「コレジャナイ感」が減る、というのも実体験として得た知見です。

## 5. Link to App or Repo（リンク）

- **GitHub Repository:** https://github.com/hideokamoto/event-publisher-on-aws
- **Architecture Deck（構成解説スライド）:** https://www.docswell.com/s/hideokamoto/K1QJ94-2026-03-26-205603
- **Live:** WordPress 管理画面にプラグインを導入し、リージョン／イベントバス名を設定 →「接続テスト」ボタンで EventBridge への疎通を確認できます。実際に wp-kyoto.net ほか3サイトで本番稼働中です。

いつも通り"公開"を押すだけで、要約・タグ付け・SNS拡散・分析までAIが片付けていく。年100記事を"書くこと"に集中し続けるための、小さくて確実な相棒になりました。 #productivity
