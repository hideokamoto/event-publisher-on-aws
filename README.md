# EventBridge Post Events

WordPressの記事更新イベントをAWS EventBridgeに送信するプラグインです。

## 特徴

- **軽量**: AWS SDKやComposerを使わず、PHPの標準機能のみで実装
- **バンドルサイズ小**: 依存ライブラリなし、単一ファイル
- **ネームスペース衝突なし**: 最小限のクラス定義のみ
- **シンプル**: wp-config.phpで設定を完結
- **EC2インスタンスロール対応**: IMDSv2を使った自動認証情報取得をサポート

## セットアップ

### 1. プラグインのインストール

このディレクトリを`wp-content/plugins/`にコピーしてください。

### 2. AWS認証情報の設定

以下のいずれかの方法で認証情報を設定してください。

#### 方法A: wp-config.phpで設定（推奨：ローカル・Lightsail等）

`wp-config.php`に以下の定数を追加してください：

```php
// AWS EventBridge設定（必須）
define('AWS_EVENTBRIDGE_ACCESS_KEY_ID', 'your-access-key-id');
define('AWS_EVENTBRIDGE_SECRET_ACCESS_KEY', 'your-secret-access-key');

// オプション設定
define('AWS_EVENTBRIDGE_REGION', 'ap-northeast-1'); // デフォルト: ap-northeast-1
define('EVENT_BUS_NAME', 'wp-kyoto'); // デフォルト: default
define('EVENT_SOURCE_NAME', 'wordpress'); // デフォルト: wordpress
```

#### 方法B: EC2インスタンスロールを使用（推奨：EC2）

EC2インスタンス上で動作している場合、IAMロールを使用した認証が可能です。wp-config.phpへの認証情報の記載は不要です。

1. EC2インスタンスにIAMロールをアタッチ
2. IAMロールに必要なポリシーを追加（下記のIAMポリシーを参照）
3. プラグインを有効化するだけで自動的にインスタンスロールから認証情報を取得

**認証情報の優先順位:**
1. wp-config.phpの定数（定義されている場合）
2. EC2インスタンスロール（IMDSv2経由で自動取得）

**オプション設定（インスタンスロール使用時）:**

リージョンやイベントバス名をカスタマイズする場合は、`wp-config.php`に以下を追加：

```php
// オプション設定
define('AWS_EVENTBRIDGE_REGION', 'ap-northeast-1'); // デフォルト: インスタンスのリージョン
define('EVENT_BUS_NAME', 'wp-kyoto'); // デフォルト: default
define('EVENT_SOURCE_NAME', 'wordpress'); // デフォルト: wordpress
```

### 3. プラグインの有効化

WordPress管理画面の「プラグイン」から「EventBridge Post Events」を有効化してください。

## 送信されるイベント

### 記事公開・更新時

```json
{
  "EventBusName": "wp-kyoto",
  "Source": "wordpress",
  "DetailType": "post.published" または "post.updated",
  "Detail": {
    "id": "123",
    "title": "記事タイトル",
    "status": "publish",
    "updated_at": 1234567890,
    "permalink": "https://example.com/post-title/",
    "api_url": "https://example.com/wp-json/wp/v2/posts/123",
    "post_type": "post",
    "previous_status": "draft"
  }
}
```

### 記事削除時

```json
{
  "EventBusName": "wp-kyoto",
  "Source": "wordpress",
  "DetailType": "post.deleted",
  "Detail": {
    "id": "123"
  }
}
```

## IAMポリシー

EventBridgeにイベントを送信するため、以下のIAMポリシーが必要です：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "events:PutEvents",
      "Resource": "arn:aws:events:ap-northeast-1:123456789012:event-bus/wp-kyoto"
    }
  ]
}
```

## トラブルシューティング

### 設定エラー

認証情報が設定されていない場合、WordPress管理画面に警告が表示されます。

### デバッグログ

イベント送信のログは`error_log`に出力されます。デバッグログを確認するには、`wp-config.php`に以下を追加してください：

```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

ログは`wp-content/debug.log`に保存されます。

## 仕組み

このプラグインは以下のように動作します：

1. **認証情報の取得**:
   - wp-config.phpに定数が定義されている場合はそれを使用
   - 定義がない場合はIMDSv2を使ってEC2インスタンスロールから一時認証情報を取得
   - 一時認証情報は有効期限の5分前に自動更新（キャッシュ機能付き）

2. **WordPressアクションフック**: `transition_post_status`と`before_delete_post`を使用してイベントをキャプチャ

3. **AWS Signature V4**: PHPの標準関数でリクエストに署名
   - セッショントークンがある場合は`X-Amz-Security-Token`ヘッダーを追加

4. **HTTP送信**: WordPressの`wp_remote_request()`でEventBridge APIにPOST

AWS SDKを使わずに、EventBridge APIを直接呼び出しています。

## ライセンス

GPL-3.0-or-later
