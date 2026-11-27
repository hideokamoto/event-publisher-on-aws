# Activation and credentials

## Sub-features

- 有効化時の認証情報チェック（静的キー / IMDS）
- 有効化警告オプション `eventbridge_activation_warnings`
- `eventbridge_post_events_activate()` によるデフォルトオプション作成

## How to get to it (user POV)

プラグイン一覧で有効化。

## Driving it with PHPUnit

| 検証内容 | テスト |
|---------|--------|
| 有効化コールバックで `eventbridge_settings` / `eventbridge_metrics` が作成される | `test_activation_callback_seeds_default_options` |
| 無効化で cron が消える | `test_deactivation_cleanup` |
| 定数による認証情報 | `test_credentials_check` |

```bash
npm run test:integration -- --filter ActivationDeactivationTest
```

手動確認: `eventbridge_post_events_activate()` 実行後、`get_option('eventbridge_activation_errors')` が false、`eventbridge_settings.send_mode` が `async` であること。

## Gotchas

- IMDS は `pre_http_request` でモックする（統合テストの `mock_http_requests`）。
- 認証情報が無い環境では有効化が `wp_die` する。CI は wp-config にテスト用キーを注入している。
- 実装は `src/lifecycle.php` の `eventbridge_post_events_activate()`。