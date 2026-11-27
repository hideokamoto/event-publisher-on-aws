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
| `eventbridge_post_events_activate()` でデフォルトオプション作成・エラーなし | `test_activation_callback_seeds_default_options` |
| 認証情報あり + IMDS 成功時は `eventbridge_activation_warnings` なし | 同上（warnings アサーション） |
| IMDS 失敗かつ `EVENT_BRIDGE_REGION` 未設定時に warnings 保存 | `test_activation_callback_records_region_warnings_without_fallback`（定数がある CI では skip） |
| 無効化で cron が消える | `test_deactivation_cleanup` |
| 定数による認証情報 | `test_credentials_check` |

```bash
npm run test:integration -- --filter ActivationDeactivationTest
```

手動確認: `eventbridge_post_events_activate()` 実行後、`eventbridge_activation_errors` が false、`eventbridge_activation_warnings` が false（または未設定）、`eventbridge_settings.send_mode` が `async` であること。

## Gotchas

- IMDS は `pre_http_request` でモックする（統合テストの `mock_http_requests`）。
- 認証情報が無い環境では有効化が `wp_die` する。CI は wp-config にテスト用キーを注入している。
- 実装は `src/lifecycle.php` の `eventbridge_post_events_activate()`。