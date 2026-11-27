# Activation and credentials

## Sub-features

- 有効化時の認証情報チェック（静的キー / IMDS）
- 有効化警告オプション `eventbridge_activation_warnings`

## How to get to it (user POV)

プラグイン一覧で有効化。

## Driving it with PHPUnit

`tests/integration/ActivationDeactivationTest.php`。

```bash
npm run test:integration -- --filter ActivationDeactivationTest
```

## Gotchas

- IMDS は `169.254.169.254` への HTTP をフィクスチャで差し替える。
- 有効化フックは `eventbridge_post_events_activate()`（ファイル末尾付近）。