# Admin settings

## Sub-features

- イベントバス名・ソース名・リージョン
- 送信モード（sync / async）
- 対象 post type、デバッグログ

## How to get to it (user POV)

WP 管理画面 → **Settings → EventBridge Post Events**（`EventBridgePostEvents::add_settings_menu`）。

## Driving it with PHPUnit

`tests/integration/AdminSettingsTest.php` — `update_option('eventbridge_settings', ...)` とプラグインの読み取り。

```bash
npm run test:integration -- --filter AdminSettingsTest
```

## Gotchas

- デフォルトはオプション未保存時にクラス内デフォルトが効く。空配列だけでは本番と同じ状態にならない場合がある。