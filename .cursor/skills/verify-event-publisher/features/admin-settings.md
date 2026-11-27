# Admin settings

## Sub-features

- イベントバス名・ソース名・リージョン
- 送信モード（sync / async）
- 対象 post type、デバッグログ

## How to get to it (user POV)

WP 管理画面 → **Settings → EventBridge Post Events**（`EventBridgePostEvents::add_settings_menu`）。

## Driving it with PHPUnit

| 検証内容 | テスト |
|---------|--------|
| `update_option` した値を **`EventBridgePostEvents::get_setting()`** が読める | `test_plugin_get_setting_reads_saved_options` |
| オプション永続化 | `test_save_send_mode_setting` ほか |

```bash
npm run test:integration -- --filter AdminSettingsTest
```

証拠: `get_option()` だけでなく、保存した `send_mode` がプラグインの `get_setting('send_mode')` と一致すること。

## Gotchas

- 定数 `EVENT_BUS_NAME` 等が定義されていると、`get_setting` は定数を優先する。
- オプション未保存時はコンストラクタ内のデフォルトが効く。空配列だけでは本番と同じ状態にならない場合がある。