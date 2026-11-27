# Admin “Test connection”

## Sub-features

- `admin_post_eventbridge_test_connection` ハンドラ
- PutEvents 疎通（モック可）

## How to get to it (user POV)

設定画面の接続テストボタン（要管理者権限）。

## Driving it with PHPUnit

統合テストで HTTP をモックしたうえでハンドラを直接呼ぶのが安定。新規テスト追加時は `EventSendingTest` / `AdminSettingsTest` のモックパターンをコピーする。

## Gotchas

- nonce と `manage_options` が必要。E2E では wp-env の admin ユーザーで操作する。