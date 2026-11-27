# Feature map（ユーザー視点）

| Feature | ファイル |
|---------|----------|
| 管理画面で EventBridge 設定を保存する | [admin-settings.md](admin-settings.md) |
| 投稿の公開・更新でイベントを送る | [post-lifecycle-events.md](post-lifecycle-events.md) |
| プラグイン有効化と認証情報チェック | [activation.md](activation.md) |
| 管理画面から接続テスト | [test-connection.md](test-connection.md) |

共通の証拠: `npm run test:integration` が green。ユニットレベルは `tests/unit/` に対応テストがあること。