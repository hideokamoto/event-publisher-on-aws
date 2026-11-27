---
name: verify-event-publisher
description: Drive and verify the EventBridge Post Events WordPress plugin via wp-env and PHPUnit. Use when changing admin settings, post events, activation, or AWS send paths.
---

# Verify Event Publisher on AWS

WordPress プラグイン。ユーザーが触るのは **WP 管理画面の設定** と **投稿のステータス変更**（公開・更新・削除）です。

## Launch

```bash
npm install
npm run wp-env start
npm run test:setup
```

Ready when `npm run wp-env run cli wp option get siteurl` succeeds.

## Doctor

```bash
npm run agent:check
docker ps | grep -q wp-env || echo "wp-env containers not running"
```

## Drive (automated)

ユニット（高速）:

```bash
npm run test:unit
```

統合（WP 実装）:

```bash
npm run test:integration
```

## Evidence

- PHPUnit が green であること（exit 0）。
- 設定・送信の変更は該当 feature ファイルのテスト名を増やすか既存テストを更新する。
- 本番 AWS には接続しない。`tests/fixtures/aws-responses.php` を使う。

## Cleanup

```bash
npm run wp-env stop
```

共有のユーザー環境では `destroy` は明示依頼があるまで実行しない。

## Helpers

| コマンド | 用途 |
|---------|------|
| `npm run agent:check` | Composer/vendor/構造ゲート |
| `npm run test:unit` | Brain Monkey スイート |
| `npm run test:integration` | wp-env 統合スイート |

Feature map: `features/README.md`