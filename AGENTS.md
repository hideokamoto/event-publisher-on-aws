# Event Publisher on AWS — エージェント向けガイド

このリポジトリは **WordPress プラグイン 1 本**（`event-publisher-on-aws.php`、約 3,200 行）です。エージェントの主な入力はこのファイルなので、ここに残った workaround がそのまま「正しいパターン」としてコピーされます（[Poteto pyramid](https://www.youtube.com/watch?v=O_zcc6Xl12g) の codebase 層）。

## 目的

投稿の公開・更新・削除時に Amazon EventBridge へ `PutEvents` する。管理画面でバス名・ソース・リージョン・送信モード等を設定する。

## アーキテクチャ（変更前に読む）

| 要素 | 役割 |
|------|------|
| `eventbridge_*()` 関数 | IMDSv2 / 有効化フック用のトップレベルヘルパー |
| `EventBridgePutEvents` | AWS 署名・HTTP・リトライ・PutEvents |
| `EventBridgePostEvents` | WP フック、設定画面、イベント組み立て・送信 |
| `tests/unit/` | Brain Monkey（WordPress なし） |
| `tests/integration/` | wp-env + 実 WP |

**境界**

- 本番コードに Composer の `require` は置かない（`require` は PHP バージョンのみ）。
- `vendor/` はリポジトリに含めない。配布物にも含めない。
- 新機能は原則 **既存の 1 ファイル** に追加する。`src/` 分割は明示的なリファクタ依頼があるまで行わない（テスト README の将来案と混同しない）。
- AWS 呼び出しは `EventBridgePutEvents` 経由。管理画面は `EventBridgePostEvents`。
- 設定の上書きは `wp-config.php` の定数（`EVENT_BUS_NAME` 等）または `eventbridge_settings` オプション。

## エージェントがやってはいけないこと（スロップ源）

1. **composer.json の `require` にパッケージを足す** — 静的ゲートと CI が落ちる。
2. **依頼なくルートに README / 設計ドキュメントを増やす** — 根拠のない Markdown はエージェントが「恒久ルール」と誤読する。
3. **動かない理由をコメントだけで正当化する** — ルールは lint / テスト / 構造に落とす（`scripts/agent-check.sh`、Semgrep、PHPUnit）。
4. **ユニットテストでプラグインを読まずロジックを再実装する** — 既存の反パターン。新規テストは integration か、実際のクラス・メソッドを叩く。
5. **`nosemgrep` 無しの `exec` 等** — 既存の Semgrep 例外形式に合わせる。
6. **本番 AWS への実送信を検証で行う** — `pre_http_request` フィクスチャ（`tests/fixtures/aws-responses.php`）を使う。

## 静的解析（コストが低い順）

```bash
npm run agent:check    # jq + 構造チェック（PHP 不要）
# CircleCI と同じ Semgrep（ローカルに semgrep がある場合）
semgrep scan --config p/default --config p/php --config semgrep/rules/agent-environment.yml .
```

ブランチでは `.circleci/config.yml` の `semgrep-scan` と `commitlint`、`.circleci/wp-test.yaml` の PHPUnit が走る。

## 検証（完了の定義）

Docker + wp-env が使える環境では **必ず** 次を実行してから PR を出す。

```bash
npm install
npm run test:setup
npm run test:unit
npm run test:integration
```

wp-env が使えない Cloud Agent では `npm run agent:check` を通し、PHP 変更時は CI の PHPUnit に委ねる。UI 挙動は `.cursor/skills/verify-event-publisher/` の feature map を参照。

## コミット

Conventional Commits（日本語件名可）。例: `feat: 予約投稿でもイベントを送る` / `chore: エージェント向け静的ゲートを追加`。

## 修正をルールに昇格する

レビューで同じ指摘が **2 回** 出たら、AGENTS.md の箇条書きではなく `semgrep/rules/` または `scripts/agent-check.sh` に移す（Encode lessons in structure）。