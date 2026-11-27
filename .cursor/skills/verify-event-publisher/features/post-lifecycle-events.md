# Post lifecycle events

## Sub-features

- `transition_post_status` による publish / update
- `before_delete_post` による削除イベント
- async cron `eventbridge_async_send_event`

## How to get to it (user POV)

投稿を下書き→公開、公開済みを更新、ゴミ箱/削除。

## Driving it with PHPUnit

`tests/integration/PostStatusTransitionTest.php` と `tests/integration/EventSendingTest.php`。

```bash
npm run test:integration -- --filter PostStatusTransitionTest
npm run test:integration -- --filter EventSendingTest
```

## Gotchas

- HTTP は `pre_http_request` でモックする。実 EventBridge には繋がない。
- post type のフィルタ設定により送らないケースがある。