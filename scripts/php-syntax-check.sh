#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILES=(
  "$ROOT/event-publisher-on-aws.php"
  "$ROOT/uninstall.php"
  "$ROOT/src/bootstrap.php"
  "$ROOT/src/imds.php"
  "$ROOT/src/EventBridgePutEvents.php"
  "$ROOT/src/EventBridgePostEvents.php"
  "$ROOT/src/lifecycle.php"
)
for f in "${FILES[@]}"; do
  php -l "$f"
done
echo "php-syntax-check: ok"