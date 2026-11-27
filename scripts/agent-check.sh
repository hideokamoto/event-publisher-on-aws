#!/usr/bin/env bash
# Agent-oriented gates: deterministic checks cheaper than prose rules.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "agent-check: $*" >&2
  exit 1
}

echo "== composer.json: require section =="
if ! command -v jq >/dev/null 2>&1; then
  fail "jq is required"
fi

REQUIRE_KEYS="$(jq -r '.require // {} | keys[]' composer.json 2>/dev/null || true)"
if [ -z "$REQUIRE_KEYS" ]; then
  echo "ok: require is empty"
else
  while IFS= read -r key; do
  [ -z "$key" ] && continue
    if [ "$key" != "php" ]; then
      fail "composer.json require must not list production package: $key"
    fi
  done <<< "$REQUIRE_KEYS"
  echo "ok: require only contains php (if any)"
fi

if [ -d vendor ]; then
  fail "vendor/ must not exist in the working tree"
fi
echo "ok: no vendor/ directory"

if ! grep -q 'vendor' .gitignore 2>/dev/null; then
  fail "vendor/ must be listed in .gitignore"
fi
echo "ok: vendor/ in .gitignore"

echo "== forbidden patterns in production PHP =="
PROD_PHP=(
  event-publisher-on-aws.php
  uninstall.php
  src/bootstrap.php
  src/imds.php
  src/EventBridgePutEvents.php
  src/EventBridgePostEvents.php
  src/lifecycle.php
)
for f in "${PROD_PHP[@]}"; do
  if [ ! -f "$f" ]; then
    continue
  fi
  if grep -nE '\beval\s*\(' "$f" >/dev/null 2>&1; then
    fail "$f contains eval()"
  fi
done
echo "ok: no eval() in production PHP"

if command -v php >/dev/null 2>&1; then
  echo "== php -l =="
  for f in "${PROD_PHP[@]}"; do
    php -l "$f"
  done
else
  echo "skip: php not in PATH (CI will lint)"
fi

echo "agent-check: all gates passed"