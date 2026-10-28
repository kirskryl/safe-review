#!/usr/bin/env bash
# collect-inventory.sh — read-only inventory (paths only; no secret contents)
set -euo pipefail

ROOT="${1:-.}"
ROOT="$(cd "$ROOT" && pwd)"

echo "root: $ROOT"
echo "--- secret-bearing paths (metadata only) ---"
find "$ROOT" \( \
  -name '.env' -o -name '.env.*' -o -name '*credentials*.json' \
  -o -name '*service_account*.json' -o -name '*.pem' -o -name 'id_rsa' \
  -o -name '*telegram-proxy.env' \
  \) -type f 2>/dev/null | head -80 | while read -r f; do
  mode=$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null || echo '?')
  echo "secret_candidate mode=$mode path=$f"
done

echo "--- config / deploy paths ---"
find "$ROOT" \( \
  -name 'Dockerfile*' -o -name 'docker-compose*.yml' -o -name 'compose*.yaml' \
  -o -name '*.service' -o -name 'nginx*.conf' \
  -o -path '*/deploy/*' -o -path '*/.github/workflows/*' \
  \) -type f 2>/dev/null | head -120

echo "--- dependency manifests ---"
find "$ROOT" \( \
  -name 'package-lock.json' -o -name 'pnpm-lock.yaml' -o -name 'yarn.lock' \
  -o -name 'poetry.lock' -o -name 'requirements*.txt' -o -name 'Pipfile.lock' \
  -o -name 'go.sum' -o -name 'Cargo.lock' \
  \) -type f 2>/dev/null | head -40

echo "--- entrypoint hints ---"
find "$ROOT" \( -name 'main.py' -o -name 'app.py' -o -name 'server.js' -o -name 'index.ts' \
  -o -name 'bot_config.json' \) -type f 2>/dev/null | head -40

echo "--- note ---"
echo "No file contents of secret-bearing paths were printed."
