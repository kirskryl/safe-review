#!/usr/bin/env bash
# detect-stack.sh — read-only stack discovery for safe-review
set -euo pipefail

ROOT="${1:-.}"
ROOT="$(cd "$ROOT" && pwd)"

echo "root: $ROOT"
echo "--- manifests ---"
for f in \
  package.json package-lock.json pnpm-lock.yaml yarn.lock \
  requirements.txt pyproject.toml poetry.lock Pipfile Pipfile.lock \
  go.mod Cargo.toml Gemfile composer.json \
  Dockerfile docker-compose.yml docker-compose.yaml compose.yaml \
  Makefile Procfile \
  ; do
  if [[ -f "$ROOT/$f" ]]; then echo "present: $f"; fi
done

echo "--- frameworks / hints ---"
[[ -f "$ROOT/package.json" ]] && grep -E '"next"|"react"|"express"|"fastify"|"nestjs"' "$ROOT/package.json" 2>/dev/null | head -20 || true
[[ -f "$ROOT/requirements.txt" ]] && grep -Ei '^(django|flask|fastapi|aiogram|telethon|uvicorn|sqlalchemy)=' "$ROOT/requirements.txt" 2>/dev/null | head -20 || true
[[ -f "$ROOT/pyproject.toml" ]] && grep -Ei 'django|flask|fastapi|aiogram|telethon' "$ROOT/pyproject.toml" 2>/dev/null | head -20 || true

echo "--- deploy / systemd ---"
find "$ROOT" \( -name '*.service' -o -name 'deploy*.sh' -o -name '*nginx*' -o -path '*/deploy/*' \) \
  -type f 2>/dev/null | head -80

echo "--- test / lint commands (heuristic) ---"
[[ -f "$ROOT/package.json" ]] && python3 - <<'PY' "$ROOT/package.json" 2>/dev/null || true
import json,sys
p=json.load(open(sys.argv[1]))
for k,v in (p.get("scripts") or {}).items():
    if any(x in k for x in ("test","lint","audit","typecheck")):
        print(f"npm:{k} -> {v}")
PY
[[ -f "$ROOT/Makefile" ]] && grep -E '^[a-zA-Z0-9_-]+:' "$ROOT/Makefile" | head -40 || true
[[ -d "$ROOT/tests" || -d "$ROOT/test" ]] && echo "tests_dir: present"

echo "--- git ---"
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "branch: $(git -C "$ROOT" branch --show-current 2>/dev/null || true)"
  echo "dirty: $(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
else
  echo "git: no"
fi
