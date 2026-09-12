#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Register the soc_lab pack, webhooks, and datastore keys on a running
# StackStorm instance. Run once after `docker compose up -d` has brought
# StackStorm healthy (usually ~2 minutes).
#
# Usage: bash scripts/setup-stackstorm.sh
# -----------------------------------------------------------------------------
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

Ctl=(docker exec -i soc-stackstorm st2)

echo "==> Waiting for StackStorm API..."
for _ in $(seq 1 30); do
  if docker exec soc-stackstorm st2ctl status >/dev/null 2>&1; then break; fi
  sleep 5
done

echo "==> Registering soc_lab pack..."
"${Ctl[@]}" pack register soc_lab || "${Ctl[@]}" pack load /opt/stackstorm/packs/soc_lab

echo "==> Ensuring webhook 'elastalert' exists..."
"${Ctl[@]}" webhook list 2>/dev/null | grep -q elastalert || \
  "${Ctl[@]}" webhook save elastalert

echo "==> Storing datastore keys (placeholders; set real values for live deploy)..."
"${Ctl[@]}" key set abuseipdb_key "${ABUSEIPDB_API_KEY:-}"
"${Ctl[@]}" key set iris_token "${IRIS_API_TOKEN:-}"
"${Ctl[@]}" key set velociraptor_token "${VELO_API_TOKEN:-}"

echo "==> Reloading rules/actions..."
"${Ctl[@]}"ctl reload

echo "StackStorm setup complete."
