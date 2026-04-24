#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail=0

check_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    printf 'ok   file exists: %s\n' "$path"
  else
    printf 'fail missing file: %s\n' "$path" >&2
    fail=1
  fi
}

required_files=(
  "docker-compose.yml"
  ".env.example"
  "pipeline/vector.toml"
  "detections/brute_force.yaml"
  "detections/powershell.yaml"
  "detections/privilege_escalation.yaml"
  "detections/lateral_movement.yaml"
  "soar/pack.yaml"
  "soar/rules/elastalert.yaml"
  "soar/actions/respond_brute_force.yaml"
  "soar/actions/investigate_powershell.yaml"
  "soar/actions/isolate_host.yaml"
  "soar/actions/create_iris_case.yaml"
  "configs/opensearch/opensearch.yml"
  "configs/opensearch/dashboards.yml"
  "configs/elastalert/config.yaml"
  "caldera/red_team.yml"
)

for path in "${required_files[@]}"; do
  check_file "$path"
done

if ! command -v docker >/dev/null 2>&1; then
  printf 'warn docker is not installed; skipped compose runtime checks\n' >&2
  exit "$fail"
fi

if ! docker compose config --quiet; then
  printf 'fail docker compose config validation failed\n' >&2
  fail=1
else
  printf 'ok   docker compose config is valid\n'
fi

expected_services=(
  opensearch
  opensearch-dashboards
  vector
  elastalert2
  stackstorm
  iris
  iris-db
  misp
  misp-db
  velociraptor
  caldera
)

running_services="$(docker compose ps --services --filter status=running 2>/dev/null || true)"
for service in "${expected_services[@]}"; do
  if grep -Fxq "$service" <<<"$running_services"; then
    printf 'ok   service running: %s\n' "$service"
  else
    printf 'warn service is not running yet: %s\n' "$service" >&2
  fi
done

exit "$fail"
