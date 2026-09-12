#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# SOC Lab health check.
# Emits PASS / WARN / FAIL for file existence, compose validity, and service
# reachability. Non-reachable optional services warn rather than fail.
# -----------------------------------------------------------------------------
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS=0; WARN=0; FAIL=0
pass() { PASS=$((PASS+1)); printf 'PASS %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf 'WARN %s\n' "$*" >&2; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*" >&2; }

check_file() {
  local path="$1" required=${2:-true}
  if [[ -f "$path" ]]; then pass "file exists: $path"
  elif $required; then fail "missing required file: $path"
  else warn "optional file missing: $path"; fi
}

# ---- Required files --------------------------------------------------------
required_files=(
  docker-compose.yml .env.example pipeline/vector.toml
  detections/brute_force.yaml detections/powershell.yaml
  detections/privilege_escalation.yaml detections/lateral_movement.yaml
  soar/pack.yaml soar/rules/elastalert.yaml
  soar/actions/respond_brute_force.yaml
  soar/actions/investigate_powershell.yaml
  soar/actions/isolate_host.yaml
  soar/actions/create_iris_case.yaml
  configs/opensearch/opensearch.yml configs/opensearch/dashboards.yml
  configs/elastalert/config.yaml caldera/red_team.yml
)
for path in "${required_files[@]}"; do check_file "$path" true; done

optional_files=(
  .env configs/velociraptor/server.config.yaml
  scripts/test-end-to-end.sh scripts/setup-stackstorm.sh
)
for path in "${optional_files[@]}"; do check_file "$path" false; done

# ---- Docker availability ----------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  warn "docker not installed; skipping runtime checks"
  echo "RESULT: PASS=$PASS WARN=$WARN FAIL=$FAIL"
  exit "$FAIL"
fi

if ! docker compose version >/dev/null 2>&1; then
  fail "docker compose subcommand not available"
  exit 1
fi

# ---- Compose validity ------------------------------------------------------
if docker compose config --quiet 2>/dev/null; then
  pass "docker compose config is valid"
else
  fail "docker compose config validation failed"
fi

http_ok() { curl -fsS --max-time 4 "$1" >/dev/null 2>&1; }

check_service_http() {
  local name="$1" url="$2" required=${3:-false}
  if http_ok "$url"; then pass "$name is reachable at $url"
  elif $required; then fail "$name not reachable at $url"
  else warn "$name not reachable at $url (service likely not started)"; fi
}

# ---- Runtime service checks (warn if not running, don't fail) --------------
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a
fi

check_service_http "OpenSearch"      "http://${OPENSEARCH_BIND_ADDRESS:-127.0.0.1}:9200/_cluster/health"
check_service_http "Vector"          "http://${VECTOR_BIND_ADDRESS:-127.0.0.1}:8686/health"
check_service_http "Dashboards"      "http://${DASHBOARDS_BIND_ADDRESS:-127.0.0.1}:5601/api/status"
check_service_http "StackStorm"      "http://${STACKSTORM_BIND_ADDRESS:-127.0.0.1}:9101/"
check_service_http "DFIR-IRIS"       "http://${IRIS_BIND_ADDRESS:-127.0.0.1}:8000/"
check_service_http "MISP"            "http://${MISP_BIND_ADDRESS:-127.0.0.1}:8080/"
check_service_http "Velociraptor"    "http://${VELOCIRAPTOR_BIND_ADDRESS:-127.0.0.1}:8889/"
check_service_http "Caldera"         "http://${CALDERA_BIND_ADDRESS:-127.0.0.1}:8888/"

echo "RESULT: PASS=$PASS WARN=$WARN FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
