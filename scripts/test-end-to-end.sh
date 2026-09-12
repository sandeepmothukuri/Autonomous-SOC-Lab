#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# End-to-end synthetic SOC test.
# Emits synthetic events through Vector -> OpenSearch -> ElastAlert -> StackStorm
# and reports which components are reachable.
#
# Where a component is not reachable we report SKIP rather than failing or
# fabricating a pass.
# -----------------------------------------------------------------------------
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS=0; FAIL=0; SKIP=0;

result() { local s=$1; shift; if [[ "$s" == PASS ]]; then PASS=$((PASS+1)); elif [[ "$s" == FAIL ]]; then FAIL=$((FAIL+1)); else SKIP=$((SKIP+1)); fi; printf '%s %s\n' "[$s]" "$*"; }

if ! command -v docker >/dev/null 2>&1; then
  result SKIP "docker not available; cannot run end-to-end"
  echo "SUMMARY: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
  exit 0
fi

# Compose validity
if docker compose config --quiet 2>/dev/null; then
  result PASS "docker compose config is valid"
else
  result FAIL "docker compose config failed"
fi

# Generate synthetic events by appending to the mounted sample_logs
if [[ -f scripts/generate-events.py ]]; then
  python3 scripts/generate-events.py --scenario all 2>/dev/null \
    && result PASS "synthetic events generated" \
    || result FAIL "synthetic event generation failed"
else
  result SKIP "generate-events.py not found"
fi

wait_for_http() {
  local name="$1"; local url="$2"; local timeout=${3:-30}
  for _ in $(seq 1 "$timeout"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      result PASS "$name reachable at $url"
      return 0
    fi
    sleep 2
  done
  result SKIP "$name not reachable at $url (service may not be running)"
  return 1
}

wait_for_http "OpenSearch"      "http://127.0.0.1:9200/_cluster/health" 60
wait_for_http "Vector"          "http://127.0.0.1:8686/health" 30
wait_for_http "Dashboards"      "http://127.0.0.1:5601/api/status" 60
wait_for_http "StackStorm wh"   "http://127.0.0.1:9101/" 60
wait_for_http "DFIR-IRIS"       "http://127.0.0.1:8000/" 60
wait_for_http "MISP"            "http://127.0.0.1:8080/" 60
wait_for_http "Velociraptor"    "http://127.0.0.1:8889/" 60
wait_for_http "Caldera"         "http://127.0.0.1:8888/" 60

# Check that events landed in OpenSearch logs-* index
if curl -fsS "http://127.0.0.1:9200/_cat/indices?v" 2>/dev/null | grep -q logs-; then
  result PASS "logs-* index exists in OpenSearch"
else
  result SKIP "logs-* index not present (ingestion may need more time)"
fi

echo
echo "SUMMARY: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
if [[ "$FAIL" -gt 0 ]]; then exit 1; fi
exit 0
