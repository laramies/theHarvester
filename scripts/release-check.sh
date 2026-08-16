#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release-check.sh [--live-domain DOMAIN]...

Runs offline contracts, HarvestView browser E2E, package build, and container smoke.
Repeat --live-domain to add one bounded live lane per authorized domain.
Live domains run bounded P0 passive-provider checks only.
Use --check-live-contract to verify the P0 source allowlist without running the gate.
EOF
}

passive_sources=(certspotter crtsh duckduckgo hackertarget otx rapiddns urlscan yahoo)
passive_contract_sources=("${passive_sources[@]}" thc)
passive_provider_tests=(
  tests/discovery/test_certspotter.py::TestCertspotterSearch::test_api
  tests/discovery/test_otx.py::TestOtx::test_api
  tests/discovery/test_thc.py::TestThcApi
)
live_domains=()
has_live_domains=false
check_live_contract=false
while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --live-domain)
      if (($# < 2)); then
        echo 'release-check: --live-domain requires a value' >&2
        exit 2
      fi
      live_domains+=("$2")
      has_live_domains=true
      shift 2
      ;;
    --check-live-contract)
      check_live_contract=true
      shift
      ;;
    *)
      echo "release-check: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$check_live_contract" == true && "$has_live_domains" == true ]]; then
  echo 'release-check: --check-live-contract cannot be combined with --live-domain' >&2
  exit 2
fi

if [[ "$has_live_domains" == true ]]; then
  for domain in "${live_domains[@]}"; do
    if [[ ! "$domain" =~ ^[[:alnum:]]([[:alnum:]-]*[[:alnum:]])?(\.[[:alnum:]]([[:alnum:]-]*[[:alnum:]])?)+$ ]]; then
      echo "release-check: invalid live domain: $domain" >&2
      exit 2
    fi
  done
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

command -v uv >/dev/null || { echo 'release-check: uv is required' >&2; exit 2; }
export UV_CACHE_DIR="${UV_CACHE_DIR:-${TMPDIR:-/tmp}/theharvester-uv-cache}"

validate_live_contract() {
  uv run python -c '
import sys
from theHarvester.lib.source_catalog import ActivityClass, get_source_spec

invalid = []
for name in sys.argv[1:]:
    try:
        activity = get_source_spec(name).activity
    except KeyError:
        invalid.append(f"{name}=unknown")
        continue
    if activity is not ActivityClass.PASSIVE:
        invalid.append(f"{name}={activity.value}")
if invalid:
    raise SystemExit("release-check: live source allowlist is not P0-only: " + ", ".join(invalid))
print(f"Validated {len(sys.argv) - 1} P0 passive sources.")
' "${passive_contract_sources[@]}"
}

if [[ "$check_live_contract" == true ]]; then
  validate_live_contract
  exit 0
fi

command -v docker >/dev/null || { echo 'release-check: Docker is required' >&2; exit 2; }
command -v curl >/dev/null || { echo 'release-check: curl is required' >&2; exit 2; }

release_tmp="$(mktemp -d "${TMPDIR:-/tmp}/theharvester-release-check.XXXXXX")"
compose_project="theharvester-release-$$"
compose_touched=false
release_succeeded=false

cleanup() {
  if [[ "$compose_touched" == true ]]; then
    docker compose -p "$compose_project" down --volumes >/dev/null 2>&1 || true
  fi
  if [[ "$release_succeeded" == true ]]; then
    rm -rf -- "$release_tmp"
  else
    printf '\nrelease-check: failure artifacts preserved at %s\n' "$release_tmp" >&2
  fi
}
trap cleanup EXIT

step() {
  local label="$1"
  shift
  printf '\n==> %s\n' "$label"
  "$@"
}

run_bounded() {
  local seconds="$1"
  shift
  .venv/bin/python -c \
    'import subprocess, sys; subprocess.run(sys.argv[2:], check=True, timeout=float(sys.argv[1]))' \
    "$seconds" "$@"
}

step 'Sync locked development environment' uv sync --all-groups --frozen
if [[ "$has_live_domains" == true ]]; then
  step 'Validate P0 live-source contract' validate_live_contract
fi
step 'Ruff lint' uv run ruff check .
step 'Ruff format check' uv run ruff format --check .
step 'Mypy' uv run mypy theHarvester
step 'Offline feature and provider-contract suite' uv run pytest
step 'Install Chromium for browser verification' uv run playwright install chromium
step 'HarvestView browser E2E' \
  uv run pytest -m harvestview_e2e --browser chromium \
  --tracing=retain-on-failure --screenshot=only-on-failure --output="$release_tmp/test-results"

step 'Build wheel and source distribution' uv build --out-dir "$release_tmp/dist"
wheel_path="$(find "$release_tmp/dist" -maxdepth 1 -name '*.whl' -print -quit)"
sdist_path="$(find "$release_tmp/dist" -maxdepth 1 -name '*.tar.gz' -print -quit)"
if [[ -z "$wheel_path" ]]; then
  echo 'release-check: wheel build produced no wheel' >&2
  exit 1
fi
if [[ -z "$sdist_path" ]]; then
  echo 'release-check: source distribution build produced no archive' >&2
  exit 1
fi
step 'Installed wheel CLI smoke' uv run --isolated --no-project --with "$wheel_path" theHarvester --help
step 'Installed wheel HarvestView smoke' uv run --isolated --no-project --with "$wheel_path" harvestview --help
step 'Installed source distribution CLI smoke' \
  uv run --isolated --no-project --with "$sdist_path" theHarvester --help

printf '%s\n' 'harvestview-release-check-key' > "$release_tmp/operator-api-key"
chmod 0444 "$release_tmp/operator-api-key"
export THEHARVESTER_API_KEY_FILE="$release_tmp/operator-api-key"
export THEHARVESTER_PORT="${THEHARVESTER_RELEASE_PORT:-8769}"

compose_touched=true
step 'Build HarvestView container' docker compose -p "$compose_project" build theharvester.svc.local
step 'Container CLI smoke' \
  docker compose -p "$compose_project" run --rm --no-deps --entrypoint theHarvester theharvester.svc.local --help
if [[ "$has_live_domains" == true ]]; then
  step "Container P0 enumeration: ${live_domains[0]} / yahoo" \
    run_bounded 300 docker compose -p "$compose_project" run --rm --no-deps \
    --entrypoint theHarvester theharvester.svc.local \
    -d "${live_domains[0]}" -b yahoo -l 10 -q
fi
step 'Start HarvestView container' docker compose -p "$compose_project" up -d --no-build

for attempt in $(seq 1 60); do
  if curl --fail --silent --show-error "http://127.0.0.1:${THEHARVESTER_PORT}/" > "$release_tmp/harvestview.html"; then
    break
  fi
  if ((attempt == 60)); then
    echo 'release-check: HarvestView container did not become ready' >&2
    exit 1
  fi
  sleep 1
done

grep --fixed-strings '<title>HarvestView</title>' "$release_tmp/harvestview.html" >/dev/null
test "$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${THEHARVESTER_PORT}/app")" = '404'
test "$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${THEHARVESTER_PORT}/api/v1/runs")" = '401'
curl --fail --silent --show-error \
  --header 'X-API-Key: harvestview-release-check-key' \
  "http://127.0.0.1:${THEHARVESTER_PORT}/api/v1/runs" >/dev/null

printf '%s\n' \
  '{"completed_at":"2026-08-16T01:01:00Z","counts":{"hostname":1,"ip":1},"evidence_status":"complete","result_count":2,"run_id":"9f9b4383-6cc4-4f3f-80a4-c8d21930dc2d","started_at":"2026-08-16T01:00:00Z","target":"example.test","type":"summary"}' \
  '{"type":"hostname","value":"www.example.test"}' \
  '{"type":"ip","value":"192.0.2.10"}' > "$release_tmp/smoke.jsonl"
curl --fail --silent --show-error \
  --request POST \
  --header 'Content-Type: application/x-ndjson' \
  --header 'X-API-Key: harvestview-release-check-key' \
  --data-binary "@$release_tmp/smoke.jsonl" \
  "http://127.0.0.1:${THEHARVESTER_PORT}/api/v1/runs/import?filename=smoke.jsonl" > "$release_tmp/imported-run.json"
run_id="$(.venv/bin/python -c \
  "import json, sys; print(json.load(open(sys.argv[1], encoding='utf-8'))['run_id'])" \
  "$release_tmp/imported-run.json")"
curl --fail --silent --show-error \
  --header 'X-API-Key: harvestview-release-check-key' \
  "http://127.0.0.1:${THEHARVESTER_PORT}/api/v1/runs/${run_id}/export" \
  | .venv/bin/python -c \
    "import json, sys; rows = [json.loads(line) for line in sys.stdin if line.strip()]; assert rows[0]['type'] == 'summary'; assert any(row.get('type') == 'ip' for row in rows[1:]); assert len(rows) == 3"
step 'Container Chromium smoke' \
  docker compose -p "$compose_project" exec -T theharvester.svc.local \
  python -c 'from playwright.sync_api import sync_playwright; p = sync_playwright().start(); browser = p.chromium.launch(headless=True); browser.close(); p.stop()'
step 'Restart HarvestView container' docker compose -p "$compose_project" restart theharvester.svc.local
curl --retry 30 --retry-all-errors --retry-delay 1 --fail --silent --show-error \
  --header 'X-API-Key: harvestview-release-check-key' \
  "http://127.0.0.1:${THEHARVESTER_PORT}/api/v1/runs/${run_id}" > "$release_tmp/persisted-run.json"
.venv/bin/python -c \
  "import json, sys; data = json.load(open(sys.argv[1], encoding='utf-8')); assert data['status'] == 'completed'; assert len(data['results']) == 2" \
  "$release_tmp/persisted-run.json"

if [[ "$has_live_domains" == true ]]; then
  for domain in "${live_domains[@]}"; do
    printf '\n==> Live provider tests: %s\n' "$domain"
    export SMOKE_TEST_DOMAIN="$domain"
    run_bounded 300 .venv/bin/pytest --run-live-network -m live_network -q "${passive_provider_tests[@]}"
    for source in "${passive_sources[@]}"; do
      printf '\n==> Installed-wheel P0 CLI smoke: %s / %s\n' "$domain" "$source"
      run_bounded 300 uv run --isolated --no-project --with "$wheel_path" \
        theHarvester -d "$domain" -b "$source" -l 10 -q
    done
  done
  unset SMOKE_TEST_DOMAIN
fi

release_succeeded=true
printf '\nRelease validation passed.\n'
