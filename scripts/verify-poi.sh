#!/usr/bin/env bash
# Verifies the PoI feature set across all five submodules before commit.
#
# The submodules land together, so they are verified together:
#   mandrel-spec    schema export and fixture tests
#   mandrel-go      vet, race tests, standalone (GOWORK=off) tests, vector drift
#   mandrel-collet  vet, race tests, standalone (GOWORK=off) build against its mandrel-go pin
#   mandrel-cli     vet, race tests, standalone (GOWORK=off) build
#   mandrel-demo    vet, build; with DEMO=1, the podman end-to-end gate
#
# Usage:
#   scripts/verify-poi.sh               # everything except the podman demo
#   DEMO=1 scripts/verify-poi.sh        # also run mandrel-demo/scripts/demo-poi.sh
#
# Environment:
#   PYTHON  Interpreter with jsonschema and pyyaml for mandrel-spec. Default: python3
#           (python3 -m venv .venv && .venv/bin/pip install jsonschema pyyaml)
#   DEMO    1 to run the podman demo gate. Default: 0
#   BRANCH  Expected submodule branch. Default: feat/poi-reference-impl
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
DEMO="${DEMO:-0}"
BRANCH="${BRANCH:-feat/poi-reference-impl}"
SUBMODULES=(mandrel-spec mandrel-go mandrel-collet mandrel-cli mandrel-demo)

FAILED=()
step() { printf '\n==> %s\n' "$*"; }
run() {
  local name="$1"; shift
  if "$@"; then
    echo "[PASS] ${name}"
  else
    echo "[FAIL] ${name}"
    FAILED+=("${name}")
  fi
}

step "Submodule branches (PoI work is edited only on ${BRANCH})"
for m in "${SUBMODULES[@]}"; do
  b="$(git -C "${ROOT}/${m}" branch --show-current)"
  if [ "${b}" = "${BRANCH}" ]; then
    echo "[PASS] ${m} on ${b}"
  else
    echo "[FAIL] ${m} is on '${b}', expected ${BRANCH}"
    FAILED+=("${m} branch")
  fi
done

step "mandrel-spec: schema export and fixture tests"
if "${PYTHON}" -c 'import jsonschema, yaml' 2>/dev/null; then
  run "mandrel-spec schemas" bash -c "cd '${ROOT}/mandrel-spec' && '${PYTHON}' -I scripts/export-schemastore.py >/dev/null && '${PYTHON}' -I scripts/test-schemas.py | tail -1"
else
  echo "[FAIL] ${PYTHON} lacks jsonschema/pyyaml; set PYTHON to a venv interpreter"
  FAILED+=("mandrel-spec python deps")
fi

step "mandrel-go: vet, race tests, vector drift against the mandrel-spec submodule"
run "mandrel-go vet" bash -c "cd '${ROOT}/mandrel-go' && go vet ./..."
run "mandrel-go tests" bash -c "cd '${ROOT}/mandrel-go' && go test -race -count=1 ./... >/dev/null"
run "mandrel-go vector drift" bash -c "cd '${ROOT}/mandrel-go' && VECTOR_SOURCE='${ROOT}/mandrel-spec/vectors' ./scripts/sync-vectors.sh --check"

step "mandrel-go: standalone tests (as its own CI runs them, outside this workspace)"
STANDALONE="$(mktemp -d)"
trap 'rm -rf "${STANDALONE}"' EXIT
(cd "${ROOT}/mandrel-go" && git ls-files -co --exclude-standard | tar -cf - -T -) | tar -xf - -C "${STANDALONE}"
run "mandrel-go standalone" bash -c "cd '${STANDALONE}' && GOWORK=off go test -count=1 ./... >/dev/null"

step "mandrel-collet: vet and race tests"
run "mandrel-collet vet" bash -c "cd '${ROOT}/mandrel-collet' && go vet ./..."
run "mandrel-collet tests" bash -c "cd '${ROOT}/mandrel-collet' && go test -race -count=1 ./... >/dev/null"
run "mandrel-collet standalone build" bash -c "cd '${ROOT}/mandrel-collet' && GOWORK=off go build ./... 2>&1 | tail -3; test \${PIPESTATUS[0]} -eq 0"

step "mandrel-cli: vet, race tests, standalone build against its mandrel-go pin"
run "mandrel-cli vet" bash -c "cd '${ROOT}/mandrel-cli' && go vet ./..."
run "mandrel-cli tests" bash -c "cd '${ROOT}/mandrel-cli' && go test -race -count=1 ./... >/dev/null"
run "mandrel-cli standalone build" bash -c "cd '${ROOT}/mandrel-cli' && GOWORK=off go build ./..."

step "mandrel-demo: vet and build"
run "mandrel-demo vet" bash -c "cd '${ROOT}/mandrel-demo' && go vet ./... && go build ./..."

if [ "${DEMO}" = "1" ]; then
  step "mandrel-demo: podman end-to-end gate"
  DEMO_WORK="$(mktemp -d)"
  run "mandrel-demo e2e" bash -c "cd '${ROOT}/mandrel-demo' && BUILD=1 WORK_DIR='${DEMO_WORK}' scripts/demo-poi.sh > '${DEMO_WORK}/demo.log' 2>&1 || { tail -40 '${DEMO_WORK}/demo.log'; exit 1; }; grep -E 'BEHAVED AS EXPECTED' '${DEMO_WORK}/demo.log'"
fi

echo
if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "VERIFY FAILED: ${#FAILED[@]} check(s)"
  printf '  - %s\n' "${FAILED[@]}"
  exit 1
fi
echo "VERIFY PASSED"
