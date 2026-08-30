#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Refresh the vendored commissioned-safety-binding corpus from ori-specs.
#
# The corpus is vendored so the suite is hermetic; the cost is drift, and a
# stale copy is worse than none because the producer's conformance test then
# certifies bytes the contract no longer describes. This script reports drift,
# and updates only when asked.
#
# Usage:
#   bash scripts/refresh-binding-vectors.sh                       # report drift
#   ORI_VECTORS_APPLY=1 bash scripts/refresh-binding-vectors.sh   # update
#
# ORI_SPECS_DIR points at a local ori-specs checkout that must be on main and
# clean; otherwise the public repository is cloned into a temporary directory.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY="${ORI_VECTORS_APPLY:-0}"
CLEANUP=""

# "<path in ori-specs>:<path in this repo>"
SETS=(
  "commissioned-safety-binding:internal/binding/testdata/vectors/commissioned_safety_binding"
)

if [ -n "${ORI_SPECS_DIR:-}" ]; then
  SPECS="${ORI_SPECS_DIR}"
else
  SPECS="$(mktemp -d)"
  CLEANUP="${SPECS}"
  git clone --quiet --filter=blob:none \
    https://github.com/ori-platform/ori-specs.git "${SPECS}"
fi
trap '[ -n "${CLEANUP}" ] && rm -rf "${CLEANUP}"' EXIT

# Provenance is defined against ori-specs main, never HEAD: a checkout on an
# unmerged branch would otherwise vendor bytes and pin a commit that main may
# never carry.
MAIN_REF=""
for candidate in refs/remotes/origin/main refs/heads/main refs/heads/master; do
  if git -C "${SPECS}" rev-parse --verify --quiet "${candidate}" >/dev/null; then
    MAIN_REF="${candidate}"
    break
  fi
done
if [ -z "${MAIN_REF}" ]; then
  echo "no main branch found in ${SPECS}; cannot establish provenance" >&2
  exit 1
fi
COMMIT="$(git -C "${SPECS}" rev-parse "${MAIN_REF}")"

if [ -n "${ORI_SPECS_DIR:-}" ]; then
  head_commit="$(git -C "${SPECS}" rev-parse HEAD)"
  if [ "${head_commit}" != "${COMMIT}" ]; then
    echo "ORI_SPECS_DIR is not on ${MAIN_REF} (${head_commit} vs ${COMMIT})." >&2
    echo "Vectors are copied from the working tree, so vendoring from an" >&2
    echo "unmerged branch would pin a commit that is not on main." >&2
    exit 1
  fi
  if [ -n "$(git -C "${SPECS}" status --porcelain 2>/dev/null)" ]; then
    echo "ORI_SPECS_DIR has uncommitted changes; the pin would name a commit" >&2
    echo "that did not produce the bytes beside it. Commit or stash first." >&2
    exit 1
  fi
fi
overall_drift=0

write_manifest() {
  python3 - "$1" "$2" "$3" <<'PY'
import hashlib, json, pathlib, sys
commit, source, dest = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
(dest / "MANIFEST.json").write_text(json.dumps({
    "source_repository": "ori-platform/ori-specs",
    "source_path": source,
    "source_commit": commit,
    "note": ("Vendored copy of the normative corpus. The producer must construct "
             "these documents from typed values and emit these exact bytes, and "
             "the verifier must reach every declared verdict, so it is a "
             "conformance fixture rather than a sample. Digests detect a local "
             "edit; the source commit is the provenance trail."),
    "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(dest.glob("*.json")) if p.name != "MANIFEST.json"},
}, indent=2) + "\n")
PY
}

for entry in "${SETS[@]}"; do
  SRC="${SPECS}/${entry%%:*}"
  DEST="${REPO}/${entry##*:}"
  label="${entry%%:*}"
  test -d "${SRC}" || { echo "no vectors at ${SRC}" >&2; exit 1; }
  mkdir -p "${DEST}"

  drift=0
  for file in "${SRC}"/*.json; do
    name="$(basename "${file}")"
    if [ ! -f "${DEST}/${name}" ]; then
      echo "NEW      ${label}/${name}"; drift=1; continue
    fi
    cmp -s "${file}" "${DEST}/${name}" || { echo "CHANGED  ${label}/${name}"; drift=1; }
  done
  for file in "${DEST}"/*.json; do
    name="$(basename "${file}")"
    [ "${name}" = "MANIFEST.json" ] && continue
    [ -f "${SRC}/${name}" ] || { echo "REMOVED  ${label}/${name}"; drift=1; }
  done

  # The pin asserts "these bytes came from that commit", which stays true as
  # main advances; so the test is reachability, not equality with the tip. A
  # squash-rewritten or never-merged SHA is not an ancestor and fails here.
  PINNED=""
  if [ -f "${DEST}/MANIFEST.json" ]; then
    PINNED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])' \
      "${DEST}/MANIFEST.json" 2>/dev/null || echo "")"
  fi
  reachable=0
  if [ -n "${PINNED}" ] && git -C "${SPECS}" merge-base --is-ancestor \
      "${PINNED}" "${COMMIT}" 2>/dev/null; then
    reachable=1
  fi

  # Reachability alone cannot tell a live pin from a stale one. If the bytes
  # here were updated out of band -- copied by hand while a contract change was
  # still in review, say -- they match main while the pin still names a commit
  # that carried different bytes. That is false provenance reported as success,
  # and it survives every later run because contents keep matching. So the pin
  # is checked against what it actually names.
  if [ "${drift}" -eq 0 ] && [ "${reachable}" -eq 1 ]; then
    for file in "${DEST}"/*.json; do
      name="$(basename "${file}")"
      [ "${name}" = "MANIFEST.json" ] && continue
      if ! git -C "${SPECS}" show "${PINNED}:${entry%%:*}/${name}" 2>/dev/null \
          | cmp -s - "${file}"; then
        echo "STALE PIN ${label}/${name}: the bytes here are not the bytes at ${PINNED}"
        drift=1
      fi
    done
  fi

  if [ "${drift}" -eq 0 ] && [ "${reachable}" -eq 1 ]; then
    if [ "${PINNED}" = "${COMMIT}" ]; then
      echo "${label}: vectors match ori-specs at ${COMMIT}"
    else
      echo "${label}: vectors match; pinned at ${PINNED} (an ancestor of ${COMMIT})"
    fi
    continue
  fi

  if [ "${APPLY}" != "1" ]; then
    if [ "${drift}" -eq 0 ]; then
      echo "${label}: contents match, but the manifest pins ${PINNED:-<none>}," >&2
      echo "  which is not an ancestor of ori-specs main at ${COMMIT}." >&2
    fi
    overall_drift=1
    continue
  fi

  for file in "${DEST}"/*.json; do
    name="$(basename "${file}")"
    [ "${name}" = "MANIFEST.json" ] && continue
    [ -f "${SRC}/${name}" ] || { rm -f "${file}"; echo "deleted  ${label}/${name}"; }
  done
  cp "${SRC}"/*.json "${DEST}/"
  write_manifest "${COMMIT}" "${entry%%:*}" "${DEST}"
  echo "${label}: updated to ${COMMIT}"
done

if [ "${overall_drift}" -ne 0 ]; then
  echo >&2
  echo "Vendored vectors differ from ori-specs at ${COMMIT}." >&2
  echo "Re-run with ORI_VECTORS_APPLY=1 to update, then review the diff:" >&2
  echo "  a vector change is a contract change, not a refresh." >&2
  exit 1
fi
