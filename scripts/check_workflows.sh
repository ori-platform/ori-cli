#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

workflow_dir=".github/workflows"
pre_commit_config=".pre-commit-config.yaml"
failures=()

add_failure() {
  failures+=("$1")
}

check_workflow_file() {
  local path="$1"
  local line_number=0
  local line

  if grep -q "pull_request_target" "$path"; then
    add_failure "$path: contains forbidden trigger pull_request_target"
  fi

  if [[ "$(basename "$path")" != "release.yml" ]] &&
    grep -Eq '\bid-token:[[:space:]]*write\b' "$path"; then
    add_failure "$path: id-token: write is allowed only in release.yml"
  fi

  if ! grep -q "permissions:" "$path"; then
    add_failure "$path: missing explicit workflow permissions"
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))

    if [[ "$line" =~ uses:[[:space:]]*[^[:space:]#]+@([^[:space:]#]+) ]]; then
      local ref="${BASH_REMATCH[1]}"
      if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        add_failure "$path:$line_number: GitHub Action ref must be a full commit SHA: ${line#"${line%%[![:space:]]*}"}"
      fi
    fi

    if [[ "$line" =~ (curl|wget).*([|][[:space:]]*(bash|sh|python[0-9]*)|&&[[:space:]]*(bash|sh|python[0-9]*)\b) ]]; then
      add_failure "$path:$line_number: remote script download/execution is forbidden"
    fi
  done <"$path"
}

check_pre_commit_config() {
  [[ -f "$pre_commit_config" ]] || return 0

  local current_repo=""
  local line_number=0
  local line stripped rev

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    stripped="${line#"${line%%[![:space:]]*}"}"

    if [[ "$stripped" == "- repo:"* ]]; then
      current_repo="${stripped#- repo:}"
      current_repo="${current_repo#"${current_repo%%[![:space:]]*}"}"
      continue
    fi

    if [[ -z "$current_repo" || "$current_repo" == "local" ]]; then
      continue
    fi

    if [[ "$line" =~ ^[[:space:]]+rev:[[:space:]]*([^[:space:]#]+) ]]; then
      rev="${BASH_REMATCH[1]}"
      if [[ ! "$rev" =~ ^[0-9a-f]{40}$ ]]; then
        add_failure "$pre_commit_config:$line_number: remote pre-commit hook $current_repo must pin rev to a full commit SHA"
      fi
    fi
  done <"$pre_commit_config"
}

if [[ -d "$workflow_dir" ]]; then
  while IFS= read -r path; do
    check_workflow_file "$path"
  done < <(find "$workflow_dir" -type f \( -name "*.yml" -o -name "*.yaml" \) | sort)
fi

check_pre_commit_config

if (( ${#failures[@]} > 0 )); then
  printf 'Supply-chain guard failed:\n' >&2
  for failure in "${failures[@]}"; do
    printf '  - %s\n' "$failure" >&2
  done
  exit 1
fi

printf 'Supply-chain guard: OK\n'
