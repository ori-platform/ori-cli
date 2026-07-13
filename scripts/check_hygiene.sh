#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

failures=()

add_failure() {
  failures+=("$1")
}

tracked_files() {
  local path
  git ls-files | while IFS= read -r path; do
    [[ -f "$path" ]] && printf '%s\n' "$path"
  done
}

go_files() {
  local path
  git ls-files "*.go" | while IFS= read -r path; do
    [[ -f "$path" ]] && printf '%s\n' "$path"
  done
}

check_gofmt() {
  local files=()
  local unformatted
  while IFS= read -r path; do
    files+=("$path")
  done < <(go_files)

  (( ${#files[@]} > 0 )) || return 0
  unformatted="$(gofmt -l "${files[@]}")"
  if [[ -n "$unformatted" ]]; then
    add_failure "Go files need gofmt:"
    while IFS= read -r path; do
      [[ -n "$path" ]] && add_failure "  $path"
    done <<<"$unformatted"
  fi
}

check_license_headers() {
  local files=()
  while IFS= read -r path; do
    files+=("$path")
  done < <(go_files)

  if (( ${#files[@]} > 0 )); then
    bash scripts/check_license_headers.sh "${files[@]}"
  fi
}

check_trailing_whitespace() {
  local files=()
  local matches
  while IFS= read -r path; do
    files+=("$path")
  done < <(tracked_files)

  (( ${#files[@]} > 0 )) || return 0
  matches="$(grep -nI '[[:blank:]]$' "${files[@]}" || true)"
  if [[ -n "$matches" ]]; then
    add_failure "Trailing whitespace found:"
    while IFS= read -r line; do
      [[ -n "$line" ]] && add_failure "  $line"
    done <<<"$matches"
  fi
}

check_final_newlines() {
  local path
  while IFS= read -r path; do
    [[ -f "$path" ]] || continue
    [[ -s "$path" ]] || continue
    if [[ "$(tail -c 1 "$path" | od -An -t x1 | tr -d '[:space:]')" != "0a" ]]; then
      add_failure "$path: missing final newline"
    fi
  done < <(tracked_files)
}

check_merge_conflicts() {
  local files=()
  local matches
  while IFS= read -r path; do
    files+=("$path")
  done < <(tracked_files)

  (( ${#files[@]} > 0 )) || return 0
  matches="$(grep -nI -E '^(<<<<<<<|=======|>>>>>>>)' "${files[@]}" || true)"
  if [[ -n "$matches" ]]; then
    add_failure "Merge conflict markers found:"
    while IFS= read -r line; do
      [[ -n "$line" ]] && add_failure "  $line"
    done <<<"$matches"
  fi
}

check_yaml_parseable() {
  local path
  while IFS= read -r path; do
    [[ -f "$path" ]] || continue
    ruby -e 'require "psych"; Psych.load_file(ARGV.fetch(0))' "$path"
  done < <(git ls-files "*.yml" "*.yaml")
}

check_gofmt
check_license_headers
check_trailing_whitespace
check_final_newlines
check_merge_conflicts
check_yaml_parseable

if (( ${#failures[@]} > 0 )); then
  printf 'Hygiene check failed:\n' >&2
  for failure in "${failures[@]}"; do
    printf '  - %s\n' "$failure" >&2
  done
  exit 1
fi

printf 'Hygiene check: OK\n'
