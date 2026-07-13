#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

copyright="Copyright 2026 Ori Nexus Systems LTD"
spdx="SPDX-License-Identifier: Apache-2.0"
missing=()

for path in "$@"; do
  if [[ ! -f "$path" ]]; then
    missing+=("$path")
    continue
  fi

  if ! grep -qF "$copyright" "$path" || ! grep -qF "$spdx" "$path"; then
    missing+=("$path")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'Missing required license header:\n'
  for path in "${missing[@]}"; do
    printf '  %s\n' "$path"
  done
  exit 1
fi
