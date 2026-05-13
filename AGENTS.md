# AGENTS.md - ori-cli

This repository implements the operator/developer CLI for Ori.

## Purpose

`ori-cli` lets installers and operators inspect, validate, and manage deployed
[`ori-runtime`](https://github.com/ori-platform/ori-runtime) devices. It is a
control surface, not the runtime and not a safety authority.

## Invariants

1. `CLI-1` `ori token use` has zero network calls.
Token presentation is fully offline. Never call ori-cloud during token use.

2. `CLI-2` `ori token generate` calls ori-cloud, not the runtime.
Token batches are registered with ori-cloud and raw tokens are returned once.

3. `CLI-3` Bridge subprocess contract is strict.
Future `python3 -m ori.cli_bridge` calls must emit JSON to stdout, diagnostics
to stderr, and non-zero exit on failure.

4. `CLI-4` Bridge contract tests are version-pinned.
When the bridge exists, tests must target a concrete runtime baseline
(`v0.9.0-beta.2+`), not an unpinned checkout.

5. `CLI-5` No command silently swallows errors.
Every failed command exits non-zero and emits a human-readable error. JSON mode
must include an `error` field.

6. `CLI-6` `ori doctor` uses runtime health contracts.
Runtime health comes from the local AF_UNIX health socket, not direct DB reads
or ad-hoc runtime imports.

7. `CLI-7` `ori config validate` delegates to the runtime bridge.
The CLI must never parse `ori.yaml` independently or reimplement runtime config
validation rules. [`ori-runtime`](https://github.com/ori-platform/ori-runtime)
is the authority on runtime configuration validity.

8. `CLI-8` `ori deploy` generates device keys on-device.
Private device keys must never leave the target device and must never be sent
to ori-cloud, the gateway, Skills Hub, logs, or stdout/stderr.

9. `CLI-9` CLI must not bypass runtime authority.
No command may actuate hardware or approve Tier C/D actions outside runtime
contracts.

10. `CLI-10` Contract fidelity is mandatory.
Command names, flags, and output shapes must match [`ori-specs`](https://github.com/ori-platform/ori-specs).
