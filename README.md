# ori-cli

Go operator CLI for the Ori platform.

`ori-cli` is the installer/operator control surface for deployed
[`ori-runtime`](https://github.com/ori-platform/ori-runtime) devices. It consumes
contracts from [`ori-specs`](https://github.com/ori-platform/ori-specs) and must
not redefine runtime safety semantics.

## Scope

Bootstrap scope:

- Go binary with Cobra-based command tree and no Python embedding.
- Command tree matching [`ori-specs/cli-commands/v1`](https://github.com/ori-platform/ori-specs/blob/main/cli-commands/v1.md).
- Runtime health socket client boundary for `ori doctor runtime-health`.
- Python bridge subprocess boundary for future runtime delegation.
- Cloud client boundary for token/deploy commands.
- Offline token-use invariant test: no network call path.
- CI, shell hygiene checks, license headers, and contribution guardrails.

Deferred implementation:

- `ori.cli_bridge` implementation in [`ori-runtime`](https://github.com/ori-platform/ori-runtime).
- SQLite state queries.
- Skills Hub install flow.
- ori-cloud token/deploy endpoints.
- Device keypair provisioning.

## Development

```bash
bash scripts/check_workflows.sh
bash scripts/check_hygiene.sh
go test ./...
go build ./...
```

## CGO Note

Future SQLite state commands may use `go-sqlite3`, which requires CGO and a C
compiler. The bootstrap intentionally has no CGO dependency until state query
implementation starts.
