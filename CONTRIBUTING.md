# Contributing

Before opening a PR:

```bash
SKIP=no-commit-to-branch pre-commit run --all-files
go test ./...
go build ./...
```

Rules:

- Keep command names and flags aligned with [`ori-specs/cli-commands/v1`](https://github.com/ori-platform/ori-specs/blob/main/cli-commands/v1.md).
- Do not embed Python; use subprocess bridge boundaries only.
- Do not add network calls to `ori token use`.
- Do not actuate hardware from the CLI.
- Do not commit secrets.
