## What does this PR do?

<!-- Describe the change. Focus on WHY, not just what. -->

## Type of change

- [ ] `feat` - new CLI command, output mode, bridge integration, or operator workflow
- [ ] `fix` - bug fix or command behavior correction
- [ ] `docs` - documentation only
- [ ] `test` - tests only
- [ ] `refactor` - no behavior change
- [ ] `security` - touches tokens, deploy keys, credentials, or local runtime authority
- [ ] `contract-change` - changes bridge, output JSON, cloud, Hub, or SDK contract usage

## Required checklist

- [ ] Linked issue is included below and acceptance criteria are addressed
- [ ] `go test ./...` passes
- [ ] `go vet ./...` passes
- [ ] Pre-commit passes for changed files
- [ ] Every new `.go` file has the Apache-2.0 license header
- [ ] Command help text is updated for new or changed flags
- [ ] JSON output is deterministic and tested when `--output json` is supported

## CLI authority and safety checklist

- [ ] Runtime-owned behavior delegates through the runtime bridge; the CLI does not parse `ori.yaml` independently
- [ ] State queries go through the bridge; the CLI does not open runtime SQLite directly
- [ ] Deploy keypairs are generated on-device; private keys never leave the device
- [ ] Token commands never print raw token material except the explicit one-time generate result
- [ ] Text output is operator-readable and error output is clear on stderr

## External integration checklist

Complete if this PR touches runtime bridge, cloud, Hub, or SDK integrations.

- [ ] Timeout, malformed JSON, auth failure, and unavailable service paths are tested
- [ ] Secrets and private keys never appear in logs or errors
- [ ] Noninteractive behavior is documented and tested if added

## If you used AI assistance

- [ ] I can explain every line of AI-generated code in this PR
- [ ] I have read and understood every file I modified
- [ ] I am not submitting code I cannot defend in review

## Related issue

<!-- Closes #<issue-number> -->

## Testing notes

<!-- Include commands run and any intentionally skipped checks. -->
