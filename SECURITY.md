# Security Policy

`ori-cli` is an operator tool. It must not bypass
[`ori-runtime`](https://github.com/ori-platform/ori-runtime) authority or weaken
Tier C/D safety workflows.

## Reporting

Report vulnerabilities through GitHub private vulnerability reporting on this
repository. If that is unavailable, contact the maintainer directly before
sharing exploit details publicly.

Expected response target: acknowledgement within 72 hours, with coordinated
remediation before public disclosure for issues that affect deployed devices.

High-priority findings include:

- `ori token use` making any network call,
- commands that actuate hardware directly,
- bridge subprocess accepting malformed output as success,
- secrets printed in logs or JSON output,
- command drift from [`ori-specs`](https://github.com/ori-platform/ori-specs),
- private device keys transmitted during deploy.
