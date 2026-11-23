# Security & privacy review checklist

Use this as an evidence checklist, not a claim of exhaustive safety. Each item should be marked Confirmed / Not observed in inspected paths / Unknown / Not applicable, with supporting path:line or artifact evidence.

## Trust and execution model

- Enumerate all entrypoints: package main/exports/bin, hooks, scripts, remote functions, hot reload, imported modules, generated code, platform-specific binaries, startup/shutdown paths, feature flags.
- What privileges and ambient authority does the *host process* grant? Run identity, elevation, repo/filesystem access, environment/credentials, cloud tokens, secret/keychain managers, browser session, OpenCode host APIs, network, remote tool privileges.
- What triggers each operation? User, tool-call event, file watch, background cron/task, startup, update, build, install script, event subscription, external message.
- Is user consent/permission enforced **at execution**, not just during display/configuration? Are approval bypasses, permission persistence, and confused-deputy conditions possible?
- Is unauthorized user input interpreted as instructions to the auditor, agent, or tool? Look for prompt injection through search output, files, README, tool descriptions, MCP responses, repo issues/PRs and malicious SKILL.md.

## Sensitive data: trace sources to sinks

Data sources:
- Environment variables, `.env`, auth headers, Azure tenant/client secrets, cached OAuth tokens, credential managers, SSH keys, Git config, browser cookies, CI variables, MCP server auth, Dataverse credentials.
- User messages, tool call input/output, code, files, attachments, IDE/editor state, shell output, session history, logs, telemetry and error traces.

Data sinks:
- `fetch`, HTTP clients, WebSocket, gRPC, sockets, DNS, telemetry SDKs, crash reporting, analytics, subprocesses running `curl`/`wget`, git push, outbound MCP calls, external tool invocations.
- On-disk logs, stdout/stderr, cloud logging, tmp/cache, SQLite/databases, clipboard, serialization, telemetry exporters, trace/span attributes.

For **every sink**, record exact code path, trigger, host/domain (avoid exposing token-bearing URLs), payload fields, transformations, opt-out, retention and whether the path is actually reachable. Follow wrappers and transitive SDKs. Network absence from `src/index.ts` is insufficient if `dist/`, imported modules, runtime plugins or installers are not inspected.

Privacy outcomes:
- **Confirmed egress**: observed implementation and data flow to external recipient; dynamic trace strengthens confidence.
- **Capable of egress**: privileged host permissions allow it; no identified path in inspected code.
- **No egress evidence in inspected paths**: does **not** mean guaranteed zero egress.
- **Unknown**: artifact, binary, dependencies, dynamic code or execution paths unreviewed.

## Execution / vulnerability classes

- Subprocess: shell injection, command templating, `shell=True`, unsafe interpolation, `Bun.$`, `child_process` and elevated command invocation.
- Code execution: `eval`, `Function`, runtime plugin loading, dynamic imports from URLs, native addons, deserialization, reflection, PowerShell generated scripts, wasm/binary payloads.
- Filesystem: arbitrary reads, writes outside workspace, path traversal, symlink following, archive extraction, temp permissions, absolute paths, data deletion, insecure caches.
- Network: destination allowlists, proxies, redirects, SSRF / metadata addresses, DNS rebinding, local-only server binding, TLS validation, certificate overrides.
- Credentials: credential access scope, logging, echoing, storage, token forwarding, shared caches, refresh and revocation, isolation between users/tenants.
- CI/release: install-time scripts, compromised GitHub Actions, broad `GITHUB_TOKEN`, pull_request_target workflow misuse, unreviewed release triggers, mutable actions, altered published dist vs source.
- Dependency: known vulnerabilities, unexpected native executables, compromised transitive dependency, registry swaps, unpinned floating resolution, postinstall/updater and optional dependencies.
- Operational: denial of service (unbounded loops, memory), false positive stopping productive work, non-idempotent repeated tool actions, unavailable cleanup, retries with credentials, concurrent sessions and isolation.

## Evidence and severity

For each finding, state `path:line`, exact artifact hash/version and whether **verified code behavior**, **potential capability**, **third-party claim**, or **untested hypothesis**. Indicate prerequisites and realistic impact. `Critical` includes confirmed credential exfiltration or remote arbitrary code execution with relevant privileges; `High` includes unapproved data export or likely unauthorized cross-tenant access; `Medium` includes risky defaults or preventable privilege exposure; `Low` includes bounded/privacy-mitigated concerns. Do not automatically classify every powerful SDK API as a vulnerability.

**Approval guardrail:** Unknown installed-artifact contents or unreviewed package entrypoints → "Insufficient evidence" / "Pilot with controls", never unqualified enterprise approval.
