# Security & Privacy Audit — [TARGET]

**Review date:** YYYY-MM-DD  
**Reviewer / tool:**  
**Target category:** OpenCode plugin / MCP server / agent skill / tool / GitHub repository / other  
**Source repository:** [URL]  
**Reviewed commit/tag:** [immutable SHA / tag]  
**Install method and resolved artifact:** [npm name@version, wheel, container digest, release asset, etc.]  
**Artifact SHA-256:** [hash or NOT VERIFIED]  
**Environment / privileges:** [host, filesystem, credentials, network, tools]  
**Review method:** [source-only / source + artifact / dynamic isolated testing]  
**Excluded and inaccessible components:** [list]

## Executive decision

**Decision:** Approve for scoped use / Pilot with controls / Reject / Insufficient evidence  
**Confidence:** High / Medium / Low  
**Security risk:** Critical / High / Medium / Low / Unknown  
**Privacy risk:** Critical / High / Medium / Low / Unknown  
**Supply-chain risk:** Critical / High / Medium / Low / Unknown  
**Operational risk:** Critical / High / Medium / Low / Unknown

**Summary:** 2–5 sentences. Include whether any apparent malicious code was actually found, and exactly how much was reviewed. Never assert guaranteed safety.

## Scope and evidence ledger

| Component | Exact ref / SHA | Inspected? | Key evidence / limitation |
|---|---|---|---|
| Source | | Yes/No/Partial | |
| Build / CI | | | |
| Published executable | | | |
| Dependencies | | | |
| Runtime behavior | | | |

## Capabilities and data flows

| Data/access | Source / trigger | Destination / sink | Actual use or merely capability? | Evidence |
|---|---|---|---|---|
| Credentials | | | | |
| Files / source code | | | | |
| Session/tool data | | | | |
| Network / telemetry | | | | |
| Persistent logs / state | | | | |

## Outbound communications matrix

| Destination / hostname | Trigger | Payload data | SDK/dependency / evidence | Verified (static or dynamic) |
|---|---|---|---|---|
| None observed in inspected paths / or list | | | | |

*Absence of observed requests does not establish absence of all possible outbound communications.*

## Findings

| ID | Severity | Confidence | Observation vs capability | Evidence (path:lines) | Exploit precondition / impact | Remediation |
|---|---|---|---|---|---|---|
| F-001 | | | | | | |

## Supply-chain verification

- Registry metadata and canonical source association:
- Install/build-time hooks:
- Source -> packaged source matching:
- Bundled compiled artifacts inspected? If not, why:
- Reproducible build / attestation / provenance:
- Dependencies and advisories (date and coverage):
- Protected release process and workflow permissions:
- Unverified artifacts or mismatches:

## Privacy assessment

- Data categories accessed:
- Data retained in memory / disk / host session:
- Destinations and logs:
- Sensitive error paths, secrets and redaction:
- Customer/tenant isolation, consent and opt-out:

## Mitigations and next steps

1. [Action, owner, rationale]
2. [Action, owner, rationale]

## Residual risk and assurance boundary

State the strongest supported claim and explicit limits. Example: "No apparent exfiltration paths found in the reviewed source at commit X. Shipped npm artifact Y and its transitive dependencies have **not** been verified; therefore this review does not approve production deployment."
