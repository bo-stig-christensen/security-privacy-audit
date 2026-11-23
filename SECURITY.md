# Security policy

## Supported versions

Security fixes are considered for the latest release and current `main` branch.

## Reporting vulnerabilities

Use GitHub's **Report a vulnerability** / private vulnerability reporting feature if it is enabled in this repository. If it is unavailable, open a minimal public issue requesting a private contact channel **without including exploit details or credentials**.

Never post private customer code, access tokens, real secrets, unredacted session transcripts or sensitive audit reports in public issues or pull requests.

## Security assumptions

- The skill is an **audit workflow**, not a sandbox or security boundary.
- The bundled Python utilities are designed to inspect local files/archives offline, without executing target code.
- Agent tooling may have extensive permissions independently of this skill; enforce host-side restrictions.
- Always confirm the exact source revision and distributed artifact before making a deployment decision.
- Findings are bounded by the reviewed code, configuration and runtime scenarios.
