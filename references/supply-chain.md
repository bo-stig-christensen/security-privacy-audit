# Source-to-artifact and dependency verification playbook

Never run target software as part of the default audit. Inspect packaging metadata and artifact bytes without execution. For private projects, avoid sending dependency trees or code to public audit services without consent.

## Identity and evidence chain

1. Pin **source**: canonical repository URL, immutable git commit SHA, tag if any. Review source at that SHA, not just current default branch.
2. Pin **distribution**: registry name/version, tarball SHA-256 (and registry integrity digest), container image **digest** rather than tag, wheel/version/hash, GitHub release asset hash.
3. Verify publisher/namespace, registry metadata, provenance attestation, and source commit correlation. A publisher-controlled `repository` field does not prove the package matches repository code.
4. Inspect **package bytes** (manifest, build output, shell scripts, native binaries, hidden/extra files, lifecycle hooks and embedded archives). Compare included readable sources to the source tag; if installed `dist/` differs by build, inspect it or reproduce the build in an isolated environment. Source file equality does not prove built binary equality.
5. Inspect **transitive dependencies** and actual resolved lockfile/SBOM. Unknown or optional dependencies may be live code paths. Separate direct dependencies, dev dependencies and peer dependencies; consider installer behavior.
6. Check the release workflow for how provenance is produced and whether generated artifacts are deterministic or can include unreviewed code. A signature verifies provenance/integrity, not benign behavior.

## Safe data collection examples (choose based on available tools)

- GitHub: browser/GitHub connector metadata, tags, commit, file content; use APIs rather than running repo scripts.
- npm: registry metadata (`npm view name@version --json` makes a registry request but does not install), direct tarball download for **inspection only**, npm provenance via official registry.
- npm `npm audit signatures`: official verification of registry signatures/attestations **after a controlled install into an isolated environment**. Do not run `npm install` on the workstation just to perform this check; installs may execute lifecycle scripts. `npm audit` uploads dependency metadata to registry; be careful with confidential manifests.
- Python package: inspect wheel/sdist metadata, setup/pyproject and wheels; do not install to main machine merely to scan; building an sdist can execute its build backend.
- Containers: inspect manifest/config/attestations and layers offline; `docker pull` downloads content, `docker run` executes it. Base images and foreign layers count as dependencies.
- Vulnerability databases: OSV / GHSA / NVD, date-stamp the result. OSV-Scanner covers many package lockfiles; do not upload a private manifest by default.
- OpenSSF Scorecard: helpful for project hygiene (branch protection, dangerous workflows, pinned deps, etc.), but never substitutes for inspecting executable behavior.

## Read-only scripts included with this skill

`python scripts/audit_static.py DIRECTORY --format json`: scans text files and emits only locations/rule IDs; does not follow symlinks; not a security proof.

`python scripts/inspect_artifact.py ARCHIVE --source-dir PATH`: archive inventory, SHA256, path traversal and symlink flags, comparison for identical-path packaged source files; no extraction, imports or execution. Supports `.tgz`, `.tar.gz`, `.tar`, `.zip`, `.whl`, `.nupkg`. Big/unreadable members are skipped and reported.

## Provenance assurance matrix

| Status | Evidence required | Defensible claim |
|---|---|---|
| Source inspected only | Files + pinned commit; no executable artifact | "No suspicious paths found in reviewed source" |
| Artifact inspected | Tarball/image/binary inspected and hash pinned; build output reviewed | "No suspicious paths found in reviewed source and delivered bytes" |
| Source ↔ artifact verified | Matching shipped source + reviewed build output or reproducible build; attestation | "Reviewed executable corresponds to source under stated verification assumptions" |
| Isolated runtime tested | Network/process monitoring and synthetic credentials under tested scenarios | "No unexpected egress observed in tested scenarios" |

**Never say "will definitely never send data" even at the final row.** Unknown future features, update mechanisms, runtime dependencies and alternate paths always limit certainty.

## Release approval blockers

- Compiled/nontransparent distributed entrypoint not inspected or not attributable to audited commit.
- Unverifiable binary, native addon, remotely downloaded payload, remote execution feature or unreviewed install hook with meaningful privileges.
- Known high-impact vulnerability without mitigation or suspicious destination/exfiltration mechanism.
- Privacy or access requirements inconsistent with the deployment's data classification or access boundary.

## References (official sources)

- npm provenance: https://docs.npmjs.com/viewing-package-provenance/
- npm audit/signatures: https://docs.npmjs.com/cli/audit/
- OpenSSF Scorecard: https://scorecard.dev/
- OSV supported lockfiles: https://google.github.io/osv-scanner/supported-languages-and-lockfiles/
- MCP official security guidance: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx
