#!/usr/bin/env python3
"""Offline, read-only *heuristic triage* of source files. Does NOT certify safety.

Does not import/execute target files, write to disk, access network, follow symlinks,
read .env/secret material, or print matched source text. Python stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path

VERSION = "1.0.0"
EXCLUDED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".next", ".nuxt", "vendor", "coverage", ".turbo", ".cache",
}
SECRET_FILENAMES = {".env", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "credentials.json"}
SOURCE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".sh", ".bash",
    ".ps1", ".psm1", ".go", ".rs", ".cs", ".java", ".kt", ".rb", ".php",
    ".md", ".mdx", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".xml", ".dockerfile", ".gradle", ".txt", ".tf", ".hcl", ".sql",
}
SPECIAL_NAMES = {"Dockerfile", "Makefile", "Procfile", "Gemfile", "Jenkinsfile", "Containerfile"}
RULES = [
    ("NETWORK_CLIENT", "network", r"\b(?:fetch\s*\(|axios\s*\.|XMLHttpRequest\b|WebSocket\s*\(|https?\.request\s*\(|httpx\s*\.|requests\s*\.|urllib\.request|aiohttp\s*\.|grpc\s*\.|socket\.socket\s*\(|Bun\.fetch\s*\()"),
    ("NETWORK_CLI", "network", r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b"),
    ("TELEMETRY_SDK", "privacy", r"\b(?:sentry|posthog|telemetry|applicationinsights|appinsights|datadog|mixpanel|amplitude|langfuse|opentelemetry|rollbar|honeycomb|segment\.track)\b"),
    ("SHELL_EXEC", "execution", r"\b(?:child_process|node:child_process|subprocess\.(?:run|Popen|call|check_output|check_call)|os\.system\s*\(|Bun\.\$|Deno\.Command\b|execFile\s*\(|spawn\s*\(|shell\s*=\s*True|Start-Process\b)"),
    ("DYNAMIC_EVAL", "execution", r"\b(?:eval\s*\(|new\s+Function\s*\(|Function\s*\(|vm\.(?:runIn|runInNewContext|runInThisContext)|exec\s*\(|importlib\.|__import__\s*\()"),
    ("ENV_ACCESS", "credentials", r"\b(?:process\.env\b|Deno\.env\b|Bun\.env\b|os\.environ\b|os\.getenv\s*\(|dotenv\b|GetEnvironmentVariable\s*\()"),
    ("CREDENTIAL_KEYWORDS", "credentials", r"\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|authorization\b|bearer\b|cookie\b|credential(?:s)?\b|secret[_-]?key|api[_-]?key)\b"),
    ("FILE_WRITE_DELETE", "filesystem", r"\b(?:writeFile(?:Sync)?\s*\(|appendFile(?:Sync)?\s*\(|unlink(?:Sync)?\s*\(|rm(?:Sync)?\s*\(|rmtree\s*\(|remove\s*\(|shutil\.rmtree\s*\(|fs\.promises\.(?:writeFile|rm|unlink)|Set-Content\b|Remove-Item\b)"),
    ("UNSAFE_INSTALL_PIPE", "supply-chain", r"(?:curl|wget|Invoke-WebRequest)\b[^\n]{0,250}\|\s*(?:sh\b|bash\b|zsh\b|powershell\b|pwsh\b)"),
    ("CI_PRIVILEGED_TRIGGER", "ci", r"\b(?:pull_request_target|workflow_run)\s*:"),
    ("CI_WRITABLE_TOKEN", "ci", r"\b(?:contents|actions|packages|id-token|pull-requests|issues)\s*:\s*write\b"),
    ("PROMPT_POLICY_OVERRIDE", "agent-instructions", r"(?:ignore\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions|disable\s+(?:security|safety|logging|guardrails)|dangerously.skip.permissions|exfiltrat\w*|send\s+(?:your\s+)?(?:secrets|credentials|tokens)\s+to)"),
    ("REMOTE_CODE_IMPORT", "execution", r"(?:import\s*\(\s*['\"]https?://|load\w*\s*\(\s*['\"]https?://|from\s+['\"]https?://)"),
]
COMPILED = [(name, category, re.compile(pattern, re.IGNORECASE)) for name, category, pattern in RULES]
URL_HOST = re.compile(r"\bhttps?://([a-z0-9][a-z0-9.-]*)(?::\d+)?(?:[/\s\"'<>]|$)", re.IGNORECASE)


def wants_scan(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_EXTENSIONS or path.name in SPECIAL_NAMES or path.name == "SKILL.md"


def sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return (lowered in SECRET_FILENAMES or lowered.startswith(".env.") or
            lowered.endswith((".pem", ".p12", ".pfx", ".key", ".kdbx")))


def scan(root: Path, *, max_files: int = 12000, max_file_bytes: int = 2_000_000,
         show_hosts: bool = False, max_findings: int = 4000) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Target must be an existing directory")
    findings: list[dict] = []
    skipped: list[dict] = []
    counts = Counter()
    hosts = set()
    scanned = 0
    exhausted = False
    for current, dirs, filenames in os.walk(root, followlinks=False):
        for d in dirs:
            if (Path(current) / d).is_symlink():
                skipped.append({"path": (Path(current) / d).relative_to(root).as_posix(),
                                "reason": "symlink directory not followed; inspect destination"})
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not (Path(current) / d).is_symlink()]
        for filename in sorted(filenames):
            if scanned >= max_files:
                skipped.append({"path": ".", "reason": "max-files limit reached"})
                exhausted = True
                break
            path = Path(current) / filename
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped.append({"path": rel, "reason": "symlink not followed; inspect destination"})
                continue
            if sensitive_name(filename):
                skipped.append({"path": rel, "reason": "potential secret material: content deliberately not read"})
                continue
            if not wants_scan(path):
                continue
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    skipped.append({"path": rel, "reason": f"file larger than {max_file_bytes} bytes"})
                    continue
                raw = path.read_bytes()
            except OSError:
                skipped.append({"path": rel, "reason": "read failed"})
                continue
            if b"\x00" in raw:
                skipped.append({"path": rel, "reason": "binary-like file skipped"})
                continue
            scanned += 1
            decoded = raw.decode("utf-8", errors="replace")
            for line_number, line in enumerate(decoded.splitlines(), 1):
                # Avoid massive single-line inputs / unusually expensive regex matching.
                short_line = line[:20000]
                if show_hosts:
                    for host in URL_HOST.findall(short_line):
                        hosts.add(host.lower())
                for rule_name, category, pattern in COMPILED:
                    if pattern.search(short_line):
                        counts[rule_name] += 1
                        if len(findings) < max_findings:
                            findings.append({"file": rel, "line": line_number,
                                             "rule": rule_name, "category": category})
            if filename == "package.json":
                try:
                    obj = json.loads(decoded)
                    scripts = obj.get("scripts", {})
                    if isinstance(scripts, dict):
                        for script in ("preinstall", "install", "postinstall", "prepare", "prepack", "postpack", "prepublish", "prepublishOnly"):
                            if script in scripts:
                                counts["PACKAGE_LIFECYCLE_SCRIPT"] += 1
                                if len(findings) < max_findings:
                                    findings.append({"file": rel, "line": None,
                                                     "rule": "PACKAGE_LIFECYCLE_SCRIPT", "category": "supply-chain",
                                                     "script_name": script})
                except (ValueError, TypeError):
                    skipped.append({"path": rel, "reason": "package.json could not be parsed"})
        if exhausted:
            break
    return {
        "schema": "offline-static-triage/v1", "version": VERSION, "target": str(root),
        "scanned_files": scanned, "findings_reported": len(findings),
        "findings_total": sum(counts.values()), "findings_truncated": sum(counts.values()) > len(findings),
        "counts_by_rule": dict(sorted(counts.items())), "findings": findings,
        "skipped": skipped[:300], "skipped_truncated": len(skipped) > 300,
        "literal_url_hostnames": sorted(hosts) if show_hosts else None,
        "notes": [
            "Heuristic indicators only: NOT confirmed vulnerabilities or malicious behavior.",
            "No target code executed; no network access; no target files written; symlinks not followed.",
            "Matched text intentionally omitted to avoid leaking secrets; manually inspect relevant lines.",
            "A negative result is NOT evidence of absence of egress or malware; inspect compiled artifacts and dependencies separately.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Repository or extracted source directory")
    parser.add_argument("--format", choices=["json", "summary"], default="json")
    parser.add_argument("--max-files", type=int, default=12000)
    parser.add_argument("--max-file-bytes", type=int, default=2_000_000)
    parser.add_argument("--show-hosts", action="store_true", help="Print literal hostnames (may be sensitive)")
    args = parser.parse_args()
    if args.max_files < 1 or args.max_file_bytes < 1:
        parser.error("Limits must be positive")
    try:
        result = scan(args.directory, max_files=args.max_files,
                      max_file_bytes=args.max_file_bytes, show_hosts=args.show_hosts)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Offline heuristic scan: {result['scanned_files']} files; {result['findings_total']} indicators")
        for rule, count in result["counts_by_rule"].items():
            print(f"  {rule}: {count}")
        print(f"Skipped/flagged paths: {len(result['skipped'])}")
        print("NOT a security clearance; inspect evidence manually.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
