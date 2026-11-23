#!/usr/bin/env python3
"""Offline, non-executing archive inventory and source-file hash comparison.

Never extracts archive members, follows archive symlinks, imports target code, invokes
package managers, performs network I/O, or writes files. Python standard library.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import tarfile
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import BinaryIO

CHUNK = 64 * 1024
LIFECYCLE_NAMES = {"preinstall", "install", "postinstall", "prepare", "prepack", "postpack", "prepublish", "prepublishOnly"}
ROOT_PREFIXES = ("package/", "nodejs/", "app/")


def digest_file(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(CHUNK), b""):
            sha.update(chunk)
    return sha.hexdigest()


def unsafe_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    return (not normalized or normalized.startswith("/") or bool(re.match(r"^[A-Za-z]:", normalized))
            or ".." in parts or "\x00" in normalized)


def mapped_path(name: str) -> str:
    normalized = name.replace("\\", "/")
    for prefix in ROOT_PREFIXES:
        if normalized.startswith(prefix):
            return normalized[len(prefix):]
    return normalized


def bounded_sha(reader: BinaryIO, size: int, max_bytes: int) -> str | None:
    if size > max_bytes:
        return None
    sha = hashlib.sha256()
    left = size
    while left:
        data = reader.read(min(CHUNK, left))
        if not data:
            return None
        sha.update(data)
        left -= len(data)
    return sha.hexdigest()


def inspect(path: Path, *, source_dir: Path | None = None,
            max_members: int = 12000, max_member_bytes: int = 8_000_000,
            max_total_bytes: int = 80_000_000, max_reported: int = 400) -> dict:
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("Artifact must be a regular archive file")
    if source_dir is not None:
        source_dir = source_dir.resolve(strict=True)
        if not source_dir.is_dir():
            raise ValueError("Source directory must be an existing directory")
    result: dict = {
        "schema": "offline-artifact-inventory/v1", "archive": str(path),
        "archive_sha256": digest_file(path), "source_dir": str(source_dir) if source_dir else None,
        "files": [], "counts": {}, "source_comparison": {}, "safety_flags": [],
        "lifecycle_scripts": [], "unreviewed_compiled_outputs": [], "limits": {
            "max_members": max_members, "max_member_bytes": max_member_bytes,
            "max_total_bytes": max_total_bytes,
        },
    }
    counts = Counter()
    diffs: list[dict] = []
    manifest_scripts = set()
    files: list[dict] = []
    considered = 0
    consumed = 0
    report_overflow = 0
    compiled_names = []

    def handle(name: str, kind: str, size: int, reader_factory):
        nonlocal considered, consumed, report_overflow
        considered += 1
        if considered > max_members:
            counts["members_limit_exceeded"] += 1
            return
        counts["members"] += 1
        entry = {"path": name, "type": kind, "declared_bytes": size}
        if unsafe_name(name):
            result["safety_flags"].append({"path": name, "reason": "unsafe archive member path"})
            counts["unsafe_paths"] += 1
            entry["sha256"] = None
        elif kind == "symlink" or kind == "hardlink":
            result["safety_flags"].append({"path": name, "reason": "archive link; never followed"})
            counts["links"] += 1
            entry["sha256"] = None
        elif kind != "file":
            entry["sha256"] = None
        elif size < 0 or size > max_member_bytes or consumed + size > max_total_bytes:
            entry["sha256"] = None
            counts["content_skipped_due_to_limits"] += 1
        else:
            try:
                reader = reader_factory()
                with reader:
                    member_sha = bounded_sha(reader, size, max_member_bytes)
                entry["sha256"] = member_sha
                if member_sha is None:
                    counts["read_incomplete"] += 1
                else:
                    consumed += size
                    counts["hashed_files"] += 1
                    if source_dir is not None:
                        mapped = mapped_path(name)
                        comparison = source_dir / mapped
                        try:
                            # No symlinks in any path component. Root is already resolved.
                            if (comparison.is_file() and not comparison.is_symlink()
                                    and comparison.resolve().is_relative_to(source_dir)
                                    and not any(p.is_symlink() for p in [comparison, *comparison.parents] if p != source_dir)):
                                cmp_sha = digest_file(comparison)
                                status = "match" if cmp_sha == member_sha else "mismatch"
                                counts["source_" + status] += 1
                                if status == "mismatch" and len(diffs) < 200:
                                    diffs.append({"archive_path": name, "source_path": mapped,
                                                  "archive_sha256": member_sha, "source_sha256": cmp_sha})
                            else:
                                counts["no_matching_local_source"] += 1
                        except OSError:
                            counts["source_read_failed"] += 1
                    if name.endswith("package.json") and size < 2_000_000:
                        try:
                            with reader_factory() as json_reader:
                                manifest = json.loads(json_reader.read(size + 1).decode("utf-8"))
                            scripts = manifest.get("scripts", {})
                            if isinstance(scripts, dict):
                                manifest_scripts.update(LIFECYCLE_NAMES.intersection(scripts))
                        except (OSError, UnicodeError, ValueError, TypeError, KeyError):
                            counts["manifest_parse_failed"] += 1
            except (OSError, EOFError, RuntimeError, ValueError, zipfile.BadZipFile, tarfile.TarError):
                counts["read_failed"] += 1
                entry["sha256"] = None
        if kind == "file" and (name.endswith((".js", ".node", ".dll", ".so", ".dylib", ".wasm", ".exe", ".bin", ".pyc"))
                               or "/dist/" in "/" + name or "/build/" in "/" + name):
            compiled_names.append(name)
        if len(files) < max_reported:
            files.append(entry)
        else:
            report_overflow += 1

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for item in archive.infolist():
                    file_type = (item.external_attr >> 16) & 0o170000
                    kind = "dir" if item.is_dir() else ("symlink" if file_type == stat.S_IFLNK else "file")
                    handle(item.filename, kind, item.file_size, lambda i=item: archive.open(i, "r"))
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, mode="r:*") as archive:
                for item in archive:
                    kind = "file" if item.isfile() else "symlink" if item.issym() else "hardlink" if item.islnk() else "dir" if item.isdir() else "special"
                    def make_reader(i=item):
                        reader = archive.extractfile(i)
                        if reader is None:
                            raise ValueError("Unable to open archive member")
                        return reader
                    handle(item.name, kind, item.size, make_reader)
        else:
            raise ValueError("Unsupported format: expected zip/wheel/nupkg or tar/tgz")
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as error:
        result["safety_flags"].append({"reason": "archive unreadable or malformed", "error_type": type(error).__name__})
        counts["archive_error"] += 1
    result["files"] = files
    result["counts"] = dict(sorted(counts.items()))
    result["files_not_reported"] = report_overflow
    result["source_comparison"] = {"matches": counts["source_match"],
                                   "mismatches": counts["source_mismatch"],
                                   "unmatched_paths": counts["no_matching_local_source"],
                                   "mismatch_examples": diffs,
                                   "note": "Matching packaged source paths does not prove generated/compiled code is equivalent."}
    result["lifecycle_scripts"] = sorted(manifest_scripts)
    result["unreviewed_compiled_outputs"] = compiled_names[:100]
    result["compiled_paths_truncated"] = len(compiled_names) > 100
    result["notes"] = [
        "Archive was read but not extracted or executed; zero network activity.",
        "All compiled JS/binaries and transitive dependencies require separate manual review.",
        "SHA256 verifies bytes, not their trustworthiness or correspondence to source.",
        "Skipped/oversize/unreadable members require explicit review before any production approval.",
    ]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--max-members", type=int, default=12000)
    parser.add_argument("--max-member-bytes", type=int, default=8_000_000)
    parser.add_argument("--max-total-bytes", type=int, default=80_000_000)
    parser.add_argument("--max-reported", type=int, default=400)
    args = parser.parse_args()
    if min(args.max_members, args.max_member_bytes, args.max_total_bytes, args.max_reported) < 1:
        parser.error("Limits must be positive")
    try:
        out = inspect(args.archive, source_dir=args.source_dir, max_members=args.max_members,
                      max_member_bytes=args.max_member_bytes, max_total_bytes=args.max_total_bytes,
                      max_reported=args.max_reported)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
