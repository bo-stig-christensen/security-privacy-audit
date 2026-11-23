"""Tests execute only our own read-only helpers, never the inspected fixture source."""
import io
import json
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_static import scan  # noqa: E402
from inspect_artifact import inspect  # noqa: E402


class AuditHelperTests(unittest.TestCase):
    def test_static_scan_redacts_content_and_skips_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "example.ts").write_text('fetch("https://private.example/?token=TOPSECRET");\n', encoding="utf-8")
            (root / ".env").write_text("SECRET=TOPSECRET", encoding="utf-8")
            result = scan(root)
            self.assertEqual(result["scanned_files"], 1)
            self.assertIn("NETWORK_CLIENT", result["counts_by_rule"])
            self.assertNotIn("TOPSECRET", json.dumps(result))
            self.assertNotIn("private.example", json.dumps(result))
            self.assertTrue(any(x["path"] == ".env" for x in result["skipped"]))

    def test_lifecycle_script_is_flagged_without_echoing_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({"scripts": {"postinstall": "echo TOPSECRET"}}))
            result = scan(root)
            self.assertIn("PACKAGE_LIFECYCLE_SCRIPT", result["counts_by_rule"])
            self.assertNotIn("TOPSECRET", json.dumps(result))

    def test_zip_inventory_no_extract_and_source_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "repo"
            src.mkdir()
            (src / "src").mkdir()
            (src / "src" / "index.ts").write_text("export const a=1;", encoding="utf-8")
            artifact = root / "test.zip"
            with zipfile.ZipFile(artifact, "w") as a:
                a.writestr("package/src/index.ts", "export const a=1;")
                a.writestr("package/package.json", json.dumps({"scripts": {"preinstall": "echo hello"}}))
                a.writestr("../escape.txt", "nothing")
            result = inspect(artifact, source_dir=src)
            self.assertEqual(result["source_comparison"]["matches"], 1)
            self.assertTrue(any("unsafe" in x["reason"] for x in result["safety_flags"]))
            self.assertIn("preinstall", result["lifecycle_scripts"])
            self.assertFalse((root / "escape.txt").exists())

    def test_tar_symlink_does_not_follow(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.tgz"
            with tarfile.open(path, "w:gz") as a:
                t = tarfile.TarInfo("package/redirect")
                t.type = tarfile.SYMTYPE
                t.linkname = "/etc/passwd"
                a.addfile(t)
                data = b"hello"
                t2 = tarfile.TarInfo("package/file.txt")
                t2.size = len(data)
                a.addfile(t2, io.BytesIO(data))
            result = inspect(path)
            self.assertTrue(any("link" in x["reason"] for x in result["safety_flags"]))
            self.assertGreater(result["counts"]["hashed_files"], 0)


if __name__ == "__main__":
    unittest.main()
