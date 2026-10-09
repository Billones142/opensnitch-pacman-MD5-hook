import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "opensnitch-md5-update.py"
spec = importlib.util.spec_from_file_location("md5_update", SCRIPT)
md5_update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md5_update)

ELF_CONTENT = b"\x7fELF fake binary"
ELF_MD5 = hashlib.md5(ELF_CONTENT).hexdigest()
OLD_MD5 = "0" * 32


def make_rule(binary_path: str, md5: str, with_path: bool = True) -> dict:
    """Build a rule shaped like the ones the OpenSnitch UI writes."""
    entries = []
    if with_path:
        entries.append(
            {
                "type": "simple",
                "operand": "process.path",
                "sensitive": False,
                "data": binary_path,
                "list": None,
            }
        )
    entries.append(
        {
            "type": "simple",
            "operand": "process.hash.md5",
            "sensitive": False,
            "data": md5,
            "list": None,
        }
    )
    return {
        "name": "test-rule",
        "enabled": True,
        "action": "allow",
        "duration": "always",
        "operator": {
            "type": "list",
            "operand": "list",
            "sensitive": False,
            "data": json.dumps(entries),
            "list": entries,
        },
    }


class MD5UpdateManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.rules_dir = root / "rules"
        self.backup_dir = root / "backups"
        self.rules_dir.mkdir()

        self.binary = root / "fakebin"
        self.binary.write_bytes(ELF_CONTENT)

        # Capture console output through the same handler setup as main()
        self.stdout = io.StringIO()
        with redirect_stdout(self.stdout):
            md5_update.setup_logging(root / "test.log")

    def tearDown(self):
        for handler in list(md5_update.logger.handlers):
            md5_update.logger.removeHandler(handler)
            handler.close()
        self.tmp.cleanup()

    def write_rule(self, name: str, rule) -> Path:
        path = self.rules_dir / name
        path.write_text(rule if isinstance(rule, str) else json.dumps(rule))
        return path

    def run_manager(self) -> int:
        manager = md5_update.MD5UpdateManager(
            auto_apply=True, rules_dir=self.rules_dir, backup_dir=self.backup_dir
        )
        return manager.run()

    def test_outdated_md5_is_updated_with_data_copy(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        self.assertEqual(self.run_manager(), 0)

        operator = json.loads(rule_path.read_text())["operator"]
        md5_entry = operator["list"][1]
        self.assertEqual(md5_entry["data"], ELF_MD5)
        self.assertEqual(json.loads(operator["data"])[1]["data"], ELF_MD5)

    def test_backup_created_before_write(self):
        self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        self.run_manager()

        backups = list(self.backup_dir.glob("r.json_*.bak"))
        self.assertEqual(len(backups), 1)
        backup_md5 = json.loads(backups[0].read_text())["operator"]["list"][1]["data"]
        self.assertEqual(backup_md5, OLD_MD5)

    def test_matching_md5_changes_nothing_and_prints_nothing(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), ELF_MD5))
        before = rule_path.read_text()

        self.assertEqual(self.run_manager(), 0)

        self.assertEqual(rule_path.read_text(), before)
        self.assertEqual(self.stdout.getvalue(), "")
        self.assertFalse(self.backup_dir.exists())

    def test_md5_without_path_is_skipped(self):
        rule_path = self.write_rule(
            "r.json", make_rule(str(self.binary), OLD_MD5, with_path=False)
        )
        before = rule_path.read_text()

        self.run_manager()

        self.assertEqual(rule_path.read_text(), before)

    def test_non_elf_target_is_skipped(self):
        script = Path(self.tmp.name) / "script.sh"
        script.write_text("#!/bin/sh\n")
        rule_path = self.write_rule("r.json", make_rule(str(script), OLD_MD5))
        before = rule_path.read_text()

        self.run_manager()

        self.assertEqual(rule_path.read_text(), before)

    def test_invalid_json_is_skipped(self):
        self.write_rule("broken.json", "{not json")
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        self.assertEqual(self.run_manager(), 0)

        operator = json.loads(rule_path.read_text())["operator"]
        self.assertEqual(operator["list"][1]["data"], ELF_MD5)

    def test_save_keeps_file_mode(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))
        rule_path.chmod(0o600)

        self.run_manager()

        self.assertEqual(rule_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
