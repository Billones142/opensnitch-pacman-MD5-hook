import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from test_md5_update import ELF_CONTENT, ELF_MD5, OLD_MD5, make_rule

SCRIPT = Path(__file__).resolve().parent.parent / "opensnitch-md5-pin.py"
spec = importlib.util.spec_from_file_location("md5_pin", SCRIPT)
md5_pin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md5_pin)
md5_update = md5_pin.md5_update


def path_condition(binary_path: str, rule_type: str = "simple") -> dict:
    return {
        "type": rule_type,
        "operand": "process.path",
        "sensitive": False,
        "data": binary_path,
        "list": None,
    }


class PinTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.rules_dir = root / "rules"
        self.rules_dir.mkdir()
        self.backup_dir = root / "backups"
        self.binary = root / "fakebin"
        self.binary.write_bytes(ELF_CONTENT)
        self.manager = md5_update.MD5UpdateManager(
            rules_dir=self.rules_dir, backup_dir=self.backup_dir
        )

        self.stdout = io.StringIO()
        with redirect_stdout(self.stdout):
            md5_update.setup_logging(root / "test.log")

    def tearDown(self):
        for handler in list(md5_update.logger.handlers):
            md5_update.logger.removeHandler(handler)
            handler.close()
        self.tmp.cleanup()

    def write_rule(self, rule) -> Path:
        path = self.rules_dir / "r.json"
        path.write_text(rule if isinstance(rule, str) else json.dumps(rule))
        return path

    def pin(self, rule_path: Path, dry_run: bool = False) -> bool:
        return md5_pin.pin_file(rule_path, self.manager, dry_run)

    def operator(self, rule_path: Path) -> dict:
        return json.loads(rule_path.read_text())["operator"]

    def test_simple_path_rule_becomes_list_with_md5(self):
        rule_path = self.write_rule(
            {"name": "r", "operator": path_condition(str(self.binary))}
        )

        self.assertTrue(self.pin(rule_path))

        operator = self.operator(rule_path)
        self.assertEqual(operator["type"], "list")
        self.assertEqual(operator["operand"], "list")
        self.assertEqual(
            [(e["operand"], e["data"]) for e in operator["list"]],
            [("process.path", str(self.binary)), ("process.hash.md5", ELF_MD5)],
        )
        self.assertEqual(json.loads(operator["data"]), operator["list"])

    def test_list_without_md5_gets_one_with_same_fields(self):
        entries = [path_condition(str(self.binary))]
        operator = {"type": "list", "operand": "list", "data": "", "list": entries}
        rule_path = self.write_rule({"name": "r", "operator": operator})

        self.pin(rule_path)

        md5_entry = self.operator(rule_path)["list"][1]
        self.assertEqual(
            md5_entry,
            {
                "type": "simple",
                "operand": "process.hash.md5",
                "sensitive": False,
                "data": ELF_MD5,
                "list": None,
            },
        )

    def test_outdated_md5_is_refreshed_with_backup(self):
        rule_path = self.write_rule(make_rule(str(self.binary), OLD_MD5))

        self.pin(rule_path)

        operator = self.operator(rule_path)
        self.assertEqual(operator["list"][1]["data"], ELF_MD5)
        self.assertEqual(json.loads(operator["data"])[1]["data"], ELF_MD5)
        self.assertEqual(len(list(self.backup_dir.glob("r.json_*.bak"))), 1)

    def test_current_md5_changes_nothing(self):
        rule_path = self.write_rule(make_rule(str(self.binary), ELF_MD5))
        before = rule_path.read_text()

        self.assertTrue(self.pin(rule_path))

        self.assertEqual(rule_path.read_text(), before)
        self.assertFalse(self.backup_dir.exists())

    def test_regexp_path_is_not_pinned(self):
        rule = {"name": "r", "operator": path_condition("^/usr/bin/.*", "regexp")}
        rule_path = self.write_rule(rule)
        before = rule_path.read_text()

        self.assertTrue(self.pin(rule_path))

        self.assertEqual(rule_path.read_text(), before)
        self.assertIn("nothing to pin", self.stdout.getvalue())

    def test_non_elf_binary_is_not_pinned(self):
        script = Path(self.tmp.name) / "script.sh"
        script.write_text("#!/bin/sh\n")
        rule_path = self.write_rule(
            {"name": "r", "operator": path_condition(str(script))}
        )
        before = rule_path.read_text()

        self.pin(rule_path)

        self.assertEqual(rule_path.read_text(), before)

    def test_dry_run_does_not_save(self):
        rule_path = self.write_rule(make_rule(str(self.binary), OLD_MD5))
        before = rule_path.read_text()

        self.assertTrue(self.pin(rule_path, dry_run=True))

        self.assertEqual(rule_path.read_text(), before)
        self.assertIn(f"{OLD_MD5} -> {ELF_MD5}", self.stdout.getvalue())

    def test_invalid_rule_file_fails(self):
        self.assertFalse(self.pin(self.write_rule("{not json")))


if __name__ == "__main__":
    unittest.main()
