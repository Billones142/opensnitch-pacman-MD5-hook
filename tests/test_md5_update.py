import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent.parent / "opensnitch-md5-update.py"
spec = importlib.util.spec_from_file_location("md5_update", SCRIPT)
md5_update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md5_update)

SHIPPED_CONFIG = SCRIPT.parent / "opensnitch-md5-update.toml"

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

    def run_manager(
        self,
        changed_paths: set[str] | None = None,
        exemptions: "md5_update.Exemptions | None" = None,
        transition_rules: bool = True,
    ) -> int:
        manager = md5_update.MD5UpdateManager(
            auto_apply=True,
            rules_dir=self.rules_dir,
            backup_dir=self.backup_dir,
            changed_paths=changed_paths,
            exemptions=exemptions,
            transition_rules=transition_rules,
        )
        return manager.run()

    def rule_md5(self, rule_path: Path) -> str:
        return json.loads(rule_path.read_text())["operator"]["list"][1]["data"]

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
        self.assertEqual(self.rule_md5(rule_path), ELF_MD5)

    def test_binary_in_changed_paths_is_updated(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        self.run_manager(changed_paths={os.path.realpath(self.binary)})

        self.assertEqual(self.rule_md5(rule_path), ELF_MD5)

    def test_binary_not_in_changed_paths_is_skipped(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        self.run_manager(changed_paths={"/usr/bin/something-else"})

        self.assertEqual(self.rule_md5(rule_path), OLD_MD5)

    def test_rule_path_through_symlinked_dir_matches(self):
        # Like /usr/sbin -> /usr/bin: the rule uses the link, pacman the real path
        link_dir = Path(self.tmp.name) / "sbin"
        link_dir.symlink_to(self.binary.parent)
        rule_path = self.write_rule(
            "r.json", make_rule(str(link_dir / self.binary.name), OLD_MD5)
        )

        self.run_manager(changed_paths={os.path.realpath(self.binary)})

        self.assertEqual(self.rule_md5(rule_path), ELF_MD5)

    def test_empty_changed_paths_skips_scan(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        self.assertEqual(self.run_manager(changed_paths=set()), 0)

        self.assertEqual(self.rule_md5(rule_path), OLD_MD5)
        self.assertEqual(self.stdout.getvalue(), "")

    def test_exempt_package_is_not_updated_and_warns(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))
        exemptions = md5_update.Exemptions(packages=["fire*"])

        with mock.patch.object(md5_update, "package_owner", return_value="firefox"):
            self.assertEqual(self.run_manager(exemptions=exemptions), 0)

        self.assertEqual(self.rule_md5(rule_path), OLD_MD5)
        output = self.stdout.getvalue()
        self.assertIn("outdated MD5 not updated in rule r.json", output)
        self.assertIn("'firefox' is in exempt_packages", output)
        self.assertIn(f"opensnitch-md5-pin.py {rule_path}", output)

    def test_non_exempt_package_is_updated(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))
        exemptions = md5_update.Exemptions(packages=["firefox"])

        with mock.patch.object(md5_update, "package_owner", return_value="curl"):
            self.run_manager(exemptions=exemptions)

        self.assertEqual(self.rule_md5(rule_path), ELF_MD5)

    def test_foreign_package_is_exempt(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        with (
            mock.patch.object(md5_update, "package_owner", return_value="yay"),
            mock.patch.object(md5_update, "foreign_packages", return_value={"yay"}),
        ):
            self.run_manager(exemptions=md5_update.Exemptions(foreign=True))

        self.assertEqual(self.rule_md5(rule_path), OLD_MD5)
        self.assertIn("foreign (AUR) package", self.stdout.getvalue())

    def test_failed_package_lookup_is_treated_as_exempt(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))
        exemptions = md5_update.Exemptions(foreign=True)

        with mock.patch.object(
            md5_update, "package_owner", side_effect=OSError("no pacman")
        ):
            self.run_manager(exemptions=exemptions)

        self.assertEqual(self.rule_md5(rule_path), OLD_MD5)
        self.assertIn("package lookup failed", self.stdout.getvalue())

    def test_no_exemptions_skips_package_lookup(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        with mock.patch.object(md5_update, "package_owner") as owner:
            self.run_manager(exemptions=md5_update.Exemptions())

        owner.assert_not_called()
        self.assertEqual(self.rule_md5(rule_path), ELF_MD5)

    def test_transition_rule_keeps_old_md5_for_running_binary(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        with mock.patch.object(md5_update, "running_old_image", return_value=True):
            self.run_manager()

        self.assertEqual(self.rule_md5(rule_path), ELF_MD5)
        transition_path = self.rules_dir / "r-md5-transition-00000000.json"
        transition = json.loads(transition_path.read_text())
        self.assertEqual(transition["name"], "r-md5-transition-00000000")
        self.assertEqual(transition["duration"], "until restart")
        self.assertEqual(transition["action"], "allow")
        self.assertEqual(transition["operator"]["list"][1]["data"], OLD_MD5)
        self.assertEqual(json.loads(transition["operator"]["data"])[1]["data"], OLD_MD5)
        self.assertEqual(transition_path.stat().st_mode & 0o777, 0o600)
        self.assertIn("until reboot", self.stdout.getvalue())

    def test_no_transition_rule_when_old_binary_not_running(self):
        self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        with mock.patch.object(md5_update, "running_old_image", return_value=False):
            self.run_manager()

        self.assertEqual([p.name for p in self.rules_dir.glob("*.json")], ["r.json"])

    def test_transition_rules_can_be_disabled(self):
        rule_path = self.write_rule("r.json", make_rule(str(self.binary), OLD_MD5))

        with mock.patch.object(md5_update, "running_old_image", return_value=True):
            self.run_manager(transition_rules=False)

        self.assertEqual(self.rule_md5(rule_path), ELF_MD5)
        self.assertEqual([p.name for p in self.rules_dir.glob("*.json")], ["r.json"])

    def test_transition_rules_keep_their_old_md5(self):
        transition_path = self.write_rule(
            "r-md5-transition-00000000.json", make_rule(str(self.binary), OLD_MD5)
        )

        self.run_manager()

        self.assertEqual(self.rule_md5(transition_path), OLD_MD5)


class RunningOldImageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proc = Path(self.tmp.name) / "proc"
        self.binary = Path(self.tmp.name) / "tool"
        self.binary.touch()

    def tearDown(self):
        self.tmp.cleanup()

    def add_process(self, pid: str, exe_target: str | None):
        process = self.proc / pid
        process.mkdir(parents=True)
        if exe_target is not None:
            (process / "exe").symlink_to(exe_target)

    def test_detects_deleted_image(self):
        self.add_process("1", None)  # e.g. a kernel thread without exe
        self.add_process("2", "/usr/bin/other (deleted)")
        self.add_process("3", f"{os.path.realpath(self.binary)} (deleted)")

        self.assertTrue(md5_update.running_old_image(str(self.binary), self.proc))

    def test_current_image_does_not_count(self):
        self.add_process("1", os.path.realpath(self.binary))
        self.add_process("self", f"{os.path.realpath(self.binary)} (deleted)")

        self.assertFalse(md5_update.running_old_image(str(self.binary), self.proc))


class LoadConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Path(self.tmp.name) / "config.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_means_defaults(self):
        config = md5_update.load_config(self.config)

        self.assertEqual(config.exemptions, md5_update.Exemptions())
        self.assertTrue(config.transition_rules)

    def test_valid_config(self):
        self.config.write_text(
            'exempt_packages = ["a", "b-*"]\n'
            "exempt_foreign = true\n"
            "transition_rules = false\n"
        )

        config = md5_update.load_config(self.config)

        self.assertEqual(config.exemptions.packages, ["a", "b-*"])
        self.assertTrue(config.exemptions.foreign)
        self.assertFalse(config.transition_rules)

    def test_shipped_config_uses_defaults(self):
        self.assertEqual(md5_update.load_config(SHIPPED_CONFIG), md5_update.Config())

    def test_shipped_config_examples_are_valid(self):
        lines = SHIPPED_CONFIG.read_text().splitlines()
        # Uncomment the multi-line exempt_packages example and the booleans
        start = lines.index("# exempt_packages = [")
        end = lines.index("# ]", start)
        example = [line[2:] for line in lines[start : end + 1]]
        for setting in ("exempt_foreign = true", "transition_rules = false"):
            self.assertIn(f"# {setting}", lines)
            example.append(setting)
        self.config.write_text("\n".join(example))

        config = md5_update.load_config(self.config)

        self.assertIn("python-*", config.exemptions.packages)
        self.assertTrue(config.exemptions.foreign)
        self.assertFalse(config.transition_rules)

    def test_invalid_configs_raise(self):
        for content in (
            "exempt_packages = [",
            'exempt_packages = "firefox"',
            "exempt_packages = [1]",
            'exempt_foreign = "yes"',
            "transition_rules = 0",
            "exempt_package = []",
        ):
            with self.subTest(content=content):
                self.config.write_text(content)
                with self.assertRaises(md5_update.ConfigError):
                    md5_update.load_config(self.config)


class ColorTest(unittest.TestCase):
    def test_colorize(self):
        self.assertEqual(md5_update.colorize("x", "red"), "\033[31mx\033[0m")
        self.assertEqual(md5_update.colorize("x", "red", enabled=False), "x")

    def test_no_color_without_tty_or_with_no_color(self):
        tty = mock.Mock(isatty=mock.Mock(return_value=True))
        self.assertFalse(md5_update.use_color(io.StringIO()))
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(md5_update.use_color(tty))
        with mock.patch.dict(os.environ, clear=True):
            self.assertTrue(md5_update.use_color(tty))


class ReadChangedPathsTest(unittest.TestCase):
    def test_paths_are_made_absolute_and_blank_lines_ignored(self):
        stream = io.StringIO("tmp\n\n  \n/tmp\n")

        self.assertEqual(
            md5_update.read_changed_paths(stream), {os.path.realpath("/tmp")}
        )

    def test_symlinked_dirs_are_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "bin"
            real.mkdir()
            (real / "tool").touch()
            (Path(tmp) / "sbin").symlink_to(real)
            relative = str(Path(tmp) / "sbin" / "tool").lstrip("/")

            paths = md5_update.read_changed_paths(io.StringIO(relative + "\n"))

        self.assertEqual(paths, {os.path.realpath(real / "tool")})


if __name__ == "__main__":
    unittest.main()
