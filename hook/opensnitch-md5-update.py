#!/usr/bin/env python3
# /usr/local/bin/opensnitch-md5-update.py

import argparse
import copy
import fnmatch
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

# Configuration
DAEMON_CONFIG = Path("/etc/opensnitchd/default-config.json")
DEFAULT_RULES_DIR = Path("/etc/opensnitchd/rules")
BACKUP_DIR = Path(os.getenv("OPENSNITCH_BACKUP_DIR", "/var/backups/opensnitch-rules"))
LOG_FILE = Path(
    os.getenv("OPENSNITCH_MD5_LOG_FILE", "/var/log/opensnitch-md5-update.log")
)
CONFIG_FILE = Path(
    os.getenv("OPENSNITCH_MD5_CONFIG", "/etc/opensnitch-md5-update.toml")
)
CONFIG_KEYS = {"exempt_packages", "exempt_foreign", "transition_rules"}
PIN_COMMAND = "opensnitch-md5-pin.py"
PROC_DIR = Path("/proc")

# Transition rules keep the old MD5 for processes started before an upgrade.
# The tmpfiles.d snippet deletes "*-md5-transition-*.json" at boot.
TRANSITION_MARKER = "-md5-transition-"
DURATION_UNTIL_RESTART = "until restart"

# OpenSnitch rule operator values (see opensnitch/config.py in the UI package)
RULE_TYPE_LIST = "list"
RULE_TYPE_SIMPLE = "simple"
OPERAND_PROCESS_PATH = "process.path"
OPERAND_PROCESS_HASH_MD5 = "process.hash.md5"

# Pass as `extra=` to keep a record out of the console (log file only)
FILE_ONLY = {"file_only": True}

# ANSI escape codes, only used when writing to a terminal
COLORS = {
    "red": "31",
    "green": "32",
    "yellow": "33",
    "cyan": "36",
    "bold": "1",
    "dim": "2",
}
LEVEL_COLORS = {logging.WARNING: "yellow", logging.ERROR: "red"}

logger = logging.getLogger("opensnitch-md5-update")


def use_color(stream: TextIO) -> bool:
    """Color only interactive terminals, and honor https://no-color.org."""
    return "NO_COLOR" not in os.environ and stream.isatty()


def colorize(text: str, color: str, enabled: bool = True) -> str:
    return f"\033[{COLORS[color]}m{text}\033[0m" if enabled else text


class ColorFormatter(logging.Formatter):
    """Color console messages by level."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        color = LEVEL_COLORS.get(min(record.levelno, logging.ERROR))
        return colorize(message, color) if color else message


class ConsoleFilter(logging.Filter):
    """Drop records flagged as file-only so the console stays quiet."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not getattr(record, "file_only", False)


def setup_logging(log_file: Path = LOG_FILE):
    """Log everything to the log file and user-facing messages to stdout."""
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console = logging.StreamHandler(sys.stdout)
    formatter_class = ColorFormatter if use_color(sys.stdout) else logging.Formatter
    console.setFormatter(formatter_class("%(message)s"))
    console.addFilter(ConsoleFilter())
    logger.addHandler(console)
    logger.setLevel(logging.INFO)

    try:
        file_handler = logging.FileHandler(log_file)
    except OSError as e:
        logger.warning(f"Cannot write log file {log_file}: {e} (console only)")
        return
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def resolve_rules_dir() -> Path:
    """Rules dir from $OPENSNITCH_RULES_DIR, the daemon config, or the default."""
    env_dir = os.getenv("OPENSNITCH_RULES_DIR")
    if env_dir:
        return Path(env_dir)

    try:
        with open(DAEMON_CONFIG, "r") as f:
            config_path = json.load(f).get("Rules", {}).get("Path")
        if config_path:
            return Path(config_path)
    except (OSError, json.JSONDecodeError, AttributeError) as e:
        logger.debug(f"Could not read rules path from {DAEMON_CONFIG}: {e}")

    return DEFAULT_RULES_DIR


def iter_list_operators(obj) -> Iterator[dict]:
    """Yield every list operator in a rule, including nested ones."""
    if isinstance(obj, dict):
        if obj.get("type") == RULE_TYPE_LIST and isinstance(obj.get("list"), list):
            yield obj
        for value in obj.values():
            yield from iter_list_operators(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_list_operators(item)


def find_entries(operator: dict, operand: str) -> list[dict]:
    """Return the simple entries of a list operator matching an operand."""
    return [
        entry
        for entry in operator["list"]
        if isinstance(entry, dict)
        and entry.get("type") == RULE_TYPE_SIMPLE
        and entry.get("operand") == operand
    ]


def binary_path_of(operator: dict) -> str | None:
    """Return the process.path of a list operator, if it has exactly one."""
    paths = find_entries(operator, OPERAND_PROCESS_PATH)
    if len(paths) != 1 or not isinstance(paths[0].get("data"), str):
        return None
    return paths[0]["data"]


def read_changed_paths(stream: TextIO) -> set[str]:
    """Read pacman NeedsTargets paths (relative to /) as resolved absolute paths."""
    paths = set()
    for line in stream:
        line = line.strip()
        if line:
            # Resolve symlinked dirs (e.g. /usr/sbin -> /usr/bin) so they match rules
            paths.add(os.path.realpath("/" + line.lstrip("/")))
    return paths


def sync_list_data(operator: dict):
    """Keep the JSON-string copy of the list in operator["data"] in sync."""
    data = operator.get("data")
    if not isinstance(data, str) or not data:
        return
    try:
        if not isinstance(json.loads(data), list):
            return
    except json.JSONDecodeError:
        return
    operator["data"] = json.dumps(operator["list"])


def notify_rule_changed(rule_path: Path, content: bytes):
    """Rewrite identical bytes in place so opensnitchd reloads the rule.

    The daemon only reloads rules on fsnotify Write events, and the atomic
    rename in save_rule_file only produces a Create event. Writing the same
    bytes over the file never exposes a partial rule.
    """
    fd = os.open(rule_path, os.O_WRONLY)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)


def running_old_image(binary_path: str, proc_dir: Path = PROC_DIR) -> bool:
    """Whether a process still runs the replaced (deleted) image of binary_path.

    opensnitchd hashes /proc/<pid>/exe, so such a process keeps the old MD5
    until it restarts.
    """
    target = os.path.realpath(binary_path) + " (deleted)"
    for exe in proc_dir.glob("[0-9]*/exe"):
        try:
            if os.readlink(exe) == target:
                return True
        except OSError:
            continue  # exited, kernel thread or not ours to read
    return False


def is_transition_rule(rule_file: Path) -> bool:
    return TRANSITION_MARKER in rule_file.name


def transition_rule(rule: dict, name: str) -> dict:
    """Copy of a rule, still holding its old MD5s, that lasts until reboot."""
    transition = copy.deepcopy(rule)
    transition["name"] = name
    transition["duration"] = DURATION_UNTIL_RESTART
    transition["description"] = (
        "Temporary: keeps the pre-upgrade binary of a running process allowed. "
        "Added by opensnitch-md5-update, removed at boot."
    )
    return transition


def run_pacman(*args: str) -> subprocess.CompletedProcess:
    """Run a read-only pacman query. Raises OSError if pacman can't run."""
    return subprocess.run(
        ["pacman", *args], capture_output=True, text=True, check=False
    )


def package_owner(path: str) -> str | None:
    """Name of the package owning path, None if no package owns it."""
    result = run_pacman("-Qqo", path)
    return (result.stdout.strip() or None) if result.returncode == 0 else None


def foreign_packages() -> set[str]:
    """Packages not found in the sync databases (AUR or locally built)."""
    # -Qm exits 1 when there are none, which is not an error here
    return set(run_pacman("-Qqm").stdout.split())


class ConfigError(Exception):
    """The hook configuration file is invalid."""


@dataclass
class Exemptions:
    """Packages whose binaries must not get their MD5 updated automatically."""

    packages: list[str] = field(default_factory=list)  # fnmatch patterns
    foreign: bool = False
    _foreign_cache: set[str] | None = field(default=None, init=False, repr=False)

    def reason(self, binary_path: str) -> str | None:
        """Why binary_path is exempt, or None if it may be updated."""
        if not self.packages and not self.foreign:
            return None
        try:
            package = package_owner(os.path.realpath(binary_path))
            if package is None:
                return None
            if any(fnmatch.fnmatchcase(package, p) for p in self.packages):
                return f"package '{package}' is in exempt_packages"
            if self.foreign:
                if self._foreign_cache is None:
                    self._foreign_cache = foreign_packages()
                if package in self._foreign_cache:
                    return f"package '{package}' is a foreign (AUR) package"
        except OSError as e:
            # Fail closed: an exemption may apply but couldn't be checked
            return f"package lookup failed: {e}"
        return None


@dataclass
class Config:
    """Settings from the hook's TOML config file."""

    exemptions: Exemptions = field(default_factory=Exemptions)
    # Keep the old MD5 for programs still running the replaced binary
    transition_rules: bool = True


def load_config(config_file: Path = CONFIG_FILE) -> Config:
    """Read the TOML config; a missing file means the defaults."""
    try:
        with open(config_file, "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        return Config()
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"Cannot read {config_file}: {e}") from e

    # A typo would silently drop a setting, so unknown keys are errors
    unknown = set(config) - CONFIG_KEYS
    if unknown:
        raise ConfigError(f"{config_file}: unknown keys: {', '.join(sorted(unknown))}")

    packages = config.get("exempt_packages", [])
    foreign = config.get("exempt_foreign", False)
    if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
        raise ConfigError(f"{config_file}: exempt_packages must be a list of strings")
    for key in ("exempt_foreign", "transition_rules"):
        if key in config and not isinstance(config[key], bool):
            raise ConfigError(f"{config_file}: {key} must be true or false")
    return Config(
        exemptions=Exemptions(packages, foreign),
        transition_rules=config.get("transition_rules", True),
    )


class MD5UpdateManager:
    """Manages OpenSnitch rule MD5 updates with backup and confirmation."""

    def __init__(
        self,
        auto_apply: bool = False,
        rules_dir: Path | None = None,
        backup_dir: Path = BACKUP_DIR,
        changed_paths: set[str] | None = None,
        exemptions: Exemptions | None = None,
        transition_rules: bool = True,
    ):
        self.auto_apply = auto_apply
        self.exemptions = exemptions or Exemptions()
        self.transition_rules = transition_rules
        # None means "check every rule"; a set limits hashing to those files
        self.changed_paths = changed_paths
        self.rules_dir = rules_dir or resolve_rules_dir()
        self.backup_dir = backup_dir
        self.changes_found = {}  # {rule_file: {binary_path: (old_md5, new_md5)}}
        # {rule_file: {binary_path: (old_md5, new_md5, reason)}}
        self.exempt_found = {}

    def ensure_backup_dir(self):
        """Create backup directory if it doesn't exist."""
        try:
            # Backups contain root-only rule files, keep the directory private
            self.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            logger.debug(f"Backup directory ready: {self.backup_dir}")
        except OSError as e:
            logger.error(f"Failed to create backup directory: {e}")
            raise

    def calculate_md5(self, file_path: Path) -> str | None:
        """Calculate MD5 hash of a file."""
        try:
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except OSError as e:
            logger.warning(f"Could not calculate MD5 for {file_path}: {e}")
            return None

    def is_binary(self, file_path: Path) -> bool:
        """Check if a file is an ELF binary."""
        try:
            with open(file_path, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except OSError:
            return False

    def load_rule_file(self, rule_path: Path) -> dict | None:
        """Load and parse a JSON rule file."""
        try:
            with open(rule_path, "r") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Could not load rule file {rule_path}: {e}")
            return None

    def create_backup(self, rule_path: Path) -> Path | None:
        """Create a timestamped backup of a rule file."""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"{rule_path.name}_{timestamp}.bak"
            shutil.copy2(rule_path, backup_path)
            logger.info(f"Backup created: {backup_path}")
            return backup_path
        except OSError as e:
            logger.error(f"Failed to create backup for {rule_path}: {e}")
            return None

    def save_rule_file(self, rule_path: Path, data: dict) -> bool:
        """Atomically save rule data, keeping the mode and owner of an existing
        file (new files get mkstemp's 0600)."""
        content = (json.dumps(data, indent=2) + "\n").encode()
        tmp_path = None
        try:
            st = rule_path.stat() if rule_path.exists() else None
            fd, tmp_path = tempfile.mkstemp(dir=rule_path.parent, suffix=".tmp")
            with os.fdopen(fd, "wb") as f:
                f.write(content)
                if st is not None:
                    os.fchmod(f.fileno(), st.st_mode & 0o7777)
                    if os.geteuid() == 0:
                        os.fchown(f.fileno(), st.st_uid, st.st_gid)
            os.replace(tmp_path, rule_path)
        except OSError as e:
            logger.error(f"Could not save rule file {rule_path}: {e}")
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            return False

        try:
            notify_rule_changed(rule_path, content)
        except OSError as e:
            logger.warning(
                f"Saved {rule_path.name}, but opensnitchd may not reload it until "
                f"it restarts: {e}"
            )
        logger.debug(f"Rule file saved: {rule_path}")
        return True

    def find_md5_changes(self, rule_data: dict) -> dict[str, tuple]:
        """Return {binary_path: (old_md5, new_md5)} for outdated MD5 entries."""
        changes = {}

        for operator in iter_list_operators(rule_data):
            md5_entries = find_entries(operator, OPERAND_PROCESS_HASH_MD5)
            if not md5_entries:
                continue

            binary_path = binary_path_of(operator)
            if binary_path is None:
                logger.debug("MD5 entry without a single process.path, skipping")
                continue

            if not self.was_changed(binary_path):
                logger.debug(f"Not changed in this transaction: {binary_path}")
                continue

            binary_file = Path(binary_path)
            if not binary_file.exists():
                logger.debug(f"Binary not found: {binary_path}")
                continue
            if not self.is_binary(binary_file):
                logger.debug(f"Not a binary file: {binary_path}")
                continue

            new_md5 = self.calculate_md5(binary_file)
            if new_md5 is None:
                continue

            for entry in md5_entries:
                if entry.get("data") != new_md5:
                    changes[binary_path] = (entry.get("data"), new_md5)

        return changes

    def was_changed(self, binary_path: str) -> bool:
        """Whether binary_path is among the changed files (always, if unfiltered)."""
        if self.changed_paths is None:
            return True
        return os.path.realpath(binary_path) in self.changed_paths

    def update_md5_in_rule(
        self, rule_data: dict, binary_path: str, new_md5: str
    ) -> bool:
        """Update MD5 entries of every list operator matching binary_path."""
        updated = False

        for operator in iter_list_operators(rule_data):
            if binary_path_of(operator) != binary_path:
                continue
            for entry in find_entries(operator, OPERAND_PROCESS_HASH_MD5):
                entry["data"] = new_md5
                updated = True
            sync_list_data(operator)

        return updated

    def scan_rules(self) -> bool:
        """Scan all rules and detect changes needed."""
        if not self.rules_dir.exists():
            logger.error(f"OpenSnitch rules directory not found: {self.rules_dir}")
            return False

        for rule_file in sorted(self.rules_dir.glob("*.json")):
            if is_transition_rule(rule_file):
                continue  # must keep its old MD5 until reboot
            rule_data = self.load_rule_file(rule_file)
            if rule_data is None:
                continue

            for binary_path, md5s in self.find_md5_changes(rule_data).items():
                reason = self.exemptions.reason(binary_path)
                if reason is None:
                    self.changes_found.setdefault(rule_file, {})[binary_path] = md5s
                else:
                    exempt = self.exempt_found.setdefault(rule_file, {})
                    exempt[binary_path] = (*md5s, reason)

        self.warn_exempt()

        if not self.changes_found:
            logger.info("No MD5 updates to apply.", extra=FILE_ONLY)
            return True

        logger.info("=" * 70)
        logger.info("OPENSNITCH RULES WITH OUTDATED MD5 HASHES")
        logger.info("=" * 70)
        for rule_file, rule_changes in self.changes_found.items():
            logger.info(f"\n[CHANGES FOUND] Rule: {rule_file.name}")
            for binary_path, (old_md5, new_md5) in rule_changes.items():
                logger.info(f"  Binary: {binary_path}")
                logger.info(f"    Old MD5: {old_md5}")
                logger.info(f"    New MD5: {new_md5}")
        logger.info("\n" + "=" * 70)
        return True

    def warn_exempt(self):
        """Warn about outdated MD5s left alone because of an exemption."""
        for rule_file, entries in self.exempt_found.items():
            logger.warning(
                f"WARNING: outdated MD5 not updated in rule {rule_file.name}"
            )
            for binary_path, (old_md5, new_md5, reason) in entries.items():
                logger.warning(f"  Binary: {binary_path} ({reason})")
                logger.warning(f"    Stored MD5:  {old_md5}")
                logger.warning(f"    Current MD5: {new_md5}")
            logger.warning(
                "  The rule won't match the new binary. If you trust it, re-pin with:"
            )
            logger.warning(f"    sudo {PIN_COMMAND} {rule_file}")

    def prompt_user(self) -> bool:
        """Prompt user to confirm MD5 updates."""
        if not self.changes_found:
            return True

        if self.auto_apply:
            logger.info("AUTO-APPLY mode enabled. Applying changes automatically...")
            return True

        binary_count = sum(len(changes) for changes in self.changes_found.values())
        logger.info(
            f"\nFound {len(self.changes_found)} rule file(s) with "
            f"{binary_count} binary path(s) that need updating.\n"
        )

        while True:
            try:
                response = input("Apply these MD5 updates? [y/n]: ").strip().lower()
                if response in ("y", "yes"):
                    return True
                elif response in ("n", "no"):
                    logger.info("Updates cancelled by user.")
                    return False
                else:
                    print("Please enter 'y' or 'n'.")
            except (EOFError, KeyboardInterrupt):
                logger.info("Updates cancelled (EOF/interrupt).")
                return False

    def apply_updates(self) -> int:
        """Apply the MD5 updates to rule files."""
        if not self.changes_found:
            return 0

        self.ensure_backup_dir()

        logger.info("=" * 70)
        logger.info("APPLYING MD5 UPDATES")
        logger.info("=" * 70)

        updated_count = 0

        for rule_file, changes in self.changes_found.items():
            # Create backup before modifying
            backup_path = self.create_backup(rule_file)
            if backup_path is None:
                logger.error(f"Skipping {rule_file.name} due to backup failure")
                continue

            # Load rule data
            rule_data = self.load_rule_file(rule_file)
            if rule_data is None:
                logger.error(f"Skipping {rule_file.name} due to load failure")
                continue

            original = copy.deepcopy(rule_data)

            # Apply updates
            for binary_path, (old_md5, new_md5) in changes.items():
                if self.update_md5_in_rule(rule_data, binary_path, new_md5):
                    logger.info(f"Updated: {binary_path}")
                    logger.info(f"  {old_md5} -> {new_md5}")
                else:
                    logger.error(f"Failed to update: {binary_path}")

            # Before the new MD5 is live, so running processes are never blocked
            if self.transition_rules:
                self.keep_old_md5_for_running(rule_file, original, changes)

            # Save updated rule file
            if self.save_rule_file(rule_file, rule_data):
                updated_count += 1
                logger.info(f"✓ Rule saved: {rule_file.name}")
            else:
                logger.error(f"✗ Failed to save: {rule_file.name}")
                logger.error(f"  Backup available at: {backup_path}")

        logger.info("=" * 70)
        return updated_count

    def keep_old_md5_for_running(self, rule_file: Path, original: dict, changes):
        """Add a transition rule with the old MD5s if an old binary still runs."""
        for binary_path, (old_md5, _new_md5) in changes.items():
            if not isinstance(old_md5, str) or not old_md5:
                continue
            if not running_old_image(binary_path):
                continue
            name = f"{rule_file.stem}{TRANSITION_MARKER}{old_md5[:8]}"
            path = rule_file.with_name(f"{name}.json")
            if self.save_rule_file(path, transition_rule(original, name)):
                logger.info(
                    f"Kept old MD5 for running {binary_path} until reboot "
                    f"(transition rule: {path.name})"
                )
            else:
                logger.warning(
                    f"Running {binary_path} may be blocked until it restarts"
                )

    def run(self) -> int:
        """Run the full update workflow."""
        try:
            if self.changed_paths is not None and not self.changed_paths:
                logger.info(
                    "No changed files received, nothing to do.", extra=FILE_ONLY
                )
                return 0

            if not self.scan_rules():
                return 1

            if not self.changes_found or not self.prompt_user():
                return 0

            updated = self.apply_updates()
            logger.info(f"Successfully updated {updated} rule file(s)")
            return 0
        except Exception:
            logger.exception("Unexpected error")
            return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Update OpenSnitch rule MD5 hashes for binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (prompts for confirmation)
  %(prog)s

  # Automatic mode (applies changes without prompting)
  %(prog)s --auto

  # Only check binaries in a list of changed files (pacman NeedsTargets)
  printf 'usr/bin/curl\n' | %(prog)s --auto --stdin-targets

  # Use custom rules directory
  OPENSNITCH_RULES_DIR=/custom/path %(prog)s --auto
        """,
    )

    parser.add_argument(
        "--auto",
        action="store_true",
        help="Automatically apply changes without user confirmation",
    )

    parser.add_argument(
        "--stdin-targets",
        action="store_true",
        help="Only check binaries whose paths are read from stdin, one per line "
        "(as passed by a pacman hook with NeedsTargets)",
    )

    args = parser.parse_args()
    if args.stdin_targets and not args.auto:
        # stdin carries the path list, so the confirmation prompt can't read from it
        parser.error("--stdin-targets requires --auto")
    setup_logging()

    mode = "AUTOMATIC" if args.auto else "INTERACTIVE"
    logger.info(f"OpenSnitch MD5 Update Hook Started (mode: {mode})", extra=FILE_ONLY)

    try:
        config = load_config()
    except ConfigError as e:
        logger.error(f"{e}; no rules were changed")
        return 1

    changed_paths = None
    if args.stdin_targets:
        changed_paths = read_changed_paths(sys.stdin)
        logger.info(f"Changed files received: {len(changed_paths)}", extra=FILE_ONLY)

    manager = MD5UpdateManager(
        auto_apply=args.auto,
        changed_paths=changed_paths,
        exemptions=config.exemptions,
        transition_rules=config.transition_rules,
    )
    return manager.run()


if __name__ == "__main__":
    sys.exit(main())
