#!/usr/bin/env python3
# /usr/local/bin/opensnitch-md5-update.py

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

# Configuration
DAEMON_CONFIG = Path("/etc/opensnitchd/default-config.json")
DEFAULT_RULES_DIR = Path("/etc/opensnitchd/rules")
BACKUP_DIR = Path(os.getenv("OPENSNITCH_BACKUP_DIR", "/var/backups/opensnitch-rules"))
LOG_FILE = Path(
    os.getenv("OPENSNITCH_MD5_LOG_FILE", "/var/log/opensnitch-md5-update.log")
)

# OpenSnitch rule operator values (see opensnitch/config.py in the UI package)
RULE_TYPE_LIST = "list"
RULE_TYPE_SIMPLE = "simple"
OPERAND_PROCESS_PATH = "process.path"
OPERAND_PROCESS_HASH_MD5 = "process.hash.md5"

# Pass as `extra=` to keep a record out of the console (log file only)
FILE_ONLY = {"file_only": True}

logger = logging.getLogger("opensnitch-md5-update")


class ConsoleFilter(logging.Filter):
    """Drop records flagged as file-only so the console stays quiet."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not getattr(record, "file_only", False)


def setup_logging(log_file: Path = LOG_FILE):
    """Log everything to the log file and user-facing messages to stdout."""
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(message)s"))
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


class MD5UpdateManager:
    """Manages OpenSnitch rule MD5 updates with backup and confirmation."""

    def __init__(
        self,
        auto_apply: bool = False,
        rules_dir: Path | None = None,
        backup_dir: Path = BACKUP_DIR,
    ):
        self.auto_apply = auto_apply
        self.rules_dir = rules_dir or resolve_rules_dir()
        self.backup_dir = backup_dir
        self.changes_found = {}  # {rule_file: {binary_path: (old_md5, new_md5)}}

    def _ensure_backup_dir(self):
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
        """Atomically save rule data, keeping the original mode and owner."""
        tmp_path = None
        try:
            st = rule_path.stat()
            fd, tmp_path = tempfile.mkstemp(dir=rule_path.parent, suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
                os.fchmod(f.fileno(), st.st_mode & 0o7777)
                if os.geteuid() == 0:
                    os.fchown(f.fileno(), st.st_uid, st.st_gid)
            os.replace(tmp_path, rule_path)
            logger.debug(f"Rule file saved: {rule_path}")
            return True
        except OSError as e:
            logger.error(f"Could not save rule file {rule_path}: {e}")
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            return False

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
            self._sync_list_data(operator)

        return updated

    def _sync_list_data(self, operator: dict):
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

    def scan_rules(self) -> bool:
        """Scan all rules and detect changes needed."""
        if not self.rules_dir.exists():
            logger.error(f"OpenSnitch rules directory not found: {self.rules_dir}")
            return False

        for rule_file in sorted(self.rules_dir.glob("*.json")):
            rule_data = self.load_rule_file(rule_file)
            if rule_data is None:
                continue

            rule_changes = self.find_md5_changes(rule_data)
            if rule_changes:
                self.changes_found[rule_file] = rule_changes

        if not self.changes_found:
            logger.info("No MD5 mismatches detected.", extra=FILE_ONLY)
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

        self._ensure_backup_dir()

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

            # Apply updates
            for binary_path, (old_md5, new_md5) in changes.items():
                if self.update_md5_in_rule(rule_data, binary_path, new_md5):
                    logger.info(f"Updated: {binary_path}")
                    logger.info(f"  {old_md5} -> {new_md5}")
                else:
                    logger.error(f"Failed to update: {binary_path}")

            # Save updated rule file
            if self.save_rule_file(rule_file, rule_data):
                updated_count += 1
                logger.info(f"✓ Rule saved: {rule_file.name}")
            else:
                logger.error(f"✗ Failed to save: {rule_file.name}")
                logger.error(f"  Backup available at: {backup_path}")

        logger.info("=" * 70)
        return updated_count

    def run(self) -> int:
        """Run the full update workflow."""
        try:
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

  # Use custom rules directory
  OPENSNITCH_RULES_DIR=/custom/path %(prog)s --auto
        """,
    )

    parser.add_argument(
        "--auto",
        action="store_true",
        help="Automatically apply changes without user confirmation",
    )

    args = parser.parse_args()
    setup_logging()

    mode = "AUTOMATIC" if args.auto else "INTERACTIVE"
    logger.info(f"OpenSnitch MD5 Update Hook Started (mode: {mode})", extra=FILE_ONLY)

    manager = MD5UpdateManager(auto_apply=args.auto)
    return manager.run()


if __name__ == "__main__":
    sys.exit(main())
