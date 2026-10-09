#!/usr/bin/env python3
"""Pin the current MD5 of a rule's binary into OpenSnitch rule files.

A rule matching a single exact process.path gets a process.hash.md5 condition
with the binary's current MD5; outdated MD5 conditions are refreshed. The rule
file is backed up first, like opensnitch-md5-update.py does.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

# Installed next to opensnitch-md5-update.py; share its rule handling
SCRIPT = Path(__file__).resolve().parent / "opensnitch-md5-update.py"
spec = importlib.util.spec_from_file_location("md5_update", SCRIPT)
md5_update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md5_update)

logger = md5_update.logger


def is_path_condition(operator) -> bool:
    """Whether operator is a simple (exact) process.path condition."""
    return (
        isinstance(operator, dict)
        and operator.get("type") == md5_update.RULE_TYPE_SIMPLE
        and operator.get("operand") == md5_update.OPERAND_PROCESS_PATH
    )


def to_list_operator(condition: dict) -> dict:
    """Wrap a single condition in a list operator, as the OpenSnitch UI does."""
    entries = [dict(condition)]
    return {
        "type": md5_update.RULE_TYPE_LIST,
        "operand": md5_update.RULE_TYPE_LIST,
        "sensitive": False,
        "data": json.dumps(entries),
        "list": entries,
    }


def current_md5(manager, binary_path: str) -> str | None:
    binary = Path(binary_path)
    if not binary.exists():
        logger.warning(f"  Binary not found: {binary_path}")
        return None
    if not manager.is_binary(binary):
        logger.warning(f"  Not an ELF binary, not pinning: {binary_path}")
        return None
    return manager.calculate_md5(binary)


def pin_rule(rule: dict, manager) -> list[tuple[str, str | None, str]]:
    """Pin current MD5s into rule in place; return (path, old_md5, new_md5)."""
    if is_path_condition(rule.get("operator")):
        rule["operator"] = to_list_operator(rule["operator"])

    pinned = []
    found_path = False
    for operator in md5_update.iter_list_operators(rule):
        binary_path = md5_update.binary_path_of(operator)
        if binary_path is None:
            continue
        found_path = True
        md5 = current_md5(manager, binary_path)
        if md5 is None:
            continue

        md5_entries = md5_update.find_entries(
            operator, md5_update.OPERAND_PROCESS_HASH_MD5
        )
        if not md5_entries:
            # Copy the path condition's fields so the new entry looks the same
            path_entry = md5_update.find_entries(
                operator, md5_update.OPERAND_PROCESS_PATH
            )[0]
            operator["list"].append(
                {
                    **path_entry,
                    "operand": md5_update.OPERAND_PROCESS_HASH_MD5,
                    "data": md5,
                }
            )
            pinned.append((binary_path, None, md5))
        for entry in md5_entries:
            if entry.get("data") != md5:
                pinned.append((binary_path, entry.get("data"), md5))
                entry["data"] = md5
        md5_update.sync_list_data(operator)

    if not found_path:
        logger.warning("  No single exact process.path condition, nothing to pin")
    return pinned


def pin_file(rule_file: Path, manager, dry_run: bool) -> bool:
    """Pin one rule file. Returns False on failure."""
    logger.info(f"{rule_file}:")
    rule = manager.load_rule_file(rule_file)
    if not isinstance(rule, dict):
        logger.error("  Not a valid rule file")
        return False

    pinned = pin_rule(rule, manager)
    if not pinned:
        logger.info("  Nothing to change")
        return True
    for binary_path, old_md5, new_md5 in pinned:
        logger.info(f"  {binary_path}: {old_md5 or '(no MD5)'} -> {new_md5}")

    if dry_run:
        logger.info("  Dry run, not saved")
        return True
    manager.ensure_backup_dir()
    if manager.create_backup(rule_file) is None:
        return False
    if not manager.save_rule_file(rule_file, rule):
        return False
    logger.info("  Saved")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog="Only pin a binary you trust, e.g. after checking it with "
        "`pacman -Qkk <package>`.",
    )
    parser.add_argument("rule_files", nargs="+", type=Path, metavar="RULE_FILE")
    parser.add_argument(
        "-n", "--dry-run", action="store_true", help="show changes without saving"
    )
    args = parser.parse_args()
    md5_update.setup_logging()

    manager = md5_update.MD5UpdateManager(auto_apply=True)
    results = [pin_file(f, manager, args.dry_run) for f in args.rule_files]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
