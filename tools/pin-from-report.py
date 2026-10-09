#!/usr/bin/env python3
"""Pin the MD5 of every candidate rule listed in an analyze-md5-rules.py report.

Each rule is pinned with opensnitch-md5-pin.py's logic (backup first, atomic
write), but only if its binary still has the MD5 shown in the report.
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "hook" / "opensnitch-md5-pin.py"
spec = importlib.util.spec_from_file_location("md5_pin", SCRIPT)
md5_pin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md5_pin)
md5_update = md5_pin.md5_update
logger = md5_update.logger

CANDIDATE = "CANDIDATE"
PINNED_OUTDATED = "PINNED-OUTDATED"
MD5_RE = re.compile(r"\b[0-9a-f]{32}\b")


class ReportError(Exception):
    """The report file is missing or not an analyze-md5-rules.py report."""


def load_report(path: Path) -> dict:
    """Read the report, raising ReportError if it isn't one."""
    try:
        with open(path) as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ReportError(f"Cannot read report {path}: {e}") from e
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ReportError(f"{path} is not an analyze-md5-rules.py JSON report")
    return report


def group_by_file(findings: list, categories: set[str]) -> dict[str, list[dict]]:
    """Findings of the wanted categories, grouped by rule file name."""
    groups = {}
    for finding in findings:
        if isinstance(finding, dict) and finding.get("category") in categories:
            groups.setdefault(finding.get("rule_file"), []).append(finding)
    return groups


def skip_reason(rules_dir: Path, name, findings: list[dict], manager) -> str | None:
    """Why a rule file from the report must not be pinned, None if it can be."""
    # The report is user-writable while this runs as root: plain names only
    if not isinstance(name, str) or Path(name).name != name or name in ("", ".", ".."):
        return f"invalid rule file name {name!r}"
    if md5_update.is_transition_rule(Path(name)):
        return "transition rule, keeps the old MD5 until reboot on purpose"
    if not (rules_dir / name).is_file():
        return "rule file not found"
    for finding in findings:
        path = finding.get("path")
        reported = MD5_RE.findall(str(finding.get("detail", "")))
        if not isinstance(path, str) or not reported:
            return "finding has no binary path or MD5"
        # The last MD5 in the detail is the binary's MD5 when the report was made
        current = manager.calculate_md5(Path(path))
        if current != reported[-1]:
            return f"{path} changed since the report, re-run the analysis"
    return None


def unpackaged_paths(paths: list[str]) -> list[str]:
    """Paths not owned by any pacman package; the hook never refreshes those."""
    unowned = []
    for path in paths:
        try:
            if md5_update.package_owner(path) is None:
                unowned.append(path)
        except OSError as e:
            logger.warning(f"Cannot look up the package of {path}: {e}")
            unowned.append(path)
    return unowned


def confirm(count: int) -> bool:
    try:
        answer = input(f"Pin {count} rule file(s)? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog="Generate the report with: sudo tools/analyze-md5-rules.py -o FILE",
    )
    parser.add_argument("report", type=Path, help="JSON report from -o/--json")
    parser.add_argument(
        "--include-outdated",
        action="store_true",
        help="also refresh PINNED-OUTDATED rules",
    )
    parser.add_argument(
        "--packaged-only",
        action="store_true",
        help="skip binaries not owned by a pacman package (the hook can't "
        "keep their MD5 up to date)",
    )
    parser.add_argument(
        "-n", "--dry-run", action="store_true", help="show changes without saving"
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="don't ask for confirmation"
    )
    args = parser.parse_args()
    md5_update.setup_logging()

    try:
        report = load_report(args.report)
    except ReportError as e:
        logger.error(str(e))
        return 1

    rules_dir = md5_update.resolve_rules_dir()
    if report.get("rules_dir") != str(rules_dir):
        logger.warning(
            f"Report is for {report.get('rules_dir')}, using the configured "
            f"rules directory {rules_dir}"
        )

    categories = {CANDIDATE} | ({PINNED_OUTDATED} if args.include_outdated else set())
    manager = md5_update.MD5UpdateManager(auto_apply=True, rules_dir=rules_dir)

    planned = {}  # {rule_file_name: [binary_path, ...]}
    skipped = 0
    for name, findings in group_by_file(report["findings"], categories).items():
        reason = skip_reason(rules_dir, name, findings, manager)
        if reason:
            logger.warning(f"Skipping {name}: {reason}")
            skipped += 1
        else:
            planned[name] = [f["path"] for f in findings]

    unowned = set(unpackaged_paths([p for ps in planned.values() for p in ps]))
    if unowned and args.packaged_only:
        for name in [n for n, ps in planned.items() if unowned.intersection(ps)]:
            logger.info(f"Skipping {name}: binary not owned by a package")
            del planned[name]
            skipped += 1
    elif unowned:
        logger.warning(
            f"{len(unowned)} binary(ies) are not owned by a pacman package, so the "
            "hook won't refresh their MD5 when they change (use --packaged-only "
            "to skip them):"
        )
        for path in sorted(unowned):
            logger.warning(f"  {path}")

    if not planned:
        logger.info(f"Nothing to pin ({skipped} skipped)")
        return 0
    if not args.dry_run and not args.yes and not confirm(len(planned)):
        logger.info("Cancelled, no rules were changed")
        return 0

    failed = [
        name
        for name in sorted(planned)
        if not md5_pin.pin_file(rules_dir / name, manager, args.dry_run)
    ]
    action = "Checked" if args.dry_run else "Pinned"
    logger.info(
        f"{action} {len(planned) - len(failed)} rule file(s), {skipped} skipped, "
        f"{len(failed)} failed"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
