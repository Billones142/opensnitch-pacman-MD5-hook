#!/usr/bin/env python3
"""Report which OpenSnitch rules pin an MD5 and which could.

Read-only: rule files are never modified. Reuses the helpers of
opensnitch-md5-update.py so both scripts agree on what a pinned rule is.
"""

import argparse
import importlib.util
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "hook" / "opensnitch-md5-update.py"
spec = importlib.util.spec_from_file_location("md5_update", SCRIPT)
md5_update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md5_update)

PINNED_OK = "PINNED-OK"
PINNED_OUTDATED = "PINNED-OUTDATED"
PINNED_UNUSABLE = "PINNED-UNUSABLE"
CANDIDATE = "CANDIDATE"
NOT_APPLICABLE = "NOT-APPLICABLE"
CATEGORIES = [PINNED_OK, PINNED_OUTDATED, PINNED_UNUSABLE, CANDIDATE, NOT_APPLICABLE]
CATEGORY_COLORS = {
    PINNED_OK: "green",
    PINNED_OUTDATED: "yellow",
    PINNED_UNUSABLE: "red",
    CANDIDATE: "cyan",
    NOT_APPLICABLE: "dim",
}

# Pinning an interpreter's MD5 says nothing about the script it runs
INTERPRETERS = ("python", "perl", "ruby", "node", "bash", "sh", "zsh", "java")

# Hashing helpers only, the manager is never run
manager = md5_update.MD5UpdateManager(rules_dir=Path("/nonexistent"))


@dataclass
class Finding:
    category: str
    rule_file: str
    rule_name: str
    enabled: bool | None  # None when the rule couldn't be parsed
    path: str | None
    detail: str


def checksums_enabled() -> bool | None:
    """Rules.EnableChecksums from the daemon config, None if unreadable."""
    try:
        with open(md5_update.DAEMON_CONFIG) as f:
            return bool(json.load(f).get("Rules", {}).get("EnableChecksums", False))
    except (OSError, json.JSONDecodeError, AttributeError):
        return None


def is_interpreter(path: str) -> bool:
    # python3.14 -> python, perl5.40 -> perl
    name = os.path.basename(os.path.realpath(path))
    return name.rstrip("0123456789.") in INTERPRETERS


def classify_path(entry: dict) -> tuple[str, str]:
    """Category and detail for a process.path condition without an MD5."""
    if entry.get("type") != md5_update.RULE_TYPE_SIMPLE:
        return NOT_APPLICABLE, f"{entry.get('type')} match, not a single binary"
    path = entry.get("data")
    if not isinstance(path, str) or not path:
        return NOT_APPLICABLE, "empty path"
    binary = Path(path)
    if not binary.exists():
        return NOT_APPLICABLE, "binary not found"
    if not manager.is_binary(binary):
        return NOT_APPLICABLE, "not an ELF binary (script?)"
    if is_interpreter(path):
        return NOT_APPLICABLE, "interpreter: MD5 would not identify the script"
    md5 = manager.calculate_md5(binary)
    if md5 is None:
        return NOT_APPLICABLE, "binary not readable"
    return CANDIDATE, f"would pin md5 {md5}"


def classify_pinned(operator: dict) -> tuple[str, str | None, str]:
    """Category, path and detail for a list operator that has MD5 entries."""
    path = md5_update.binary_path_of(operator)
    if path is None:
        return PINNED_UNUSABLE, None, "no single process.path in the same list"
    binary = Path(path)
    if not binary.exists():
        return PINNED_UNUSABLE, path, "binary not found"
    if not manager.is_binary(binary):
        return PINNED_UNUSABLE, path, "not an ELF binary"
    current = manager.calculate_md5(binary)
    if current is None:
        return PINNED_UNUSABLE, path, "binary not readable"
    stored = [
        e.get("data")
        for e in md5_update.find_entries(operator, md5_update.OPERAND_PROCESS_HASH_MD5)
    ]
    if all(md5 == current for md5 in stored):
        return PINNED_OK, path, f"md5 {current}"
    return PINNED_OUTDATED, path, f"stored {', '.join(map(str, stored))} != {current}"


def path_entries(operator: dict) -> list[dict]:
    """process.path conditions of a list operator, any match type."""
    return [
        e
        for e in operator["list"]
        if isinstance(e, dict) and e.get("operand") == md5_update.OPERAND_PROCESS_PATH
    ]


def analyze_rule(rule_file: Path) -> list[Finding]:
    rule = manager.load_rule_file(rule_file)
    if not isinstance(rule, dict):
        return [
            Finding(
                NOT_APPLICABLE,
                rule_file.name,
                "?",
                None,
                None,
                "invalid or unreadable JSON",
            )
        ]

    def finding(category, path, detail):
        return Finding(
            category,
            rule_file.name,
            rule.get("name", rule_file.stem),
            bool(rule.get("enabled")),
            path,
            detail,
        )

    findings = []
    top = rule.get("operator")
    if isinstance(top, dict) and top.get("operand") == md5_update.OPERAND_PROCESS_PATH:
        category, detail = classify_path(top)
        findings.append(finding(category, top.get("data"), detail))

    for operator in md5_update.iter_list_operators(rule):
        md5s = md5_update.find_entries(operator, md5_update.OPERAND_PROCESS_HASH_MD5)
        if md5s:
            findings.append(finding(*classify_pinned(operator)))
            continue
        for entry in path_entries(operator):
            category, detail = classify_path(entry)
            findings.append(finding(category, entry.get("data"), detail))

    return findings or [finding(NOT_APPLICABLE, None, "no process.path condition")]


class ProgressBar:
    """Single-line progress bar on stderr, drawn only on a terminal."""

    def __init__(self, total: int, stream=sys.stderr):
        self.total = total
        self.stream = stream
        self.enabled = total > 0 and stream.isatty()

    def update(self, done: int, label: str = ""):
        if not self.enabled:
            return
        width = shutil.get_terminal_size().columns
        counter = f" {done}/{self.total} "
        bar_width = max(10, min(40, width // 3))
        filled = bar_width * done // self.total
        bar = "[" + "#" * filled + "-" * (bar_width - filled) + "]"
        line = (bar + counter + label)[: width - 1]
        # \r back to column 0, \033[K clears what's left of the previous line
        self.stream.write(f"\r{line}\033[K")
        self.stream.flush()

    def close(self):
        if self.enabled:
            self.stream.write("\r\033[K")
            self.stream.flush()


def analyze_rules(rule_files: list[Path]) -> list[Finding]:
    progress = ProgressBar(len(rule_files))
    findings = []
    try:
        for done, rule_file in enumerate(rule_files):
            progress.update(done, rule_file.name)
            findings.extend(analyze_rule(rule_file))
        progress.update(len(rule_files))
    finally:
        progress.close()
    return findings


def painter(stream):
    color = md5_update.use_color(stream)
    return lambda text, name: md5_update.colorize(text, name, color)


def print_checksums_warning(checksums: bool | None):
    paint = painter(sys.stdout)
    if checksums is False:
        warning = "WARNING: Rules.EnableChecksums is false, the daemon ignores MD5s."
        print(paint(warning, "yellow") + "\n")
    elif checksums is None:
        note = f"NOTE: could not read EnableChecksums from {md5_update.DAEMON_CONFIG}"
        print(paint(note, "yellow") + "\n")


def print_findings(findings: list[Finding]):
    paint = painter(sys.stdout)
    for category in CATEGORIES:
        group = [f for f in findings if f.category == category]
        if not group:
            continue
        category_color = CATEGORY_COLORS[category]
        print(paint(paint(f"== {category} ({len(group)})", category_color), "bold"))
        for f in group:
            state = paint(" (disabled)", "dim") if f.enabled is False else ""
            print(f"  {paint(f.rule_name, 'bold')}{state} [{f.rule_file}]")
            print(f"    path: {f.path or '-'}")
            print(f"    {paint(f.detail, category_color)}")
        print()


def print_summary(findings: list[Finding]):
    paint = painter(sys.stdout)
    summary = ", ".join(
        paint(f"{c}: {sum(f.category == c for f in findings)}", CATEGORY_COLORS[c])
        for c in CATEGORIES
    )
    print(f"Summary: {summary}")


def report_json(findings: list[Finding], checksums: bool | None, rules_dir) -> str:
    report = {
        "rules_dir": str(rules_dir),
        "checksums_enabled": checksums,
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(report, indent=2) + "\n"


def write_output(path: Path, content: str) -> bool:
    try:
        path.write_text(content)
        # Under sudo, hand the report to the invoking user instead of root
        sudo_uid, sudo_gid = os.getenv("SUDO_UID"), os.getenv("SUDO_GID")
        if os.geteuid() == 0 and sudo_uid and sudo_gid:
            os.chown(path, int(sudo_uid), int(sudo_gid))
    except OSError as e:
        print(f"Cannot write {path}: {e}", file=sys.stderr)
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print JSON output")
    output.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="write the JSON report to FILE and only print the summary",
    )
    args = parser.parse_args()

    rules_dir = md5_update.resolve_rules_dir()
    try:
        # listdir, unlike glob, raises on a missing or unreadable dir
        names = os.listdir(rules_dir)
    except PermissionError:
        print(
            f"Cannot read {rules_dir}: permission denied (run as root)", file=sys.stderr
        )
        return 1
    except FileNotFoundError:
        print(f"Rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    rule_files = sorted(rules_dir / n for n in names if n.endswith(".json"))
    unreadable = [f for f in rule_files if not os.access(f, os.R_OK)]
    if unreadable:
        print(
            f"Cannot read {len(unreadable)} rule file(s) in {rules_dir} (run as root)",
            file=sys.stderr,
        )
        return 1

    findings = analyze_rules(rule_files)
    checksums = checksums_enabled()

    if args.json:
        print(report_json(findings, checksums, rules_dir), end="")
        return 0

    if args.output:
        if not write_output(args.output, report_json(findings, checksums, rules_dir)):
            return 1
        print_checksums_warning(checksums)
        print_summary(findings)
        print(f"Report written to {args.output}")
        return 0

    print_checksums_warning(checksums)
    print_findings(findings)
    print_summary(findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
