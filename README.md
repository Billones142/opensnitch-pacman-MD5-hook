# opensnitch-pacman-MD5-hook

A pacman hook for Arch Linux that keeps [OpenSnitch](https://github.com/evilsocket/opensnitch) rules with MD5 hashes working after package upgrades by refreshing the binary MD5 hashes they pin.

## The problem

OpenSnitch rules can match a process by its path **and** its MD5 checksum(`process.hash.md5`). That's a good guard against a tampered binary, but every legitimate package upgrade changes the binary, the hash stops matching, and the rule silently stops applying, so you get prompted again or the connection is denied.

## What it does

After every pacman install/upgrade transaction, the hook runs `opensnitch-md5-update.py --auto --stdin-targets`. It's a `Type = Path` hook with `NeedsTargets`, so pacman passes the list of files the transaction installed or upgraded on stdin. The script then:

1. Reads every `*.json` rule in the OpenSnitch rules directory.
2. Finds each `list` operator that contains both a `process.path` and a `process.hash.md5` entry, e.g.:

   ```json
   "operator": {
     "type": "list",
     "operand": "list",
     "list": [
       { "type": "simple", "operand": "process.path",     "data": "/usr/bin/curl" },
       { "type": "simple", "operand": "process.hash.md5", "data": "5d41402abc4b2a76b9719d911017c592" }
     ]
   }
   ```

3. Skips the rule unless its binary is one of the files pacman just changed. Paths are resolved first, so a rule on `/usr/sbin/foo` matches the `/usr/bin/foo` that pacman reports (on Arch, `/usr/sbin` is a symlink).
4. Hashes the binary on disk (ELF files only) and compares it with the stored MD5.
5. If the binary belongs to an [exempt package](#exemptions), it leaves the rule alone and prints a warning that the MD5 is outdated instead.
6. For every other mismatch: backs up the rule file, writes the new MD5 (also keeping the JSON-string copy of the list in the operator's `data` field in sync), and saves the file atomically, keeping its original mode and owner.
7. If a program is still running the old binary, it first adds a temporary [transition rule](#programs-running-during-an-upgrade) with the old MD5, so the program isn't blocked before you restart it.

If nothing changed, it prints nothing; the run is only recorded in the log file. Output is colored when run from a terminal (set `NO_COLOR` to disable it); pacman passes hook output through a pipe, so it stays plain there. opensnitchd watches the rules directory and reloads edited rules on its own (unless it was started with `-no-live-reload`). Its watcher only reacts to writes, not to the rename of an atomic save, so every saved rule is also rewritten in place with identical bytes to trigger the reload.

### Programs running during an upgrade

opensnitchd hashes the image a process is actually running (`/proc/<pid>/exe`), not the file on disk. pacman replaces a binary by renaming the new file over it, so a program started before the upgrade keeps running the old image and keeps the old MD5. Updating the rule alone would block it until you restart it.

So when the hook updates a rule and a process still runs the replaced binary, it first writes a copy of the rule with the old MD5:

- named `<rule>-md5-transition-<first 8 chars of the old MD5>.json`, with the duration `until restart` and the same action;
- removed at boot by `/etc/tmpfiles.d/opensnitch-md5-update.conf`, before opensnitchd starts. If the daemon restarts without a reboot, it simply loads them again;
- never updated by the hook itself, so it keeps matching the old binary.

Restarting the program (or rebooting) is enough to move it to the new binary; the transition rule is then unused until it's removed. If your rules live somewhere other than `/etc/opensnitchd/rules`, edit the path in the tmpfiles file. They can be turned off with [`transition_rules = false`](#transition-rules).

> **Note:** the daemon only enforces MD5 operands when checksums are enabled (`"Rules": { "EnableChecksums": true }` in `/etc/opensnitchd/default-config.json`). With checksums disabled, the hashes are ignored and this hook has no practical effect.

## Requirements

- Arch Linux (or another pacman-based distro)
- Python 3.11+ (standard library only, uses `tomllib`)
- OpenSnitch with rules stored as JSON files

## Repository layout

| Directory | Contents                                                                                                 |
| --------- | -------------------------------------------------------------------------------------------------------- |
| `hook/`   | Everything `make install` installs: the hook, its scripts, the default config and the tmpfiles.d snippet |
| `tools/`  | Standalone helpers, run from the checkout and never installed ([tools](#tools))                          |
| `tests/`  | Unit tests for `hook/`                                                                                   |

## Install / uninstall

Root is needed because the files are installed outside your home directory (`/usr/local/bin`, `/etc/pacman.d/hooks`, `/etc/tmpfiles.d` and `/etc`):

```sh
sudo make install
sudo make uninstall
```

This installs:

| File                                  | Destination                                                      |
| ------------------------------------- | ---------------------------------------------------------------- |
| `hook/opensnitch-md5-update.py`       | `/usr/local/bin/opensnitch-md5-update.py`                        |
| `hook/opensnitch-md5-pin.py`          | `/usr/local/bin/opensnitch-md5-pin.py`                           |
| `hook/opensnitch-md5-update.hook`     | `/etc/pacman.d/hooks/opensnitch-md5-update.hook`                 |
| `hook/opensnitch-md5-update.tmpfiles` | `/etc/tmpfiles.d/opensnitch-md5-update.conf`                     |
| `hook/opensnitch-md5-update.toml`     | `/etc/opensnitch-md5-update.toml` (only if it doesn't exist yet) |

`PREFIX`, `BINDIR`, `HOOKDIR`, `TMPFILESDIR` and `DESTDIR` can be overridden (e.g. `sudo make install PREFIX=/usr`); the hook's `Exec` line is rewritten to match `BINDIR`.

`make uninstall` leaves the config, the log and the rule backups in place. Remove them by hand if you no longer need them:

```sh
sudo rm /etc/opensnitch-md5-update.toml
sudo rm /var/log/opensnitch-md5-update.log
sudo rm -r /var/backups/opensnitch-rules
```

## Manual usage

The script can also be run on its own. Root is needed to read and write the rule files (they are `0600 root`):

```sh
# Interactive: shows the mismatches and asks before applying
sudo opensnitch-md5-update.py

# Automatic: checks every pinned binary and applies without asking
sudo opensnitch-md5-update.py --auto

# Only check the given files, one per line (what the pacman hook uses).
# Paths may be relative to / like pacman sends them. Requires --auto,
# because stdin carries the path list and can't answer the prompt.
printf 'usr/bin/curl\n' | sudo opensnitch-md5-update.py --auto --stdin-targets
```

Without `--stdin-targets` the script does a full scan. That's useful right after enabling checksums, or to catch binaries changed outside pacman. Exemptions apply to manual runs too.

### Pinning a rule

`opensnitch-md5-pin.py` writes the current MD5 of a rule's binary into the rule. A rule on a single exact `process.path` gets a `process.hash.md5` condition (a plain path rule is turned into a list rule, like the OpenSnitch UI does), and an outdated MD5 is refreshed. Rules with regexp paths or non-ELF targets (scripts) are left alone. The file is backed up first, and the change is logged to the same log file as the hook. It's the way to accept an update of an exempt package.

```sh
sudo opensnitch-md5-pin.py --dry-run /etc/opensnitchd/rules/<rule>.json  # preview
sudo opensnitch-md5-pin.py /etc/opensnitchd/rules/<rule>.json
```

Only pin a binary you trust. For a package, `pacman -Qkk <package>` checks its files against the package database first.

## Configuration

The hook reads `/etc/opensnitch-md5-update.toml`. `make install` copies a default file where every setting is a commented-out example with its explanation, so the defaults below apply until you uncomment one. It never overwrites the file once it exists.

| Setting            | Default | Purpose                                                                                       |
| ------------------ | ------- | --------------------------------------------------------------------------------------------- |
| `exempt_packages`  | `[]`    | Packages whose binaries never get their MD5 updated automatically ([exemptions](#exemptions)) |
| `exempt_foreign`   | `false` | Exempt every foreign (AUR or locally built) package                                           |
| `transition_rules` | `true`  | Add [transition rules](#transition-rules) for programs still running the old binary           |

### Exemptions

Example settings:

```toml
# Package names, shell-style wildcards allowed
exempt_packages = ["firefox", "python-*"]

# Every foreign package: AUR or locally built (see `pacman -Qm`)
exempt_foreign = true
```

The owning package is looked up with `pacman -Qqo`. When an exempt binary changes, the rule is left untouched, so OpenSnitch stops matching it, and the hook warns you:

```
WARNING: outdated MD5 not updated in rule allow-firefox.json
  Binary: /usr/lib/firefox/firefox (package 'firefox' is in exempt_packages)
    Stored MD5:  ...
    Current MD5: ...
  The rule won't match the new binary. If you trust it, re-pin with:
    sudo opensnitch-md5-pin.py /etc/opensnitchd/rules/allow-firefox.json
```

The config fails closed: an invalid file (bad TOML, wrong types or unknown keys, which are usually typos) stops the run without changing any rule, and a binary whose package can't be looked up is treated as exempt.

### Transition rules

The temporary rules described in [Programs running during an upgrade](#programs-running-during-an-upgrade) are on by default. To turn them off:

```toml
transition_rules = false
```

Rules are then updated without a transition copy, so a program that was running during the upgrade is prompted or blocked until you restart it. Transition rules that already exist are kept until the next reboot.

### Environment variables

| Environment variable      | Default                                                                                 | Purpose                  |
| ------------------------- | --------------------------------------------------------------------------------------- | ------------------------ |
| `OPENSNITCH_RULES_DIR`    | `Rules.Path` from `/etc/opensnitchd/default-config.json`, else `/etc/opensnitchd/rules` | Rules directory to scan  |
| `OPENSNITCH_BACKUP_DIR`   | `/var/backups/opensnitch-rules`                                                         | Where backups are stored |
| `OPENSNITCH_MD5_LOG_FILE` | `/var/log/opensnitch-md5-update.log`                                                    | Log file                 |
| `OPENSNITCH_MD5_CONFIG`   | `/etc/opensnitch-md5-update.toml`                                                       | Hook config file         |

## Backups and restoring

Before a rule file is modified, a copy is saved as `/var/backups/opensnitch-rules/<rule>.json_<YYYYmmdd_HHMMSS>.bak`. To restore one:

```sh
sudo cp -p /var/backups/opensnitch-rules/<rule>.json_<timestamp>.bak /etc/opensnitchd/rules/<rule>.json
```

## Tools

`tools/` has two helpers for pinning many existing rules at once, e.g. right after enabling checksums. They aren't part of the hook and aren't installed: run them from the checkout. They reuse the code in `hook/`, so they have to stay next to it. Root is needed to read and write the rule files (`0600 root`).

### Analyzing the rules

`tools/analyze-md5-rules.py` is read-only. It sorts every `process.path` condition of every rule into a category:

| Category          | Meaning                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------- |
| `PINNED-OK`       | Has an MD5 that matches the binary on disk                                                           |
| `PINNED-OUTDATED` | Has an MD5 that no longer matches (the hook fixes these when pacman updates the binary)              |
| `PINNED-UNUSABLE` | Has an MD5 the hook can't use: no single path next to it, missing binary or not an ELF file          |
| `CANDIDATE`       | Exact path to an existing ELF binary without an MD5: it can be pinned                                |
| `NOT-APPLICABLE`  | Regexp path, script, interpreter (its MD5 says nothing about the script it runs), missing or invalid |

```sh
sudo tools/analyze-md5-rules.py                      # colored report grouped by category
sudo tools/analyze-md5-rules.py --json               # JSON on stdout
sudo tools/analyze-md5-rules.py -o rules-report.json # JSON to a file, only the summary on screen
```

A progress bar is drawn on stderr while it runs, only on a terminal. With `-o` under `sudo`, the report file is handed back to your user.

### Pinning from a report

`tools/pin-from-report.py` pins the current MD5 into every `CANDIDATE` rule of a report, using the same code as `opensnitch-md5-pin.py` (backup first, then an atomic write).

```sh
tools/pin-from-report.py -n rules-report.json                   # preview only
sudo tools/pin-from-report.py --packaged-only rules-report.json # recommended
sudo tools/pin-from-report.py rules-report.json                 # all candidates
```

- It only pins a binary whose MD5 still matches the report; otherwise it asks you to re-run the analysis.
- It only writes to the configured rules directory and ignores `rules_dir` from the JSON, since the report is a user-writable file and this runs as root.
- It shows the plan and asks for confirmation unless `-y` is given. `--include-outdated` also refreshes `PINNED-OUTDATED` rules; transition rules are always skipped.
- Binaries not owned by any pacman package (e.g. Steam/Proton under your home) are listed with a warning: the hook never refreshes them, so their rules stop matching after their next self-update. `--packaged-only` skips them.

## Development

```sh
make test   # unit tests (stdlib unittest, no root needed)
make lint   # ruff check + ruff format --check on hook/, tools/ and tests/
```

Tests never touch the real rules: they use temp dirs and mock the `pacman` queries. For a manual end-to-end run, point the scripts at temp files with the [environment variables](#environment-variables).

## Limitations

- A rule is updated only if its MD5 entry sits in the same `list` operator as exactly one `process.path` entry; otherwise there's no way to know which binary the hash belongs to.
- The hook only sees files changed by pacman (AUR packages count, since helpers install them with `pacman -U`). Binaries updated some other way, such as self-updating apps, manually extracted tarballs or `pip`, need a manual full run.
- Updating the hash means trusting whatever the package manager installed. That's the point of the hook, but it also means a compromised package would get its hash accepted automatically. Exempt packages you trust less (e.g. AUR ones) to review their updates by hand.
- Transition rules are only added by the hook. `opensnitch-md5-pin.py` writes the MD5 of the file on disk, so a program still running an older image of it needs a restart after pinning.
- A transition rule also allows the old binary to be started again until reboot, e.g. from a copy kept elsewhere. It's limited to the exact old MD5 of a binary you already trusted.
