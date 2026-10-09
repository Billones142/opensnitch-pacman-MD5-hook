# opensnitch-pacman-MD5-hook

A pacman hook for Arch Linux that keeps [OpenSnitch](https://github.com/evilsocket/opensnitch)
rules working after package upgrades by refreshing the binary MD5 hashes they pin.

## The problem

OpenSnitch rules can match a process by its path **and** its MD5 checksum
(`process.hash.md5`). That's a good guard against a tampered binary, but every
legitimate package upgrade changes the binary, the hash stops matching, and the
rule silently stops applying, so you get prompted again or the connection is denied.

## What it does

After every pacman install/upgrade transaction, the hook runs
`opensnitch-md5-update.py --auto`, which:

1. Reads every `*.json` rule in the OpenSnitch rules directory.
2. Finds each `list` operator that contains both a `process.path` and a
   `process.hash.md5` entry, e.g.:

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

3. Hashes the binary on disk (ELF files only) and compares it with the stored MD5.
4. For every mismatch: backs up the rule file, writes the new MD5 (also keeping
   the JSON-string copy of the list in the operator's `data` field in sync), and
   saves the file atomically, keeping its original mode and owner.

If nothing changed, it prints nothing; the run is only recorded in the log file.
opensnitchd watches the rules directory and reloads edited rules on its own
(unless it was started with `-no-live-reload`).

> **Note:** the daemon only enforces MD5 operands when checksums are enabled
> (`"Rules": { "EnableChecksums": true }` in `/etc/opensnitchd/default-config.json`).
> With checksums disabled, the hashes are ignored and this hook has no practical effect.

## Requirements

- Arch Linux (or another pacman-based distro)
- Python 3 (standard library only)
- OpenSnitch with rules stored as JSON files

## Install / uninstall

Root is needed because the files are installed outside your home directory
(`/usr/local/bin` and `/etc/pacman.d/hooks`):

```sh
sudo make install
sudo make uninstall
```

This installs:

| File | Destination |
|------|-------------|
| `opensnitch-md5-update.py` | `/usr/local/bin/opensnitch-md5-update.py` |
| `opensnitch-md5-update.hook` | `/etc/pacman.d/hooks/opensnitch-md5-update.hook` |

`PREFIX`, `BINDIR`, `HOOKDIR` and `DESTDIR` can be overridden
(e.g. `sudo make install PREFIX=/usr`); the hook's `Exec` line is rewritten to
match `BINDIR`.

`make uninstall` leaves the log and the rule backups in place. Remove them by hand
if you no longer need them:

```sh
sudo rm /var/log/opensnitch-md5-update.log
sudo rm -r /var/backups/opensnitch-rules
```

## Manual usage

The script can also be run on its own. Root is needed to read and write the rule
files (they are `0600 root`):

```sh
# Interactive: shows the mismatches and asks before applying
sudo opensnitch-md5-update.py

# Automatic: applies without asking (what the pacman hook uses)
sudo opensnitch-md5-update.py --auto
```

## Configuration

| Environment variable | Default | Purpose |
|----------------------|---------|---------|
| `OPENSNITCH_RULES_DIR` | `Rules.Path` from `/etc/opensnitchd/default-config.json`, else `/etc/opensnitchd/rules` | Rules directory to scan |
| `OPENSNITCH_BACKUP_DIR` | `/var/backups/opensnitch-rules` | Where backups are stored |
| `OPENSNITCH_MD5_LOG_FILE` | `/var/log/opensnitch-md5-update.log` | Log file |

## Backups and restoring

Before a rule file is modified, a copy is saved as
`/var/backups/opensnitch-rules/<rule>.json_<YYYYmmdd_HHMMSS>.bak`. To restore one:

```sh
sudo cp -p /var/backups/opensnitch-rules/<rule>.json_<timestamp>.bak /etc/opensnitchd/rules/<rule>.json
```

## Development

```sh
make test   # unit tests (stdlib unittest, no root needed)
make lint   # ruff check + ruff format --check
```

## Limitations

- A rule is updated only if its MD5 entry sits in the same `list` operator as
  exactly one `process.path` entry; otherwise there's no way to know which binary
  the hash belongs to.
- The hook triggers on every package (`Target = *`) and rescans all rules each time
  instead of only the files touched by the transaction.
- Updating the hash means trusting whatever the package manager installed. That's
  the point of the hook, but it also means a compromised package would get its
  hash accepted automatically.
