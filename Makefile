PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
HOOKDIR ?= /etc/pacman.d/hooks
TMPFILESDIR ?= /etc/tmpfiles.d
DESTDIR ?=

# Installed files live in hook/; tools/ holds standalone helpers that aren't installed
SRC    := hook
SCRIPT := opensnitch-md5-update.py
PIN    := opensnitch-md5-pin.py
HOOK   := opensnitch-md5-update.hook
CONFIG := opensnitch-md5-update.toml
TMPFILES := opensnitch-md5-update.tmpfiles
# Fixed path, the script reads it from here (override with $$OPENSNITCH_MD5_CONFIG)
CONFIG_PATH := /etc/$(CONFIG)

# Only the project's own sources (a local opensnitch checkout may sit next to them)
PY_SOURCES := hook tools tests

.PHONY: help install uninstall test lint

help:
	@echo "Targets:"
	@echo "  install    Install scripts, hook, tmpfiles snippet and config (needs root)"
	@echo "  uninstall  Remove the installed scripts, hook and tmpfiles snippet (needs root)"
	@echo "  test       Run the unit tests"
	@echo "  lint       Run ruff check and format check"
	@echo ""
	@echo "Variables: PREFIX=$(PREFIX) BINDIR=$(BINDIR) HOOKDIR=$(HOOKDIR) TMPFILESDIR=$(TMPFILESDIR) DESTDIR=$(DESTDIR)"

install:
	install -Dm755 $(SRC)/$(SCRIPT) $(DESTDIR)$(BINDIR)/$(SCRIPT)
	install -Dm755 $(SRC)/$(PIN) $(DESTDIR)$(BINDIR)/$(PIN)
	install -dm755 $(DESTDIR)$(HOOKDIR)
	# Point the hook's Exec line at the actual install location
	sed 's|^Exec = .*/$(SCRIPT)|Exec = $(BINDIR)/$(SCRIPT)|' $(SRC)/$(HOOK) > $(DESTDIR)$(HOOKDIR)/$(HOOK)
	chmod 644 $(DESTDIR)$(HOOKDIR)/$(HOOK)
	# Deletes the "until reboot" transition rules at boot
	install -Dm644 $(SRC)/$(TMPFILES) $(DESTDIR)$(TMPFILESDIR)/opensnitch-md5-update.conf
	# Never overwrite an existing config, it holds the user's exemptions
	@if test -e $(DESTDIR)$(CONFIG_PATH); then \
		echo "Keeping existing $(DESTDIR)$(CONFIG_PATH)"; \
	else \
		echo "install -Dm644 $(SRC)/$(CONFIG) $(DESTDIR)$(CONFIG_PATH)"; \
		install -Dm644 $(SRC)/$(CONFIG) $(DESTDIR)$(CONFIG_PATH); \
	fi

# The config (/etc/opensnitch-md5-update.toml), logs (/var/log/opensnitch-md5-update.log)
# and rule backups (/var/backups/opensnitch-rules) are kept on purpose; remove them by hand.
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(SCRIPT)
	rm -f $(DESTDIR)$(BINDIR)/$(PIN)
	rm -f $(DESTDIR)$(HOOKDIR)/$(HOOK)
	rm -f $(DESTDIR)$(TMPFILESDIR)/opensnitch-md5-update.conf

test:
	python3 -m unittest discover -s tests -v

lint:
	ruff check $(PY_SOURCES)
	ruff format --check $(PY_SOURCES)
