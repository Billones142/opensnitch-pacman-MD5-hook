PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
HOOKDIR ?= /etc/pacman.d/hooks
DESTDIR ?=

SCRIPT := opensnitch-md5-update.py
PIN    := opensnitch-md5-pin.py
HOOK   := opensnitch-md5-update.hook
CONFIG := opensnitch-md5-update.toml
# Fixed path, the script reads it from here (override with $$OPENSNITCH_MD5_CONFIG)
CONFIG_PATH := /etc/$(CONFIG)

# Only the project's own sources (a local opensnitch checkout may sit next to them)
PY_SOURCES := $(wildcard *.py) tests

.PHONY: help install uninstall test lint

help:
	@echo "Targets:"
	@echo "  install    Install scripts to \$$(BINDIR), hook to \$$(HOOKDIR) and config (needs root)"
	@echo "  uninstall  Remove the installed scripts and hook (needs root)"
	@echo "  test       Run the unit tests"
	@echo "  lint       Run ruff check and format check"
	@echo ""
	@echo "Variables: PREFIX=$(PREFIX) BINDIR=$(BINDIR) HOOKDIR=$(HOOKDIR) DESTDIR=$(DESTDIR)"

install:
	install -Dm755 $(SCRIPT) $(DESTDIR)$(BINDIR)/$(SCRIPT)
	install -Dm755 $(PIN) $(DESTDIR)$(BINDIR)/$(PIN)
	install -dm755 $(DESTDIR)$(HOOKDIR)
	# Point the hook's Exec line at the actual install location
	sed 's|^Exec = .*/$(SCRIPT)|Exec = $(BINDIR)/$(SCRIPT)|' $(HOOK) > $(DESTDIR)$(HOOKDIR)/$(HOOK)
	chmod 644 $(DESTDIR)$(HOOKDIR)/$(HOOK)
	# Never overwrite an existing config, it holds the user's exemptions
	@if test -e $(DESTDIR)$(CONFIG_PATH); then \
		echo "Keeping existing $(DESTDIR)$(CONFIG_PATH)"; \
	else \
		echo "install -Dm644 $(CONFIG) $(DESTDIR)$(CONFIG_PATH)"; \
		install -Dm644 $(CONFIG) $(DESTDIR)$(CONFIG_PATH); \
	fi

# The config (/etc/opensnitch-md5-update.toml), logs (/var/log/opensnitch-md5-update.log)
# and rule backups (/var/backups/opensnitch-rules) are kept on purpose; remove them by hand.
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(SCRIPT)
	rm -f $(DESTDIR)$(BINDIR)/$(PIN)
	rm -f $(DESTDIR)$(HOOKDIR)/$(HOOK)

test:
	python3 -m unittest discover -s tests -v

lint:
	ruff check $(PY_SOURCES)
	ruff format --check $(PY_SOURCES)
