PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
HOOKDIR ?= /etc/pacman.d/hooks
DESTDIR ?=

SCRIPT := opensnitch-md5-update.py
HOOK   := opensnitch-md5-update.hook

.PHONY: help install uninstall test lint

help:
	@echo "Targets:"
	@echo "  install    Install script to \$$(BINDIR) and hook to \$$(HOOKDIR) (needs root)"
	@echo "  uninstall  Remove the installed script and hook (needs root)"
	@echo "  test       Run the unit tests"
	@echo "  lint       Run ruff check and format check"
	@echo ""
	@echo "Variables: PREFIX=$(PREFIX) BINDIR=$(BINDIR) HOOKDIR=$(HOOKDIR) DESTDIR=$(DESTDIR)"

install:
	install -Dm755 $(SCRIPT) $(DESTDIR)$(BINDIR)/$(SCRIPT)
	install -dm755 $(DESTDIR)$(HOOKDIR)
	# Point the hook's Exec line at the actual install location
	sed 's|^Exec = .*/$(SCRIPT)|Exec = $(BINDIR)/$(SCRIPT)|' $(HOOK) > $(DESTDIR)$(HOOKDIR)/$(HOOK)
	chmod 644 $(DESTDIR)$(HOOKDIR)/$(HOOK)

# Logs (/var/log/opensnitch-md5-update.log) and rule backups
# (/var/backups/opensnitch-rules) are kept on purpose; remove them by hand.
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(SCRIPT)
	rm -f $(DESTDIR)$(HOOKDIR)/$(HOOK)

test:
	python3 -m unittest discover -s tests -v

lint:
	ruff check .
	ruff format --check .
