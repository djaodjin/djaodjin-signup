# -*- Makefile -*-

-include $(buildTop)/share/dws/prefix.mk

srcDir        ?= .
installTop    ?= $(VIRTUAL_ENV)
binDir        ?= $(installTop)/bin

PYTHON        := $(binDir)/python

install::
	cd $(srcDir) && $(PYTHON) ./setup.py install --quiet

initdb:
	-rm -f db.sqlite3
	cd $(srcDir) && $(PYTHON) ./manage.py syncdb --noinput

