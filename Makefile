# -*- Makefile -*-

-include $(buildTop)/share/dws/prefix.mk

srcDir        ?= .
installTop    ?= $(VIRTUAL_ENV)
binDir        ?= $(installTop)/bin
CONFIG_DIR    ?= $(srcDir)
# XXX CONFIG_DIR should really be $(installTop)/etc/testsite
LOCALSTATEDIR ?= $(installTop)/var

installDirs   ?= install -d
installFiles  ?= install -p -m 644
NPM           ?= npm
PYTHON        := $(binDir)/python
PIP           := $(binDir)/pip
# As of sqlite3 version  3.42.0 (2023-05-16) we need to pass `-unsafe-testing`
# to make adjustments in the demo database.
SQLITE_NO_UNSAFE_TESTING := $(shell echo '.schema' | sqlite3 -unsafe-testing > /dev/null 2>&1; echo $$?)
ifeq ($(SQLITE_NO_UNSAFE_TESTING),0)
SQLITE        ?= sqlite3
SQLITE_UNSAFE ?= sqlite3 -unsafe-testing
else
SQLITE        ?= sqlite3
SQLITE_UNSAFE ?= $(SQLITE)
endif
TWINE         := $(binDir)/twine

RUN_DIR       ?= $(srcDir)
DB_NAME       ?= $(RUN_DIR)/db.sqlite

MANAGE        := TESTSITE_SETTINGS_LOCATION=$(CONFIG_DIR) RUN_DIR=$(RUN_DIR) $(PYTHON) manage.py

# Django 1.7,1.8 sync tables without migrations by default while Django 1.9
# requires a --run-syncdb argument.
# Implementation Note: We have to wait for the config files to be installed
# before running the manage.py command (else missing SECRECT_KEY).
RUNSYNCDB     = $(if $(findstring --run-syncdb,$(shell cd $(srcDir) && $(MANAGE) migrate --help 2>/dev/null)),--run-syncdb,)

install::
	cd $(srcDir) && $(PIP) install .


install-conf:: $(DESTDIR)$(CONFIG_DIR)/credentials \
                $(DESTDIR)$(CONFIG_DIR)/gunicorn.conf
	$(installDirs) $(DESTDIR)$(LOCALSTATEDIR)/db
	$(installDirs) $(DESTDIR)$(LOCALSTATEDIR)/run
	$(installDirs) $(DESTDIR)$(LOCALSTATEDIR)/log/gunicorn


dist::
	$(PYTHON) -m build
	$(TWINE) check dist/*
	$(TWINE) upload dist/*


build-assets: vendor-assets-prerequisites


clean:: clean-dbs
	[ ! -f $(srcDir)/package-lock.json ] || rm $(srcDir)/package-lock.json
	find $(srcDir) -name '__pycache__' -exec rm -rf {} +
	find $(srcDir) -name '*~' -exec rm -rf {} +


clean-dbs:
	[ ! -f $(DB_NAME) ] || rm $(DB_NAME)
	[ ! -f $(srcDir)/testsite-app.log ] || rm $(srcDir)/testsite-app.log


doc:
	$(installDirs) build/docs
	cd $(srcDir) && sphinx-build -b html ./docs $(PWD)/build/docs


initdb: clean-dbs install-conf
	$(installDirs) $(dir $(DB_NAME))
	cd $(srcDir) && $(MANAGE) migrate $(RUNSYNCDB) --noinput
	cat $(srcDir)/testsite/migrations/adjustments1-sqlite3.sql | $(SQLITE_UNSAFE) $(DB_NAME)
	cat $(srcDir)/testsite/migrations/adjustments2-sqlite3.sql | $(SQLITE) $(DB_NAME)
	cd $(srcDir) && $(MANAGE) loaddata testsite/fixtures/default-db.json


vendor-assets-prerequisites: $(installTop)/.npm/djaodjin-signup-packages


$(DESTDIR)$(CONFIG_DIR)/credentials: $(srcDir)/testsite/etc/credentials
	$(installDirs) $(dir $@)
	[ -f $@ ] || \
		sed -e "s,\%(SECRET_KEY)s,`$(PYTHON) -c 'import sys ; from random import choice ; sys.stdout.write("".join([choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^*-_=+") for i in range(50)]))'`," -e "s,\%(FERNET_KEY)s,`$(PYTHON) -c 'import sys ; from random import choice ; sys.stdout.write("".join([choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^*-_=+") for i in range(50)]))'`," $< > $@


$(DESTDIR)$(CONFIG_DIR)/gunicorn.conf: $(srcDir)/testsite/etc/gunicorn.conf
	$(installDirs) $(dir $@)
	[ -f $@ ] || sed \
		-e 's,%(LOCALSTATEDIR)s,$(LOCALSTATEDIR),' $< > $@


$(installTop)/.npm/djaodjin-signup-packages: $(srcDir)/testsite/package.json
	$(installFiles) $^ $(installTop)
	$(NPM) install --loglevel verbose --cache $(installTop)/.npm --tmp $(installTop)/tmp --prefix $(installTop)
	$(installDirs) -d $(srcDir)/testsite/static/vendor
	$(installFiles) $(installTop)/node_modules/jquery/dist/jquery.js $(srcDir)/testsite/static/vendor
	$(installFiles) $(installTop)/node_modules/moment/moment.js $(srcDir)/testsite/static/vendor
	$(installFiles) $(installTop)/node_modules/moment-timezone/builds/moment-timezone-with-data.js $(srcDir)/testsite/static/vendor
	$(installFiles) $(installTop)/node_modules/qrcode/build/qrcode.js* $(srcDir)/testsite/static/vendor
	$(installFiles) $(installTop)/node_modules/vue/dist/vue.js $(srcDir)/testsite/static/vendor
	$(installFiles) $(installTop)/node_modules/vue-croppa/dist/vue-croppa.js $(srcDir)/testsite/static/vendor
	touch $@


.PHONY: all check dist doc install
