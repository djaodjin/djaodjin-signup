# -*- Makefile -*-

-include $(buildTop)/share/dws/prefix.mk

srcDir        ?= .
installTop    ?= $(if $(VIRTUAL_ENV),$(VIRTUAL_ENV),$(abspath $(srcDir))/.venv)
binDir        ?= $(installTop)/bin
libDir        ?= $(installTop)/lib
CONFIG_DIR    ?= $(installTop)/etc/testsite
LOCALSTATEDIR ?= $(installTop)/var
# because there is no site.conf
RUN_DIR       ?= $(abspath $(srcDir))

installDirs   ?= install -d
installFiles  ?= install -p -m 644
NPM           ?= npm
PYTHON        := python
PIP           := pip
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
TWINE         := twine

ASSETS_DIR    := $(srcDir)/testsite/static
DB_NAME       ?= $(RUN_DIR)/db.sqlite

$(info Path to python executable (i.e. PYTHON) while running make: $(shell which $(PYTHON)))

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


initdb: clean-dbs
	$(installDirs) $(dir $(DB_NAME))
	cd $(srcDir) && $(MANAGE) migrate $(RUNSYNCDB) --noinput
	cat $(srcDir)/testsite/migrations/adjustments1-sqlite3.sql | $(SQLITE_UNSAFE) $(DB_NAME)
	cat $(srcDir)/testsite/migrations/adjustments2-sqlite3.sql | $(SQLITE) $(DB_NAME)
	cd $(srcDir) && $(MANAGE) loaddata testsite/fixtures/default-db.json


vendor-assets-prerequisites: $(libDir)/.npm/djaodjin-signup-packages


$(DESTDIR)$(CONFIG_DIR)/credentials: $(srcDir)/testsite/etc/credentials
	$(installDirs) $(dir $@)
	@if [ ! -f $@ ] ; then \
		sed -e "s,\%(SECRET_KEY)s,`$(PYTHON) -c 'import sys ; from random import choice ; sys.stdout.write("".join([choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^*-_=+") for i in range(50)]))'`," -e "s,\%(FERNET_KEY)s,`$(PYTHON) -c 'import sys ; from random import choice ; sys.stdout.write("".join([choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^*-_=+") for i in range(50)]))'`," $< > $@ ; \
	else \
		echo "warning: We are keeping $@ intact but $< contains updates that might affect behavior of the testsite." ; \
	fi


$(DESTDIR)$(CONFIG_DIR)/gunicorn.conf: $(srcDir)/testsite/etc/gunicorn.conf
	$(installDirs) $(dir $@)
	[ -f $@ ] || sed \
		-e 's,%(LOCALSTATEDIR)s,$(LOCALSTATEDIR),' \
		-e 's,%(RUN_DIR)s,$(RUN_DIR),' $< > $@


$(libDir)/.npm/djaodjin-signup-packages: $(srcDir)/testsite/package.json
	$(installFiles) $^ $(libDir)
	$(NPM) install --cache $(libDir)/.npm --prefix $(libDir)
	$(installDirs) -d $(ASSETS_DIR)/vendor
	$(installFiles) $(libDir)/node_modules/jquery/dist/jquery.js $(ASSETS_DIR)/vendor
	$(installFiles) $(libDir)/node_modules/qrcode/build/qrcode.js $(ASSETS_DIR)/vendor
	$(installFiles) $(libDir)/node_modules/vue/dist/vue.js $(ASSETS_DIR)/vendor
	$(installFiles) $(libDir)/node_modules/vue-croppa/dist/vue-croppa.js $(ASSETS_DIR)/vendor
	touch $@


.PHONY: all check dist doc install
