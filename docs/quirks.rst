Installation Quirks
===================

SAML and native libraries
-------------------------

The SAML implementation depends on ``python-saml`` which transitively depends
on ``xmlsec1`` native libraries through ``xmlsec`` bindings. ``xmlsec1`` itself
depends on ``openssl``.

On some distributions (ex: AWS Linux 2), the ``xmlsec1`` rpm package is built
against OpenSSL 1.0 and thus depends on ``openssl``. Python3.11 is built
against OpenSSL 1.1 (minimum). ``openssl11`` is available on AWS Linux 2
but there is conflict when you try to install both ``openssl`` and
``openssl11``.

Installing xmlsec1 (here ``xmlsec1-1.3.0.tar.gz``) from source is a bit tricky.
Somehow it requires ``libgcrypt`` on the system we run tests with. That required
to install both ``libgpg-error`` and ``libgcrypt`` from source. Looking through
``libgcrypt`` rpm spec file we can find the following comment:

    # The original libgcrypt sources now contain potentially patented ECC

Installing ``python-xmlsec`` when ``xmlsec1`` was compiled from source
and installed in ``/usr/local``can be tricky. Typically it requires to
export ``PKG_CONFIG_PATH`` to the shell environment beforehand as in:

    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

Python-ldap and native libraries
--------------------------------

The LDAP authentication backend requires ``python-ldap`` which transitively
depends on `openldap native libraries <https://www.python-ldap.org/en/python-ldap-3.4.3/installing.html#build-prerequisites>`_.


Django Rest Framework
---------------------

``djangorestframework`` version 3.14.0 introduces compatibility with Django4.1
but drops support for Django2.2. If you are still using Django2.2, you can
use ``djangorestframework==3.12.4`` with ``djaodjin-signup``. It should work.





