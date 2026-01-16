DjaoDjin-Signup
===============

[![PyPI version](https://badge.fury.io/py/djaodjin-signup.svg)](https://badge.fury.io/py/djaodjin-signup)

This repository contains a Django App for user authentication (intended
as a replacement for the ``django.contrib.auth.views`` pages), and user account
pages.

Major Features:

- HTML forms and API-based authentication
- Cookies, JWT, API Keys
- OTP codes


This project contains bare bone templates which are compatible with Django
and Jinja2 template engines. To see djaodjin-signup in action as part
of a full-fledged subscription-based session proxy, take a look
at [djaoapp](https://github.com/djaodjin/djaoapp/).


Install
=======

Add the signup urls to your urlpatterns and EmailOrUsernameModelBackend
to the settings AUTHENTICATION_BACKENDS.

    urls.py:

        urlpatterns = ('',
            (r'^api/', include('signup.urls.api')),
            (r'^', include('signup.urls.views')),

        )

    settings.py:

        AUTHENTICATION_BACKENDS = (
            'signup.backends.auth.EmailOrUsernameModelBackend',
            'django.contrib.auth.backends.ModelBackend'

        )

Development
===========

After cloning the repository, create a virtualenv environment, install
the prerequisites, create and load initial data into the database, then
run the testsite webapp.

    $ python -m venv .venv
    $ source .venv/bin/activate
    $ pip install -r testsite/requirements.txt
    $ make vendor-assets-prerequisites
    $ make initdb
    $ python manage.py runserver

    # Browse http://localhost:8000/

Release Notes
=============

Tested with

- **Python:** 3.10, **Django:** 4.2 ([LTS](https://www.djangoproject.com/download/))
- **Python:** 3.12, **Django:** 5.2 (next)
- **Python:** 3.9, **Django:** 3.2 (legacy)

0.11.0

  * replaces 'register/', 'activate/', and 'recover/' pages by 'login/'
  * re-auths with password, email_code or phone_code
  * renames SKIP_EXPIRATION_CHECK to SKIP_VERIFICATION_CHECK

[previous release notes](changelog)
