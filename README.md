DjaoDjin-Signup
===============

[![PyPI version](https://badge.fury.io/py/djaodjin-signup.svg)](https://badge.fury.io/py/djaodjin-signup)

This repository contains a Django App for frictionless signup.

The app will register and login a user with as little as only an email address.

When the user logs out and tries to logs back in with the same email address,
the app will first verify the email address through an activation url send
to the registered email address. Setting the password is deferred to after
the email address has been verified.

If during the first login and/or subsequent login, the email address should
be verified before moving forward (ex: before presenting a payment view),
you should decorate the view with an *active_required* decorator.

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
- **Python:** 3.12, **Django:** 5.1 (next)
- **Python:** 3.7, **Django:** 3.2 (legacy)

0.10.1

  * enables use of codes or links to verify channels (email, phone)
  * adds APIs to create account activities

[previous release notes](changelog)
