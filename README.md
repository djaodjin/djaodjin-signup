This code a frictionless signup Django app.

The app will register and login a user with as little as only an email address.

When the user logs out and tries to logs back in with the same email address,
the app will first verify the email address through an activation url send
to the registered email address. Setting the password is deferred to after
the email address has been verified.

If during the first login and/or subsequent login, the email address should
be verified before moving forward (ex: before presenting a payment view),
you should decorate the view with an *active_required* decorator.

Tested with

- **Python:** 3.7, **Django:** 3.2 ([LTS](https://www.djangoproject.com/download/)), **Django Rest Framework:** 3.12
- **Python:** 3.10, **Django:** 4.0 (latest), **Django Rest Framework:** 3.12 - see [#55](https://github.com/djaodjin/djaodjin-signup/issues/55)
- **Python:** 2.7, **Django:** 1.11 (legacy), **Django Rest Framework:** 3.9.4

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

To make the application useable accross a variety of websites, ``signup`` never
sends any e-mails directly. It relies on triggering ``signals`` whenever
a notification must be generated. As a result, to verify a user email address
and activate her account, you will need to implement a listener for the
``user_verification`` signal and send the e-mail from there.

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

0.7.6

  * fixes issue on login API when using incorrect password
  * fixes issue when username is changed on activate page

[previous release notes](changelog)
