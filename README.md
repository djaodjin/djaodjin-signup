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

- **Python:** 2.7, **Django:** 1.11 ([LTS](https://www.djangoproject.com/download/)), **Django Rest Framework:** 3.8.2
- **Python:** 3.6, **Django:** 1.11 ([LTS](https://www.djangoproject.com/download/)), **Django Rest Framework:** 3.8.2
- **Python:** 3.6, **Django:** 2.1 (latest),       **Django Rest Framework:** 3.8.2

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
            (r'^accounts/', include('signup.urls')),
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

    $ virtualenv _installTop_
    $ source _installTop_/bin/activate
    $ pip install -r testsite/requirements.txt
    $ python manage.py syncdb
    $ python manage.py loaddata testsite/fixtures/test_data.json
    $ python manage.py runserver

    # Browse http://localhost:8000/

Release Notes
=============

0.2.9

  * adds /api/users/{user}/activate/ API to send activation e-mail
  * fixes in /api/users to return Contact and User models.
  * merges disabled templates

[previous release notes](changelog)
