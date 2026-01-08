Getting Started
===============

djaodjin-signup is a Django application that implements the logic to support
user authentication (intended as a replacement for the
``django.contrib.auth.views`` pages), and user account pages.

As such you will need to be familiar with Django Apps and Django Projects (see
`Getting started with Django`_).

If you are looking to see the features djaodjin-signup brings to your Django
project without going through the setup inside your own Django project, run
the testsite committed alongside the application code (see steps in
`README.md`_).

If you are interested in what a fully-integrated SaaS Django project could look
like, browse the `djaoapp`_ code
repository and/or the `djaoapp livedemo`_
(**Warning:** the livedemo is for the djaoapp, fully-integrated SaaS Django
project. There is quite some work to integrate an auth app, a rule-based
access control app as well as HTML/CSS required to make all of it acceptable
to modern UI standards).


Installation and configuration
------------------------------

We assume here you already created a
`Python virtual environment<https://docs.python.org/3/library/venv.html>`,
installed Django and created a Django project which will be using
the `djaodjin-signup`_ Django App.

First download and install the latest version of djaodjin-signup into your
Python virtual environment.

.. code-block:: shell

    $ pip install djaodjin-signup


Edit your project settings.py to add signup into the ``INSTALLED_APPS``
and a SIGNUP configuration block

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'signup'
    )

    SIGNUP = {
      'JWT_SECRET_KEY': **secret key to sign JSON Web Tokens**,
    }


The latest versions of django-restframework implement paginators disconnected
from parameters in  views (i.e. no more paginate_by). You will thus need
to define ``PAGE_SIZE`` in your settings.py

.. code-block:: python

    REST_FRAMEWORK = {
        'PAGE_SIZE': 25,
        'DEFAULT_PAGINATION_CLASS':
            'rest_framework.pagination.PageNumberPagination',
    }


Edit your project urls.py to add the djaodjin-signup urls

.. code-block:: python

    urlpatterns += [
        path('api/', include('signup.urls.api.dashboard')),
        path('api/', include('signup.urls.api.auth')),
        path('', include('signup.urls.views.dashboard')),
        path('', include('signup.urls.views.auth')),
    ]

There is no access policies by default on the djaodjin-signup URLs. It is thus
your responsability to add the appropriate decorators to restrict which users
can access the dashboard URLs. A set of common decorators
in Software-as-a-Service setups is provided as part
of `djaodjin-saas Flexible Security Framework`_.

If you are solely interested in authentication and do not require the user
account management pages or APIs, remove the 'signup.urls.*.dashboard'.

.. code-block:: python

    urlpatterns += [
        path('api/', include('signup.urls.api.auth')),
        path('', include('signup.urls.views.auth')),
    ]

If you are building an API server, and serve the authentication UI through
different means (ex: a Single Page Application) remove
the 'signup.urls.views.auth'.

.. code-block:: python

    urlpatterns += [
        path('api/', include('signup.urls.api.auth')),
    ]


.. _djaodjin-signup: https://github.com/djaodjin-signup/
.. _README.md: https://github.com/djaodjin/djaodjin-signup/blob/master/README.md
.. _djaoapp: https://github.com/djaodjin/djaoapp/
.. _djaoapp livedemo: https://livedemo.djaoapp.com/
.. _djaodjin-saas Flexible Security Framework: https://djaodjin-saas.readthedocs.io/en/latest/security.html
.. _Getting started with Django: https://docs.djangoproject.com/en/4.2/intro/
.. _How to load fixtures in a Django project: https://docs.djangoproject.com/en/4.2/topics/db/fixtures/
