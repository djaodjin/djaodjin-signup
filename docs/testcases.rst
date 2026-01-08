Configuration for various use cases
===================================

Disabling authentication and registration
-----------------------------------------

When you disable registration, the default behavior is for active users to be
able to login but otherwise no new visitors to the site will be able
to register.

To disable registration, add the following to your project settings.py:

.. code::

    SIGNUP = {
        'DISABLED_REGISTRATION': True
    }

You can also specify a function that will be called instead. This is useful
if you want to enable registration to users with a work e-mail address
for example. The function should take an `django.http.request.HttpRequest`
instance argument and returns `True` if registration are enabled or `False`
otherwise.

.. code::

    SIGNUP = {
        'DISABLED_REGISTRATION':
            'djaoapp.thread_locals.get_disabled_registration'
    }

When you disable authentication, no users will either be able to login
nor register.

To disable authentication altogether, add the following to your project
settings.py:

.. code::

    SIGNUP = {
        'DISABLED_AUTHENTICATION': True
    }

You can also specify a function that will be called instead. This is useful
if you want to temporarly lock all users out except site administrators.
The function should take an `django.http.request.HttpRequest` instance argument
and returns `True` if registration are enabled or `False` otherwise.

.. code::

    SIGNUP = {
        'DISABLED_AUTHENTICATION':
            'djaoapp.thread_locals.get_disabled_authentication'
    }
