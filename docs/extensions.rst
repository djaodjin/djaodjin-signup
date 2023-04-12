Integration within a multi-app project
======================================

There are two mechanisms to help integrating djaodjin-signup within a project
composed of multiple Django applications.

- Overriding models
- Replacing default functions

Overriding models
-----------------

``Activity`` can be attached to a specific account. The definition of the
underlying account model is specified by ``ACCOUNT_MODEL`` and serialized
in APIs by an ``ACCOUNT_SERIALIZER``.

If the ``AUTH_USER_MODEL`` (as returned by ``get_user_model``) has been
overridden, ``USER_SERIALIZER`` should be defined and implement
a user model serialization as used in API calls.


Replacing default functions
---------------------------

.. autodata:: signup.settings.DISABLED_AUTHENTICATION

.. autodata:: signup.settings.DISABLED_REGISTRATION

.. autodata:: signup.settings.EMAIL_DYNAMIC_VALIDATOR

.. autodata:: signup.settings.LOGIN_THROTTLE

.. autodata:: signup.settings.PICTURE_STORAGE_CALLABLE


