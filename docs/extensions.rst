Integration within a multi-app project
======================================

There are two mechanisms to help integrating djaodjin-signup within a project
composed of multiple Django applications.

- Overriding models
- Replacing default functions

``Activity`` can be attached to a specific account. The definition of the
underlying account model is specified by ``ACCOUNT_MODEL`` and serialized
in APIs by an ``ACCOUNT_SERIALIZER``.

If the ``AUTH_USER_MODEL`` (as returned by ``get_user_model``) has been
overridden, ``USER_SERIALIZER`` should be defined and implement
a user model serialization as used in API calls.

.. autodata:: signup.settings.ENCRYPTED_FIELD

.. autodata:: signup.settings.EXTRA_FIELD

.. autodata:: signup.settings.EMAIL_VERIFICATION_BACKEND

.. autodata:: signup.settings.PHONE_VERIFICATION_BACKEND

.. autodata:: signup.settings.PICTURE_STORAGE_CALLABLE

.. autodata:: signup.settings.EXTRA_MIXIN

.. autodata:: signup.settings.SSO_PROVIDERS


Miscellaneous
-------------

.. autodata:: signup.settings.LOGOUT_CLEAR_COOKIES

.. autodata:: signup.settings.NOTIFICATION_TYPE

.. autodata:: signup.settings.NOTIFICATIONS_OPT_OUT

.. autodata:: signup.settings.LANGUAGE_CODE
