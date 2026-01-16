Authentication workflow
=======================

Login with username, e-mail, or phone. Recover forgotten password. One-Time
Passwords. Single Sign-On. Cookies and JWT...

Authentication workflows can quickly spiral out of control. None-the-less
these workflows are particularly important because they transition HTTP
requests from anonymous visitors to authenticated users.

The security requirements together with the complexity, and the simple
insight of a user asking "Do I have an account on this Website?", lead
us to redesign authentication around a single flexible workflow.

+-------------------------------------+----------------------------------------+
|  Auth pipeline steps                | Configuration                          |
+=====================================+========================================+
| Enter the authentication pipeline                                            |
|  ``POST /login/`` or ``POST /api/auth``                                      |
+-------------------------------------+----------------------------------------+
| Generic HTTP Rate-limiter                                                    |
|   This rate-limiter is intended to prevent brute-force attempts. It is       |
|   generally implemented in the gateway and out-of-scope of this project.     |
+-------------------------------------+----------------------------------------+
| Bot prevention                      |                                        |
|   - no extra characters on URL path |                                        |
|   - validate fields through regex   |                                        |
|   - optional Captcha                |  ``settings.REQUIRES_RECAPTCHA``       |
+-------------------------------------+----------------------------------------+
|  Find candidate ``User``            |                                        |
+-------------------------------------+----------------------------------------+
| Check if auth is disabled for       |                                        |
| ``user``, or auth disabled globally.| ``settings.DISABLED_AUTHENTICATION``   |
+-------------------------------------+----------------------------------------+
| Auth rate-limiter based on ``user`` | ``settings.LOGIN_THROTTLE``            |
+-------------------------------------+----------------------------------------+
| Redirects if ``email`` requires SSO | row in ``DelegateAuth`` table          |
+-------------------------------------+----------------------------------------+
| Interrupts pipeline if we need      | ``settings.PHONE_VERIFICATION_BACKEND``|
| a verification code for the phone   | ``settings.PHONE_DYNAMIC_VALIDATOR``   |
| number, and we do not have it.      | ``settings.VERIFIED_LIFETIME``         |
|                                     | ``Contact.phone_verification_required``|
+-------------------------------------+----------------------------------------+
| Interrupts pipeline if we need      | ``settings.EMAIL_VERIFICATION_BACKEND``|
| a verification code for the email   | ``settings.EMAIL_DYNAMIC_VALIDATOR``   |
| address, and we do not have it.     | ``settings.VERIFIED_LIFETIME``         |
|                                     | ``Contact.email_verification_required``|
+-------------------------------------+----------------------------------------+
| Check the one-time code on record   | ``settings.SKIP_VERIFICATION_CHECK``   |
| for the phone number matches the one| ``settings.VERIFICATION_LIFETIME``     |
| provided as input.                  |                                        |
+-------------------------------------+----------------------------------------+
| Check the one-time code on record   | ``settings.SKIP_VERIFICATION_CHECK``   |
| for the email address matches       | ``settings.VERIFICATION_LIFETIME``     |
| the one provided as input.          |                                        |
+-------------------------------------+----------------------------------------+
| Check the password for the ``user`` |                                        |
| matches the one provided as input.  |                                        |
+-------------------------------------+----------------------------------------+
| Check the OTP code for the ``user`` | row in ``OTPGenerator`` table          |
| matches the one provided as input.  |     ``settings.MFA_MAX_ATTEMPTS``      |
+-------------------------------------+----------------------------------------+
| If we still don't have an authenticated user by this point, we will recover  |
| an existing account or create a new one.                                     |
+-------------------------------------+----------------------------------------+
| Additional checks on input data     | Django ``AUTH_PASSWORD_VALIDATORS``    |
+-------------------------------------+----------------------------------------+
| Recover and update existing user    | ``settings.DISABLED_USER_UPDATE``      |
+-------------------------------------+----------------------------------------+
| Create a new user                   | ``settings.DISABLED_REGISTRATION``     |
+-------------------------------------+----------------------------------------+
| Create an authenticated session for the user.                                |
+-------------------------------------+----------------------------------------+

Multi-factor authentication
---------------------------

The :doc:`authentication workflow<auth-workflows>` will authenticate a user
with either a password, verified email address, or verified phone number
(when a ``settings.PHONE_VERIFICATION_BACKEND`` is set).

To enable OTP as a second factor for a user, you need to create an
``OTPGenerator`` instance. This can be done by passing ``"otp_enabled": true``
when calling the ``OTPChangeAPIView`` API endpoint.

The ``otp_generator.priv_key`` field contains the key used to generate an OTP
at a specified time. The key can be used on the command line with a tool
like *oathtool* to generate a one-time code. Example:

    /opt/local/bin/oathtool --totp -b *priv_key*

Or the key can be imported into an Authenticator App. The Vue component
``'user-update-otp'`` in `djaodjin-signup-vue.js`_ uses ``QRCode`` to generate
a QR code of the OTP key that Google Authenticator recognizes.


Configuring authentication pipeline
-----------------------------------

Bot prevention
~~~~~~~~~~~~~~

.. autodata:: signup.settings.EMAIL_DYNAMIC_VALIDATOR

.. autodata:: signup.settings.PHONE_DYNAMIC_VALIDATOR

.. autodata:: signup.settings.LOGIN_THROTTLE


On/Off Toggles
~~~~~~~~~~~~~~

.. autodata:: signup.settings.DISABLED_AUTHENTICATION

.. autodata:: signup.settings.DISABLED_REGISTRATION

.. autodata:: signup.settings.DISABLED_USER_UPDATE

.. autodata:: signup.settings.MFA_MAX_ATTEMPTS

.. autodata:: signup.settings.DISABLED_VERIFY_EMAIL_ON_REGISTRATION

.. autodata:: signup.settings.DISABLED_VERIFY_PHONE_ON_REGISTRATION

.. autodata:: signup.settings.REQUIRES_RECAPTCHA

.. autodata:: signup.settings.USE_VERIFICATION_LINKS

.. autodata:: signup.settings.VERIFICATION_LIFETIME

.. autodata:: signup.settings.VERIFIED_LIFETIME


Cybersecurity policies
----------------------

.. autodata:: signup.settings.PASSWORD_MIN_LENGTH

.. autodata:: signup.settings.USER_API_KEY_LIFETIME

.. autodata:: signup.settings.USER_OTP_REQUIRED


Debugging
---------

.. autodata:: signup.settings.RANDOM_SEQUENCE

.. autodata:: signup.settings.SKIP_VERIFICATION_CHECK


.. _djaodjin-signup-vue.js: https://github.com/djaodjin/djaodjin-signup/blob/main/signup/static/js/djaodjin-signup-vue.js
