# Copyright (c) 2026, Djaodjin Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Convenience module for access of signup app settings, which enforces
default settings when the main settings module does not contain
the appropriate settings.
"""
import datetime
from django.conf import settings

_DEFAULT_ENCRYPTED_FIELD = 'fernet_fields.EncryptedCharField'

_SETTINGS = {
    'ACCOUNT_MODEL': getattr(settings, 'AUTH_USER_MODEL', None),
    'ACCOUNT_SERIALIZER': 'signup.serializers_overrides.UserSerializer',
    'AUTH_USER_MODEL': getattr(settings, 'AUTH_USER_MODEL'),
    'AWS_EXTERNAL_ID': "",
    'AWS_REGION': getattr(settings, 'AWS_REGION', None),
    'AWS_UPLOAD_ROLE': None,
    'SKIP_VERIFICATION_CHECK': False,
    'DEFAULT_FROM_EMAIL': getattr(settings, 'DEFAULT_FROM_EMAIL'),
    'DISABLED_AUTHENTICATION': False,
    'DISABLED_REGISTRATION': False,
    'DISABLED_USER_UPDATE': False,
    'DISABLED_VERIFY_EMAIL_ON_REGISTRATION': False,
    'DISABLED_VERIFY_PHONE_ON_REGISTRATION': False,
    'EMAIL_DYNAMIC_VALIDATOR': None,
    'EMAIL_VERIFICATION_BACKEND':
        'signup.backends.email_verification.base.EmailVerificationBackend',
    'ENCRYPTED_FIELD': _DEFAULT_ENCRYPTED_FIELD,
    'EXTRA_FIELD': None,
    'EXTRA_MIXIN': object,
    'JWT_ALGORITHM': 'HS256',
    'JWT_SECRET_KEY': getattr(settings, 'SECRET_KEY'),
    'LDAP': {
        'SERVER_URI': None,
        'USER_SEARCH_DN': None
    },
    'LOGIN_THROTTLE': None,
    'LOGOUT_CLEAR_COOKIES' : None,
    'MFA_MAX_ATTEMPTS': 3,
    'NOTIFICATION_TYPE': tuple([]),
    'NOTIFICATIONS_OPT_OUT': True,
    'PASSWORD_MIN_LENGTH': 10,
    'PICTURE_STORAGE_CALLABLE': None,
    'PHONE_DYNAMIC_VALIDATOR': None,
    'PHONE_VERIFICATION_BACKEND': None,
    'RANDOM_SEQUENCE': [],
    'REQUIRES_RECAPTCHA': False,
    'SEARCH_FIELDS_PARAM': 'q_f',
    'SSO_PROVIDERS': {
        'azuread-oauth2': {'name': 'Microsoft'},
        'github': {'name': 'GitHub'},
        'google-oauth2': {'name': 'Google'},
    },
    'USE_VERIFICATION_LINKS': False,
    'USER_CONTACT_CALLABLE': None,  # XXX deprecated?
    'USER_OTP_REQUIRED': None,
    'USER_SERIALIZER': 'signup.serializers_overrides.UserSerializer',
    'USER_API_KEY_LIFETIME': None, # ex: `datetime.timedelta(days=365)`
    'VERIFICATION_LIFETIME': datetime.timedelta(hours=1),
    'VERIFIED_LIFETIME': None # ex: `datetime.timedelta(days=365)`
}
_SETTINGS.update(getattr(settings, 'SIGNUP', {}))

#: specifies the model that stores profile accounts linked to ``Activity``
ACCOUNT_MODEL = _SETTINGS.get('ACCOUNT_MODEL')

#: specifies the serializer for ``ACCOUNT_MODEL``
ACCOUNT_SERIALIZER = _SETTINGS.get('ACCOUNT_SERIALIZER')

AUTH_USER_MODEL = _SETTINGS.get('AUTH_USER_MODEL')
USER_SERIALIZER = _SETTINGS.get('USER_SERIALIZER')

#: specifies the Django class to use for encrypted fields in a model
#: Keys (ex: ``OTPGenerator.priv_key``) are best stored encrypted
#: in the database.
#: This setting defaults to ``fernet_fields.EncryptedCharField``.
ENCRYPTED_FIELD = _SETTINGS.get('ENCRYPTED_FIELD')

#: In the circumstances where you want to leverage postgresql JSON fields
#: for example, you can override the Django class used for ``extra`` fields
#: in the models defined in this app.
#: This setting defaults to ``models.TextField``.
EXTRA_FIELD = _SETTINGS.get('EXTRA_FIELD')

#: This setting enables a project to integrate the ``View``s of multiple apps
#: into a single class hierarchy. This is useful when you are building
#: a dashboard with links in a sidebar menu that are `reverse` from different
#: Django apps (see djaoapp for an example of user).
#: This setting defaults to ``object``.
EXTRA_MIXIN = _SETTINGS.get('EXTRA_MIXIN')

#: Backend class used to e-mail verification codes
#: This setting defaults to
#: ``signup.backends.email_verification.base.EmailVerificationBackend``.
EMAIL_VERIFICATION_BACKEND = _SETTINGS.get('EMAIL_VERIFICATION_BACKEND')

#: Backend class used to text verification codes to a phone number
#: This setting defaults to ``None``, disabling phone verification.
PHONE_VERIFICATION_BACKEND = _SETTINGS.get('PHONE_VERIFICATION_BACKEND')

#: A callable function which returns a `Storage` object that will be used
#: to upload a contact picture
PICTURE_STORAGE_CALLABLE = _SETTINGS.get('PICTURE_STORAGE_CALLABLE')

#: A dictionnary of SSO providers that are enabled on the site
SSO_PROVIDERS = _SETTINGS.get('SSO_PROVIDERS')


# Bot prevention
# --------------

#: A callable function which is passed an email address and that returns `False`
#: when the email suspiciously looks like it belongs to a bot.
EMAIL_DYNAMIC_VALIDATOR = _SETTINGS.get('EMAIL_DYNAMIC_VALIDATOR')

#: A callable function which is passed a phone number and that returns `False`
#: when the phone suspiciously looks like it belongs to a bot.
PHONE_DYNAMIC_VALIDATOR = _SETTINGS.get('PHONE_DYNAMIC_VALIDATOR')

#: A callable function, which is passed a triplet (request, view, user), and
#: that throttles the HTTP request when there are too many attempts for that
#: particular user to login.
LOGIN_THROTTLE = _SETTINGS.get('LOGIN_THROTTLE')


# Configuring authentication pipeline
# -----------------------------------

#: When `True`, authentication on the site is totally locked down.
#: A page will be displayed on login, registration, etc. No new
#: authentication can be performed.
DISABLED_AUTHENTICATION = _SETTINGS.get('DISABLED_AUTHENTICATION')

#: When `True`, registration of new users on the site is disabled.
#: This setting can either be a boolean value or a callable function.
DISABLED_REGISTRATION = _SETTINGS.get('DISABLED_REGISTRATION')

#: When `True`, modifications of user fields is disabled. This will
#: also disable registration of new users.
#: This setting is useful to provide interactive demos publicly accessible.
DISABLED_USER_UPDATE = _SETTINGS.get('DISABLED_USER_UPDATE')

#: Secret key used to sign JSON Web Tokens
JWT_SECRET_KEY = _SETTINGS.get('JWT_SECRET_KEY')

#: Algorithm used to sign JSON Web Tokens
JWT_ALGORITHM = _SETTINGS.get('JWT_ALGORITHM')

# A ``datetime.timedelta`` that specifies how long a verification link
# or verification code is valid after it was created. When `None`,
# verification links and codes never expire.
VERIFICATION_LIFETIME = _SETTINGS.get('VERIFICATION_LIFETIME')

#: Maximum number of attempts a user has to verify a one-time code
#: before being kicked out.
MFA_MAX_ATTEMPTS = _SETTINGS.get('MFA_MAX_ATTEMPTS')

#: When `True`, verify email before allowing registration to proceed.
DISABLED_VERIFY_EMAIL_ON_REGISTRATION = _SETTINGS.get(
    'DISABLED_VERIFY_EMAIL_ON_REGISTRATION')

#: When `True`, verify phone before allowing registration to proceed.
DISABLED_VERIFY_PHONE_ON_REGISTRATION = _SETTINGS.get(
    'DISABLED_VERIFY_PHONE_ON_REGISTRATION')

#: When `True`, validates ReCaptcha before continuing with authentication.
REQUIRES_RECAPTCHA = _SETTINGS.get('REQUIRES_RECAPTCHA')

#: When `True`, email verification links instead of verification codes.
USE_VERIFICATION_LINKS = _SETTINGS.get('USE_VERIFICATION_LINKS')

#: A ``datetime.timedelta`` that specifies how long before an email address
#: or phone number needs to be verified again. When `None`, email addresses
#: and phone numbers need to be verified only once.
VERIFIED_LIFETIME = _SETTINGS.get('VERIFIED_LIFETIME')


# Cybersecurity policies
# ----------------------

#: Minimum password length
PASSWORD_MIN_LENGTH = _SETTINGS.get('PASSWORD_MIN_LENGTH')

#: Default number of days before an API Key expires
#: A ``datetime.timedelta`` that specifies how long a newly created API Key
#: is valid for. When `None`, API keys never expire.
USER_API_KEY_LIFETIME = _SETTINGS.get('USER_API_KEY_LIFETIME')

#: When `True` user is required to setup OTP.
USER_OTP_REQUIRED = _SETTINGS.get('USER_OTP_REQUIRED')


# Debugging
# ---------

#: When `True`, skips the expiration of verification code and links.
#: This setting is only intended to simplify automated testing and should
#: never be set to `True` in a production environment.
SKIP_VERIFICATION_CHECK = _SETTINGS.get('SKIP_VERIFICATION_CHECK')

#: List to fetch from when a random slug is required.
#: This setting is only intended to simplify automated testing and should
#: never be set to `True` in a production environment.
RANDOM_SEQUENCE = _SETTINGS.get('RANDOM_SEQUENCE')

# Miscellaneous
# -------------

#: List of HTTP Cookie to clear when a user logs out
LOGOUT_CLEAR_COOKIES = _SETTINGS.get('LOGOUT_CLEAR_COOKIES')

#: List of notifications that a user can opt in or out of.
NOTIFICATION_TYPE = _SETTINGS.get('NOTIFICATION_TYPE')

#: `True` if the database records opt-outs, and `False` if the database
#: records opt-ins.
NOTIFICATIONS_OPT_OUT = _SETTINGS.get('NOTIFICATIONS_OPT_OUT')

#: The default language code when registering a new user.
LANGUAGE_CODE = getattr(settings, 'LANGUAGE_CODE')

#: region used to create STS temporary credentials
AWS_REGION = _SETTINGS.get('AWS_REGION')

#: role to assume in order to load directly from browser to S3
AWS_UPLOAD_ROLE = _SETTINGS.get('AWS_UPLOAD_ROLE')
AWS_EXTERNAL_ID = _SETTINGS.get('AWS_EXTERNAL_ID')
LDAP_SERVER_URI = _SETTINGS.get('LDAP', {}).get('SERVER_URI', None)
LDAP_USER_SEARCH_DN = _SETTINGS.get('LDAP', {}).get('USER_SEARCH_DN', None)

DEFAULT_FROM_EMAIL = _SETTINGS.get('DEFAULT_FROM_EMAIL')
LOGIN_URL = getattr(settings, 'LOGIN_URL')
LOGIN_REDIRECT_URL = getattr(settings, 'LOGIN_REDIRECT_URL')
SEARCH_FIELDS_PARAM = _SETTINGS.get('SEARCH_FIELDS_PARAM')

# XXX Not used anymore?
USER_CONTACT_CALLABLE = _SETTINGS.get('USER_CONTACT_CALLABLE')

EMAIL_VERIFICATION_PAT = r'[a-f0-9]{40}'
FULL_NAME_PAT = r"^([^\W\d_]|[ \.\'\-])+$"
USERNAME_PAT = r"[-a-zA-Z0-9_]+"

RANDOM_SEQUENCE_IDX = 0
