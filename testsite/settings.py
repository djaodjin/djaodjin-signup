"""
Django settings for testsite project.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.6/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import logging, os, re, sys

from django.contrib.messages import constants as messages
from signup.compat import reverse_lazy

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_DIR = os.getenv('RUN_DIR', os.getcwd())
DB_NAME = os.path.join(RUN_DIR, 'db.sqlite')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
BYPASS_VERIFICATION_KEY_EXPIRED_CHECK = False
JS_FRAMEWORK = 'vuejs'

ALLOWED_HOSTS = []
APPEND_SLASH = False # Django will return a 500 error by default on
                     # `POST /login/.` though that's what bots would do.

FERNET_KEYS = []
SOCIAL_AUTH_SAML_ENABLED_IDPS = {}


def load_config(confpath):
    '''
    Given a path to a file, parse its lines in ini-like format, and then
    set them in the current namespace.
    '''
    # todo: consider using something like ConfigObj for this:
    # http://www.voidspace.org.uk/python/configobj.html
    if os.path.isfile(confpath):
        sys.stderr.write('config loaded from %s\n' % confpath)
        with open(confpath) as conffile:
            line = conffile.readline()
            while line != '':
                if not line.startswith('#'):
                    look = re.match(r'(\w+)\s*=\s*(.*)', line)
                    if look:
                        value = look.group(2) \
                            % {'LOCALSTATEDIR': BASE_DIR + '/var'}
                        # Once Django 1.5 introduced ALLOWED_HOSTS (a tuple
                        # definitely in the site.conf set), we had no choice
                        # other than using eval. The {} are here to restrict
                        # the globals and locals context eval has access to.
                        # pylint: disable=eval-used
                        setattr(sys.modules[__name__],
                            look.group(1).upper(), eval(value, {}, {}))
                line = conffile.readline()
    else:
        sys.stderr.write('warning: config file %s does not exist.\n' % confpath)

load_config(os.path.join(
    os.getenv('TESTSITE_SETTINGS_LOCATION', RUN_DIR), 'credentials'))
load_config(os.path.join(
    os.getenv('TESTSITE_SETTINGS_LOCATION', RUN_DIR), 'site.conf'))

if not hasattr(sys.modules[__name__], "SECRET_KEY"):
    from random import choice
    SECRET_KEY = "".join([choice(
        "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^*-_=+") for i in range(50)])

if os.getenv('BYPASS_VERIFICATION_KEY_EXPIRED_CHECK'):
    BYPASS_VERIFICATION_KEY_EXPIRED_CHECK = (int(os.getenv(
        'BYPASS_VERIFICATION_KEY_EXPIRED_CHECK')) > 0)

SILENCED_SYSTEM_CHECKS = ['captcha.recaptcha_test_key_error']

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_extensions',
    'rest_framework',
    'phonenumber_field',
    'captcha',
    'signup',
    'social_django',
    'rules',
    'testsite'
)

ROOT_URLCONF = 'testsite.urls'
WSGI_APPLICATION = 'testsite.wsgi.application'

MIDDLEWARE = (
    'django.middleware.common.CommonMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'signup.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
)

# Database
# https://docs.djangoproject.com/en/1.6/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DB_NAME,
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'signup.authentication.JWTAuthentication',
        'signup.authentication.APIKeyAuthentication',
        # `rest_framework.authentication.SessionAuthentication` is the last
        # one in the list because it will raise a PermissionDenied if the CSRF
        # is absent.
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PAGINATION_CLASS':
        'rest_framework.pagination.PageNumberPagination',
    'NON_FIELD_ERRORS_KEY': 'detail',
    'ORDERING_PARAM': 'o',
    'PAGE_SIZE': 25,
    'SEARCH_PARAM': 'q',
}


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue'
        },
    },
    'formatters': {
        'simple': {
            'format': 'X X %(levelname)s [%(asctime)s] %(message)s',
            'datefmt': '%d/%b/%Y:%H:%M:%S %z'
        },
    },
    'handlers': {
        'log': {
            'level': 'DEBUG',
            'formatter': 'simple',
            'class':'logging.StreamHandler',
        },
        'db_log': {
            'level': 'DEBUG',
            'formatter': 'simple',
            'filters': ['require_debug_true'],
            'class':'logging.StreamHandler',
        },
    },
    'loggers': {
        'rules': {
            'handlers': [],
            'level': 'INFO',
        },
        'signup': {
            'handlers': [],
            'level': 'INFO',
        },
#        'django.db.backends': {
#           'handlers': ['db_log'],
#           'level': 'DEBUG',
#           'propagate': False
#        },
        # This is the root logger.
        # The level will only be taken into account if the record is not
        # propagated from a child logger.
        #https://docs.python.org/2/library/logging.html#logging.Logger.propagate
        '': {
            'handlers': ['log'],
            'level': 'INFO'
        },
    },
}
if hasattr(sys.modules[__name__], 'LOG_FILE') and LOG_FILE:
    if DEBUG:
        sys.stderr.write("writing log into %s ...\n" % LOG_FILE)
    LOGGING['handlers']['log'].update({
        'class':'logging.handlers.WatchedFileHandler',
        'filename': LOG_FILE
    })


SOCIAL_AUTH_RAISE_EXCEPTIONS = False
SOCIAL_AUTH_LOGIN_ERROR_URL = reverse_lazy('homepage')
SOCIAL_AUTH_GITHUB_SCOPE = ['user:email']
SOCIAL_AUTH_USER_FIELDS = ['username', 'email', 'first_name', 'last_name']
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
#    'social_core.pipeline.social_auth.social_uid',
    'signup.utils.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    # adds the following to the default pipeline because sites offer
    # login by e-mail, which be definition then is unique in `auth_user`.
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
)

AUTHENTICATION_BACKENDS = (
    'social_core.backends.azuread.AzureADOAuth2',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.github.GithubOAuth2',
# SAML is not supported when running on python2.7 because we end up
# with a "Segmentation fault".
#    'social_core.backends.saml.SAMLAuth',
    'signup.backends.auth.UsernameOrEmailPhoneModelBackend',
    'django.contrib.auth.backends.ModelBackend'
)

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': (os.path.join(BASE_DIR, 'testsite', 'templates'),
             os.path.join(BASE_DIR, 'signup', 'templates')),
    'OPTIONS': {
        'builtins': [
            'testsite.templatetags.testsite_tags',
        ],
        'context_processors': [
            'django.contrib.auth.context_processors.auth', # because of admin/
            'django.template.context_processors.request',
            'django.template.context_processors.media',
            'testsite.context_processors.js_framework'
        ],
        'loaders': [
            'django.template.loaders.filesystem.Loader',
            'django.template.loaders.app_directories.Loader'
        ],
    }
}]

# Messages
# --------

MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'
MESSAGE_TAGS = {
    messages.ERROR: 'danger'
}

# Internationalization
# https://docs.djangoproject.com/en/1.6/topics/i18n/

LANGUAGE_CODE = 'en'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
MEDIA_ROOT = os.path.join(BASE_DIR, 'testsite', 'media')
MEDIA_URL = '/media/'
STATIC_URL = '/static/'


ACCOUNT_ACTIVATION_DAYS = 2

# Mail server and accounts for notifications.
# Host, port, TLS for sending email.
EMAIL_HOST = "localhost"
EMAIL_PORT = 1025
EMAIL_USE_TLS = False

# Default email address to use for various automated correspondence from
# the site managers (also django-registration settings)
DEFAULT_FROM_EMAIL = "admin@localhost.localdomain"

# Optional SMTP authentication information for EMAIL_HOST.
EMAIL_HOST_USER = ""
EMAIL_HOST_PASSWORD = ""

LOGIN_URL = reverse_lazy('login')
LOGIN_REDIRECT_URL = '/app/'

# Applications settings

# Debug toolbar and panel
# -----------------------
DEBUG_TOOLBAR_PATCH_SETTINGS = False
DEBUG_TOOLBAR_CONFIG = {
    'JQUERY_URL': '/static/vendor/jquery.js',
    'SHOW_COLLAPSED': True,
    'SHOW_TEMPLATE_CONTEXT': True,
}

SIGNUP = {
    'BYPASS_VERIFICATION_KEY_EXPIRED_CHECK':
        BYPASS_VERIFICATION_KEY_EXPIRED_CHECK,
    'RANDOM_SEQUENCE': getattr(
        sys.modules[__name__], 'SIGNUP_RANDOM_SEQUENCE', []),
#    'REQUIRES_RECAPTCHA': True
}

INTERNAL_IPS = ('127.0.0.1', '::1')

NOCAPTCHA = True
