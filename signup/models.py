# Copyright (c) 2019, Djaodjin Inc.
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
User Model for the signup app
"""
from __future__ import absolute_import
from __future__ import unicode_literals

import datetime, hashlib, logging, random, re

from django.core.exceptions import ValidationError
from django.contrib.auth.models import UserManager
from django.db import models, transaction, IntegrityError
from django.template.defaultfilters import slugify
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.hashers import check_password, make_password

from . import settings, signals
from .backends.mfa import EmailMFABackend
from .compat import User, import_string
from .helpers import datetime_or_now, full_name_natural_split
from .utils import generate_random_slug


LOGGER = logging.getLogger(__name__)
EMAIL_VERIFICATION_RE = re.compile('^%s$' % settings.EMAIL_VERIFICATION_PAT)


def _get_extra_field_class():
    extra_class = settings.EXTRA_FIELD
    if extra_class is None:
        from django.db.models import TextField
        extra_class = TextField
    elif isinstance(extra_class, str):
        extra_class = import_string(extra_class)
    return extra_class


class ActivatedUserManager(UserManager):

    def create_user_from_email(self, email, password=None, **kwargs):
        #pylint:disable=protected-access
        field = self.model._meta.get_field('username')
        max_length = field.max_length
        username = email.split('@')[0]
        try:
            field.run_validators(username)
        except ValidationError:
            username = 'user'
        err = IntegrityError()
        trials = 0
        username_base = username
        while trials < 10:
            try:
                return super(ActivatedUserManager, self).create_user(
                    username, email=email, password=password, **kwargs)
            except IntegrityError as exp:
                err = exp
                if len(username_base) + 4 > max_length:
                    username_base = username_base[:(max_length - 4)]
                username = generate_random_slug(
                    length=len(username_base) + 4, prefix=username_base + '-',
                    allowed_chars='0123456789')
                trials = trials + 1
        raise err

    def create_user(self, username, email=None, password=None, **kwargs):
        """
        Create an inactive user with a default username.

        We have a different notion of an active user than Django does.
        For Django when is_active is False, the user cannot be identified
        and requests fall back to Anonymous. That's a problem because
        we want a user who has given us a name and email address to be
        able to use the site. We only require a password for the second
        login. Our definition of inactive is thus a user that has an invalid
        password.
        """
        with transaction.atomic():
            if not username:
                user = self.create_user_from_email(
                    email, password=password, **kwargs)
            else:
                user = super(ActivatedUserManager, self).create_user(
                    username, email=email, password=password, **kwargs)
            # Force is_active to True and create an email verification key
            # (see above definition of active user).
            Contact.objects.update_or_create_token(user)
            user.is_active = True
            user.save()
            LOGGER.info("'%s %s <%s>' registered with username '%s'",
                user.first_name, user.last_name, user.email, user,
                extra={'event': 'register', 'user': user})
            signals.user_registered.send(sender=__name__, user=user)
        return user


class ContactManager(models.Manager):

    def get_token(self, verification_key):
        if EMAIL_VERIFICATION_RE.search(verification_key):
            try:
                token = self.filter(
                    verification_key=verification_key).select_related(
                    'user').get()
                if not token.verification_key_expired():
                    return token
            except Contact.DoesNotExist:
                pass # We return None instead here.
        return None

    def update_or_create_token(self, user, verification_key=None, reason=None):
        if verification_key is None:
            random_key = str(random.random()).encode('utf-8')
            salt = hashlib.sha1(random_key).hexdigest()[:5]
            verification_key = hashlib.sha1(
                (salt+user.username).encode('utf-8')).hexdigest()
        kwargs = {}
        if hasattr(user, 'email'):
            kwargs.update({'email': user.email})
        defaults = {
#XXX            'slug': user.username,
            'full_name': user.get_full_name(),
            'verification_key': verification_key
        }
        if reason:
            # XXX It is possible a 'reason' field would be a better
            # implementation.
            defaults.update({'extra': reason})

        # XXX The get() needs to be targeted at the write database in order
        # to avoid potential transaction consistency problems.
        try:
            with transaction.atomic():
                # We have to wrap in a transaction.atomic here, otherwise
                # we end-up with a TransactionManager error when Contact.slug
                # already exists in db and we generate new one.
                token = self.get(user=user, **kwargs)
                if token.verification_key_expired():
                    # In case we sent multiple activate links in a short
                    # period, we want to use the same `verification_key`
                    # so users can click on any e-mail link.
                    token.verification_key = verification_key
                # We are about to send a link that expires so better update
                # date of creation in case the `Contact` for that `User`
                # was not created recently.
                token.created_at = datetime_or_now()
                # XXX It is possible a 'reason' field would be a better
                # implementation.
                token.extra = reason
                token.save()
                return token, False
        except self.model.DoesNotExist:
            kwargs.update(defaults)
        return self.create(user=user, **kwargs), True

    def find_user(self, verification_key):
        """
        Find a user based on a verification key but do not activate the user.
        """
        token = self.get_token(verification_key=verification_key)
        return token if token else None

    def activate_user(self, verification_key, username=None, password=None,
                      first_name=None, last_name=None):
        """
        Activate a user whose email address has been verified.
        """
        #pylint:disable=too-many-arguments
        try:
            token = self.get_token(verification_key=verification_key)
            if token:
                LOGGER.info('user %s activated through code: %s',
                    token.user, token.verification_key,
                    extra={'event': 'activate', 'username': token.user.username,
                        'email_verification_key': token.verification_key})
                with transaction.atomic():
                    token.verification_key = Contact.VERIFIED
                    token.user.is_active = True
                    if username:
                        token.user.username = username
                    if password:
                        token.user.set_password(password)
                    if first_name:
                        token.user.first_name = first_name
                    if last_name:
                        token.user.last_name = last_name
                    token.user.save()
                    token.save()
                return token.user
        except Contact.DoesNotExist:
            pass # We return None instead here.
        return None

    def unverified_for_user(self, user):
        return self.filter(user=user).exclude(verification_key=Contact.VERIFIED)

    def is_reachable(self, user):
        """
        Returns True if the user is reachable by email.
        """
        return self.filter(user=user,
            verification_key=Contact.VERIFIED).exists()


@python_2_unicode_compatible
class Contact(models.Model):
    """
    Used in workflow to verify the email address of a ``User``.
    """
    NO_MFA = 0
    EMAIL_BACKEND = 1

    MFA_BACKEND_TYPE = (
        (NO_MFA, "password only"),
        (EMAIL_BACKEND, "send one-time authentication code through email"),
    )

    VERIFIED = "VERIFIED"

    objects = ContactManager()

    slug = models.SlugField(unique=True,
        help_text=_("Unique identifier shown in the URL bar, effectively"\
            " the username for profiles with login credentials."))
    created_at = models.DateTimeField(auto_now_add=True,
        help_text=_("Date/time of creation (in ISO format)"))
    email = models.EmailField(_("E-mail address"),
        help_text=_("E-mail address for the contact"))
    full_name = models.CharField(_("Full name"), max_length=60, blank=True,
        help_text=_("Full name for the contact (effectively first name"\
        " followed by last name)"))
    nick_name = models.CharField(_("Nick name"), max_length=60, blank=True,
        help_text=_("Short casual name used to address the contact"))
    # 2083 number is used because it is a safe option to choose based
    # on some older browsers behavior
    # https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=4&cad=rja&uact=8&ved=2ahUKEwi2hbjPwIPgAhULXCsKHQ-lAj4QFjADegQIBhAL&url=https%3A%2F%2Fstackoverflow.com%2Fquestions%2F417142%2Fwhat-is-the-maximum-length-of-a-url-in-different-browsers&usg=AOvVaw0QgMo_L7jjK0YsXchrJgOQ
    picture = models.URLField(_("URL to a profile picture"), max_length=2083,
        null=True, blank=True,
        help_text=_("Profile picture"))
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
        null=True, on_delete=models.CASCADE, related_name='contact')
    verification_key = models.CharField(_("Verification key"), max_length=40)
    mfa_backend = models.PositiveSmallIntegerField(
        choices=MFA_BACKEND_TYPE, default=NO_MFA,
        help_text=_("Backend to use for multi-factor authentication"))
    mfa_priv_key = models.IntegerField(
        _("One-time authentication code"), null=True)
    mfa_nb_attempts = models.IntegerField(
        _("Number of attempts to pass the MFA code"), default=0)
    extra = _get_extra_field_class()(null=True,
        help_text=_("Extra meta data (can be stringify JSON)"))

    def __str__(self):
        return self.slug

    @property
    def username(self):
        return self.slug

    @property
    def printable_name(self):
        if self.nick_name:
            return self.nick_name
        if self.full_name:
            # pylint:disable=unused-variable
            first_name, mid_name, last_name = full_name_natural_split(
                self.full_name)
            return first_name
        return self.username

    def get_mfa_backend(self):
        if self.mfa_backend == self.EMAIL_BACKEND:
            return EmailMFABackend()
        return None

    def create_mfa_token(self):
        return self.get_mfa_backend().create_token(self)

    def clear_mfa_token(self):
        self.mfa_priv_key = None
        self.mfa_nb_attempts = 0
        self.save()

    def save(self, force_insert=False, force_update=False,
             using=None, update_fields=None):
        if self.slug: # serializer will set created slug to '' instead of None.
            return super(Contact, self).save(
                force_insert=force_insert, force_update=force_update,
                using=using, update_fields=update_fields)
        max_length = self._meta.get_field('slug').max_length
        slug_base = (self.user.username
            if self.user else slugify(self.email.split('@')[0]))
        if not slug_base:
            # email might be empty
            slug_base = generate_random_slug(15)
        elif len(slug_base) > max_length:
            slug_base = slug_base[:max_length]
        self.slug = slug_base
        for idx in range(1, 10): #pylint:disable=unused-variable
            try:
                with transaction.atomic():
                    if self.user:
                        # pylint:disable=unused-variable
                        first_name, mid_name, last_name = \
                            full_name_natural_split(self.full_name)
                        if (self.user.first_name != first_name or
                            self.user.last_name != last_name or
                            self.user.email != self.email):
                            self.user.first_name = first_name
                            self.user.last_name = last_name
                            self.user.email = self.email
                            self.user.save()
                    return super(Contact, self).save(
                        force_insert=force_insert, force_update=force_update,
                        using=using, update_fields=update_fields)
            except IntegrityError as err:
                if 'uniq' not in str(err).lower():
                    raise
                if len(slug_base) + 8 > max_length:
                    slug_base = slug_base[:(max_length - 8)]
                self.slug = generate_random_slug(
                    length=len(slug_base) + 8, prefix=slug_base + '-')
        raise ValidationError({'detail':
            _("Unable to create a unique URL slug with a base of '%s'")
                % slug_base})

    def verification_key_expired(self):
        expiration_date = datetime.timedelta(days=settings.KEY_EXPIRATION)
        start_at = self.created_at
        return self.verification_key == self.VERIFIED or \
               (start_at + expiration_date <= datetime_or_now())
    verification_key_expired.boolean = True


@python_2_unicode_compatible
class Activity(models.Model):
    """
    Activity associated to a contact.
    """
    created_at = models.DateTimeField(auto_now_add=True,
        help_text=_("Date/time of creation (in ISO format)"))
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL,
        null=True, on_delete=models.SET_NULL,
        help_text=_("User that created the activity"))
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE)
    text = models.TextField(blank=True,
        help_text=_("Free form text description of the activity"))
    account = models.ForeignKey(
        settings.ACCOUNT_MODEL, null=True, on_delete=models.CASCADE,
        related_name='activities',
        help_text=_("Account the activity is associated to"))
    extra = _get_extra_field_class()(null=True)

    def __str__(self):
        return "%s-%s" % (self.created_at, self.created_by)


@python_2_unicode_compatible
class Notification(models.Model):
    """
    Notification model, represent a single notification type,
    has a M2M relation with users, which allows to store a user's
    email notifications preferences
    """
    slug = models.SlugField(unique=True,
        help_text=_("Unique identifier shown in the URL bar"))
    title = models.CharField(max_length=100, blank=True)
    description = models.TextField(null=True, blank=True)
    users = models.ManyToManyField(settings.AUTH_USER_MODEL,
        related_name='notifications')
    extra = _get_extra_field_class()(null=True)

    def __str__(self):
        return self.slug


@python_2_unicode_compatible
class Credentials(models.Model):
    """
    API Credentials to authenticate a `User`.
    """
    API_PUB_KEY_LENGTH = 32
    API_PRIV_KEY_LENGTH = 32

    api_pub_key = models.SlugField(unique=True, max_length=API_PUB_KEY_LENGTH)
    api_priv_key = models.CharField(max_length=128)
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE, related_name='credentials')

    def __str__(self):
        return self.api_pub_key

    def set_priv_key(self, api_priv_key):
        self.api_priv_key = make_password(api_priv_key)
        self._api_priv_key = api_priv_key

    def check_priv_key(self, raw_api_priv_key):
        """
        Return a boolean of whether the raw api_priv_key was correct. Handles
        hashing formats behind the scenes.
        """
        def setter(raw_api_priv_key):
            self.set_priv_key(raw_api_priv_key)
            # Password hash upgrades shouldn't be considered password changes.
            self._api_priv_key = None
            self.save(update_fields=["api_priv_key"])
        return check_password(raw_api_priv_key, self.api_priv_key, setter)


# Hack to install our create_user method.
User.objects = ActivatedUserManager()
User.objects.model = User
