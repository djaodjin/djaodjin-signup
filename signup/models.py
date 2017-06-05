# Copyright (c) 2017, Djaodjin Inc.
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

import datetime, hashlib, logging, random, re

from django.core.exceptions import ValidationError
from django.contrib.auth.models import UserManager
from django.db import models, transaction, IntegrityError
from django.utils.decorators import method_decorator
from django.utils.encoding import python_2_unicode_compatible
from django.utils.timezone import now as datetime_now
from django.utils.translation import ugettext_lazy as _

from signup import settings, signals

LOGGER = logging.getLogger(__name__)

EMAIL_VERIFICATION_RE = re.compile('^%s$' % settings.EMAIL_VERIFICATION_PAT)

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
                suffix = '-%s' % ''.join(
                    random.choice('0123456789') for count in range(3))
                if len(username_base) + len(suffix) > max_length:
                    username = '%s%s' % (
                        username_base[:(max_length - len(suffix))],
                        suffix)
                else:
                    username = '%s%s' % (username_base, suffix)
                trials = trials + 1
        raise err

    @method_decorator(transaction.atomic)
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
        if not password and not username:
            user = self.create_user_from_email(
                email, password=password, **kwargs)
        else:
            user = super(ActivatedUserManager, self).create_user(
                username, email=email, password=password, **kwargs)
        # Force is_active to True and create an email verification key
        # (see above definition of active user).
        EmailContact.objects.get_or_create_token(user)
        user.is_active = True
        user.save()
        LOGGER.info("'%s %s <%s>' registered with username '%s'",
            user.first_name, user.last_name, user.email, user,
            extra={'event': 'register', 'user': user})
        signals.user_registered.send(sender=__name__, user=user)
        return user


class EmailContactManager(models.Manager):

    def _get_token(self, verification_key):
        return self.get(verification_key=verification_key)

    def get_or_create_token(self, user, verification_key=None):
        if verification_key is None:
            random_key = str(random.random()).encode('utf-8')
            salt = hashlib.sha1(random_key).hexdigest()[:5]
            verification_key = hashlib.sha1(
                (salt+user.username).encode('utf-8')).hexdigest()
        return self.get_or_create(user=user, verification_key=verification_key)

    def find_user(self, verification_key):
        """
        Find a user based on a verification key but do not activate the user.
        """
        if EMAIL_VERIFICATION_RE.search(verification_key):
            try:
                token = self._get_token(
                    verification_key=verification_key)
                if not token.verification_key_expired():
                    return token.user
            except EmailContact.DoesNotExist:
                pass # We return None instead here.
        return None

    def activate_user(self, verification_key):
        """
        Activate a user whose email address has been verified.
        """
        try:
            token = self._get_token(
                verification_key=verification_key)
            if not token.verification_key_expired():
                LOGGER.info('user %s activated through code: %s',
                    token.user, token.verification_key,
                    extra={'event': 'activate', 'username': token.user.username,
                        'email_verification_key': token.verification_key})
                with transaction.atomic():
                    token.verification_key = EmailContact.VERIFIED
                    token.user.is_active = True
                    token.user.save()
                    token.save()
                return token.user
        except EmailContact.DoesNotExist:
            pass # We return None instead here.
        return None

    def unverified_for_user(self, user):
        return self.filter(user=user).exclude(
            verification_key=EmailContact.VERIFIED)

    def is_reachable(self, user):
        """
        Returns True if the user is reachable by email.
        """
        return self.filter(user=user,
            verification_key=EmailContact.VERIFIED).exists()


@python_2_unicode_compatible
class EmailContact(models.Model):
    """
    Used in workflow to verify the email address of a ``User``.
    """

    VERIFIED = "VERIFIED"

    objects = EmailContactManager()

    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    verification_key = models.CharField(
        _('email verification key'), max_length=40)
    extra = settings.get_extra_field_class()(null=True)

    def __str__(self):
        return u"%s-%s" % (self.user.username, self.verification_key)

    def verification_key_expired(self):
        expiration_date = datetime.timedelta(days=settings.KEY_EXPIRATION)
        start_at = self.created_at
        return self.verification_key == self.VERIFIED or \
               (start_at + expiration_date <= datetime_now())
    verification_key_expired.boolean = True
