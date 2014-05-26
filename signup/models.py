# Copyright (c) 2014, Djaodjin Inc.
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

from django.db import models
from django.db import transaction
from django.contrib.auth.models import AbstractUser, UserManager
from django.utils.translation import ugettext_lazy as _
from django.utils.timezone import now as datetime_now

from signup import settings

LOGGER = logging.getLogger(__name__)

EMAIL_VERIFICATION_RE = re.compile('^%s$' % settings.EMAIL_VERIFICATION_PAT)

class ActivatedUserManager(UserManager):

    def create_inactive_user(self, email, **kwargs):
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
        username = kwargs.pop('username', None)
        if not username:
            username = email.split('@')[0] \
                + ''.join(random.choice('0123456789') for count in range(3))
        user = self.create_user(username, email=email, **kwargs)

        # Force is_active to True and create an email verification key
        # (see above definition of active user).
        user.is_active = True
        salt = hashlib.sha1(str(random.random())).hexdigest()[:5]
        if isinstance(username, unicode):
            username = username.encode('utf-8')
        user.email_verification_key = hashlib.sha1(salt+username).hexdigest()
        user.save()
        return user
    create_inactive_user = transaction.commit_on_success(create_inactive_user)

    def find_user(self, email_verification_key):
        """
        Find a user based on a verification key but do not activate the user.
        """
        if EMAIL_VERIFICATION_RE.search(email_verification_key):
            try:
                user = self.get(email_verification_key=email_verification_key)
                if not user.email_verification_key_expired():
                    return user
            except self.model.DoesNotExist:
                pass # We return None instead here.
        return None

    def activate_user(self, email_verification_key):
        """
        Activate a user whose email address has been verified.
        """
        user = self.find_user(email_verification_key)
        if user:
            LOGGER.info('user #%d activated through code: %s',
                        user.id, user.email_verification_key)
            user.email_verification_key = self.model.VERIFIED
            user.is_active = True
            user.save()
        return user


class ActivatedUser(AbstractUser):
    """
    A user model that requires activation. We use it to verify
    the email address.
    """
    VERIFIED = "VERIFIED"

    objects = ActivatedUserManager()

    email_verification_key = models.CharField(
        _('email verification key'), max_length=40)

    def email_verification_key_expired(self):
        expiration_date = datetime.timedelta(days=settings.KEY_EXPIRATION)
        return self.email_verification_key == self.VERIFIED or \
               (self.last_login + expiration_date <= datetime_now())
    email_verification_key_expired.boolean = True

    @property
    def has_invalid_password(self):
        return self.password.startswith('!')

    @property
    def is_reachable(self):
        """
        Returns True if the user is reachable by email.
        """
        return self.email_verification_key == ActivatedUser.VERIFIED

    def __unicode__(self):
        return self.username

    class Meta:
        db_table = u'auth_user'
        swappable = 'AUTH_USER_MODEL'
