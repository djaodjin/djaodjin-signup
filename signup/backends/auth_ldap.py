# Copyright (c) 2018, Djaodjin Inc.
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
Optional Backend to authenticate through a LDAP server.

Install preprequisites before using:

    $ pip install python-ldap==3.1.0

settings.py:

AUTHENTICATION_BACKENDS = (
    'signup.backends.auth_ldap.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend'
)
"""
import logging

import ldap  # pip install python-ldap==3.1.0
from django.utils.encoding import force_text, force_bytes

from .. import settings
from ..compat import User


LOGGER = logging.getLogger(__name__)


class LDAPUser(object):

    def __init__(self, backend, db_user=None):
        self.backend = backend
        self._dbuser = db_user

    def set_password(self, raw_password, bind_password=None):
        bind_dn = settings.USER_SEARCH_DN % force_text(self.db_user.username)
        try:
            ldap_connection = ldap.initialize(
                settings.AUTH_LDAP_SERVER_URI, bytes_mode=False)
            ldap_connection.simple_bind_s(
                force_text(bind_dn),
                force_text(bind_password))
            ldap_connection.passwd_s(
                force_text(bind_dn),
                oldpw=force_text(bind_password),
                newpw=force_text(raw_password))
        finally:
            ldap_connection.unbind_s()

    def set_pubkey(self, pubkey, bind_password=None):
        bind_dn = settings.USER_SEARCH_DN % force_text(self.db_user.username)
        try:
            ldap_connection = ldap.initialize(
                settings.AUTH_LDAP_SERVER_URI, bytes_mode=False)
            ldap_connection.simple_bind_s(
                force_text(bind_dn),
                force_text(bind_password))
            ldap_connection.modify_s(force_text(bind_dn),
                [(ldap.MOD_REPLACE, 'sshPublicKey',
                  [force_bytes(pubkey)])])
        finally:
            ldap_connection.unbind_s()


class LDAPBackend(object):
    """
    Backend to authenticate a user through a LDAP server.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        #pylint:disable=unused-argument
        user = None
        bind_dn = settings.USER_SEARCH_DN % force_text(username)
        try:
            ldap_connection = ldap.initialize(
                settings.AUTH_LDAP_SERVER_URI, bytes_mode=False)
            ldap_connection.simple_bind_s(
                force_text(bind_dn), force_text(password))

            defaults = {}
            #pylint:disable=protected-access
            db_user, created = User._default_manager.get_or_create(**{
                User.USERNAME_FIELD: username,
                'defaults': defaults,
            })
            if created:
                LOGGER.debug("created user '%s' in database.", username)
            user = LDAPUser(self, db_user=db_user)
        finally:
            ldap_connection.unbind_s()

        return user

    def get_user(self, user_id):#pylint:disable=no-self-use
        try:
            return LDAPUser(self, db_user=User.objects.get(pk=user_id))
        except User.DoesNotExist:
            return None
