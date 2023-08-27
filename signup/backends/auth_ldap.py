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

from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.utils.encoding import force_bytes

from .. import settings
from ..compat import force_str

LOGGER = logging.getLogger(__name__)

try:
    import ldap  # pip install python-ldap>=3.1.0
except ImportError:
    LOGGER.warning("ldap module was not imported. LDAP login is disabled.")


# Implementation Note:
# `django.db.models.fields.related_lookups.get_normalized_value` will check
# our model is an instance of `django.db.models.Model` so we might as well
# make it an instance of `AbstractBaseUser`.
# That works until queries are built by the ORM...

def _get_bind_dn(user):
    return settings.LDAP_USER_SEARCH_DN % {'user': force_str(user)}


def is_ldap_user(user):
    found = False
    if ('signup.backends.auth_ldap.LDAPBackend'
        in django_settings.AUTHENTICATION_BACKENDS):
        bind_dn = _get_bind_dn(user.username)
        try:
            ldap_connection = ldap.initialize(
                settings.LDAP_SERVER_URI, bytes_mode=False)
            ldap_connection.search_s(
                bind_dn, ldap.SCOPE_BASE) #pylint:disable=no-member
            found = True
        except ldap.LDAPError: #pylint:disable=no-member
            found = False
        finally:
            ldap_connection.unbind_s()
    return found


def set_ldap_password(dbuser, raw_password, bind_password=None):
    bind_dn = _get_bind_dn(dbuser.username)
    ldap_connection = ldap.initialize(
        settings.LDAP_SERVER_URI, bytes_mode=False)
    try:
        ldap_connection.simple_bind_s(
            force_str(bind_dn),
            force_str(bind_password))
        ldap_connection.passwd_s(
            force_str(bind_dn),
            oldpw=force_str(bind_password),
            newpw=force_str(raw_password))
    except ldap.LDAPError as err: #pylint:disable=no-member
        raise PermissionDenied(str(err))
    finally:
        ldap_connection.unbind_s()


def set_ldap_pubkey(dbuser, pubkey, bind_password=None):
    bind_dn = _get_bind_dn(dbuser.username)
    ldap_connection = ldap.initialize(
        settings.LDAP_SERVER_URI, bytes_mode=False)
    try:
        ldap_connection.simple_bind_s(
            force_str(bind_dn),
            force_str(bind_password))
        ldap_connection.modify_s(force_str(bind_dn),
            [(ldap.MOD_REPLACE, 'sshPublicKey', #pylint:disable=no-member
              [force_bytes(pubkey)])])
    except ldap.LDAPError as err:               #pylint:disable=no-member
        raise PermissionDenied(str(err))
    finally:
        ldap_connection.unbind_s()


class LDAPBackend(object):
    """
    Backend to authenticate a user through a LDAP server.
    """
    model = get_user_model()

    def authenticate(self, request, username=None, password=None, **kwargs):
        #pylint:disable=unused-argument
        user = None
        bind_dn = _get_bind_dn(username)
        ldap_connection = None
        try:
            ldap_connection = ldap.initialize(
                settings.LDAP_SERVER_URI, bytes_mode=False)
            ldap_connection.simple_bind_s(
                force_str(bind_dn), force_str(password))

            resp = ldap_connection.search_s(
                bind_dn, ldap.SCOPE_BASE) #pylint:disable=no-member
            ldap_user = resp[0][1] if resp else {}
            defaults = {
                'first_name': force_str(ldap_user.get('sn', "")),
                'last_name': force_str(ldap_user.get('cn', "")),
                'email': force_str(ldap_user.get('mail', "")),
                'password': "ldap" # prevent user from showing as inactive
                                   # (see `has_invalid_password`).
            }
            #pylint:disable=protected-access
            db_user, created = self.model._default_manager.get_or_create(**{
                self.model.USERNAME_FIELD: username,
                'defaults': defaults,
            })
            if created:
                LOGGER.debug("created user '%s' in database.", username)
            user = db_user
        except ldap.LDAPError: #pylint:disable=no-member
            user = None
        finally:
            if ldap_connection:
                ldap_connection.unbind_s()

        return user

    def get_user(self, user_id):
        try:
            user = self.model.objects.get(pk=user_id)
            return user
        except self.model.DoesNotExist:
            return None
