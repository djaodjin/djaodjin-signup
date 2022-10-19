# Copyright (c) 2021, DjaoDjin inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Middleware to create AWS temporary credentials
"""
import logging

from django.contrib.auth.middleware import (
    AuthenticationMiddleware as BaseAuthenticationMiddleware)
from django.http import HttpResponseNotFound
from django.utils import translation
from rest_framework import exceptions
from rest_framework.settings import api_settings

from .backends.sts_credentials import temporary_security_token
from .compat import is_authenticated
from .models import get_user_contact


LOGGER = logging.getLogger(__name__)


class AWSTemporaryCredentialsMiddleware(object):
    """
    Create temporary credentials on AWS into the ``request.user`` session.
    """

    @staticmethod
    def process_request(request):
        assert hasattr(request, 'user'), (
        """The Django AWS temporary security token middleware requires session
           middleware to be installed. Edit your MIDDLEWARE_CLASSES setting
           to insert 'django.contrib.auth.middleware.AuthenticationMiddleware'
           before 'AWSTemporaryCredentialsMiddleware'."""
        )
        temporary_security_token(request)


class AuthenticationMiddleware(BaseAuthenticationMiddleware):
    """
    Authenticate using a list of authenticators (i.e. Authorization Header).
    """

    @staticmethod
    def get_authenticators():
        return [auth() for auth in api_settings.DEFAULT_AUTHENTICATION_CLASSES]

    def process_request(self, request):
        super(AuthenticationMiddleware, self).process_request(request)
        if not is_authenticated(request):
            try:
                for authenticator in self.get_authenticators():
                    try:
                        user_auth_tuple = authenticator.authenticate(request)
                    except AttributeError:
                        # DRF is using a wrapper around a Django request
                        # which we don't have here.
                        continue
                    if user_auth_tuple is not None:
                        #pylint:disable=protected-access
                        request._authenticator = authenticator
                        request.user, request.auth = user_auth_tuple
                        break
            except exceptions.AuthenticationFailed:
                # Keep the anonymous user.
                pass

        if is_authenticated(request):
            accept = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
            if not accept:
                contact = get_user_contact(request.user)
                if contact:
                    LOGGER.debug("no Accept-Language HTTP header,"\
                        " defaults to language '%s' in contact.", contact.lang)
                    translation.activate(contact.lang)


    def process_exception(self, request, exception):
        # It is better to return a 404 instead of a 500 when the iDP does
        # not exist in `SOCIAL_AUTH_SAML_ENABLED_IDPS`, especially that it is
        # a URL query parameter.
        if isinstance(exception, KeyError):
            return HttpResponseNotFound("couldn't find %s" % str(exception))
        return None
