# Copyright (c) 2018, DjaoDjin inc.
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

import logging

from django.core.exceptions import PermissionDenied
from django.contrib.auth import (authenticate, login as auth_login,
    logout as auth_logout)
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
import jwt
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from .. import settings
from ..compat import User, reverse
from ..decorators import check_user_active
from ..serializers import (CredentialsSerializer, CreateUserSerializer,
    TokenSerializer, UserSerializer)
from ..utils import (as_timestamp, datetime_or_now,
    verify_token as verify_token_base)


LOGGER = logging.getLogger(__name__)


class JWTBase(GenericAPIView):

    def create_token(self, user, expires_at=None):
        if not expires_at:
            exp = (as_timestamp(datetime_or_now())
                + self.request.session.get_expiry_age())
        else:
            exp = as_timestamp(expires_at)
        payload = UserSerializer().to_representation(user)
        payload.update({'exp': exp})
        token = jwt.encode(payload, settings.JWT_SECRET_KEY,
            settings.JWT_ALGORITHM).decode('utf-8')
        return Response({'token': token})


class JWTLogin(JWTBase):
    """
    Returns a JSON Web Token that can be used in requests that require
    authentication.

    **Example request**:

    .. sourcecode:: http

        POST /api/login/
        {
          "username": "donny",
          "password": "yoyo"
        }

    **Example response**:

    .. sourcecode:: http

        {
            "token": "34rotlgqpoxzmw435Alr...",
        }
    """
    serializer_class = CredentialsSerializer

    def post(self, request, *args, **kwargs): #pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)
            if user:
                auth_login(request, user)
                return self.create_token(user)
        raise PermissionDenied()


class JWTRegister(JWTBase):
    """
    Creates a new user and returns a JSON Web Token that can be used
    in requests that require authentication.

    **Example request**:

    .. sourcecode:: http

        POST /api/register/
        {
          "username": "donny",
          "password": "yoyo",
          "email": "donny.smith@example.com",
          "first_name": "Donny",
          "last_name": "Smith"
        }

    **Example response**:

    .. sourcecode:: http

        {
            "token": "34rotlgqpoxzmw435Alr...",
        }
    """
    serializer_class = CreateUserSerializer

    def register(self, serializer):
        #pylint: disable=maybe-no-member
        email = serializer.validated_data['email']
        users = User.objects.filter(email=email)
        if users.exists():
            user = users.get()
            if check_user_active(self.request, user,
                                 next_url=self.get_success_url()):
                raise ValidationError(mark_safe(_(
                    'This email address has already been registered!'\
' Please <a href="%s">login</a> with your credentials. Thank you.'
                    % reverse('login'))))
            else:
                ValidationError(mark_safe(_(
                    "This email address has already been registered!"\
" You should now secure and activate your account following "\
" the instructions we just emailed you. Thank you.")))
            return None

        first_name = serializer.validated_data['first_name']
        last_name = serializer.validated_data['last_name']
        username = serializer.validated_data.get('username', None)
        password = serializer.validated_data.get('password', None)
        user = User.objects.create_user(username,
            email=email, password=password,
            first_name=first_name, last_name=last_name)

        # Bypassing authentication here, we are doing frictionless registration
        # the first time around.
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        auth_login(self.request, user)
        return user

    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = self.register(serializer)
            if user:
                return self.create_token(user)
        raise PermissionDenied()


class JWTLogout(JWTBase):
    """
    Removes all cookies associated with the session
    and returns a new expired token.

    **Example request**:

    .. sourcecode:: http

        POST /api/login/
        Authorization: JWT 34rotlgqpoxzmw435Alr

    **Example response**:

    .. sourcecode:: http
        {
          "token": 670yoaq34rotlgqpoxzmw435Alr...",
        }
    """
    serializer_class = TokenSerializer

    @staticmethod
    def verify_token(token):
        return verify_token_base(token)

    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            user = super(JWTLogout, self).verify_token(token)
            LOGGER.info("%s signed out.", self.request.user,
                extra={'event': 'logout', 'request': request})
            auth_logout(request)
            response = self.create_token(user, expires_at=datetime_or_now())
            if settings.LOGOUT_CLEAR_COOKIES:
                for cookie in settings.LOGOUT_CLEAR_COOKIES:
                    response.delete_cookie(cookie)
            return response
        return Response({})
