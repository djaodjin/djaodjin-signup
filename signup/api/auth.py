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
from django.core.urlresolvers import reverse
from django.contrib.auth import (authenticate, login as auth_login,
    logout as auth_logout)
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
import jwt
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from .. import settings
from ..compat import User
from ..decorators import check_user_active
from ..serializers import (CredentialsSerializer, CreateUserSerializer,
    UserSerializer)
from ..utils import as_timestamp, datetime_or_now
from .tokens import JWTVerify


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
        token = jwt.encode(payload, settings.JWT_PRIVATE_KEY,
            settings.JWT_ALGORITHM).decode('utf-8')
        return Response({'token': token})


class JWTLogin(JWTBase):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    serializer_class = CredentialsSerializer

    def post(self, request, *args, **kwargs): #pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)
            auth_login(request, user)
            return self.create_token(user)
        raise PermissionDenied()


class JWTRegister(GenericAPIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
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


class JWTLogout(JWTVerify):

    def post(self, request, *args, **kwargs):
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
