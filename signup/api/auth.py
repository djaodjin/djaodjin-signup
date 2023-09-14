# Copyright (c) 2023, DjaoDjin inc.
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

from django.contrib.auth import get_user_model, logout as auth_logout
from django.contrib.auth.tokens import default_token_generator
import jwt
from rest_framework import exceptions, permissions, status, serializers
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response


from .. import settings
from ..compat import gettext_lazy as _
from ..docs import OpenAPIResponse, no_body, swagger_auto_schema
from ..helpers import as_timestamp, datetime_or_now
from ..mixins import (LoginMixin, PasswordResetConfirmMixin, RegisterMixin,
    VerifyMixin, VerifyCompleteMixin, SSORequired)
from ..models import Contact
from ..serializers_overrides import UserDetailSerializer
from ..serializers import (CredentialsSerializer, NoModelSerializer,
    RecoverSerializer, TokenSerializer, UserActivateSerializer,
    UserCreateSerializer, ValidationErrorSerializer)
from ..utils import get_disabled_registration


LOGGER = logging.getLogger(__name__)


class AllowRegistrationEnabled(permissions.BasePermission):
    """
    Allows access only when registration is not disabled.
    """
    message = _("registration is disabled.")

    def has_permission(self, request, view):
        return not get_disabled_registration(request)


class JWTBase(GenericAPIView):

    serializer_class = TokenSerializer

    def create_token(self, user, expires_at=None):
        if not expires_at:
            exp = (as_timestamp(datetime_or_now())
                + self.request.session.get_expiry_age())
        else:
            exp = as_timestamp(expires_at)
        payload = UserDetailSerializer().to_representation(user)
        payload.update({'exp': exp})
        token = jwt.encode(payload, settings.JWT_SECRET_KEY,
            settings.JWT_ALGORITHM)
        try:
            token = token.decode('utf-8')
        except AttributeError:
            # PyJWT==2.0.1 already returns an oject of type `str`.
            pass
        return Response(TokenSerializer().to_representation({'token': token}),
            status=status.HTTP_201_CREATED)

    def permission_denied(self, request, message=None, code=None):
        # We override this function from `APIView`. The request will never
        # be authenticated by definition since we are dealing with login
        # and register APIs.
        raise exceptions.PermissionDenied(detail=message)


class JWTLogin(LoginMixin, JWTBase):
    """
    Authenticates a user

    Returns a JSON Web Token that can be used in HTTP requests that require
    authentication.

    The API is typically used within an HTML
    `login page </docs/guides/themes/#workflow_login>`_
    as present in the default theme.

    **Tags: auth, visitor, usermodel

    **Example

    .. code-block:: http

        POST /api/auth HTTP/1.1

    .. code-block:: json

        {
          "username": "donny",
          "password": "yoyo"
        }

    responds

    .. code-block:: json

        {"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6\
ImRvbm55IiwiZW1haWwiOiJzbWlyb2xvKzRAZGphb2RqaW4uY29tIiwiZnV\
sbF9uYW1lIjoiRG9ubnkgQ29vcGVyIiwiZXhwIjoxNTI5NjU4NzEwfQ.F2y\
1iwj5NHlImmPfSff6IHLN7sUXpBFmX0qjCbFTe6A"}
    """
    # XXX add "How to enable MFA" in the documentation
    model = get_user_model()
    serializer_class = CredentialsSerializer

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("", TokenSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):
        try:
            user_with_backend = self.run_pipeline()
            return self.create_token(user_with_backend)
        except SSORequired as err:
            raise serializers.ValidationError({'detail': _(
                "SSO required through %(provider)s") % {
                    'provider': err.printable_name},
                    'provider': err.delegate_auth.provider,
                    'url': self.request.build_absolute_uri(err.url)})

        raise exceptions.PermissionDenied()


class JWTRegister(RegisterMixin, JWTBase):
    """
    Registers a user

    Creates a new user and returns a JSON Web Token that can subsequently
    be used to authenticate the new user in HTTP requests.

    The API is typically used within an HTML
    `register page </docs/guides/themes/#workflow_register>`_
    as present in the default theme.

    **Tags: auth, visitor, usermodel

    **Example

    .. code-block:: http

        POST /api/auth/register HTTP/1.1

    .. code-block:: json

        {
          "email": "joe+1@example.com",
          "full_name": "Joe Card1",
          "new_password": "yoyo",
          "username": "joe1"
        }

    responds

    .. code-block:: json

        {
            "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6\
ImpvZTEiLCJlbWFpbCI6ImpvZSsxQGRqYW9kamluLmNvbSIsImZ1bGxfbmFtZ\
SI6IkpvZSAgQ2FyZDEiLCJleHAiOjE1Mjk2NTUyMjR9.GFxjU5AvcCQbVylF1P\
JwcBUUMECj8AKxsHtRHUSypco"
        }
    """
    model = get_user_model()
    permission_classes = [AllowRegistrationEnabled]
    serializer_class = UserCreateSerializer

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("", TokenSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        try:
            user_with_backend = self.run_pipeline()
            return self.create_token(user_with_backend)
        except SSORequired as err:
            raise serializers.ValidationError({'detail': _(
                "SSO required through %(provider)s") % {
                    'provider': err.printable_name},
                    'provider': err.delegate_auth.provider,
                    'url': self.request.build_absolute_uri(err.url)})

        raise serializers.ValidationError({'detail': "invalid request"})


class JWTActivate(VerifyCompleteMixin, JWTBase):
    """
    Retrieves an activation key

    Retrieves information about a contact or user associated
    to the activation key.

    This API is typically used to pre-populate a registration form
    when a user was invited to the site by another user.

    The response is usually presented in an HTML
    `activate page </docs/guides/themes/#workflow_activate>`_
    as present in the default theme.

    **Tags: auth, visitor, usermodel

    **Example

    .. code-block:: http

        GET /api/auth/activate/16793aa72a4c7ae94b50b20c2eca52df5b0fe2c6\
 HTTP/1.1

    responds

    .. code-block:: json

        {
          "slug": "joe1",
          "username": "joe1",
          "email": "joe1@localhost.localdomain",
          "full_name": "Joe Act",
          "printable_name": "Joe Act",
          "created_at": "2020-05-30T00:00:00Z"
        }
    """
    model = get_user_model()
    serializer_class = UserActivateSerializer

    def get_serializer_class(self):
        if self.request.method.lower() == 'get':
            return  UserDetailSerializer
        return super(JWTActivate, self).get_serializer_class()

    def get(self, request, *args, **kwargs):#pylint:disable=unused-argument
        verification_key = self.kwargs.get(self.key_url_kwarg)
        token = Contact.objects.get_token(verification_key=verification_key)
        if not token:
            raise serializers.ValidationError({'detail': "invalid request"})
        serializer = self.get_serializer(token.user)
        return Response(serializer.data)

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("", TokenSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        """
        Activates a user

        Activates a new user and returns a JSON Web Token that can subsequently
        be used to authenticate the new user in HTTP requests.

        **Tags: auth, visitor, usermodel

        **Example

        .. code-block:: http

            POST /api/auth/activate/16793aa72a4c7ae94b50b20c2eca52df5b0fe2c6\
 HTTP/1.1

        .. code-block:: json

            {
              "username": "joe1",
              "email": "joe1@locahost.localdomain",
              "new_password": "yoyo",
              "full_name": "Joe Card1"
            }

        responds

        .. code-block:: json

            {
                "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6\
    ImpvZTEiLCJlbWFpbCI6ImpvZSsxQGRqYW9kamluLmNvbSIsImZ1bGxfbmFtZ\
    SI6IkpvZSAgQ2FyZDEiLCJleHAiOjE1Mjk2NTUyMjR9.GFxjU5AvcCQbVylF1P\
    JwcBUUMECj8AKxsHtRHUSypco"
            }
        """
        try:
            user_with_backend = self.run_pipeline()
            return self.create_token(user_with_backend)
        except SSORequired as err:
            raise serializers.ValidationError({'detail': _(
                "SSO required through %(provider)s") % {
                    'provider': err.printable_name},
                    'provider': err.delegate_auth.provider,
                    'url': self.request.build_absolute_uri(err.url)})

        raise serializers.ValidationError({'detail': "invalid request"})


class JWTPasswordConfirm(PasswordResetConfirmMixin, JWTBase):
    """
    Resets a user password

    Resets a user password, hence triggering an activation
    workflow the next time a user attempts to login.

    **Tags: auth, visitor, usermodel

    **Example

    .. code-block:: http

        POST /api/auth/reset/16793aa72a4c7ae94b50b20c2eca52df5b0fe2c6\
 HTTP/1.1

    """
    serializer_class = NoModelSerializer

    @swagger_auto_schema(responses={
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        try:
            self.run_pipeline()
            return {}
        except SSORequired as err:
            raise serializers.ValidationError({'detail': _(
                "SSO required through %(provider)s") % {
                    'provider': err.printable_name},
                    'provider': err.delegate_auth.provider,
                    'url': self.request.build_absolute_uri(err.url)})

        raise serializers.ValidationError({'detail': "invalid request"})


class JWTLogout(JWTBase):
    """
    Logs a user out

    Removes all cookies associated with the session.

    This API endpoint is only useful when the user is using Cookie-based
    authentication. Tokens expire; they cannot be revoked.

    **Tags: auth, user, usermodel

    **Example

    .. code-block:: http

        POST /api/auth/logout  HTTP/1.1
    """
    @swagger_auto_schema(request_body=no_body, responses={
        200: OpenAPIResponse("success", no_body)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        LOGGER.info("%s signed out.", self.request.user,
            extra={'event': 'logout', 'request': request})
        auth_logout(request)
        response = Response(status=status.HTTP_200_OK)
        if settings.LOGOUT_CLEAR_COOKIES:
            for cookie in settings.LOGOUT_CLEAR_COOKIES:
                response.delete_cookie(cookie)
        return response


class RecoverAPIView(VerifyMixin, JWTBase):
    """
    Sends a verification link

    Sends a one time code to verify an e-mail or phone number.

    The user is uniquely identified by her email address or phone number.

    The API is typically used within an HTML
    `recover credentials page </docs/guides/themes/#workflow_recover>`_
    as present in the default theme.

    **Tags: auth, visitor, usermodel

    **Examples

    .. code-block:: http

         POST /api/auth/recover HTTP/1.1

    .. code-block:: json

        {
            "email": "xia@localhost.localdomain"
        }

    responds

    .. code-block:: json

        {
            "email": "xia@localhost.localdomain"
        }
    """
    model = get_user_model()
    serializer_class = RecoverSerializer
    token_generator = default_token_generator

    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        try:
            user_with_backend = self.run_pipeline()
            return self.create_token(user_with_backend)
        except SSORequired as err:
            raise serializers.ValidationError({'detail': _(
                "SSO required through %(provider)s") % {
                    'provider': err.printable_name},
                    'provider': err.delegate_auth.provider,
                    'url': self.request.build_absolute_uri(err.url)})

        raise exceptions.PermissionDenied()
