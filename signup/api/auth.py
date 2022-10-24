# Copyright (c) 2022, DjaoDjin inc.
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

from django.contrib.auth import (get_user_model,
    authenticate, login as auth_login, logout as auth_logout)
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
import jwt
from rest_framework import exceptions, permissions, status, serializers
from rest_framework.generics import GenericAPIView, CreateAPIView
from rest_framework.response import Response


from .. import settings
from ..compat import gettext_lazy as _, six
from ..docs import OpenAPIResponse, no_body, swagger_auto_schema
from ..helpers import as_timestamp, datetime_or_now
from ..mixins import (ActivateMixin, LoginMixin, RecoverMixin, RegisterMixin,
    SSORequired)
from ..models import Contact
from ..serializers_overrides import UserDetailSerializer
from ..serializers import (ActivateSerializer, CredentialsSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer,
    TokenSerializer, UserCreateSerializer, ValidationErrorSerializer)
from ..utils import get_disabled_authentication, get_disabled_registration


LOGGER = logging.getLogger(__name__)


class AllowAuthenticationEnabled(permissions.BasePermission):
    """
    Allows access only authentication is not disabled.
    """
    message = _("authentication has been temporarly disabled.")

    def has_permission(self, request, view):
        return not get_disabled_authentication(request)


class AllowRegistrationEnabled(permissions.BasePermission):
    """
    Allows access only when registration is not disabled.
    """
    message = _("registration is disabled.")

    def has_permission(self, request, view):
        return not get_disabled_registration(request)


class JWTBase(GenericAPIView):

    permission_classes = [AllowAuthenticationEnabled]
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
        LOGGER.info("%s signed in.", user,
            extra={'event': 'login', 'request': self.request})
        return Response(TokenSerializer().to_representation({'token': token}),
            status=status.HTTP_201_CREATED)

    @staticmethod
    def optional_session_cookie(request, user):
        if request.query_params.get('cookie', False):
            auth_login(request, user)

    def permission_denied(self, request, message=None, code=None):
        # We override this function from `APIView`. The request will never
        # be authenticated by definition since we are dealing with login
        # and register APIs.
        raise exceptions.PermissionDenied(detail=message)


class JWTActivate(ActivateMixin, JWTBase):
    """
    Retrieves an activation key

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
    serializer_class = ActivateSerializer

    def get_serializer_class(self):
        if self.request.method.lower() == 'get':
            return UserDetailSerializer
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
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # We are not using `is_valid(raise_exception=True)` here
            # because we do not want to give clues on the reasons for failure.
            user = self.activate_user(**serializer.validated_data)
            if user:
                # Okay, security check complete. Log the user in.
                user_with_backend = authenticate(
                    request, username=user.username,
                    password=serializer.validated_data.get('new_password'))
                self.optional_session_cookie(request, user_with_backend)
                return self.create_token(user_with_backend)
        raise serializers.ValidationError({'detail': "invalid request"})


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
        #pylint:disable=unused-argument,too-many-nested-blocks
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = self.login_user(**serializer.validated_data)
                self.optional_session_cookie(request, user)
                return self.create_token(user)
            except SSORequired as err:
                raise serializers.ValidationError({'detail': _(
                    "SSO required through %(provider)s") % {
                        'provider': err.printable_name},
                    'provider': err.delegate_auth.provider,
                    'url': self.request.build_absolute_uri(err.url)})

        raise exceptions.PermissionDenied()


class JWTPasswordResetConfirm(JWTBase):
    """
    Confirms a password reset

    Sets a new password after a recover password was triggered
    and returns a JSON Web Token that can subsequently
    be used to authenticate the new user in HTTP requests.

    The API is typically used within an HTML
    `reset password page </docs/guides/themes/#workflow_reset>`_
    as present in the default theme.

    **Tags: auth, visitor, usermodel

    **Example

    .. code-block:: http

        POST /api/auth/reset/0123456789abcef0123456789abcef/abc123 HTTP/1.1

    .. code-block:: json

        {
          "new_password": "yoyo"
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
    serializer_class = PasswordResetConfirmSerializer
    token_generator = default_token_generator

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("", TokenSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # We are not using `is_valid(raise_exception=True)` here
            # because we do not want to give clues on the reasons for failure.
            try:
                uid = urlsafe_base64_decode(self.kwargs.get('uidb64'))
                if not isinstance(uid, six.string_types):
                    # See Django2.2 release notes
                    uid = uid.decode()
                user = self.model.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError,
                    self.model.DoesNotExist):
                user = None
            if user is not None and self.token_generator.check_token(
                                        user, self.kwargs.get('token')):
                new_password = serializer.validated_data['new_password']
                user.set_password(new_password)
                user.save()
                LOGGER.info("%s reset her/his password.", user,
                    extra={'event': 'resetpassword', 'request': request})
                user_with_backend = authenticate(
                    request, username=user.username, password=new_password)
                self.optional_session_cookie(request, user_with_backend)
                return self.create_token(user_with_backend)
        raise serializers.ValidationError({'detail': "invalid request"})


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
          "username": "joe1",
          "password": "yoyo",
          "email": "joe+1@example.com",
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
    model = get_user_model()
    permission_classes = [AllowAuthenticationEnabled, AllowRegistrationEnabled]
    serializer_class = UserCreateSerializer

    def register(self, serializer):
        return self.register_user(**serializer.validated_data)

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("", TokenSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            # It is OK to use `raise_exception=True` because the serializer
            # purely does field validation (i.e. no checks of values
            # in database).
            user = self.register(serializer)
            if user:
                self.optional_session_cookie(request, user)
                return self.create_token(user)
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


class PasswordResetAPIView(RecoverMixin, CreateAPIView):
    """
    Sends a password reset link

    The user is uniquely identified by her email address.

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
    permission_classes = [AllowAuthenticationEnabled]
    serializer_class = PasswordResetSerializer
    token_generator = default_token_generator

    def perform_create(self, serializer):
        try:
            self.recover_user(**serializer.validated_data)
        except SSORequired as err:
            raise serializers.ValidationError({'detail': _(
                "SSO required through %(provider)s") % {
                    'provider': err.printable_name},
                'provider': err.delegate_auth.provider,
                'url': self.request.build_absolute_uri(err.url)})

    def permission_denied(self, request, message=None, code=None):
        # We override this function from `APIView`. The request will never
        # be authenticated by definition since we are dealing with login
        # and register APIs.
        raise exceptions.PermissionDenied(detail=message)
