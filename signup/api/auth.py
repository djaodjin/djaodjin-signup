# Copyright (c) 2019, DjaoDjin inc.
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
from django.contrib.auth import (get_user_model, authenticate,
    REDIRECT_FIELD_NAME, logout as auth_logout)
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
import jwt
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView, CreateAPIView
from rest_framework.response import Response


from .. import settings, signals
from ..auth import validate_redirect
from ..compat import reverse
from ..decorators import check_user_active
from ..docs import OpenAPIResponse, swagger_auto_schema
from ..helpers import as_timestamp, datetime_or_now, full_name_natural_split
from ..models import Contact
from ..serializers import (CredentialsSerializer, CreateUserSerializer,
    TokenSerializer, UserSerializer, ValidationErrorSerializer,
    PasswordResetSerializer)
from ..utils import verify_token as verify_token_base


LOGGER = logging.getLogger(__name__)


class JWTBase(GenericAPIView):

    serializer_class = TokenSerializer

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
        LOGGER.info("%s signed in.", user,
            extra={'event': 'login', 'request': self.request})
        return Response(TokenSerializer().to_representation({'token': token}))


class JWTLogin(JWTBase):
    """
    Returns a JSON Web Token that can be used in requests that require
    authentication.

    **Tags: auth

    **Example

    .. code-block:: http

        POST /api/auth/ HTTP/1.1

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
    serializer_class = CredentialsSerializer

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("", TokenSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs): #pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            user = authenticate(username=username, password=password)
            if user:
                contact = Contact.objects.filter(user=user).first()
                if contact and contact.mfa_backend:
                    if not contact.mfa_priv_key:
                        contact.create_mfa_token()
                        raise ValidationError({'detail': _(
                            "missing MFA token")})
                    code = serializer.validated_data.get('code')
                    if code != contact.mfa_priv_key:
                        if (contact.mfa_nb_attempts
                            >= settings.MFA_MAX_ATTEMPTS):
                            contact.clear_mfa_token()
                            raise PermissionDenied({'detail': _(
"You have exceeded the number of attempts to enter the MFA code."\
" Please start again.")})
                        contact.mfa_nb_attempts += 1
                        contact.save()
                        raise ValidationError({'detail': _(
                            "MFA code does not match.")})
                    contact.clear_mfa_token()
                return self.create_token(user)
        raise PermissionDenied()


class JWTRegister(JWTBase):
    """
    Creates a new user and returns a JSON Web Token that can subsequently
    be used to authenticate the new user in HTTP requests.

    **Tags: auth

    **Example

    .. code-block:: http

        POST /api/auth/register/ HTTP/1.1

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
    serializer_class = CreateUserSerializer

    def register_user(self, **validated_data):
        #pylint: disable=maybe-no-member
        email = validated_data['email']
        users = self.model.objects.filter(email=email)
        if users.exists():
            user = users.get()
            if check_user_active(self.request, user):
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

        first_name, mid_initials, last_name = full_name_natural_split(
            validated_data['full_name'])
        username = validated_data.get('username', None)
        password = validated_data.get('password', None)
        user = self.model.objects.create_user(username,
            email=email, password=password,
            first_name=first_name + " " + mid_initials, last_name=last_name)

        # Bypassing authentication here, we are doing frictionless registration
        # the first time around.
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        return user

    def register(self, serializer):
        return self.register_user(**serializer.validated_data)

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("", TokenSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # We are not using `is_valid(raise_exception=True)` here
            # because we do not want to give clues on the reasons for failure.
            user = self.register(serializer)
            if user:
                return self.create_token(user)
        raise ValidationError({'detail': "invalid request"})


class JWTLogout(JWTBase):
    """
    Removes all cookies associated with the session.

    This API endpoint is only useful when the user is using Cookie-based
    authentication. Tokens expire; they cannot be revoked.

    **Tags: auth

    **Example

    .. code-block:: http

        POST /api/auth/logout/  HTTP/1.1

    .. code-block:: json

        {
          "token": "670yoaq34rotlgqpoxzmw435Alrdf"
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


class PasswordResetAPIView(CreateAPIView):

    model = get_user_model()
    serializer_class = PasswordResetSerializer
    token_generator = default_token_generator

    def perform_create(self, serializer):
        try:
            user = self.model.objects.get(
                email__iexact=serializer.data.get('email'), is_active=True)
            next_url = validate_redirect(self.request)
            if check_user_active(self.request, user, next_url=next_url):
                # Make sure that a reset password email is sent to a user
                # that actually has an activated account.
                uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()
                token = self.token_generator.make_token(user)
                back_url = self.request.build_absolute_uri(
                    reverse('password_reset_confirm', args=(uid, token)))
                if next_url:
                    back_url += '?%s=%s' % (REDIRECT_FIELD_NAME, next_url)
                signals.user_reset_password.send(
                    sender=__name__, user=user, request=self.request,
                    back_url=back_url, expiration_days=settings.KEY_EXPIRATION)
            else:
                raise ValidationError({'detail': _("Please activate your"\
                    " account first. You should receive an email shortly.")})
        except self.model.DoesNotExist:
            # We don't want to give a clue about registered users, yet
            # it already possible to do a straight register to get the same.
            raise ValidationError({'detail': _("We cannot find an account"\
                " for this e-mail address. Please verify the spelling.")})
