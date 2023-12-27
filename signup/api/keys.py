# Copyright (c) 2023, Djaodjin Inc.
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

import datetime, logging

from django.contrib.auth.hashers import make_password
from django.core.exceptions import PermissionDenied
from rest_framework import status
from rest_framework.generics import (GenericAPIView, ListAPIView,
    get_object_or_404)
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError

from .. import filters, settings
from ..backends.auth_ldap import is_ldap_user, set_ldap_pubkey
from ..compat import gettext_lazy as _
from ..docs import extend_schema, OpenApiResponse
from ..helpers import datetime_or_now
from ..mixins import AuthenticatedUserPasswordMixin, UserMixin
from ..models import Credentials
from ..serializers import (AuthenticatedUserPasswordSerializer,
    APIKeypairSerializer, APIKeySeralizer, NewKeypairSerializer,
    PublicKeySerializer, ValidationErrorSerializer)
from ..utils import generate_random_slug


LOGGER = logging.getLogger(__name__)


class ListCreateAPIKeysAPIView(AuthenticatedUserPasswordMixin,
                          UserMixin, ListAPIView):
    """
    Lists user API keys

    Lists the API keys with which a user can authenticate
    with the service.

    **Tags: auth, user, usermodel

    **Example

    .. code-block:: http

        GET /api/users/xia/api-keys  HTTP/1.1

    responds

    .. code-block:: json

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [
                {
                  "api_pub_key": "k9Q9YppQMnZ7Yh5bDkx2wsQvDfL4U3TM",
                  "title": "production"
                }
            ]
        }
    """
    search_fields = (
        'title',
    )
    ordering_fields = (
        ('title', 'title'),
        ('ends_at', 'ends_at'),
    )
    ordering = ('title',)

    filter_backends = (filters.SearchFilter, filters.OrderingFilter)
    serializer_class = APIKeySeralizer


    def get_serializer_class(self):
        if self.request.method.lower() == 'post':
            return NewKeypairSerializer
        return super(ListCreateAPIKeysAPIView, self).get_serializer_class()

    def get_queryset(self):
        return Credentials.objects.filter(user=self.user)

    @extend_schema(responses={
        201: OpenApiResponse(APIKeypairSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        """
        Creates an API key

        Creates an API key with which a user can authenticate
        with the service.

        **Tags: auth, user, usermodel

        **Example

        .. code-block:: http

            POST /api/users/xia/api-keys  HTTP/1.1

        .. code-block:: json

            {
              "password": "yoyo"
            }

        responds

        .. code-block:: json

            {
                "secret": "tgLwDw5ErQ2pQr5TTdAzSYjvZenHC9pSy7fB3sXWERzynbG5zG6h\
    67pTN4dh7fpy"
            }
        """
        serializer = NewKeypairSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.re_auth(request, serializer.validated_data)

        allowed_chars = 'abcdefghjkmnpqrstuvwxyz'\
            'ABCDEFGHJKLMNPQRSTUVWXYZ'\
            '23456789'
        api_pub_key = generate_random_slug(
            length=Credentials.API_PUB_KEY_LENGTH,
            allowed_chars=allowed_chars)
        api_password = generate_random_slug(
            length=Credentials.API_PASSWORD_LENGTH,
            allowed_chars=allowed_chars)
        title = serializer.validated_data.get('title', "")
        Credentials.objects.create(
            user=self.user,
            api_pub_key=api_pub_key,
            api_password=make_password(api_password),
            ends_at=datetime_or_now() + datetime.timedelta(
                days=settings.USER_API_KEY_LIFETIME_DAYS),
            title=title
        )
        return Response(APIKeypairSerializer().to_representation({
            'secret': api_pub_key + api_password
        }), status=status.HTTP_201_CREATED)


class DestroyAPIKeyAPIView(AuthenticatedUserPasswordMixin,
                            UserMixin, GenericAPIView):
    """
    Deletes a user secret API key
    """
    serializer_class = AuthenticatedUserPasswordSerializer

    @extend_schema(operation_id='users_api_keys_delete', responses={
        200: OpenApiResponse(ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        """
        Deletes a user API key

        Deletes the API key which user used to authenticate
        with the service.

        **Tags: auth, user, usermodel

        **Example

        .. code-block:: http

            POST /api/users/xia/api-keys/k9Q9YppQMnZ7Yh5bDkx2wsQvDfL4U3TM \
 HTTP/1.1

        .. code-block:: json

            {
              "password": "yoyo"
            }

        responds

        .. code-block:: json

            {
              "detail": "API key deleted successfully."
            }

        """
        serializer = AuthenticatedUserPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.re_auth(request, serializer.validated_data)

        obj = get_object_or_404(Credentials.objects.filter(
            user=self.user), api_pub_key=kwargs['key'])
        obj.delete()

        return Response({"detail": _("API key deleted successfully.")})


class PublicKeyAPIView(AuthenticatedUserPasswordMixin,
                       UserMixin, GenericAPIView):
    """
    Updates a user public RSA key
    """
    serializer_class = PublicKeySerializer

    @extend_schema(responses={
        200: OpenApiResponse(ValidationErrorSerializer)})
    def put(self, request, *args, **kwargs):
        """
        Updates a user public RSA key

        Sets a new public RSA key for a user. Any or a combination of
        the HTTP request user secrets must be passed along for authorization.

        **Tags: auth, user, usermodel

        **Example

        .. code-block:: http

            PUT /api/users/xia/ssh-keys  HTTP/1.1

        .. code-block:: json

            {
              "pubkey": "ssh-rsa AAAAB3N...",
              "password": "yoyo"
            }

        responds

        .. code-block:: json

            {
              "detail": "Public key updated successfully."
            }
        """
        #pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data.get('password')
        try:
            if is_ldap_user(self.user):
                set_ldap_pubkey(self.user,
                    serializer.validated_data['pubkey'],
                    bind_password=password)
                LOGGER.info("%s updated pubkey for %s.",
                    self.request.user, self.user, extra={
                    'event': 'update-pubkey', 'request': self.request,
                    'modified': self.user.username})
            else:
                self.re_auth(request, serializer.validated_data)
        except AttributeError:
            raise ValidationError(
                'Cannot store public key in the User model.')
        except PermissionDenied as err:
            raise ValidationError(str(err))

        return Response({'detail': _("Public key updated successfully.")})
