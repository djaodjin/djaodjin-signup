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

from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response

from ..mixins import UserMixin
from ..models import Credentials
from ..serializers import APIKeysSerializer


class ResetAPIKeysAPIView(UserMixin, CreateAPIView):
    """
    Reset the secret API key with which a user can authenticate
    with the service.

    **Example

    .. code-block:: http

        POST /api/auth/keys/donny/  HTTP/1.1

    responds

    .. code-block:: json

        {
            "secret": "tgLwDw5ErQ2pQr5TTdAzSYjvZenHC9pSy7fB3sXWERzynbG5zG6h\
67pTN4dh7fpy"
        }

    """

    serializer_class = APIKeysSerializer

    def create(self, request, *args, **kwargs):
        allowed_chars = 'abcdefghjkmnpqrstuvwxyz'\
            'ABCDEFGHJKLMNPQRSTUVWXYZ'\
            '23456789'
        api_pub_key = get_random_string(
            length=Credentials.API_PUB_KEY_LENGTH, allowed_chars=allowed_chars)
        api_priv_key = get_random_string(
            length=Credentials.API_PRIV_KEY_LENGTH, allowed_chars=allowed_chars)
        Credentials.objects.update_or_create(
            user=self.user,
            defaults={
                'api_pub_key': api_pub_key,
                'api_priv_key': make_password(api_priv_key)
            })
        return Response(APIKeysSerializer().to_representation({
            'secret': api_pub_key + api_priv_key
        }), status=status.HTTP_201_CREATED)
