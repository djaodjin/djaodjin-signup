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
from rest_framework.response import Response

from ..serializers import TokenSerializer
from ..utils import verify_token as verify_token_base
from .auth import JWTBase


LOGGER = logging.getLogger(__name__)


class JWTVerify(JWTBase):
    """
    Verifies a JSON Web Token.

    **Example request**:

    .. sourcecode:: http

        POST /api/tokens/verify/
        {
            "token": "34rotlgqpoxzmw435Alr...",
        }

    **Example response**:

    .. sourcecode:: http

        {
            "token": "34rotlgqpoxzmw435Alr...",
        }
    """
    serializer_class = TokenSerializer

    @staticmethod
    def verify_token(token):
        return verify_token_base(token)

    def post(self, request, *args, **kwargs): #pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            self.verify_token(token)
            return Response({'token': token})
        raise PermissionDenied()


class JWTRefresh(JWTVerify):
    """
    Creates a new JSON Web Token that expires further in the future.

    **Example request**:

    .. sourcecode:: http

        POST /api/tokens/refresh/
        {
            "token": "34rotlgqpoxzmw435Alr...",
        }

    **Example response**:

    .. sourcecode:: http

        {
            "token": "tokdwwoaQ135Alr...",
        }
    """
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            user = super(JWTRefresh, self).verify_token(token)
            return self.create_token(user)
        raise PermissionDenied()
