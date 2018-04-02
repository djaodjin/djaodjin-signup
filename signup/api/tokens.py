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
from django.utils.translation import ugettext_lazy as _
import jwt
from rest_framework import serializers
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from .. import settings
from ..compat import User
from ..serializers import TokenSerializer


LOGGER = logging.getLogger(__name__)


class JWTVerify(GenericAPIView):

    serializer_class = TokenSerializer

    @staticmethod
    def verify_token(token):
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                True, # verify
                options={'verify_exp': True},
                algorithms=[settings.JWT_ALGORITHM])
        except jwt.ExpiredSignature:
            raise serializers.ValidationError(
                _('Signature has expired.'))
        except jwt.DecodeError:
            raise serializers.ValidationError(
                _('Error decoding signature.'))
        username = payload.get('username', None)
        if not username:
            raise serializers.ValidationError(
                _('Missing username in payload'))
        # Make sure user exists
        try:
            user = User.objects.get(usermane=username)
        except User.DoesNotExist:
            raise serializers.ValidationError(_("User doesn't exist."))
        return user

    def post(self, request, *args, **kwargs): #pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            self.verify_token(token)
            return Response({'token': token})
        raise PermissionDenied()


class JWTRefresh(JWTVerify):

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            user = super(JWTRefresh, self).verify_token(token)
            return self.create_token(user)
        raise PermissionDenied()
