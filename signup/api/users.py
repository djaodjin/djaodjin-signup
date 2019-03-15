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
from django.contrib.auth import update_session_auth_hash
from django.utils.translation import ugettext_lazy as _
from rest_framework.generics import UpdateAPIView

from ..compat import User
from ..serializers import (PasswordChangeSerializer, NotificationsSerializer)


LOGGER = logging.getLogger(__name__)


class PasswordChangeAPIView(UpdateAPIView):
    """
    Changes the password for a user.

    **Example

    .. code-block:: http

        PUT /api/users/donny/password/ HTTP/1.1

    responds

    .. code-block:: json

        {
          "password": "yeye"
        }
    """

    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    serializer_class = PasswordChangeSerializer
    queryset = User.objects.all()

    def perform_update(self, serializer):
        password = serializer.validated_data['password']
        new_password = serializer.validated_data.get('new_password')
        if not self.request.user.check_password(password):
            raise PermissionDenied(_("Incorrect credentials"))
        if new_password:
            serializer.instance.set_password(new_password)
            serializer.instance.save()
            # Updating the password logs out all other sessions for the user
            # except the current one if
            # django.contrib.auth.middleware.SessionAuthenticationMiddleware
            # is enabled.
            update_session_auth_hash(self.request, serializer.instance)


class UserNotificationsAPIView(UpdateAPIView):
    """
    Changes notifications preferences for a user.

    **Example

    .. code-block:: http

        POST /api/users/donny/notifications/ HTTP/1.1

    .. code-block:: json

        {
          "notifications": ["user_registered_notice"]
        }

    responds

    .. code-block:: json

        {
          "notifications": ["user_registered_notice"]
        }
    """
    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    serializer_class = NotificationsSerializer
    queryset = User.objects.all()
