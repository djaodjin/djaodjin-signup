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

from django.contrib.auth import logout as auth_logout
from django.db.models import Q
from django.http import Http404
from django.contrib.auth import update_session_auth_hash
from rest_framework.generics import (ListAPIView, RetrieveUpdateDestroyAPIView,
    UpdateAPIView)

from ..compat import User
from ..serializers import (PasswordChangeSerializer, UserSerializer,
    NotificationsSerializer)


LOGGER = logging.getLogger(__name__)


class PasswordChangeAPIView(UpdateAPIView):
    """
    Changes the password for a user.

    **Example request**:

    .. sourcecode:: http

        POST /api/users/{user}/password/
        {
          "password": "yoyo"
        }
    """

    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    serializer_class = PasswordChangeSerializer
    queryset = User.objects.all()

    def perform_update(self, serializer):
        password = serializer.validated_data['password']
        serializer.instance.set_password(password)
        serializer.save()
        # Updating the password logs out all other sessions for the user
        # except the current one if
        # django.contrib.auth.middleware.SessionAuthenticationMiddleware
        # is enabled.
        update_session_auth_hash(self.request, serializer.instance)


class UserNotificationsAPIView(UpdateAPIView):
    """
    Changes notifications preferences for a user.

    **Example request**:

    .. sourcecode:: http

        POST /api/users/{user}/notifications/
        {
          "notifications": ["notification_slug"]
        }
    """

    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    serializer_class = NotificationsSerializer
    queryset = User.objects.all()


class UserProfileAPIView(RetrieveUpdateDestroyAPIView):
    """
    Retrieves and update the profile information of a user.

    **Example request**:

    .. sourcecode:: http

        GET /api/users/{user}

    Response:
        {
         "username": "donny",
         "email": "donny.smith@example.com"
         "first_name": "Donny",
         "last_name": "Smith"
        }
    """

    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def perform_destroy(self, instance):
        LOGGER.info("user %s deleted.", instance,
            extra={'event': 'delete', 'request': self.request})
        requires_logout = (self.request.user == instance)
        instance.delete()
        if requires_logout:
            auth_logout(self.request)


class UserListAPIView(ListAPIView):

    serializer_class = UserSerializer

    def get_queryset(self):
        startswith = self.request.GET.get('q', None)
        if not startswith:
            raise Http404
        return User.objects.filter(Q(username__startswith=startswith)
            | Q(email__startswith=startswith))
