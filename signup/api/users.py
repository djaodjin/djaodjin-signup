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

import logging, re

from django.contrib.auth import logout as auth_logout
from django.db.models import Q
from django.http import Http404
from django.contrib.auth import update_session_auth_hash
from rest_framework.generics import (ListAPIView, RetrieveUpdateDestroyAPIView,
    UpdateAPIView)

from .. import settings
from ..compat import User
from ..serializers import (PasswordChangeSerializer, UserSerializer,
    NotificationsSerializer)


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
        serializer.instance.set_password(password)
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


class UserProfileAPIView(RetrieveUpdateDestroyAPIView):
    """
    Retrieves, updates or deletes the profile information of a user.

    **Example

    .. code-block:: http

        GET /api/users/donny HTTP/1.1

    responds

    .. code-block:: json

        {
         "username": "donny",
         "email": "donny.smith@example.com"
         "full_name": "Donny Smith"
        }
    """

    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def perform_destroy(self, instance):
        slug = '_archive_%d' % instance.id
        requires_logout = (self.request.user == instance)

        # We mark the user as inactive and scramble personal information
        # such that we don't remove audit records (ex: billing transactions)
        # from the database.
        LOGGER.info("%s deleted user profile for '%s <%s>' (%s).",
                    self.request.user, instance.username, instance.email, slug,
                    extra={'event': 'delete', 'request': self.request,
                        'username': instance.username, 'email': instance.email,
                        'pk': instance.pk})

        email = instance.email
        look = re.match(r'.*(@\S+)', settings.DEFAULT_FROM_EMAIL)
        if look:
            email = '%s+%d%s' % (instance.username, instance.id, look.group(1))
        instance.username = slug
        instance.email = email
        instance.password = '!'
        instance.is_active = False
        instance.save()
        if requires_logout:
            auth_logout(self.request)


class UserListAPIView(ListAPIView):
    """
    Returns the list of users registered with the service.

    **Example

    .. code-block:: http

        GET /api/users/ HTTP/1.1

    responds

    .. code-block:: json

        [{
         "username": "donny",
         "email": "donny.smith@example.com"
         "full_name": "Donny Smith"
        }]
    """
    serializer_class = UserSerializer

    def get_queryset(self):
        startswith = self.request.GET.get('q', None)
        if not startswith:
            raise Http404
        return User.objects.filter(Q(username__startswith=startswith)
            | Q(email__startswith=startswith))
