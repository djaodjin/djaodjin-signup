# Copyright (c) 2025, Djaodjin Inc.
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

"""APIs for activities"""

import logging

from rest_framework import generics

from .. import filters
from ..models import Activity
from ..serializers import ActivitySerializer, ActivityByAccountCreateSerializer
from ..utils import get_account_model

LOGGER = logging.getLogger(__name__)


class AccountMixin(object):

    lookup_field = 'slug'
    lookup_url_kwarg = 'profile'
    account_url_kwarg = 'profile'

    @property
    def account(self):
        if not hasattr(self, '_account'):
            kwargs = {self.lookup_field: self.kwargs.get(self.lookup_url_kwarg)}
            self._account = generics.get_object_or_404(
                get_account_model().objects.all(), **kwargs)
        return self._account


class ActivityByAccountAPIView(AccountMixin, generics.ListCreateAPIView):
    """
    Lists activities for an account

    Returns a list of {{PAGE_SIZE}} activity records for {account}.

    **Tags: profile, broker, usermodel

    **Example

    .. code-block:: http

        GET /api/profile/xia/activities HTTP/1.1

    responds

    .. code-block:: json

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
              "created_at": "2018-01-01T00:00:00Z",
              "text": "Phone call",
              "created_by": {
                "username": "alice",
                "printable_name": "Alice",
                "picture": null,
                "slug": "alice"
              },
              "account": null
            }, {
              "created_at": "2018-01-02T00:00:00Z",
              "text": "Follow up e-mail",
              "created_by": {
                "username": "alice",
                "printable_name": "Alice",
                "picture": null,
                "slug": "alice"
              },
              "account": {
                "slug": "cowork",
                "printable_name": "Coworking Space",
                "picture": null,
                "type": "organization",
                "credentials": false
              }
            }]
        }
    """
    search_fields = (
        'text',
    )
    ordering_fields = (
        ('created_at', 'created_at'),
    )
    ordering = ('created_at',)

    filter_backends = (filters.SearchFilter, filters.OrderingFilter)
    serializer_class = ActivitySerializer

    def get_queryset(self):
        return Activity.objects.filter(
            account__slug=self.kwargs.get(self.account_url_kwarg))

    def get_serializer_class(self):
        if self.request.method.lower() == 'post':
            return ActivityByAccountCreateSerializer
        return super(ActivityByAccountAPIView, self).get_serializer_class()

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, account=self.account)

    def post(self, request, *args, **kwargs):
        """
        Records new activity with a profile

        **Tags: profile, broker

        **Examples

        .. code-block:: http

            POST /api/profile/xia/activities HTTP/1.1

        .. code-block:: json

            {
              "text": "Phone call",
              "account": "cowork"
            }

        responds

        .. code-block:: json

            {
              "text": "Phone call",
              "account": "cowork"
            }
        """
        return self.create(request, *args, **kwargs)


class ActivityByAccountIndexAPIView(ActivityByAccountAPIView):
    """
    Lists activities for an account

    Returns a list of {{PAGE_SIZE}} activity records for {account}.

    **Tags: profile, broker, usermodel

    **Example

    .. code-block:: http

        GET /api/activities HTTP/1.1

    responds

    .. code-block:: json

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
              "created_at": "2018-01-01T00:00:00Z",
              "text": "Phone call",
              "created_by": {
                "username": "alice",
                "printable_name": "Alice",
                "picture": null,
                "slug": "alice"
              },
              "account": null
            }, {
              "created_at": "2018-01-02T00:00:00Z",
              "text": "Follow up e-mail",
              "created_by": {
                "username": "alice",
                "printable_name": "Alice",
                "picture": null,
                "slug": "alice"
              },
              "account": {
                "slug": "cowork",
                "printable_name": "Coworking Space",
                "picture": null,
                "type": "organization",
                "credentials": false
              }
            }]
        }
    """
    def get_queryset(self):
        return Activity.objects.all()
