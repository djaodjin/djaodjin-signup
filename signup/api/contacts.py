# Copyright (c) 2021, Djaodjin Inc.
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

"""APIs for profiles and profile activities"""

import logging

from rest_framework.generics import ListCreateAPIView

from .users import UserDetailAPIView, UserListCreateAPIView, UserPictureAPIView
from .. import filters
from ..mixins import ContactMixin
from ..models import Activity
from ..serializers import ActivitySerializer


LOGGER = logging.getLogger(__name__)


# XXX smart list? search and order?
class ActivityListCreateAPIView(ContactMixin, ListCreateAPIView):
    """
    Lists activities for a user

    Returns a list of {{PAGE_SIZE}} activity records for user account {user}.

    **Tags: profile, broker, usermodel

    **Example

    .. code-block:: http

        GET /api/contacts/xia/activities/ HTTP/1.1

    responds

    .. code-block:: json

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
              "created_at": "2018-01-01T00:00:00Z",
              "created_by": "alice",
              "text": "Phone call",
              "account": null
            },{
              "created_at": "2018-01-02T00:00:00Z",
              "created_by": "alice",
              "text": "Follow up e-mail",
              "account": "cowork"
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
        return Activity.objects.filter(contact=self.contact)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, contact=self.contact)

    def post(self, request, *args, **kwargs):
        """
        Records new activity with a user

        **Tags: profile, broker, usermodel

        **Examples

        .. code-block:: http

            POST /api/contacts/xia/activities/ HTTP/1.1

        .. code-block:: json

            {
              "text": "Phone call",
              "account": null
            }

        responds

        .. code-block:: json

            {
              "text": "Phone call",
              "account": null
            }
        """
        return self.create(request, *args, **kwargs)


class ContactDetailAPIView(UserDetailAPIView):
    """
    This API end-point is a shadow of `UserDetailAPIView` and is marked
    to be deprecated in the future.
    """
    schema = None


class ContactListAPIView(UserListCreateAPIView):
    """
    This API end-point is a shadow of `UserListCreateAPIView` and is marked
    to be deprecated in the future.
    """
    schema = None


class ContactPictureAPIView(UserPictureAPIView):
    """
        Uploads a picture for the user profile

        **Examples

        .. code-block:: http

            POST /api/contacts/xia/picture/ HTTP/1.1

        responds

        .. code-block:: json

            {
              "location": "https://cowork.net/picture.jpg"
            }
    """
