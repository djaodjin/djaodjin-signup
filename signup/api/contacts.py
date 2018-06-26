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

"""API about contact activities"""

from rest_framework.generics import ListCreateAPIView, RetrieveUpdateAPIView

from ..mixins import ContactMixin
from ..models import Activity, Contact
from ..serializers import ActivitySerializer, ContactSerializer


class ActivityListAPIView(ContactMixin, ListCreateAPIView):
    """
    Lists activities for a contact.

    **Example

    .. code-block:: http

        GET /api/contacts/xia/activities HTTP/1.1

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

    serializer_class = ActivitySerializer

    def get_queryset(self):
        return Activity.objects.filter(contact=self.contact)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, contact=self.contact)

    def post(self, request, *args, **kwargs):
        """
        Records new activity with a contact.

        **Examples

        .. code-block:: http

            POST /api/contacts/xia/activities/ HTTP/1.1

        .. code-block:: json

            {
              "text": "Phone call",
              "account": null
            }
        """
        return self.create(request, *args, **kwargs)


class ContactDetailAPIView(ContactMixin, RetrieveUpdateAPIView):
    """
    Retrieves information on a ``Contact``.

    **Examples

    .. code-block:: http

        GET /api/contacts/xia HTTP/1.1

    .. code-block:: json

        {
            "slug": "xia",
            "email": "xia@locahost.localdomain",
            "full_name": "Xia Lee",
            "nick_name": "Xia",
            "created_at": "2018-01-01T00:00:00Z",
            "activities": [{
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
    serializer_class = ContactSerializer
    queryset = Contact.objects.all()

    def put(self, request, *args, **kwargs):
        """
        Updates a ``Contact``

        **Examples

        .. code-block:: http

            PUT /api/contacts/xia/ HTTP/1.1

        .. code-block:: json

            {
              "email": "xia@locahost.localdomain",
              "full_name": "Xia Lee",
              "nick_name": "Xia",
            }
        """
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a `Contact``.

        **Examples

        .. code-block:: http

            DELETE /api/contacts/xia/ HTTP/1.1
        """
        return self.destroy(request, *args, **kwargs)


class ContactListAPIView(ListCreateAPIView):
    """
    Lists or creates a contact.

    **Examples

    .. code-block:: http

        GET /api/contacts HTTP/1.1

    .. code-block:: json

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
              "slug": "xia",
              "email": "xia@locahost.localdomain",
              "full_name": "Xia Lee",
              "nick_name": "Xia",
              "created_at": "2018-01-01T00:00:00Z",
              "activities": [{
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
            }]
        }
    """
    serializer_class = ContactSerializer
    queryset = Contact.objects.all()

    def post(self, request, *args, **kwargs):
        """
        Creates a new ``Contact``

        **Examples

        .. code-block:: http

            POST /api/contacts/ HTTP/1.1

        .. code-block:: json

            {
              "email": "xia@locahost.localdomain",
              "full_name": "Xia Lee",
              "nick_name": "Xia"
            }
        """
        return self.create(request, *args, **kwargs)
