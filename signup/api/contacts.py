# Copyright (c) 2020, Djaodjin Inc.
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

import hashlib, logging, os

from django.db import transaction
from django.utils.encoding import force_text
from rest_framework import filters, parsers, status
from rest_framework.generics import CreateAPIView, ListCreateAPIView
from rest_framework.response import Response

from .users import UserDetailAPIView, UserListCreateAPIView
from ..mixins import ContactMixin
from ..models import Activity, Contact
from ..serializers import ActivitySerializer, UploadBlobSerializer

from ..utils import get_picture_storage


LOGGER = logging.getLogger(__name__)


# XXX smart list? search and order?
class ActivityListCreateAPIView(ContactMixin, ListCreateAPIView):
    """
    Lists activities for a contact

    Returns ``PAGE_SIZE`` activity records for a user.

    **Tags: profile

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
    filter_backends = (filters.SearchFilter, filters.OrderingFilter)
    search_fields = ('text',)
    ordering_fields = ('created_at',)
    ordering = ('created_at',)
    serializer_class = ActivitySerializer

    def get_queryset(self):
        return Activity.objects.filter(contact=self.contact)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, contact=self.contact)

    def post(self, request, *args, **kwargs):
        """
        Records new activity with a contact

        **Tags: profile

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
    swagger_schema = None


class ContactListAPIView(UserListCreateAPIView):
    """
    This API end-point is a shadow of `UserListCreateAPIView` and is marked
    to be deprecated in the future.
    """
    swagger_schema = None


class ContactPictureAPIView(ContactMixin, CreateAPIView):
    """
        Uploads a static asset file

        **Examples

        .. code-block:: http

            POST /api/contacts/xia/picture/ HTTP/1.1
    """
    parser_classes = (parsers.FormParser, parsers.MultiPartParser)
    serializer_class = UploadBlobSerializer

    def post(self, request, *args, **kwargs):
        #pylint:disable=unused-argument
        uploaded_file = request.data.get('file')
        if not uploaded_file:
            return Response({'details': "no location or file specified."},
                status=status.HTTP_400_BAD_REQUEST)

        # tentatively extract file extension.
        parts = os.path.splitext(
            force_text(uploaded_file.name.replace('\\', '/')))
        ext = parts[-1].lower() if len(parts) > 1 else ""
        key_name = "%s%s" % (
            hashlib.sha256(uploaded_file.read()).hexdigest(), ext)
        default_storage = get_picture_storage()
        location = self.request.build_absolute_uri(default_storage.url(
            default_storage.save(key_name, uploaded_file)))
        user_model = self.user_queryset.model
        with transaction.atomic():
            try:
                user = user_model.objects.get(
                    username=self.kwargs.get(self.lookup_url_kwarg))
            except user_model.DoesNotExist:
                user = None
            Contact.objects.update_or_create(
                slug=self.kwargs.get(self.lookup_url_kwarg),
                defaults={'picture': location, 'user': user})
        return Response({'location': location}, status=status.HTTP_201_CREATED)
