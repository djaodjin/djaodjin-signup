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

import logging, re
from hashlib import sha256

from django.contrib.auth import logout as auth_logout
from django.db import transaction, IntegrityError
from django.core.exceptions import PermissionDenied
from django.contrib.auth import update_session_auth_hash
from django.utils.translation import ugettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.generics import (ListCreateAPIView,
    RetrieveUpdateDestroyAPIView, GenericAPIView, UpdateAPIView)
from rest_framework.response import Response
from rest_framework.settings import api_settings

from .. import filters, settings
from ..compat import User
from ..decorators import check_user_active
from ..docs import OpenAPIResponse, swagger_auto_schema
from ..helpers import full_name_natural_split
from ..mixins import ContactMixin
from ..models import Contact
from ..serializers import (ContactSerializer, PasswordChangeSerializer,
    NoModelSerializer, NotificationsSerializer, ValidationErrorSerializer)
from ..utils import get_picture_storage, generate_random_code, handle_uniq_error


LOGGER = logging.getLogger(__name__)


def get_order_func(fields):
    """
    Builds a lambda function that can be used to order two records
    based on a sequence of fields.

    When a field name is preceeded by '-', the order is reversed.
    """
    if len(fields) == 1:
        if fields[0].startswith('-'):
            field_name = fields[0][1:]
            return lambda left, right: (
                getattr(left, field_name) > getattr(right, field_name))
        field_name = fields[0]
        return lambda left, right: (
            getattr(left, field_name) < getattr(right, field_name))
    if fields[0].startswith('-'):
        field_name = fields[0][1:]
        return lambda left, right: (
            getattr(left, field_name) > getattr(right, field_name) or
            get_order_func(fields[1:])(left, right))
    field_name = fields[0]
    return lambda left, right: (
        getattr(left, field_name) < getattr(right, field_name) or
        get_order_func(fields[1:])(left, right))


class UserActivateAPIView(ContactMixin, GenericAPIView):
    """
    Re-send an activation e-mail if the user is not already activated.

    **Tags: auth

    **Example

    .. code-block:: http

        POST /api/users/donny/activate/ HTTP/1.1

    responds

    .. code-block:: json

        {
            "slug": "xia",
            "email": "xia@locahost.localdomain",
            "full_name": "Xia Lee",
            "nick_name": "Xia",
            "created_at": "2018-01-01T00:00:00Z",
        }
    """
    serializer_class = ContactSerializer
    queryset = Contact.objects.all().select_related('user')

    @swagger_auto_schema(request_body=NoModelSerializer, responses={
        201: OpenAPIResponse("success", ContactSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        instance = self.get_object()
        if check_user_active(request, instance.user):
            raise ValidationError({'detail': _("User is already active")})
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class UserDetailAPIView(ContactMixin, RetrieveUpdateDestroyAPIView):
    """
    Retrieves details on one single user profile with slug ``{user}``.

    **Tags: profile

    **Examples

    .. code-block:: http

        GET /api/users/xia HTTP/1.1

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
    queryset = Contact.objects.all().select_related('user')

    def put(self, request, *args, **kwargs):
        """
        Updates a user profile.

        **Tags: profile

        **Examples

        .. code-block:: http

            PUT /api/users/xia/ HTTP/1.1

        .. code-block:: json

            {
              "email": "xia@locahost.localdomain",
              "full_name": "Xia Lee",
              "nick_name": "Xia",
            }
        """
        storage = get_picture_storage()
        picture = request.data.get('picture')
        if picture:
            name = '%s.%s' % (sha256(picture.read()).hexdigest(), 'jpg')
            storage.save(name, picture)
            request.data['picture'] = storage.url(name)
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a user profile.

        **Tags: profile

        **Examples

        .. code-block:: http

            DELETE /api/users/xia/ HTTP/1.1
        """
        return self.destroy(request, *args, **kwargs)

    def perform_destroy(self, instance):
        if instance.user:
            pkid = instance.user.pk
            email = instance.user.email
            username = instance.user.username
        else:
            email = instance.email
            pkid = instance.pk if instance.pk else generate_random_code()
            username = instance.slug if instance.slug else ("%d" % pkid)

        # We mark the user as inactive and scramble personal information
        # such that we don't remove audit records (ex: billing transactions)
        # from the database.
        slug = '_archive_%d' % pkid
        LOGGER.info("%s deleted user profile for '%s <%s>' (%s).",
            self.request.user, username, email, slug, extra={'event': 'delete',
                'request': self.request, 'username': username, 'email': email,
                'pk': pkid})

        look = re.match(r'.*(@\S+)', settings.DEFAULT_FROM_EMAIL)
        if look:
            email = '%s%s' % (slug, look.group(1))

        with transaction.atomic():
            if instance.pk:
                instance.slug = slug
                instance.email = email
            user = instance.user
            if user:
                requires_logout = (self.request.user == user)
                user.username = slug
                user.email = email
                user.password = '!'
                user.is_active = False
                user.save()
                if requires_logout:
                    auth_logout(self.request)

    def perform_update(self, serializer):
        with transaction.atomic():
            user = serializer.instance.user
            try:
                if user:
                    if serializer.validated_data.get('email'):
                        user.email = serializer.validated_data.get('email')
                    if serializer.validated_data.get('slug'):
                        user.username = serializer.validated_data.get('slug')
                    if serializer.validated_data.get('full_name'):
                        #pylint:disable=unused-variable
                        first_name, mid_name, last_name = \
                            full_name_natural_split(
                                serializer.validated_data.get('full_name'))
                        user.first_name = first_name
                        user.last_name = last_name
                    user.save()
                serializer.save()
            except IntegrityError as err:
                handle_uniq_error(err)


class UserListAPIView(ListCreateAPIView):
    """
    Queries a page (``PAGE_SIZE`` records) of organization and user profiles.

    The queryset can be filtered for at least one field to match a search
    term (``q``).

    The queryset can be ordered by a field by adding an HTTP query parameter
    ``o=`` followed by the field name. A sequence of fields can be used
    to create a complete ordering by adding a sequence of ``o`` HTTP query
    parameters. To reverse the natural order of a field, prefix the field
    name by a minus (-) sign.

    **Tags: profile

    **Example

    .. code-block:: http

        GET /api/users/?q=xia HTTP/1.1

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
    filter_backends = (filters.SearchFilter, filters.OrderingFilter)
    search_fields = (
        'email',
        # fields in User model:
        'username',
    )
    ordering_fields = (
        'full_name',
        'created_at',
        'date_joined')

    ordering = ('full_name',)
    alternate_ordering = ('first_name', 'last_name')
    serializer_class = ContactSerializer
    queryset = Contact.objects.all().select_related('user')

    def post(self, request, *args, **kwargs):
        """
        Creates a new user profile.

        **Tags: profile

        **Examples

        .. code-block:: http

            POST /api/users/ HTTP/1.1

        .. code-block:: json

            {
              "email": "xia@locahost.localdomain",
              "full_name": "Xia Lee",
              "nick_name": "Xia"
            }
        """
        return self.create(request, *args, **kwargs)

    @staticmethod
    def as_contact(user):
        return Contact(slug=user.username, email=user.email,
            full_name=user.get_full_name(), nick_name=user.first_name,
            created_at=user.date_joined, user=user)

    @staticmethod
    def get_users_queryset():
        return User.objects.filter(is_active=True, contact__isnull=True)

    def list(self, request, *args, **kwargs):
        #pylint:disable=too-many-locals,too-many-statements
        contacts_queryset = self.filter_queryset(self.get_queryset())
        contacts_page = self.paginate_queryset(contacts_queryset)
        # XXX When we use a `rest_framework.PageNumberPagination`,
        # it will hold a reference to the page created by a `DjangoPaginator`.
        # The `LimitOffsetPagination` paginator holds its own count.
        if hasattr(self.paginator, 'page'):
            contacts_count = self.paginator.page.paginator.count
        else:
            contacts_count = self.paginator.count

        users_queryset = self.filter_queryset(self.get_users_queryset())
        users_page = self.paginate_queryset(users_queryset)
        # Since we run a second `paginate_queryset`, the paginator.count
        # is not the number of users.
        if hasattr(self.paginator, 'page'):
            self.paginator.page.paginator.count += contacts_count
        else:
            self.paginator.count += contacts_count

        order_func = get_order_func(filters.OrderingFilter().get_ordering(
            self.request, contacts_queryset, self))

        # XXX merge `users_page` into page.
        page = []
        user = None
        contact = None
        users_iterator = iter(users_page)
        contacts_iterator = iter(contacts_page)
        try:
            contact = next(contacts_iterator)
        except StopIteration:
            pass
        try:
            user = self.as_contact(next(users_iterator))
        except StopIteration:
            pass
        try:
            while contact and user:
                if order_func(contact, user):
                    page += [contact]
                    contact = None
                    contact = next(contacts_iterator)
                elif order_func(user, contact):
                    page += [user]
                    user = None
                    user = self.as_contact(next(users_iterator))
                else:
                    page += [contact]
                    contact = None
                    contact = next(contacts_iterator)
                    page += [user]
                    user = None
                    user = self.as_contact(next(users_iterator))
        except StopIteration:
            pass
        try:
            while contact:
                page += [contact]
                contact = next(contacts_iterator)
        except StopIteration:
            pass
        try:
            while user:
                page += [user]
                user = self.as_contact(next(users_iterator))
        except StopIteration:
            pass

        # XXX It could be faster to stop previous loops early but it is not
        # clear. The extra check at each iteration might in fact be slower.
        page = page[:api_settings.PAGE_SIZE]

        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def perform_create(self, serializer):
        with transaction.atomic():
            try:
                user = User.objects.get(
                    email=serializer.validated_data.get('email'))
            except User.DoesNotExist:
                user = None
            serializer.save(user=user)


class PasswordChangeAPIView(UpdateAPIView):
    """
    Changes the password for a user.

    **Tags: auth

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

    **Tags: profile

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
