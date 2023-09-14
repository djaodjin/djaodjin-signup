# Copyright (c) 2023, DjaoDjin inc.
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

import hashlib, logging, os, re

import pyotp
from django.contrib.auth import logout as auth_logout
from django.db import transaction, IntegrityError
from django.contrib.auth import update_session_auth_hash, get_user_model
from rest_framework import generics, parsers, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.settings import api_settings


from .. import filters, settings
from ..backends.auth_ldap import is_ldap_user, set_ldap_password
from ..compat import (force_str, gettext_lazy as _, reverse, six,
    urlparse, urlunparse)
from ..decorators import check_has_credentials
from ..docs import OpenAPIResponse, no_body, swagger_auto_schema
from ..helpers import full_name_natural_split
from ..mixins import AuthenticatedUserPasswordMixin, ContactMixin, UserMixin
from ..models import (Contact, Credentials, Notification, OTPGenerator,
    get_disabled_email_update)
from ..serializers_overrides import UserSerializer, UserDetailSerializer
from ..serializers import (OTPSerializer, OTPUpdateSerializer,
    PasswordChangeSerializer, NotificationsSerializer, UploadBlobSerializer,
    UserCreateSerializer, ValidationErrorSerializer)
from ..utils import get_picture_storage, handle_uniq_error


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


class UserActivateAPIView(ContactMixin, generics.GenericAPIView):
    """
    Sends an activation link

    Re-sends an activation e-mail if the user is not already activated.

    The template for the e-mail sent to the user can be found in
    notification/verification.eml.

    **Tags: auth, user, usermodel

    **Example

    .. code-block:: http

        POST /api/users/donny/activate HTTP/1.1

    responds

    .. code-block:: json

        {
            "slug": "xia",
            "username": "xia",
            "printable_name": "Xia",
            "full_name": "Xia Lee",
            "nick_name": "Xia",
            "email": "xia@locahost.localdomain",
            "created_at": "2018-01-01T00:00:00Z"
        }
    """
    serializer_class = UserDetailSerializer
    queryset = Contact.objects.all().select_related('user')

    @swagger_auto_schema(request_body=no_body, responses={
        201: OpenAPIResponse("success", UserDetailSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):#pylint:disable=unused-argument
        instance = self.get_object()
        if check_has_credentials(request, instance.user):
            raise ValidationError({'detail': _("User is already active")})
        serializer = self.get_serializer(instance.user)
        resp_data = serializer.data
        resp_data.update({
            'detail': _("Activation e-mail successfuly sent to %(email)s") % {
                'email': instance.email}
        })
        return Response(resp_data)


class UserDetailAPIView(UserMixin, generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieves a user account

    Retrieves details on one single user account with slug ``{user}``.

    The API is typically used within an HTML
    `contact information page </docs/guides/themes/#dashboard_profile>`_
    as present in the default theme.

    **Tags: profile, user, usermodel

    **Examples

    .. code-block:: http

        GET /api/users/xia HTTP/1.1

    responds

    .. code-block:: json

        {
            "slug": "xia",
            "username": "xia",
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
    serializer_class = UserDetailSerializer

    def get_object(self):
        return self.user

    def put(self, request, *args, **kwargs):
        """
        Updates a user account

        The API is typically used within an HTML
        `contact information page </docs/guides/themes/#dashboard_profile>`_
        as present in the default theme.

        **Tags: profile, user, usermodel

        **Examples

        .. code-block:: http

            PUT /api/users/xia HTTP/1.1

        .. code-block:: json

            {
              "email": "xia@locahost.localdomain",
              "full_name": "Xia Lee",
              "nick_name": "Xia"
            }

        responds

        .. code-block:: json

            {
              "slug": "xia",
              "username": "xia",
              "created_at": "2018-01-01T00:00:00Z",
              "printable_name": "Xia",
              "full_name": "Xia Lee",
              "nick_name": "Xia",
              "email": "xia@locahost.localdomain"
            }
        """
        return self.update(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        """
        Updates a user account

        The API is typically used within an HTML
        `contact information page </docs/guides/themes/#dashboard_profile>`_
        as present in the default theme.

        **Tags: profile, user, usermodel

        **Examples

        .. code-block:: http

            PATCH /api/users/xia HTTP/1.1

        .. code-block:: json

            {
              "email": "xia@locahost.localdomain",
              "full_name": "Xia Lee",
              "nick_name": "Xia"
            }

        responds

        .. code-block:: json

            {
              "slug": "xia",
              "username": "xia",
              "created_at": "2018-01-01T00:00:00Z",
              "printable_name": "Xia",
              "full_name": "Xia Lee",
              "nick_name": "Xia",
              "email": "xia@locahost.localdomain"
            }
        """
        return self.partial_update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a user account

        The API is typically used within an HTML
        `contact information page </docs/guides/themes/#dashboard_profile>`_
        as present in the default theme.

        **Tags: profile, user, usermodel

        **Examples

        .. code-block:: http

            DELETE /api/users/xia HTTP/1.1
        """
        return self.destroy(request, *args, **kwargs)

    def perform_destroy(self, instance):
        user = instance
        email = user.email
        username = user.username
        if user.pk:
            # We mark the user as inactive and scramble personal information
            # such that we don't remove audit records (ex: billing transactions)
            # from the database.
            pkid = user.pk
            slug = '_archive_%d' % pkid
            LOGGER.info("%s deleted user profile for '%s <%s>' (%s).",
                self.request.user, username, email, slug, extra={
                    'event': 'delete', 'request': self.request,
                    'username': username, 'email': email, 'pk': pkid})
            look = re.match(r'.*(@\S+)', settings.DEFAULT_FROM_EMAIL)
            if look:
                email = '%s%s' % (slug, look.group(1))
            # We are deleting a `User` model. Let's unlink the `Contact`
            # info but otherwise leave the poor-man's CRM's data intact.
            with transaction.atomic():
                user.contacts.all().update(user=None)
                self.delete_records(user)
                requires_logout = (self.request.user == user)
                user.username = slug
                user.email = email
                user.password = '!'
                user.is_active = False
                user.save()
                if requires_logout:
                    auth_logout(self.request)
        else:
            contacts = Contact.objects.filter(
                slug=self.kwargs.get(self.lookup_url_kwarg))
            if contacts:
                for contact in contacts:
                    LOGGER.info("%s deleted contact for '%s <%s>'.",
                        self.request.user, contact.full_name, contact.email,
                        extra={'event': 'delete', 'request': self.request,
                            'full_name': contact.full_name,
                            'email': contact.email, 'pk': contact.pk})
                contacts.delete()

    def delete_records(self, user):
        user.notifications.all().delete()
        if Credentials.objects.filter(user=user).exists():
            user.credentials.delete()


    def perform_update(self, serializer):
        update_fields = {}
        slug = serializer.validated_data.get('slug',
            serializer.validated_data.get('username'))
        if slug:
            update_fields.update({'slug': slug})
        full_name = serializer.validated_data.get('full_name',
            serializer.validated_data.get('get_full_name'))
        if full_name:
            update_fields.update({'full_name': full_name})
        nick_name = serializer.validated_data.get('nick_name',
            serializer.validated_data.get('get_nick_name'))
        if nick_name:
            update_fields.update({'nick_name': nick_name})
        phone = serializer.validated_data.get('phone',
            serializer.validated_data.get('get_phone'))
        if phone:
            update_fields.update({'phone': phone})
        lang = serializer.validated_data.get('lang',
            serializer.validated_data.get('get_lang'))
        if lang:
            update_fields.update({'lang': lang})
        with transaction.atomic():
            user = self.get_object()
            try:
                if user.pk:
                    update_fields.update({'user': user})
                    if slug:
                        user.username = slug
                    if full_name:
                        first_name, mid_name, last_name = \
                            full_name_natural_split(
                                full_name, middle_initials=False)
                        user.first_name = first_name
                        if mid_name:
                            user.first_name = (
                                first_name + " " + mid_name).strip()
                        user.last_name = last_name
                    if get_disabled_email_update(user):
                        serializer.validated_data.pop('email')
                    else:
                        email = serializer.validated_data.get('email')
                        if email:
                            user.email = email
                    user.save()
                    update_fields.update({'email': user.email})
                if 'email' not in update_fields:
                    email = serializer.validated_data.get('email')
                    if email:
                        update_fields.update({'email': email})
                Contact.objects.update_or_create(
                    slug=self.kwargs.get(self.lookup_url_kwarg),
                    defaults=update_fields)
            except IntegrityError as err:
                handle_uniq_error(err)
        # A little patchy but it works. Otherwise we would need to override
        # `update` as well.
        #pylint:disable=pointless-statement,protected-access
        serializer.data
        serializer._data.update({'detail': _("Profile updated.")})


class UserListMixin(object):

    search_fields = (
        'email',
        # fields in User model:
        'username',
    )
    ordering_fields = (
        ('full_name', 'full_name'),
        ('created_at', 'created_at'),
        ('date_joined', 'date_joined'),
    )
    ordering = ('full_name',)
    alternate_ordering = ('first_name', 'last_name')

    filter_backends = (filters.SearchFilter, filters.OrderingFilter)
    serializer_class = UserSerializer
    queryset = Contact.objects.all().select_related('user')
    user_queryset = get_user_model().objects.filter(is_active=True)

    def as_user(self, contact):
        user_model = self.user_queryset.model
        #pylint:disable=unused-variable
        first_name, unused, last_name = full_name_natural_split(
            contact.full_name)
        return user_model(username=contact.slug, email=contact.email,
            first_name=first_name, last_name=last_name)

    def get_users_queryset(self):
        return self.user_queryset.filter(contacts__isnull=True)

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
            self.request, users_queryset, self))

        # XXX merge `users_page` into page.
        page = []
        user = None
        contact = None
        users_iterator = iter(users_page)
        contacts_iterator = iter(contacts_page)
        try:
            contact = self.as_user(next(contacts_iterator))
        except StopIteration:
            pass
        try:
            user = next(users_iterator)
        except StopIteration:
            pass
        try:
            while contact and user:
                if order_func(contact, user):
                    page += [contact]
                    contact = None
                    contact = self.as_user(next(contacts_iterator))
                elif order_func(user, contact):
                    page += [user]
                    user = None
                    user = next(users_iterator)
                else:
                    page += [contact]
                    contact = None
                    contact = self.as_user(next(contacts_iterator))
                    page += [user]
                    user = None
                    user = next(users_iterator)
        except StopIteration:
            pass
        try:
            while contact:
                page += [contact]
                contact = self.as_user(next(contacts_iterator))
        except StopIteration:
            pass
        try:
            while user:
                page += [user]
                user = next(users_iterator)
        except StopIteration:
            pass

        # XXX It could be faster to stop previous loops early but it is not
        # clear. The extra check at each iteration might in fact be slower.
        page = page[:api_settings.PAGE_SIZE]

        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class UserListCreateAPIView(UserListMixin, generics.ListCreateAPIView):
    """
    Lists user accounts

    Returns a list of {{PAGE_SIZE}} profile and user accounts.

    The queryset can be filtered for at least one field to match a search
    term (``q``).

    The queryset can be ordered by a field by adding an HTTP query parameter
    ``o=`` followed by the field name. A sequence of fields can be used
    to create a complete ordering by adding a sequence of ``o`` HTTP query
    parameters. To reverse the natural order of a field, prefix the field
    name by a minus (-) sign.

    **Tags: profile, broker, usermodel

    **Example

    .. code-block:: http

        GET /api/users?q=xia HTTP/1.1

    responds

    .. code-block:: json

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
              "slug": "xia",
              "username": "xia",
              "printable_name": "Xia"
            }]
        }
    """
    def get_serializer_class(self):
        if self.request.method.lower() == 'post':
            return UserCreateSerializer
        return super(UserListCreateAPIView, self).get_serializer_class()

    @swagger_auto_schema(responses={
        201: OpenAPIResponse("success", UserDetailSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def post(self, request, *args, **kwargs):
        """
        Creates a user account

        **Tags: profile, broker, usermodel

        **Examples

        .. code-block:: http

            POST /api/users HTTP/1.1

        .. code-block:: json

            {
              "full_name": "Xia Lee",
              "nick_name": "Xia",
              "email": "xia@locahost.localdomain"
            }

        responds

        .. code-block:: json

            {
              "slug": "xia",
              "username": "xia",
              "created_at": "2018-01-01T00:00:00Z",
              "printable_name": "Xia",
              "full_name": "Xia Lee",
              "nick_name": "Xia",
              "email": "xia@locahost.localdomain"
            }
        """
        return self.create(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        #pylint:disable=too-many-locals
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_model = self.user_queryset.model
        slug = serializer.validated_data.get('slug',
            serializer.validated_data.get('username'))
        full_name = serializer.validated_data.get('full_name',
            serializer.validated_data.get('get_full_name'))
        nick_name = serializer.validated_data.get('nick_name')
        if not nick_name:
            #pylint:disable=unused-variable
            nick_name, unused1, unused2 = full_name_natural_split(
                full_name, middle_initials=False)
        phone = serializer.validated_data.get('phone',
            serializer.validated_data.get('get_phone'))
        lang = serializer.validated_data.get('lang',
            serializer.validated_data.get('get_lang'))
        with transaction.atomic():
            try:
                user = user_model.objects.get(
                    email__iexact=serializer.validated_data.get('email'))
            except user_model.DoesNotExist:
                user = None
            try:
                contact = Contact.objects.create(
                    slug=slug,
                    full_name=full_name,
                    nick_name=nick_name,
                    email=serializer.validated_data.get('email'),
                    phone=phone,
                    lang=lang,
                    user=user)
                if not user:
                    user = self.as_user(contact)
            except IntegrityError as err:
                handle_uniq_error(err)

        location = self.request.build_absolute_uri(
            reverse('api_user_profile', args=(user,)))
        return Response(UserDetailSerializer().to_representation(user),
            status=status.HTTP_201_CREATED, headers={'Location': location})


class ActivityByAccountContactAPIView(UserListMixin, generics.ListAPIView):
    """
    Lists contacts for activities on an account

    Returns a list of {{PAGE_SIZE}} contacts for activities on {account}.

    **Tags: profile, broker, usermodel

    **Example

    .. code-block:: http

        GET /api/activities/xia/contacts HTTP/1.1

    responds

    .. code-block:: json

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
              "slug": "xia",
              "username": "xia",
              "printable_name": "Xia"
            }]
        }
    """
    account_url_kwarg = 'profile'

    def get_queryset(self):
        return Contact.objects.filter(activities__account__slug=self.kwargs.get(
            self.account_url_kwarg)).select_related('user')


class OTPChangeAPIView(AuthenticatedUserPasswordMixin,
                       UserMixin, generics.GenericAPIView):

    serializer_class = OTPUpdateSerializer

    def get_issuer_name(self):
        return None

    def get_queryset(self):
        return OTPGenerator.objects.filter(user=self.user)

    @swagger_auto_schema(responses={
        200: OpenAPIResponse("success", OTPSerializer),
        201: OpenAPIResponse("success", OTPSerializer),
        400: OpenAPIResponse("parameters error", ValidationErrorSerializer)})
    def put(self, request, *args, **kwargs):
        """
        Enables multi-factor authentication

        Enables multi-factor authentication, through either an OTP one-time
        code, email verification, phone verification or any combination
        of the above.

        To disable any of the MFA requirements, pass a `false` value for
        its respective field.

        The API is typically used within an HTML
        `update password page </docs/guides/themes/#dashboard_users_password>`_
        as present in the default theme.

        **Tags: auth, user, usermodel

        **Example

        .. code-block:: http

            POST /api/users/xia/otp HTTP/1.1

        .. code-block:: json

            {
              "password": "yoyo",
              "otp_enabled": true,
              "email_verification_enabled": false,
              "phone_verification_enabled": false
            }

        responds

        .. code-block:: json

            {
              "priv_key": "**********************",
              "provisioning_uri": "https://localhost:8020/"
            }
        """
        #pylint:disable=unused-argument
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.re_auth(request, serializer.validated_data)

        if serializer.validated_data.get('otp_enabled'):
            otp, created = OTPGenerator.objects.get_or_create(
                user=self.user, defaults={
                    'priv_key': pyotp.random_base32()
                })

            return Response(OTPSerializer().to_representation({
                'priv_key': otp.priv_key,
                'provisioning_uri': otp.provisioning_uri(
                    issuer_name=self.get_issuer_name())
            }), status=(status.HTTP_201_CREATED
                if created else status.HTTP_200_OK))

        try:
            OTPGenerator.objects.get(user=self.user).delete()
        except OTPGenerator.DoesNotExist:
            pass

        return Response(status=status.HTTP_204_NO_CONTENT)


class PasswordChangeAPIView(AuthenticatedUserPasswordMixin,
                            generics.GenericAPIView):
    """
    Updates a user password
    """
    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    serializer_class = PasswordChangeSerializer
    queryset = get_user_model().objects.filter(is_active=True)

    @swagger_auto_schema(responses={
        200: OpenAPIResponse("success", ValidationErrorSerializer)})
    def put(self, request, *args, **kwargs):
        """
        Updates a user password

        Sets a new password for a user. Any or a combination of
        the HTTP request user secrets must be passed along for authorization.

        The API is typically used within an HTML
        `update password page </docs/guides/themes/#dashboard_users_password>`_
        as present in the default theme.

        **Tags: auth, user, usermodel

        **Example

        .. code-block:: http

            PUT /api/users/xia/password HTTP/1.1

        .. code-block:: json

            {
              "password": "yoyo",
              "new_password": "yeye"
            }

        responds

        .. code-block:: json

            {
              "detail": "Password updated successfully."
            }
        """
        #pylint:disable=unused-argument
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']
        new_password = serializer.validated_data.get('new_password')
        if new_password:
            if is_ldap_user(serializer.instance):
                set_ldap_password(serializer.instance, new_password,
                    bind_password=password)
            else:
                self.re_auth(request, serializer.validated_data)

                serializer.instance.set_password(new_password)
                serializer.instance.save()
            # Updating the password logs out all other sessions for the user
            # except the current one if
            # django.contrib.auth.middleware.SessionAuthenticationMiddleware
            # is enabled.
            update_session_auth_hash(self.request, serializer.instance)

        return Response({'detail': _("Password updated successfully.")})


class UserNotificationsAPIView(UserMixin, generics.RetrieveUpdateAPIView):
    """
    Lists a user notifications preferences

    The API is typically used within an HTML
    `notifications page </docs/guides/themes/#dashboard_users_notifications>`_
    as present in the default theme.

    **Tags: profile, user, usermodel

    **Example

    .. code-block:: http

        GET /api/users/xia/notifications HTTP/1.1

    responds

    .. code-block:: json

        {
          "notifications": ["user_registered_notice"]
        }
    """
    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    queryset = get_user_model().objects.filter(is_active=True)
    serializer_class = NotificationsSerializer

    def put(self, request, *args, **kwargs):
        """
        Updates a user notifications preferences

        The API is typically used within an HTML
        `notifications page </docs/guides/themes/#dashboard_users_notifications>`_
        as present in the default theme.

        **Tags: profile, user, usermodel

        **Example

        .. code-block:: http

            PUT /api/users/xia/notifications HTTP/1.1

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
        return self.update(request, *args, **kwargs)


    def retrieve(self, request, *args, **kwargs):
        notification_slugs = self.user.notifications.values_list(
            'slug', flat=True)
        notifications = []
        for notification_slug in six.iterkeys(self.get_notifications(
                    user=self.user)):
            enabled = (notification_slug in notification_slugs)
            if settings.NOTIFICATIONS_OPT_OUT:
                if not enabled:
                    notifications += [notification_slug]
            else:
                if enabled:
                    notifications += [notification_slug]
        return Response({'notifications': notifications})

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        serializer = self.get_serializer(
            self.user, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return self.retrieve(request, *args, **kwargs)

    def perform_update(self, serializer):
        notification_slugs = serializer.validated_data.get('notifications', [])
        with transaction.atomic():
            self.user.notifications.clear()
            for notification_slug in six.iterkeys(self.get_notifications(
                    user=self.user)):
                enabled = (notification_slug in notification_slugs)
                #pylint:disable=unused-variable
                notification, notused = Notification.objects.get_or_create(
                    slug=notification_slug)
                if settings.NOTIFICATIONS_OPT_OUT:
                    if not enabled:
                        self.user.notifications.add(notification)
                else:
                    if enabled:
                        self.user.notifications.add(notification)


class UserPictureAPIView(ContactMixin, generics.CreateAPIView):
    """
    Uploads a picture for a user account

    The API is typically used within an HTML
    `contact information page </docs/guides/themes/#dashboard_profile>`_
    as present in the default theme.

    **Examples

    .. code-block:: http

    POST /api/users/xia/picture HTTP/1.1

    responds

    .. code-block:: json

        {
            "location": "https://cowork.net/picture.jpg"
        }
    """
    parser_classes = (parsers.FormParser, parsers.MultiPartParser)
    serializer_class = UploadBlobSerializer

    def post(self, request, *args, **kwargs):
        #pylint:disable=unused-argument
        uploaded_file = request.data.get('file')
        if not uploaded_file:
            return Response({'detail': _("no location or file specified.")},
                status=status.HTTP_400_BAD_REQUEST)

        # tentatively extract file extension.
        parts = os.path.splitext(
            force_str(uploaded_file.name.replace('\\', '/')))
        ext = parts[-1].lower() if len(parts) > 1 else ""
        key_name = "%s%s" % (
            hashlib.sha256(uploaded_file.read()).hexdigest(), ext)
        default_storage = get_picture_storage(request)

        LOGGER.debug("upload picture to %s on storage %s",
            key_name, default_storage)
        location = default_storage.url(
            default_storage.save(key_name, uploaded_file))
        # We are removing the query parameters, as they contain
        # signature information, not the relevant URL location.
        parts = urlparse(location)
        location = urlunparse((parts.scheme, parts.netloc, parts.path,
            "", "", ""))
        location = self.request.build_absolute_uri(location)
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
        return Response(self.get_serializer().to_representation(
            {'location': location}), status=status.HTTP_201_CREATED)
