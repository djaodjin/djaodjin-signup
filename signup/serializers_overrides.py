# Copyright (c) 2022, DjaoDjin inc.
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
"""
Default implementation when not overriden
"""

from __future__ import unicode_literals

import logging

from django.core import validators
from django.contrib.auth import get_user_model
import phonenumbers
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .compat import gettext_lazy as _
from .helpers import has_invalid_password


LOGGER = logging.getLogger(__name__)


class PhoneField(serializers.Field):

    def to_representation(self, value):
        return str(value)

    def to_internal_value(self, data):
        """
        Returns a formatted phone number as a string.
        """
        try:
            phone_number = phonenumbers.parse(data, None)
        except phonenumbers.NumberParseException as err:
            LOGGER.info("tel %s:%s", data, err)
            phone_number = None
        if not phone_number:
            try:
                phone_number = phonenumbers.parse(data, "US")
            except phonenumbers.NumberParseException as err:
                LOGGER.info("tel (defaults to US) %s:%s", data, err)
                phone_number = None

        if not phone_number:
            if self.required:
                raise ValidationError(self.error_messages['required'])
            return None

        if not phonenumbers.is_valid_number(phone_number):
            raise ValidationError(self.error_messages['invalid'])
        return phonenumbers.format_number(
            phone_number, phonenumbers.PhoneNumberFormat.E164)


class UserSerializer(serializers.ModelSerializer):
    """
    This serializer is used in lists and other places where a Contact/User
    profile is referenced. Its intent is to facilitate composition of this App
    with other Django Apps which references a `django.contrib.auth.User model`.

    For a detailed profile, see `UserDetailSerializer`.
    """
    # Only way I found out to remove the ``UniqueValidator``. We are not
    # interested to create new instances here.
    slug = serializers.CharField(source='username', validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')],
        help_text=_("Unique identifier that can safely be used"\
            " in place of username"))
    username = serializers.CharField(validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')],
        help_text=_("Unique identifier for the user, typically used in URLs"))
    printable_name = serializers.SerializerMethodField(read_only=True,
        help_text=_("Name that can be safely used for display in HTML pages"))
    picture = serializers.SerializerMethodField(read_only=True,
        help_text=_("URL location of the profile picture"))

    class Meta:
        model = get_user_model()
        fields = ('slug', 'username', 'printable_name', 'picture',)
        read_only_fields = ('printable_name', 'picture',)

    @staticmethod
    def get_picture(obj):
        if hasattr(obj, 'picture'):
            return obj.picture
        opk = obj.pk if hasattr(obj, 'pk') else None
        if opk:
            contact = obj.contacts.filter(picture__isnull=False).order_by(
                'created_at').first()
            if contact:
                return contact.picture
        return None

    @staticmethod
    def get_printable_name(obj):
        printable_name = None
        if hasattr(obj, 'nick_name'):
            printable_name = obj.nick_name
        if printable_name:
            return printable_name
        if hasattr(obj, 'full_name'):
            printable_name = obj.full_name
        if printable_name:
            return printable_name
        if isinstance(obj, get_user_model()):
            opk = obj.pk if hasattr(obj, 'pk') else None
            if opk:
                contact = obj.contacts.filter(nick_name__isnull=False).order_by(
                    'created_at').first()
                if contact:
                    printable_name = contact.nick_name
            if printable_name:
                return printable_name
            printable_name = obj.get_full_name()
            if printable_name:
                return printable_name
            return obj.username
        if hasattr(obj, 'slug'):
            printable_name = obj.slug
        return printable_name


class UserDetailSerializer(UserSerializer):
    """
    This serializer is used in APIs where a single Contact/User
    profile is returned.

    For a summary profile, see `UserSerializer`.
    """
    # difference with `slug` definition in UserSerializer is `required=False`.
    slug = serializers.CharField(source='username', required=False, validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')],
        help_text=_("Unique identifier that can safely be used"\
            " in place of username"))

    # XXX username and full_name are duplicates of slug and printable_name
    # respectively. They are still included in this version for backward
    # compatibility.
    username = serializers.CharField(read_only=True,
        validators=[validators.RegexValidator(
            r'^[\w.@+-]+$', _("Enter a valid username."), 'invalid')],
        help_text=_("Unique identifier for the user, typically used in URLs"))

    full_name = serializers.CharField(source='get_full_name',
        help_text=_("Full name (effectively first name followed by last name)"))
    # Implementation Note: relies on patching of User class in models.py
    nick_name = serializers.CharField(source='get_nick_name', required=False,
        help_text=_("Short casual name used to address the user"))

    email = serializers.EmailField(required=False,
        help_text=_("Primary e-mail address to contact user"))
    phone = PhoneField(source='get_phone', required=False,
        help_text=_("Primary phone number to contact user"))
    lang = serializers.CharField(source='get_lang', required=False,
        help_text=_("Preferred communication language"))

    created_at = serializers.DateTimeField(source='date_joined', read_only=True,
        help_text=_("Date at which the user account was created"))
    last_login = serializers.DateTimeField(read_only=True,
        help_text=_("Date at which the user last logged in"))
    credentials = serializers.SerializerMethodField(read_only=True,
        help_text=_("True if the user has valid login credentials"))

    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + ('email', 'phone',
            'full_name', 'nick_name', 'lang',
            'credentials', 'created_at', 'last_login')
        read_only_fields = ('credentials', 'created_at', 'last_login')

    @staticmethod
    def get_credentials(obj):
        return ((isinstance(obj, get_user_model()) and
            hasattr(obj, 'pk') and (not has_invalid_password(obj))) or
            hasattr(obj, 'user') and obj.user and
                (not has_invalid_password(obj.user)))
