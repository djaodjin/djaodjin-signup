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

import logging

from django.core import validators
from django.contrib.auth import get_user_model
import phonenumbers
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .compat import gettext_lazy as _
from .models import Activity, Notification
from .serializers_overrides import UserSerializer
from .utils import (get_account_model, get_account_serializer,
    get_user_serializer, has_invalid_password)
from .validators import (validate_email_or_phone,
    validate_username_or_email_or_phone)

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


class CommField(serializers.CharField):
    """
    Either an e-mail address or a phone number
    """
    default_error_messages = {
        'invalid': _('Enter a valid email address or phone number.')
    }

    def __init__(self, **kwargs):
        super(CommField, self).__init__(**kwargs)
        self.validators.append(validate_email_or_phone)


class UsernameOrCommField(serializers.CharField):
    """
    Either a username, e-mail address or a phone number
    """
    default_error_messages = {
        'invalid': _('Enter a valid username, email address or phone number.')
    }

    def __init__(self, **kwargs):
        super(UsernameOrCommField, self).__init__(**kwargs)
        self.validators.append(validate_username_or_email_or_phone)


class NoModelSerializer(serializers.Serializer):

    def create(self, validated_data):
        raise RuntimeError('`create()` should not be called.')

    def update(self, instance, validated_data):
        raise RuntimeError('`update()` should not be called.')


class ActivateSerializer(serializers.ModelSerializer):

    username = serializers.CharField(required=False,
        help_text=_("Username to identify the account"))
    new_password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'}, help_text=_("Password with which"\
            " a user can authenticate with the service"))
    full_name = serializers.CharField(required=False,
        help_text=_("Full name (effectively first name followed by last name)"))

    class Meta:
        model = get_user_model()
        fields = ('username', 'new_password', 'full_name')


class ActivitySerializer(serializers.ModelSerializer):

    account = get_account_serializer()(allow_null=True,
        help_text=_("Account the activity is associated to"))
    created_by = get_user_serializer()(read_only=True,
        help_text=_("User that created the activity"))

    class Meta:
        model = Activity
        fields = ('created_at', 'created_by', 'text', 'account')
        read_only_fields = ('created_at', 'created_by')


class ActivityCreateSerializer(serializers.ModelSerializer):

    account = serializers.SlugRelatedField(allow_null=True,
        slug_field='slug', queryset=get_account_model().objects.all(),
        help_text=_("Account the activity is associated to"))

    class Meta:
        model = Activity
        fields = ('text', 'account')


class AuthenticatedUserPasswordSerializer(NoModelSerializer):

    password = serializers.CharField(write_only=True,
        style={'input_type': 'password'},
        help_text=_("Password of the user making the HTTP request"))

    class Meta:
        fields = ('password',)


class APIKeysSerializer(NoModelSerializer):
    """
    username and password for authentication through API.
    """
    secret = serializers.CharField(max_length=128, read_only=True,
        help_text=_("Secret API Key used to authenticate user on every HTTP"\
        " request"))

    class Meta:
        fields = ('secret',)


class PublicKeySerializer(AuthenticatedUserPasswordSerializer):
    """
    Updates a user public key
    """
    pubkey = serializers.CharField(max_length=500,
        style={'input_type': 'password'},
        help_text=_("New public key for the user referenced in the URL"))


class StringListField(serializers.ListField):
    child = serializers.CharField()


class NotificationsSerializer(serializers.ModelSerializer):

    notifications = StringListField(allow_empty=True,
        help_text=_("List of notifications from %s") %
            ', '.join([item[0] for item in Notification.NOTIFICATION_TYPE]))

    class Meta:
        model = get_user_model()
        fields = ('notifications',)


class CredentialsSerializer(NoModelSerializer):
    """
    username and password for authentication through API.
    """
    username = UsernameOrCommField(
        help_text=_("Username, e-mail address or phone number to identify"\
        " the account"))
    password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'},
        help_text=_("Secret password for the account"))
    code = serializers.IntegerField(required=False, write_only=True,
        style={'input_type': 'password'},
        help_text=_("One-time code. This field will be checked against"\
            " an expected code when multi-factor authentication (MFA)"\
            " is enabled."))


class PasswordResetConfirmSerializer(NoModelSerializer):

    new_password = serializers.CharField(write_only=True,
        style={'input_type': 'password'},
        help_text=_("New password for the user referenced in the URL"))


class PasswordChangeSerializer(PasswordResetConfirmSerializer):

    password = serializers.CharField(write_only=True,
        style={'input_type': 'password'},
        help_text=_("Password of the user making the HTTP request"))


class PasswordResetSerializer(NoModelSerializer):
    """
    Serializer to send an e-mail to a user in order to recover her account.
    """
    email = CommField(
        help_text=_("Email or phone number to recover the account"))


class TokenSerializer(NoModelSerializer):
    """
    token to verify or refresh.
    """
    token = serializers.CharField(
        help_text=_("Token used to authenticate user on every HTTP request"))


class ValidationErrorSerializer(NoModelSerializer):
    """
    Details on why token is invalid.
    """
    detail = serializers.CharField(help_text=_("Describes the reason for"\
        " the error in plain text"))


class UploadBlobSerializer(NoModelSerializer):
    """
    Upload a picture or other POD content
    """
    location = serializers.URLField(
        help_text=_("URL to uploaded content"))


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
        return hasattr(obj, 'pk') and (not has_invalid_password(obj))


class UserCreateSerializer(UserDetailSerializer):

    username = serializers.CharField(required=False,
        help_text=_("Unique identifier for the user, typically used in URLs"))
    password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'}, help_text=_("Password with which"\
            " a user can authenticate with the service"))
    full_name = serializers.CharField(
        help_text=_("Full name (effectively first name followed by last name)"))

    class Meta(UserDetailSerializer.Meta):
        fields = UserDetailSerializer.Meta.fields + ('password',)

    def validate(self, attrs):
        if not (attrs.get('email') or
            attrs.get('phone', attrs.get('get_phone'))):
            raise ValidationError(
                {'email': _("Either email or phone must be valid."),
                 'phone': _("Either email or phone must be valid.")})
        return super(UserCreateSerializer, self).validate(attrs)
