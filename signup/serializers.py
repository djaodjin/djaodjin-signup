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
from .utils import get_account_model, has_invalid_password
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
            except phonenumbers.NumberParseException:
                LOGGER.info("tel %s:%s", data, err)
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


class ActivateUserSerializer(serializers.ModelSerializer):

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

    account = serializers.SlugRelatedField(allow_null=True,
        slug_field='slug', queryset=get_account_model().objects.all(),
        help_text=_("Account the activity is associated to"))
    created_by = serializers.SlugRelatedField(
        read_only=True, slug_field='username',
        help_text=_("User that created the activity"))

    class Meta:
        model = Activity
        fields = ('created_at', 'created_by', 'text', 'account')
        read_only_fields = ('created_at', 'created_by')


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
        help_text=_("Username"))
    username = serializers.CharField(validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')],
        help_text=_("Username"))
    printable_name = serializers.CharField(source='get_full_name',
        read_only=True,
        help_text=_("Name that can be safely used for display in HTML pages"))
    picture = serializers.SerializerMethodField(read_only=True,
        help_text=_("URL location of the profile picture"))
    email = serializers.EmailField(
        help_text=_("Primary e-mail to contact user"), required=False)
    created_at = serializers.DateTimeField(source='date_joined',
        read_only=True,
        help_text=_("date at which the account was created"))
    credentials = serializers.SerializerMethodField(read_only=True,
        help_text=_("True if the user has valid login credentials"))

    class Meta:
        model = get_user_model()
        fields = ('slug', 'username', 'printable_name', 'created_at', 'picture',
            'email', 'credentials', 'last_login')
        read_only_fields = ('printable_name', 'created_at', 'credentials',
            'last_login')

    @staticmethod
    def get_credentials(obj):
        return hasattr(obj, 'pk') and (not has_invalid_password(obj))

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
    def get_nick_name(obj):
        if hasattr(obj, 'nick_name'):
            return obj.nick_name
        opk = obj.pk if hasattr(obj, 'pk') else None
        if opk:
            contact = obj.contacts.filter(nick_name__isnull=False).order_by(
                'created_at').first()
            if contact:
                return contact.nick_name
        return obj.first_name


class UserDetailSerializer(UserSerializer):
    """
    This serializer is used in APIs where a single Contact/User
    profile is returned.

    For a summary profile, see `UserSerializer`.
    """
    slug = serializers.CharField(source='username', required=False,
        validators=[validators.RegexValidator(
            r'^[\w.@+-]+$', _("Enter a valid username."), 'invalid')],
        help_text=_("Username"))
    full_name = serializers.CharField(source='get_full_name',
        help_text=_("Full name (effectively first name followed by last name)"))
    nick_name = serializers.SerializerMethodField(required=False,
        help_text=_("Short casual name used to address the user"))
    phone = PhoneField(
        help_text=_("Primary phone number to contact user"), required=False)
    lang = serializers.CharField(
        help_text=_("Preferred communication language"), required=False)
    # XXX username and full_name are duplicates of slug and printable_name
    # respectively. They are still included in this version for backward
    # compatibility.
    username = serializers.CharField(read_only=True,
        validators=[validators.RegexValidator(
            r'^[\w.@+-]+$', _("Enter a valid username."), 'invalid')],
        help_text=_("Username"))

    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + ('phone',
            'full_name', 'nick_name', 'lang',)


class UserCreateSerializer(UserDetailSerializer):

    username = serializers.CharField(required=False,
        help_text=_("Username to identify the account"))
    password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'}, help_text=_("Password with which"\
            " a user can authenticate with the service"))
    full_name = serializers.CharField(
        help_text=_("Full name (effectively first name followed by last name)"))

    class Meta(UserDetailSerializer.Meta):
        fields = UserDetailSerializer.Meta.fields + ('password',)

    def validate(self, attrs):
        if not (attrs.get('email') or attrs.get('phone')):
            raise ValidationError(
                {'email': _("Either email or phone must be valid."),
                 'phone': _("Either email or phone must be valid.")})
        return super(UserCreateSerializer, self).validate(attrs)
