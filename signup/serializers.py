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

import logging

from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import NotAuthenticated, ValidationError

from .compat import gettext_lazy as _
from .models import Activity, Notification
from .serializers_overrides import UserDetailSerializer
from .utils import (get_account_model, get_account_serializer,
    get_user_serializer)
from .validators import (validate_email_or_phone,
    validate_username_or_email_or_phone)


LOGGER = logging.getLogger(__name__)


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


class AuthenticatedUserSerializer(NoModelSerializer):
    """
    All secrets can be optional during authentication such that we are able to
    raise a `ValidationError` when the authentication should proceed through
    a SSO provider for a particular user.
    """

    # If we define those fields in a Mixin, they don't show up
    # in the API documentation.
    password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'},
        help_text=_("Password of the user making the HTTP request"))
    otp_code = serializers.IntegerField(required=False, write_only=True,
        style={'input_type': 'password'},
        help_text=_("One-time code. This field will be checked against"\
            " an expected code when multi-factor authentication (MFA)"\
            " is enabled."))
    email_code = serializers.IntegerField(required=False, write_only=True,
        style={'input_type': 'password'},
        help_text=_("Email verification code."))
    phone_code = serializers.IntegerField(required=False, write_only=True,
        style={'input_type': 'password'},
        help_text=_("Phone verification code."))

    class Meta:
        fields = ('password', 'otp_code', 'email_code', 'phone_code')


class AuthenticatedUserPasswordSerializer(AuthenticatedUserSerializer):
    """
    We need at least on secret of the HTTP `request.user` to commit changes.
    """

    def validate(self, attrs):
        if not (attrs.get('password') or attrs.get('otp_code') or
            attrs.get('email_code') or attrs.get('phone_code')):
            raise NotAuthenticated(
                {'detail': _("At least one of password, otp_code,"\
                " email_code or phone_code must be present.")})
        return super(AuthenticatedUserPasswordSerializer, self).validate(attrs)

    class Meta(AuthenticatedUserSerializer.Meta):
        fields = ('password', 'otp_code', 'email_code', 'phone_code')


class APIKeysSerializer(NoModelSerializer):
    """
    username and password for authentication through API.
    """
    secret = serializers.CharField(max_length=128, read_only=True,
        help_text=_("Secret API Key used to authenticate user on every HTTP"\
        " request"))

    class Meta:
        fields = ('secret',)


class StringListField(serializers.ListField):
    child = serializers.CharField()


class NotificationsSerializer(serializers.ModelSerializer):

    notifications = StringListField(allow_empty=True,
        help_text=_("List of notifications from %s") %
            ', '.join([item[0] for item in Notification.NOTIFICATION_TYPE]))

    class Meta:
        model = get_user_model()
        fields = ('notifications',)


class CredentialsSerializer(AuthenticatedUserSerializer):
    """
    username and password for authentication through API.
    """
    username = UsernameOrCommField(
        help_text=_("Username, e-mail address or phone number to identify"\
        " the account"))

    class Meta(AuthenticatedUserSerializer.Meta):
        fields = AuthenticatedUserSerializer.Meta.fields + ('username',)


class OTPUpdateSerializer(AuthenticatedUserPasswordSerializer):
    """
    Returns sensitive information to setup OTP generator
    """
    otp_enabled = serializers.BooleanField(write_only=True,
        help_text=_("Enables/disables OTP"))
    email_verification_enabled = serializers.BooleanField(write_only=True,
        help_text=_("Enables/disables E-mail verification"))
    phone_verification_enabled = serializers.BooleanField(write_only=True,
        help_text=_("Enables/disables Phone verification"))

    class Meta(AuthenticatedUserPasswordSerializer.Meta):
        fields = AuthenticatedUserPasswordSerializer.Meta.fields + (
            'otp_enabled', 'email_verification_enabled',
            'phone_verification_enabled')


class OTPSerializer(NoModelSerializer):
    """
    Returns sensitive information to setup OTP generator
    """
    priv_key = serializers.CharField(
        help_text=_("Private key"))
    provisioning_uri = serializers.URLField(
        help_text=_("Provisioning URI"))

    class Meta:
        fields = ('priv_key', 'provisioning_uri')
        read_only_fields = ('priv_key', 'provisioning_uri')


class PublicKeySerializer(AuthenticatedUserPasswordSerializer):
    """
    Updates a user public key
    """
    pubkey = serializers.CharField(max_length=500,
        style={'input_type': 'password'},
        help_text=_("New public key for the user referenced in the URL"))


class PasswordChangeSerializer(AuthenticatedUserPasswordSerializer):

    new_password = serializers.CharField(write_only=True,
        style={'input_type': 'password'},
        help_text=_("New password for the user referenced in the URL"))

    class Meta(AuthenticatedUserPasswordSerializer.Meta):
        fields = AuthenticatedUserPasswordSerializer.Meta.fields + (
            'new_password',)


class RecoverSerializer(NoModelSerializer):
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


class UserCreateSerializer(UserDetailSerializer):

    username = serializers.CharField(required=False,
        help_text=_("Unique identifier for the user, typically used in URLs"))
    full_name = serializers.CharField(
        help_text=_("Full name (effectively first name followed by last name)"))
    new_password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'}, help_text=_("Password with which"\
            " a user can authenticate with the service"))

    class Meta(UserDetailSerializer.Meta):
        fields = UserDetailSerializer.Meta.fields + (
            'new_password',)

    def validate(self, attrs):
        if not (attrs.get('email') or
            attrs.get('phone', attrs.get('get_phone'))):
            raise ValidationError(
                {'email': _("Either email or phone must be valid."),
                 'phone': _("Either email or phone must be valid.")})
        return super(UserCreateSerializer, self).validate(attrs)


class UserActivateSerializer(UserCreateSerializer):

    new_password = serializers.CharField(required=True, write_only=True,
        style={'input_type': 'password'}, help_text=_("Password with which"\
            " a user can authenticate with the service"))
    full_name = serializers.CharField(required=False,
        help_text=_("Full name (effectively first name followed by last name)"))
