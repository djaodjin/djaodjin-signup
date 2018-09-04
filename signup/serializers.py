# Copyright (c) 2018, DjaoDjin inc.
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

from django.core import validators
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers

from .models import Activity, Contact, Notification
from .utils import get_account_model


class ActivitySerializer(serializers.ModelSerializer):

    account = serializers.SlugRelatedField(
        slug_field='slug', queryset=get_account_model().objects.all())
    created_by = serializers.SlugRelatedField(
        read_only=True, slug_field='username')

    class Meta:
        #pylint:disable=old-style-class,no-init
        model = Activity
        fields = ('created_at', 'created_by', 'text', 'account')
        read_only_fields = ('created_at', 'created_by')


class APIKeysSerializer(serializers.Serializer):
    """
    username and password for authentication through API.
    """
    secret = serializers.CharField(max_length=128, read_only=True,
        help_text=_("Secret API Key used to authenticate user on every HTTP"\
        " request"))

    class Meta:
        #pylint:disable=old-style-class,no-init
        fields = ('secret',)

    def update(self, instance, validated_data):
        raise NotImplementedError('`update()` must be implemented.')

    def create(self, validated_data):
        raise NotImplementedError('`create()` must be implemented.')


class ContactSerializer(serializers.ModelSerializer):

    activities = ActivitySerializer(many=True, read_only=True)

    class Meta:
        #pylint:disable=old-style-class,no-init
        model = Contact
        fields = ('slug', 'email', 'full_name', 'nick_name',
            'created_at', 'activities')
        read_only_fields = ('slug', 'created_at', 'activities')


class NotificationsSerializer(serializers.ModelSerializer):

    notifications = serializers.SlugRelatedField(many=True,
        slug_field='slug', queryset=Notification.objects.all())

    class Meta:
        #pylint:disable=old-style-class,no-init
        model = get_user_model()
        fields = ('notifications',)


class CredentialsSerializer(serializers.Serializer):
    """
    username and password for authentication through API.
    """
    username = serializers.CharField(validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')],
        help_text=_("username to identify the account"))
    password = serializers.CharField(write_only=True,
        style={'input_type': 'password'},
        help_text=_("secret password for the account"))

    def update(self, instance, validated_data):
        raise NotImplementedError('`update()` must be implemented.')

    def create(self, validated_data):
        raise NotImplementedError('`create()` must be implemented.')


class CreateUserSerializer(serializers.ModelSerializer):
    #pylint: disable=no-init,old-style-class

    username = serializers.CharField(required=False)
    password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'}, help_text=_("Password with which"\
            " a user can authenticate with the service"))
    email = serializers.EmailField(
        help_text=_("Primary email to contact user"))
    full_name = serializers.CharField(
        help_text=_("Full name of user"))

    class Meta:
        model = get_user_model()
        fields = ('username', 'password', 'email', 'full_name')


class PasswordChangeSerializer(serializers.Serializer):

    password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'})

    def update(self, instance, validated_data):
        raise NotImplementedError('`update()` must be implemented.')

    def create(self, validated_data):
        raise NotImplementedError('`create()` must be implemented.')


class TokenSerializer(serializers.Serializer):
    """
    token to verify or refresh.
    """
    token = serializers.CharField(
        help_text=_("Token used to authenticate user on every HTTP request"))

    def update(self, instance, validated_data):
        raise NotImplementedError('`update()` must be implemented.')

    def create(self, validated_data):
        raise NotImplementedError('`create()` must be implemented.')


class UserSerializer(serializers.ModelSerializer):
    #pylint: disable=no-init,old-style-class

    # Only way I found out to remove the ``UniqueValidator``. We are not
    # interested to create new instances here.
    username = serializers.CharField(validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')])
    email = serializers.EmailField(
        help_text=_("Primary email to contact user"))
    full_name = serializers.SerializerMethodField(
        help_text=_("Full name of user"))

    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'full_name')

    def get_full_name(self, obj):#pylint:disable=no-self-use
        return obj.get_full_name()


class ValidationErrorSerializer(serializers.Serializer):
    """
    Details on why token is invalid.
    """
    detail = serializers.CharField(help_text=_("describes the reason for"\
        " the error in plain text"))

    def update(self, instance, validated_data):
        raise NotImplementedError('`update()` must be implemented.')

    def create(self, validated_data):
        raise NotImplementedError('`create()` must be implemented.')
