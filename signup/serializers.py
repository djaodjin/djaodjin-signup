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
from django.db import IntegrityError
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers

from .models import Activity, Contact, Notification
from .helpers import full_name_natural_split
from .utils import get_account_model, handle_uniq_error


class NoModelSerializer(serializers.Serializer):

    def create(self, validated_data):
        raise RuntimeError('`create()` should not be called.')

    def update(self, instance, validated_data):
        raise RuntimeError('`update()` should not be called.')


class ActivitySerializer(serializers.ModelSerializer):

    account = serializers.SlugRelatedField(
        slug_field='slug', queryset=get_account_model().objects.all(),
        help_text=_("Account the activity is associated to"))
    created_by = serializers.SlugRelatedField(
        read_only=True, slug_field='username',
        help_text=_("User that created the activity"))

    class Meta:
        #pylint:disable=old-style-class,no-init
        model = Activity
        fields = ('created_at', 'created_by', 'text', 'account')
        read_only_fields = ('created_at', 'created_by')


class APIKeysSerializer(NoModelSerializer):
    """
    username and password for authentication through API.
    """
    secret = serializers.CharField(max_length=128, read_only=True,
        help_text=_("Secret API Key used to authenticate user on every HTTP"\
        " request"))
    password = serializers.CharField(max_length=128, required=False,
        help_text=_("Your password"))

    class Meta:
        #pylint:disable=old-style-class,no-init
        fields = ('secret', 'password')


class ContactSerializer(serializers.ModelSerializer):

    activities = ActivitySerializer(many=True, read_only=True)

    class Meta:
        #pylint:disable=old-style-class,no-init
        model = Contact
        fields = ('slug', 'email', 'full_name', 'nick_name', 'extra',
            'created_at', 'activities', 'picture')
        read_only_fields = ('slug', 'created_at', 'activities')


class NotificationsSerializer(serializers.ModelSerializer):

    notifications = serializers.SlugRelatedField(many=True,
        slug_field='slug', queryset=Notification.objects.all())

    class Meta:
        #pylint:disable=old-style-class,no-init
        model = get_user_model()
        fields = ('notifications',)


class CredentialsSerializer(NoModelSerializer):
    """
    username and password for authentication through API.
    """
    username = serializers.CharField(validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')],
        help_text=_("Username to identify the account"))
    password = serializers.CharField(write_only=True,
        style={'input_type': 'password'},
        help_text=_("Secret password for the account"))


class CreateUserSerializer(serializers.ModelSerializer):
    #pylint: disable=no-init,old-style-class

    username = serializers.CharField(required=False)
    password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'}, help_text=_("Password with which"\
            " a user can authenticate with the service"))
    email = serializers.EmailField(
        help_text=_("Primary e-mail to contact user"))
    full_name = serializers.CharField(
        help_text=_("Full name"))

    class Meta:
        model = get_user_model()
        fields = ('username', 'password', 'email', 'full_name')


class PasswordChangeSerializer(NoModelSerializer):

    password = serializers.CharField(required=True, write_only=True,
        style={'input_type': 'password'})
    new_password = serializers.CharField(required=False, write_only=True,
        style={'input_type': 'password'})


class TokenSerializer(NoModelSerializer):
    """
    token to verify or refresh.
    """
    token = serializers.CharField(
        help_text=_("Token used to authenticate user on every HTTP request"))


class UserSerializer(serializers.ModelSerializer):
    #pylint: disable=no-init,old-style-class

    # Only way I found out to remove the ``UniqueValidator``. We are not
    # interested to create new instances here.
    username = serializers.CharField(validators=[
        validators.RegexValidator(r'^[\w.@+-]+$', _("Enter a valid username."),
            'invalid')])
    email = serializers.EmailField(
        help_text=_("Primary e-mail to contact user"))
    full_name = serializers.CharField(source='get_full_name',
        help_text=_("Full name"))

    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'full_name')

    def get_full_name(self, obj):#pylint:disable=no-self-use
        return obj.get_full_name()

    def save(self):
        full_name = self.validated_data.get('get_full_name')
        if full_name:
            user = self.instance
            first_name, mid_name, last_name = full_name_natural_split(full_name)
            if mid_name:
                first_name = first_name + ' ' + mid_name
            user.first_name = first_name
            user.last_name = last_name
        try:
            return super(UserSerializer, self).save()
        except IntegrityError as err:
            handle_uniq_error(err)
        return None


class ValidationErrorSerializer(NoModelSerializer):
    """
    Details on why token is invalid.
    """
    detail = serializers.CharField(help_text=_("Describes the reason for"\
        " the error in plain text"))


class PublicKeySerializer(NoModelSerializer):
    pubkey = serializers.CharField(max_length=None, help_text=_("Public key"))
    password = serializers.CharField(required=False, max_length=500,
        help_text=_("Password"))
