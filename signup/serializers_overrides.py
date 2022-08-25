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

from django.core import validators
from django.contrib.auth import get_user_model
from rest_framework import serializers

from .compat import gettext_lazy as _


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
        opk = obj.pk if hasattr(obj, 'pk') else None
        if opk:
            contact = obj.contacts.filter(nick_name__isnull=False).order_by(
                'created_at').first()
            if contact:
                printable_name = contact.nick_name
        if printable_name:
            return printable_name
        printable_name = obj.first_name
        if printable_name:
            return printable_name
        return obj.username


