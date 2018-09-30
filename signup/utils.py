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

import re

from django.apps import apps as django_apps
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError
from django.utils.translation import ugettext_lazy as _
import jwt
from rest_framework import serializers

from . import settings
from .compat import User


def get_accept_list(request):
    http_accept = request.META.get('HTTP_ACCEPT', '*/*')
    return [item.strip() for item in http_accept.split(',')]


def get_account_model():
    """
    Returns the ``Account`` model that is active in this project.
    """
    try:
        return django_apps.get_model(settings.ACCOUNT_MODEL)
    except ValueError:
        raise ImproperlyConfigured(
            "ACCOUNT_MODEL must be of the form 'app_label.model_name'")
    except LookupError:
        raise ImproperlyConfigured("ACCOUNT_MODEL refers to model '%s'"\
" that has not been installed" % settings.ACCOUNT_MODEL)


def has_invalid_password(user):
    return user.password.startswith('!')


def printable_name(user):
    full_name = user.get_full_name()
    if full_name:
        return full_name
    return user.username


def update_db_row(instance, form):
    """
    Updates the record in the underlying database, or adds a validation
    error in the form. When an error is added, the form is returned otherwise
    this function returns `None`.
    """
    try:
        instance.save()
        return None
    except IntegrityError as err:
        err_msg = str(err).splitlines().pop()
        # PostgreSQL unique constraint.
        look = re.match(
            r'DETAIL:\s+Key \(([a-z_]+)\)=\(.*\) already exists\.', err_msg)
        if look:
            form.add_error(look.group(1),
                _("This %(field)s is already taken.") % {
                    'field': look.group(1)})
            return form
        # SQLite unique constraint.
        look = re.match(
            r'UNIQUE constraint failed: [a-z_]+\.([a-z_]+)', err_msg)
        if look:
            form.add_error(look.group(1),
                _("This %(field)s is already taken.") % {
                    'field': look.group(1)})
            return form
        raise


def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            True, # verify
            options={'verify_exp': True},
            algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignature:
        raise serializers.ValidationError(
            _("Signature has expired."))
    except jwt.DecodeError:
        raise serializers.ValidationError(
            _("Error decoding signature."))
    username = payload.get('username', None)
    if not username:
        raise serializers.ValidationError(
            _("Missing username in payload"))
    # Make sure user exists
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        raise serializers.ValidationError(_("User does not exist."))
    return user
