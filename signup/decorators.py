# Copyright (c) 2023, Djaodjin Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Decorators that check a User a verified email address.
"""
from __future__ import unicode_literals

from functools import wraps

from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, logout as auth_logout
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied

from . import settings
from .auth import validate_redirect
from .backends.email_verification import send_verification_email
from .backends.phone_verification import send_verification_phone
from .compat import (available_attrs, gettext_lazy as _, is_authenticated,
    reverse, six)
from .helpers import get_accept_list, has_invalid_password
from .models import Contact


def _insert_url(request, redirect_field_name=REDIRECT_FIELD_NAME,
                inserted_url=None):
    '''Redirects to the *inserted_url* before going to the orginal
    request path.'''
    # This code is pretty much straightforward
    # from contrib.auth.user_passes_test
    path = request.build_absolute_uri()
    # If the login url is the same scheme and net location then just
    # use the path as the "next" url.
    login_scheme, login_netloc = six.moves.urllib.parse.urlparse(
        inserted_url)[:2]
    current_scheme, current_netloc = six.moves.urllib.parse.urlparse(path)[:2]
    if ((not login_scheme or login_scheme == current_scheme) and
        (not login_netloc or login_netloc == current_netloc)):
        path = request.get_full_path()
    return redirect_to_login(path, inserted_url, redirect_field_name)


def redirect_or_denied(request, inserted_url,
                       redirect_field_name=REDIRECT_FIELD_NAME, descr=None):
    http_accepts = get_accept_list(request)
    if ('text/html' in http_accepts
        and isinstance(inserted_url, six.string_types)):
        return _insert_url(request, redirect_field_name=redirect_field_name,
                           inserted_url=inserted_url)
    if descr is None:
        descr = ""
    raise PermissionDenied(descr)


# The user we are looking to activate might be different from
# the request.user (which can be Anonymous)
def check_has_credentials(request, user,
                          redirect_field_name=REDIRECT_FIELD_NAME,
                          next_url=None):
    """
    Checks that a *user* has set login credentials (i.e. password).
    """
    if has_invalid_password(user):
        # Let's send e-mail again.
        #pylint:disable=unused-variable
        contact, created = Contact.objects.prepare_email_verification(
            user.email, user=user)
        if not next_url:
            next_url = validate_redirect(request)
        send_verification_email(
            contact, request, next_url=next_url,
            redirect_field_name=redirect_field_name)
        return False
    return True


def check_email_verified(request, user,
                         redirect_field_name=REDIRECT_FIELD_NAME,
                         next_url=None):
    """
    Checks that a *user*'s e-mail is verified. If it hasn't, send an
    e-mail to verify the user e-mail address, and returns the associated
    `Contact` object.
    """
    #pylint:disable=unused-variable
    if Contact.objects.is_reachable_by_email(user):
        return None

    contact, created = Contact.objects.prepare_email_verification(
        user.email, user=user)
    # Let's send e-mail again.
    if not next_url:
        next_url = validate_redirect(request)
    send_verification_email(
        contact, request, next_url=next_url,
        redirect_field_name=redirect_field_name)
    return contact


def check_phone_verified(request, user,
                         redirect_field_name=REDIRECT_FIELD_NAME,
                         next_url=None):
    """
    Checks that a *user*'s phone number is verified. If it hasn't, send an
    text message to verify the user phone number, and returns the associated
    `Contact` object.
    """
    #pylint:disable=unused-variable
    if Contact.objects.is_reachable_by_phone(user):
        return None

    contact, created = Contact.objects.prepare_phone_verification(
        user.phone, user=user) # XXX
    # Let's send e-mail again.
    if not next_url:
        next_url = validate_redirect(request)
    send_verification_phone(
        contact, request, next_url=next_url,
        redirect_field_name=redirect_field_name)
    return contact


def fail_authenticated(request):
    """
    Authenticated
    """
    if not is_authenticated(request):
        return str(settings.LOGIN_URL)
    return False


def fail_registered(request):
    """
    Registered
    """
    if not is_authenticated(request):
        return str(reverse('registration_register'))
    return False


def fail_active(request):
    """
    Active with valid credentials
    """
    if not check_has_credentials(request, request.user):
        return str(settings.LOGIN_URL)
    return False


def fail_verified_email(request):
    """
    Active with a verified e-mail address
    """
    contact = check_email_verified(request, request.user)
    if contact:
        if settings.USE_VERIFICATION_LINKS:
            return str(reverse('email_verification_link'))
        return str(reverse('verify_channel', args=(
            contact.email_verification_key,)))
    return False


def fail_verified_phone(request):
    """
    Active with a verified phone number
    """
    contact = check_phone_verified(request, request.user)
    if contact:
        if settings.USE_VERIFICATION_LINKS:
            return str(reverse('phone_verification_link'))
        return str(reverse('verify_channel', args=(
            contact.phone_verification_key,)))
    return False


def active_required(function=None,
                    redirect_field_name=REDIRECT_FIELD_NAME,
                    login_url=None):
    """
    Decorator for views that checks that the user is active. We won't
    activate the account of a user until we checked the email address
    is valid.
    """
    def decorator(view_func):
        @wraps(view_func, assigned=available_attrs(view_func))
        def _wrapped_view(request, *args, **kwargs):
            redirect_url = login_url or str(settings.LOGIN_URL)
            if is_authenticated(request):
                redirect_url = fail_active(request)
                if not redirect_url:
                    return view_func(request, *args, **kwargs)
                # User is logged in but her email has not been verified yet.
                http_accepts = get_accept_list(request)
                if 'text/html' in http_accepts:
                    messages.info(request, _(
"You should now secure and activate your account following the instructions"\
" we just emailed you. Thank you."))
                auth_logout(request)
            return redirect_or_denied(request, redirect_url,
                redirect_field_name=redirect_field_name)
        return _wrapped_view

    if function:
        return decorator(function)
    return decorator


def verified_email_required(function=None,
                            redirect_field_name=REDIRECT_FIELD_NAME,
                            login_url=None):
    """
    Decorator for views that checks that the user has a verified e-mail address.
    """
    def decorator(view_func):
        @wraps(view_func, assigned=available_attrs(view_func))
        def _wrapped_view(request, *args, **kwargs):
            redirect_url = login_url or str(settings.LOGIN_URL)
            if is_authenticated(request):
                redirect_url = fail_verified_email(request)
                if not redirect_url:
                    return view_func(request, *args, **kwargs)
                # User is logged in but her email has not been verified yet.
                http_accepts = get_accept_list(request)
                if 'text/html' in http_accepts:
                    messages.info(request, _(
"You should now secure and activate your account following the instructions"\
" we just emailed you. Thank you."))
                auth_logout(request)
            return redirect_or_denied(request, redirect_url,
                redirect_field_name=redirect_field_name)
        return _wrapped_view

    if function:
        return decorator(function)
    return decorator
