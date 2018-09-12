# Copyright (c) 2018, Djaodjin Inc.
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

from functools import wraps

from django.contrib import messages
from django.contrib.auth import (REDIRECT_FIELD_NAME, logout as auth_logout)
from django.core.exceptions import PermissionDenied
from django.utils.decorators import available_attrs
from django.utils import six
from django.utils.translation import ugettext_lazy as _

from . import settings, signals
from .auth import validate_redirect
from .compat import is_authenticated, reverse
from .models import Contact
from .utils import has_invalid_password, get_accept_list


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
    from django.contrib.auth.views import redirect_to_login
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


def send_verification_email(email_contact, request,
                           next_url=None,
                           redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Send an email to the user to verify her email address.

    The email embed a link to a verification url and a redirect to the page
    the verification email was sent from so that the user stays on her
    workflow once verification is completed.
    """
    back_url = request.build_absolute_uri(reverse('registration_activate',
        args=(email_contact.verification_key,)))
    if next_url:
        back_url += '?%s=%s' % (redirect_field_name, next_url)
    signals.user_verification.send(
        sender=__name__, user=email_contact.user, request=request,
        back_url=back_url, expiration_days=settings.KEY_EXPIRATION)


# The user we are looking to activate might be different from
# the request.user (which can be Anonymous)
def check_user_active(request, user,
                      redirect_field_name=REDIRECT_FIELD_NAME,
                      next_url=None):
    """
    Checks that a *user* is active. We won't activate the account of
    a user until we checked the email address is valid.
    """
    if has_invalid_password(user):
        # Let's send e-mail again.
        #pylint:disable=unused-variable
        contact, created = Contact.objects.update_or_create_token(user)
        if not next_url:
            next_url = validate_redirect(request)
        send_verification_email(
            contact, request, next_url=next_url,
            redirect_field_name=redirect_field_name)
        return False
    return True


def fail_active(request):
    """
    Active with valid credentials
    """
    if not check_user_active(request, request.user):
        return reverse(settings.LOGIN_URL)
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
            redirect_url = login_url or settings.LOGIN_URL
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
