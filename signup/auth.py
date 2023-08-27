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
import re

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http.request import split_domain_port, validate_host
from rest_framework import exceptions

from .compat import gettext_lazy as _, urlparse, urlunparse


class IncorrectPath(exceptions.AuthenticationFailed):
    """
    Incorrect path
    """


def validate_path_pattern(request):
    # The authentication URLs are anonymously accessible, hence
    # prime candidates for bots. These will POST to '/login/.' for
    # example because there is a `action="."` in the <form> tag
    # in login.html.
    # We cannot catch these by restricting the match pattern.
    # 1. '^login/$' will not match 'login/.' hence trigger the catch
    #    all pattern that might forward the HTTP request.
    # 2. 'login/(?P<extra>.*)' will through a missing argument
    #    exception in `reverse` calls.
    try:
        pat = (r'(?P<expected_path>%s)(?P<extra>.*)' %
            request.resolver_match.route)
        look = re.match(pat, request.path.lstrip('/'))
        if look:
            expected_path = '/' + look.group('expected_path')
            extra =  look.group('extra')
            if extra:
                raise IncorrectPath(
                    {'detail': (
                     _("Incorrect path in URL. Expecting %(path)s") % {
                    'path': request.build_absolute_uri(expected_path)}
                )})
    except AttributeError:
        pass # Django<=1.11 ResolverMatch does not have
             # a route attribute.


def validate_redirect(request):
    """
    Get the REDIRECT_FIELD_NAME and validates it is a URL on allowed hosts.
    """
    return validate_redirect_url(request.GET.get(REDIRECT_FIELD_NAME, None))


def validate_redirect_url(next_url):
    """
    Returns the next_url path if next_url matches allowed hosts.
    """
    if not next_url:
        return None
    parts = urlparse(next_url)
    if parts.netloc:
        domain, _ = split_domain_port(parts.netloc)
        allowed_hosts = ['*'] if settings.DEBUG else settings.ALLOWED_HOSTS
        if not (domain and validate_host(domain, allowed_hosts)):
            return None
    return urlunparse(("", "", parts.path,
        parts.params, parts.query, parts.fragment))
