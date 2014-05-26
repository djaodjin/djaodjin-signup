# Copyright (c) 2014, Djaodjin Inc.
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
URLconf for frictionless signup.

If the default behavior of these views is acceptable to you, simply
use a line like this in your root URLconf to set up the default URLs
for registration::

    (r'^accounts/', include('signup.urls')),
"""

from django.conf.urls import patterns, include, url

from signup.backends.auth import UsernameOrEmailAuthenticationForm
from signup.views import (
    SignupView, ActivationView, PasswordResetView,
    registration_password_confirm, redirect_to_user_profile)
from signup import settings

urlpatterns = patterns('',
    url(r'^profile/$', redirect_to_user_profile, name='accounts_profile'),

    # When the key and/or token are wrong we don't want to give any clue
    # as to why that is so. Less information communicated to an attacker,
    # the better.
    url(r'^activate/(?P<verification_key>%s)/password/(?P<token>.+)/$'
        % settings.EMAIL_VERIFICATION_PAT,
        registration_password_confirm,
        name='registration_password_confirm'),
    url(r'^activate/(?P<verification_key>%s)/$'
        % settings.EMAIL_VERIFICATION_PAT,
        ActivationView.as_view(),
        name='registration_activate'),
    url(r'^register/$',
        SignupView.as_view(),
        name='registration_register'),
    url(r'^login/$', 'django.contrib.auth.views.login',
        {'authentication_form': UsernameOrEmailAuthenticationForm},
        name='login'),
    url(r'^password_reset/$',
        PasswordResetView.as_view(), name='password_reset'),
    (r'', include('django.contrib.auth.urls')),
)

