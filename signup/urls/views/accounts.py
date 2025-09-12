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

from django.views.generic import TemplateView

from ... import settings
from ...compat import include, path, re_path
from ...forms import AuthenticationForm
from ...views.auth import (ActivationView, PasswordResetConfirmView,
    RecoverView, SigninView, SignoutView, SignupView, VerificationView)
from ...views.saml import saml_metadata_view

urlpatterns = [
    # When the key and/or token are wrong we don't want to give any clue
    # as to why that is so. Less information communicated to an attacker,
    # the better.
    re_path(r'^verify/(?P<verification_key>%s)/'
        % settings.EMAIL_VERIFICATION_PAT,
        VerificationView.as_view(), name='verify_channel'),
    re_path(r'^reset/(?P<verification_key>%s)/'
        % settings.EMAIL_VERIFICATION_PAT,
        PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('activate/email/',
        TemplateView.as_view(template_name='accounts/activate/email.html'),
        name='email_verification_link'),
    path('activate/phone/',
        TemplateView.as_view(template_name='accounts/activate/phone.html'),
        name='phone_verification_link'),
    re_path(r'^activate/(?P<verification_key>%s)/'
        % settings.EMAIL_VERIFICATION_PAT,
        ActivationView.as_view(), name='registration_activate'),
    path('activate/',
        SigninView.as_view(
            template_name='accounts/activate/index.html'),
        name='registration_activate_start'),
    path('', include('social_django.urls', namespace='social')),
    path('login/',
        SigninView.as_view(form_class=AuthenticationForm), name='login'),
    path('logout/',
        SignoutView.as_view(), name='logout'),
    path('recover/',
        RecoverView.as_view(), name='password_reset'),
    path('register/',
        SignupView.as_view(), name='registration_register'),
    path('saml/', saml_metadata_view),
]
