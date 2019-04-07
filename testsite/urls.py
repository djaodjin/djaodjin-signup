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

from django.views.generic.base import RedirectView, TemplateView
from django.views.i18n import JavaScriptCatalog
from signup.compat import reverse_lazy
from signup.forms import NameEmailForm
from signup.views.auth import SignupView
from urldecorators import include, url

from .forms import SignupWithCaptchaForm


urlpatterns = [
    url(r'^api/',
        include('signup.urls.api.contacts'),
        decorators=['django.contrib.auth.decorators.login_required']),
    url(r'^api/',
        include('signup.urls.api.keys'),
        decorators=['django.contrib.auth.decorators.login_required']),
    url(r'^api/',
        include('signup.urls.api.tokens'),
        decorators=['django.contrib.auth.decorators.login_required']),
    url(r'^api/',
        include('signup.urls.api.users'),
        decorators=['django.contrib.auth.decorators.login_required']),
    url(r'^api/',
        include('signup.urls.api.auth')),
    url(r'^jsi18n/$', JavaScriptCatalog.as_view(), name='javascript-catalog'),
    url(r'^contacts/',
        include('signup.urls.contacts'),
        decorators=['django.contrib.auth.decorators.login_required']),
    url(r'^users/',
        include('signup.urls.users'),
        decorators=['django.contrib.auth.decorators.login_required']),
    url(r'^register/frictionless/',
        SignupView.as_view(form_class=NameEmailForm),
        name='registration_frictionless'),
    url(r'^register/$',
        SignupView.as_view(form_class=SignupWithCaptchaForm),
        name='registration_register'),
    url(r'^', include('signup.urls.accounts')),
    url(r'^app/', TemplateView.as_view(template_name='app.html'),
        decorators=['django.contrib.auth.decorators.login_required']),
    url(r'^$', RedirectView.as_view(url=reverse_lazy('registration_register'))),
]
