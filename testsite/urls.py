# Copyright (c) 2021, Djaodjin Inc.
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

from django.conf import settings
from django.conf.urls.static import static
from django.views.generic.base import RedirectView, TemplateView
from rules.urldecorators import include, url
from signup.compat import reverse_lazy
from signup.decorators import fail_authenticated
from signup.views.auth import SignupView

from .forms import SignupWithCaptchaForm

urlpatterns = \
    static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + [
    url(r'^api/',
        include('signup.urls.api.contacts'),
        redirects=[fail_authenticated]),
    url(r'^api/',
        include('signup.urls.api.keys'),
        redirects=[fail_authenticated]),
    url(r'^api/',
        include('signup.urls.api.tokens'),
        redirects=[fail_authenticated]),
    url(r'^api/',
        include('signup.urls.api.users'),
        redirects=[fail_authenticated]),
    url(r'^api/',
        include('signup.urls.api.activate')),
    url(r'^api/',
        include('signup.urls.api.auth')),
    url(r'^contacts/',
        include('signup.urls.views.contacts'),
        redirects=[fail_authenticated]),
    url(r'^users/',
        include('signup.urls.views.users'),
        redirects=[fail_authenticated]),
    url(r'^register/frictionless/',
        SignupView.as_view(),
        name='registration_frictionless'),
    url(r'^register/$',
        SignupView.as_view(form_class=SignupWithCaptchaForm),
        name='registration_register'),
    url(r'^', include('signup.urls.views.accounts')),

    url(r'^app/', TemplateView.as_view(template_name='app.html'),
        redirects=[fail_authenticated]),
    url(r'^$', RedirectView.as_view(url=reverse_lazy('registration_register')),
        name='homepage'),
]
