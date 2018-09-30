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
Backend to authenticate a User through her username or email address.

Add to the UsernameOrEmailModelBackend to your project
settings.AUTHENTICATION_BACKENDS and use UsernameOrEmailAuthenticationForm
for the authentication_form parameter to your login urlpattern.

settings.py:

AUTHENTICATION_BACKENDS = (
    'signup.backends.auth.EmailOrUsernameModelBackend',
    'django.contrib.auth.backends.ModelBackend'
)

urls.py:

urlpatterns = patterns('',
    url(r'^login/$', 'django.contrib.auth.views.login',
        { 'authentication_form': UsernameOrEmailAuthenticationForm }
        name='login'),
)
"""
from __future__ import unicode_literals

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import ugettext_lazy as _

from signup.compat import User


class UsernameOrEmailAuthenticationForm(AuthenticationForm):

    username = forms.CharField(widget=forms.TextInput(
        attrs={'placeholder': _("Username or e-mail")}),
        max_length=254, label=_("Username or e-mail"))
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={'placeholder': _("Password")}), label=_("Password"))

    def __init__(self, *args, **kwargs):
        super(UsernameOrEmailAuthenticationForm, self).__init__(*args, **kwargs)
        username_label = self.initial.get('username_label', None)
        if username_label:
            placeholder_label = _('%(username)s or e-mail' % {
                'username': username_label})
            self.fields['username'].label = placeholder_label
            self.fields['username'].widget.attrs['placeholder'] \
                = placeholder_label


class UsernameOrEmailModelBackend(object):
    """
    Backend to authenticate a user through either her username
    or email address.
    """
    #pylint: disable=no-self-use

    def authenticate(self, username=None, password=None):
        if '@' in username:
            kwargs = {'email__iexact': username}
        else:
            kwargs = {'username__iexact': username}
        try:
            user = User.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user (#20760).
            User().set_password(password)
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
