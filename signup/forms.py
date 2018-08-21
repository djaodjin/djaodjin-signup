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

"""Forms for the signup app"""

from captcha.fields import ReCaptchaField
from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import (
    PasswordResetForm as PasswordResetBaseForm, SetPasswordForm)
from django.utils.translation import ugettext_lazy as _
from django.utils import six

from . import settings
from .compat import User

#pylint: disable=old-style-class,no-init

class NameEmailForm(forms.Form):
    """
    Form for frictionless registration of a new account. Just supply
    a full name and an email and you are in. We will ask for username
    and password later.
    """
    full_name = forms.RegexField(
        regex=r'^[\w\s]+$', max_length=60,
        widget=forms.TextInput(attrs={'placeholder':'Full name'}),
        label=_("Full name"),
        error_messages={'invalid':
            _("Sorry we do not recognize some characters in your full name.")})
    email = forms.EmailField(
        widget=forms.TextInput(attrs={'placeholder':'Email',
                                      'maxlength': 75}),
        label=_("Email address"))

    def __init__(self, *args, **kwargs):
        super(NameEmailForm, self).__init__(*args, **kwargs)
        if settings.REQUIRES_RECAPTCHA:
            self.fields['captcha'] = ReCaptchaField()


class PasswordChangeForm(SetPasswordForm):

    submit_title = 'Update'

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('instance')
        super(PasswordChangeForm, self).__init__(user, *args, **kwargs)


class PasswordResetForm(PasswordResetBaseForm):

    pass


class PasswordResetConfirmForm(SetPasswordForm):

    submit_title = 'Update'

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('instance')
        super(PasswordResetConfirmForm, self).__init__(user, *args, **kwargs)


class ActivationForm(forms.Form):
    """
    Form to set password, and optionally user's profile information
    in an activation view.
    """
    submit_title = 'Activate'

    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }

    email = forms.EmailField(
        widget=forms.TextInput(attrs={'placeholder':'Email', 'maxlength': 75}),
        label=_("Email address"), disabled=True)
    full_name = forms.RegexField(
        regex=r'^[\w\s]+$', max_length=60,
        widget=forms.TextInput(attrs={'placeholder':'Full name'}),
        label=_("Full name"),
        error_messages={'invalid':
            _("Sorry we do not recognize some characters in your full name.")})
    username = forms.CharField(widget=forms.TextInput(
        attrs={'placeholder': _("Username")}),
        max_length=254, label=_("Username"),
        error_messages={'invalid': _("username may only contain letters,"\
" digits and -/_ characters.")})
    new_password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(attrs={'placeholder': _("Password")}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password2 = forms.CharField(
        label=_("Confirm password"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'placeholder': _("Confirm password")}),
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('instance')
        super(ActivationForm, self).__init__(*args, **kwargs)
        if settings.REQUIRES_RECAPTCHA:
            self.fields['captcha'] = ReCaptchaField()

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        password_validation.validate_password(password2, self.user)
        return password2


class PublicKeyForm(forms.Form):

    submit_title = 'Update'
    pubkey = forms.CharField(widget=forms.Textarea)
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(attrs={'placeholder': _("Password")}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html())

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('instance')
        super(PublicKeyForm, self).__init__(*args, **kwargs)


class UserForm(forms.ModelForm):
    """
    Form to update a ``User`` profile.
    """
    submit_title = 'Update'

    username = forms.CharField(widget=forms.TextInput(
        attrs={'placeholder': _("Username")}),
        max_length=254, label=_("Username"),
        error_messages={'invalid': _("username may only contain letters,"\
" digits and -/_ characters.")})

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']


class UserNotificationsForm(forms.Form):
    """
    Form to update a ``User`` notification preferences.
    """
    submit_title = 'Update'

    def __init__(self, instance, *args, **kwargs):
        #pylint:disable=unused-argument
        super(UserNotificationsForm, self).__init__(*args, **kwargs)
        for item, initial in six.iteritems(self.initial.get('notifications')):
            self.fields[item] = forms.BooleanField(
                label=initial[0].title, help_text=initial[0].description,
                required=False, initial=initial[1])
