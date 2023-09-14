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
Forms for the signup Django app
"""

from django import forms
from django.conf import locale
from django.core import validators
from django.contrib.auth import password_validation, get_user_model
from django.contrib.auth.forms import (
    AuthenticationForm as AuthenticationBaseForm)
from phonenumber_field.formfields import PhoneNumberField

from . import settings, validators
from .compat import gettext_lazy as _, six
from .helpers import full_name_natural_split
from .models import get_disabled_email_update
from .utils import get_recaptcha_form_field


class PhoneField(PhoneNumberField):

    def __init__(self, *args, **kwargs):
        region = kwargs.get('region')
        if not region:
            params = {'region': 'US'}
            params.update(kwargs)
        else:
            params = kwargs
        if settings.PHONE_VERIFICATION_BACKEND:
            self.verification_enabled = True
        super(PhoneField, self).__init__(*args, **params)


class CommField(forms.CharField):

    default_validators = [validators.validate_email_or_phone]
    default_label = _("E-mail address or phone number")
    widget = forms.TextInput(
        attrs={'placeholder': _("ex: john@myorganization.com"),
               'maxlength': 75})

    def __init__(self, **kwargs):
        super(CommField, self).__init__(strip=True, **kwargs)
        if not self.label:
            self.label = self.default_label


class UsernameOrCommField(CommField):

    default_validators = [validators.validate_username_or_email_or_phone]
    default_label = _("Username, e-mail address or phone number")
    widget = forms.TextInput(
        attrs={'placeholder': _("ex: john@myorganization.com"),
               'maxlength': 75})

    def __init__(self, **kwargs):
        super(UsernameOrCommField, self).__init__(**kwargs)
        if not self.label:
            self.label = self.default_label


class AuthenticatedUserPasswordMixin(object):

    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(attrs={'placeholder': _("Your password")}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html())
    otp_code = forms.IntegerField(required=False,
        widget=forms.TextInput(attrs={'placeholder': _("OTP code")}),
        label=_("OTP code"))
    email_code = forms.IntegerField(required=False,
        widget=forms.TextInput(
            attrs={'placeholder': _("Email verification code")}),
        label=_("Email verification code"))
    phone_code = forms.IntegerField(required=False,
        widget=forms.TextInput(
            attrs={'placeholder': _("Phone verification code")}),
        label=_("Phone verification code"))


class FrictionlessSignupForm(forms.Form):
    """
    Form for frictionless registration of a new user. Just supply
    a full name and a way to notify user (email or phone) and you are in.
    We will ask for username and password later.
    """
    email = forms.EmailField(label=_("E-mail address"), required=False,
        widget=forms.TextInput(attrs={
            'placeholder': _("ex: john@myorganization.com")}))
    phone = PhoneField(label=_("Phone number"), required=False,
        widget=forms.TextInput(attrs={
            'placeholder': _("ex: +14155555555")}))
    full_name = forms.RegexField(label=_("Full name"),
        regex=settings.FULL_NAME_PAT, max_length=60,
        widget=forms.TextInput(attrs={
            'placeholder': 'ex: John Smith'}),
        error_messages={'invalid':
            _("Sorry we do not recognize some characters in your full name.")})

    def __init__(self, *args, **kwargs):
        super(FrictionlessSignupForm, self).__init__(*args, **kwargs)
        if settings.REQUIRES_RECAPTCHA:
            self.fields['captcha'] = get_recaptcha_form_field()

    def clean_email(self):
        # If we don't convert `''` to `None`, the database will later complain
        # unique constraints are not respected.
        email = self.cleaned_data['email']
        if not email:
            self.cleaned_data['email'] = None
        return self.cleaned_data['email']

    def clean_phone(self):
        # If we don't convert `''` to `None`, the database will later complain
        # unique constraints are not respected.
        phone = self.cleaned_data['phone']
        if not phone:
            self.cleaned_data['phone'] = None
        return self.cleaned_data['phone']

    def clean(self):
        super(FrictionlessSignupForm, self).clean()
        if not ('email' in self._errors or 'phone' in self._errors):
            if 'email' in self.data and 'phone' in self.data:
                email = self.cleaned_data['email']
                phone = self.cleaned_data['phone']
                if not (email or phone):
                    raise forms.ValidationError(
                        {'email': _("Either email or phone must be valid."),
                         'phone': _("Either email or phone must be valid.")})
            elif 'email' in self.data:
                email = self.cleaned_data['email']
                if not email:
                    raise forms.ValidationError(
                        {'email': _("An email must be valid.")})
            elif 'phone' in self.data:
                phone = self.cleaned_data['phone']
                if not phone:
                    raise forms.ValidationError(
                        {'phone': _("A phone must be valid.")})
        return self.cleaned_data


class PasswordConfirmMixin(object):

    new_password = forms.CharField(strip=False,
        label=_("New password"),
        widget=forms.PasswordInput(
            attrs={'placeholder': _("New password")}),
        help_text=password_validation.password_validators_help_text_html())
    new_password2 = forms.CharField(strip=False,
        label=_("Confirm password"),
        widget=forms.PasswordInput(
            attrs={'placeholder': _("Type password again")}))

    def clean_new_password(self):
        password = ""
        if 'new_password' in self.data:
            password = self.cleaned_data['new_password']
            if not password:
                raise forms.ValidationError(_("Password cannot be empty."))
            user = self.user if hasattr(self, 'user') else None
            password_validation.validate_password(password, user=user)
        return password

    def clean_new_password2(self):
        password = ""
        if 'new_password2' in self.data:
            password = self.cleaned_data['new_password2']
            if not password:
                raise forms.ValidationError(
                    _("Password confirmation cannot be empty."))
        return password

    def clean(self):
        """
        Validates that both passwords respectively match.
        """
        super(PasswordConfirmMixin, self).clean()
        if not ('new_password' in self._errors
                or 'new_password2' in self._errors):
            if 'new_password' in self.data and 'new_password2' in self.data:
                new_password = self.cleaned_data['new_password']
                new_password2 = self.cleaned_data['new_password2']
                if new_password != new_password2:
                    self._errors['new_password'] = self.error_class([
                        _("This field does not match password confirmation.")])
                    self._errors['new_password2'] = self.error_class([
                        _("This field does not match password.")])
                    if 'new_password' in self.cleaned_data:
                        del self.cleaned_data['new_password']
                    if 'new_password2' in self.cleaned_data:
                        del self.cleaned_data['new_password2']
                    raise forms.ValidationError(
                        _("Password and password confirmation do not match."))
        return self.cleaned_data


class PasswordUpdateForm(PasswordConfirmMixin, forms.ModelForm):

    submit_title = _("Update")

    new_password = forms.CharField(strip=False,
        label=_("New password"),
        widget=forms.PasswordInput(
            attrs={'placeholder': _("New password")}),
        help_text=password_validation.password_validators_help_text_html())
    new_password2 = forms.CharField(strip=False,
        label=_("Confirm password"),
        widget=forms.PasswordInput(
            attrs={'placeholder': _("Type password again")}))

    class Meta:
        model = get_user_model()
        fields = ['new_password', 'new_password2']


class PasswordResetConfirmForm(PasswordUpdateForm):
    """
    Form displayed when a user clicked on the link sent in the reset e-mail.
    """


class PasswordChangeForm(AuthenticatedUserPasswordMixin, PasswordUpdateForm):

    # If we don't duplicate those here, `fields = []` raises an error.
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(attrs={'placeholder': _("Your password")}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html())
    otp_code = forms.IntegerField(required=False,
        widget=forms.TextInput(attrs={'placeholder': _("OTP code")}),
        label=_("OTP code"))
    email_code = forms.IntegerField(required=False,
        widget=forms.TextInput(
            attrs={'placeholder': _("Email verification code")}),
        label=_("Email verification code"))
    phone_code = forms.IntegerField(required=False,
        widget=forms.TextInput(
            attrs={'placeholder': _("Phone verification code")}),
        label=_("Phone verification code"))

    class Meta:
        model = get_user_model()
        fields = ['password', 'otp_code', 'email_code', 'phone_code',
                  'new_password', 'new_password2']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('instance')
        super(PasswordUpdateForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        new_password = self.cleaned_data['new_password']
        self.user.set_password(new_password)
        if commit:
            self.user.save()
        return self.user


class RecoverForm(forms.Form):
    """
    Form displayed to authenticate through a verification link.
    """
    username = UsernameOrCommField()


class ActivationForm(PasswordConfirmMixin, forms.Form):
    """
    Form to set password, and optionally user's profile information
    in an activation view.
    """
    submit_title = _("Activate")

    error_messages = {
        'password_mismatch': _("Password and password confirmation"\
        " do not match."),
    }

    email = forms.EmailField(label=_("E-mail address"), required=False,
        widget=forms.TextInput(attrs={
            'placeholder': _("ex: john@myorganization.com")}))
    phone = PhoneField(label=_("Phone number"), required=False,
        widget=forms.TextInput(attrs={
            'placeholder': _("ex: +14155555555")}))
    full_name = forms.RegexField(label=_("Full name"),
        regex=r'^[\w\s]+$', max_length=60,
        widget=forms.TextInput(attrs={'placeholder':'ex: John Smith'}),
        error_messages={'invalid':
            _("Sorry we do not recognize some characters in your full name.")})
    username = forms.SlugField(widget=forms.TextInput(
        attrs={'placeholder': _("ex: john")}),
        max_length=30, label=_("Username"),
        error_messages={'invalid': _("Username may only contain letters,"\
            " digits and -/_ characters. Spaces are not allowed.")})
    new_password = forms.CharField(strip=False,
        label=_("Password"),
        widget=forms.PasswordInput(attrs={'placeholder': _("Password")}),
        help_text=password_validation.password_validators_help_text_html())
    new_password2 = forms.CharField(strip=False,
        label=_("Confirm password"),
        widget=forms.PasswordInput(attrs={
            'placeholder': _("Type password again")}))

    def __init__(self, *args, **kwargs):
        initial = kwargs.get('initial')
        email_verification = initial.pop('email_verification', False)
        phone_verification = initial.pop('phone_verification', False)
        super(ActivationForm, self).__init__(*args, **kwargs)
        if email_verification:
            self.fields['email'].disabled = True
        if phone_verification:
            self.fields['phone'].disabled = True
        if settings.REQUIRES_RECAPTCHA:
            self.fields['captcha'] = get_recaptcha_form_field()


class PublicKeyForm(AuthenticatedUserPasswordMixin, forms.Form):

    submit_title = _("Update")

    pubkey = forms.CharField(widget=forms.Textarea)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('instance')
        super(PublicKeyForm, self).__init__(*args, **kwargs)


class UserForm(forms.ModelForm):
    """
    Form to update a ``User`` profile.
    """
    submit_title = _("Update")

    username = forms.SlugField(widget=forms.TextInput(
        attrs={'placeholder': _("Username")}),
        max_length=30, label=_("Username"),
        error_messages={'invalid': _("Username may only contain letters,"\
            " digits and -/_ characters. Spaces are not allowed.")})
    full_name = forms.CharField(widget=forms.TextInput(
        attrs={'placeholder': _("First and last names")}),
        max_length=254, label=_("Full name"))
    nick_name = forms.CharField(required=False, widget=forms.TextInput(
        attrs={'placeholder': _("Short casual name used to address the user")}),
        max_length=254, label=_("Nick name"))

    class Meta:
        model = get_user_model()
        fields = ['username', 'full_name', 'email']

    def __init__(self, instance=None, **kwargs):
        super(UserForm, self).__init__(instance=instance, **kwargs)
        if instance:
            if get_disabled_email_update(instance):
                self.fields['email'].disabled = True
            # define other fields dynamically
            self.fields['phone'] = PhoneField(required=False)
            lang_code = settings.LANGUAGE_CODE
            contact = instance.contacts.order_by('pk').first()
            if contact:
                self.fields['nick_name'].initial = contact.nick_name
                self.fields['phone'].initial = contact.phone
                lang_code = contact.lang
            else:
                self.fields['nick_name'].initial = instance.first_name
            lang_choices = [(lang['code'], lang['name_local'])
                for lang in six.itervalues(locale.LANG_INFO) if 'code' in lang]
            lang_codes = dict(lang_choices)
            if lang_code not in lang_codes:
                lang_code = lang_code.split('-')[0]
            if lang_code not in lang_codes:
                # At this point, buggy data was loaded from the database,
                # default to the application language code.
                lang_code = settings.LANGUAGE_CODE
            self.fields['lang'] = forms.CharField(
                initial=lang_code, widget=forms.Select(choices=lang_choices))

    def clean_full_name(self):
        if self.cleaned_data.get('full_name'):
            first_name, mid_name, last_name = \
                full_name_natural_split(
                    self.cleaned_data.get('full_name'), middle_initials=False)
            if mid_name:
                first_name = (first_name + " " + mid_name).strip()
            self.cleaned_data.update({
                'first_name': first_name,
                'last_name': last_name})
            if self.instance:
                self.instance.first_name = first_name
                self.instance.last_name = last_name
        return self.cleaned_data.get('full_name')


class UserNotificationsForm(forms.Form):
    """
    Form to update a ``User`` notification preferences.
    """
    submit_title = _("Update")

    def __init__(self, instance, *args, **kwargs):
        #pylint:disable=unused-argument
        super(UserNotificationsForm, self).__init__(*args, **kwargs)
        for item, initial in six.iteritems(self.initial.get('notifications')):
            self.fields[item] = forms.BooleanField(
                label=initial[0].get('summary', ""),
                help_text=initial[0].get('description', ""),
                required=False, initial=initial[1])


class AuthenticationForm(AuthenticationBaseForm):

    # The field is called `username`, yet it is technically
    # a username, e-mail or phone.
    username = UsernameOrCommField()
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={'placeholder': _("Password")}), label=_("Password"))

    def __init__(self, *args, **kwargs):
        super(AuthenticationForm, self).__init__(*args, **kwargs)
        username_label = self.initial.get('username_label', None)
        if username_label:
            placeholder_label = _('%(username)s, e-mail or phone' % {
                'username': username_label})
            self.fields['username'].label = placeholder_label
            self.fields['username'].widget.attrs['placeholder'] \
                = placeholder_label


class StartAuthenticationForm(forms.Form):
    """
    Form to present a user who may or may not have an account yet.
    """
    username = UsernameOrCommField()
    submit_title = _("Submit")

    def __init__(self, *args, **kwargs):
        kwargs.pop('request')
        super(StartAuthenticationForm, self).__init__(*args, **kwargs)


class PasswordAuthForm(StartAuthenticationForm):

    password = forms.CharField(widget=forms.PasswordInput(
        attrs={'placeholder': _("Password")}), label=_("Password"))

    def __init__(self, *args, **kwargs):
        super(PasswordAuthForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget = forms.HiddenInput()


class MFACodeForm(PasswordAuthForm):

    code = forms.IntegerField(widget=forms.TextInput(
        attrs={'placeholder': _("One-time authentication code"),
            'autofocus': True}),
        label=_("One-time authentication code"))

    def __init__(self, *args, **kwargs):
        super(MFACodeForm, self).__init__(*args, **kwargs)
        self.fields['password'].widget = forms.HiddenInput()
