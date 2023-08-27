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

"""Extra Views that might prove useful to register users."""
from __future__ import unicode_literals

import logging

from django.contrib.auth import logout as auth_logout, REDIRECT_FIELD_NAME
from django.forms.utils import ErrorDict
from django.http import HttpResponseRedirect
from django.views.decorators.cache import add_never_cache_headers
from django.views.generic.base import TemplateResponseMixin, View
from django.views.generic.edit import FormMixin, ProcessFormView
from rest_framework import exceptions, serializers

from .. import settings
from ..auth import validate_redirect
from ..compat import gettext_lazy as _, reverse
from ..forms import (ActivationForm, AuthenticationForm, FrictionlessSignupForm,
    MFACodeForm, PasswordAuthForm, PasswordResetConfirmForm, RecoverForm)
from ..helpers import update_context_urls
from ..mixins import (LoginMixin, PasswordResetConfirmMixin,
    RegisterMixin, VerifyMixin, VerifyCompleteMixin, AuthDisabled, OTPRequired,
    PasswordRequired, VerifyRequired, SSORequired, RegistrationDisabled)
from ..models import Contact
from ..utils import fill_form_errors, get_disabled_registration


LOGGER = logging.getLogger(__name__)


class AuthResponseMixin(TemplateResponseMixin, FormMixin):
    """
    Returns a *disabled* page regardless when get_disabled_authentication
    is True.
    """
    success_url = settings.LOGIN_REDIRECT_URL
    mfa_code_form_class = MFACodeForm

    def get_mfa_form(self):
        form = self.mfa_code_form_class(**self.get_form_kwargs())
        # We must pass the username and password back to the browser
        # as hidden fields, but prevent calls to `form.non_field_errors()`
        # in the templates to inadvertently trigger a call
        # to `MFACodeForm.clean()`.
        form._errors = {} #pylint:disable=protected-access
        return form

    def get_success_url(self):
        next_url = validate_redirect(self.request)
        if not next_url:
            next_url = super(AuthResponseMixin, self).get_success_url()
        return next_url

    def get_context_data(self, **kwargs):
        context = super(AuthResponseMixin, self).get_context_data(
            **kwargs)
        next_url = validate_redirect(self.request)
        if next_url:
            context.update({REDIRECT_FIELD_NAME: next_url})
        # URLs for user
        disabled_registration = get_disabled_registration(self.request)
        update_context_urls(context, {
            'api': {
                'login': reverse('api_login'),
                'recover': reverse('api_recover'),
                'register': (reverse('api_register')
                    if not disabled_registration else None),
            },
            'user': {
                'login': reverse('login'),
                'password_reset': reverse('password_reset'),
                'register': (reverse('registration_register')
                    if not disabled_registration else None),
        }})
        return context



class RecoverView(VerifyMixin, AuthResponseMixin, View):
    """
    Enter email address or phone number to reset password.
    """
    form_class = RecoverForm
    template_name = 'accounts/recover.html'

    def get(self, request, *args, **kwargs):
        return self.render_to_response(self.get_context_data())

    def post(self, request, *args, **kwargs):
        context = None
        try:
            self.run_pipeline()
            return HttpResponseRedirect(self.get_success_url())
        except serializers.ValidationError as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except VerifyRequired as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
        except AuthDisabled:
            context = {'disabled_authentication': True}
        except exceptions.AuthenticationFailed as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
        if not context:
            context = self.get_context_data()
        return self.render_to_response(context)


class SignupView(RegisterMixin, AuthResponseMixin, View):
    """
    A frictionless registration backend With a full name and email
    address, the user is immediately signed up and logged in.
    """
    form_class = FrictionlessSignupForm
    fail_url = ('registration_register', (), {})
    template_name = 'accounts/register.html'

    def get(self, request, *args, **kwargs):
        return self.render_to_response(self.get_context_data())

    def post(self, request, *args, **kwargs):
        context = None
        try:
            self.run_pipeline()
            return HttpResponseRedirect(self.get_success_url())
        except serializers.ValidationError as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except RegistrationDisabled:
            context = {'disabled_registration': True}
        except exceptions.AuthenticationFailed as err:
            # This could be an IncorrectPath or any other forms of
            # bots activity.
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)

        if context is None:
            context = self.get_context_data()
        return self.render_to_response(context)


class ActivationView(VerifyCompleteMixin, AuthResponseMixin, View):
    """
    The user is now on the activation url that was sent in an email.
    It is time to complete the registration and activate the account.

    View that checks the hash in a password activation link and presents a
    form for entering a new password. We can activate the account for real
    once we know the email is valid and a password has been set.
    """
    form_class = ActivationForm
    template_name = 'accounts/activate/verification_key.html'

    @property
    def contact(self):
        if not hasattr(self, '_contact'):
            #pylint:disable=attribute-defined-outside-init
            self._contact = Contact.objects.get_token(
                self.kwargs.get(self.key_url_kwarg))
        return self._contact

    def get_context_data(self, **kwargs):
        context = super(ActivationView, self).get_context_data(**kwargs)
        context.update({'object': self.contact})
        if self.contact and self.contact.extra:
            # XXX 'reason' might be best as a separate field.
            context.update({'reason': self.contact.extra})
        return context

    def get_initial(self):
        initial = {}
        if self.contact:
            # It is important to set the values to the User if it exists
            # such that straight e-mail verification does not inadvertently
            # update the `username`.
            email = self.contact.email
            if not email and self.contact.user:
                email = self.contact.user.email
            full_name = self.contact.full_name
            if not full_name and self.contact.user:
                full_name = self.contact.user.get_full_name()
            initial = {
                'email': email,
                'full_name': full_name,
                'username': (self.contact.user.username
                    if self.contact.user else self.contact.slug),
                'phone': self.contact.phone,
            }
            verification_key = self.kwargs.get(self.key_url_kwarg)
            if self.contact.email_verification_key == verification_key:
                initial.update({'email_verification': True})
            if self.contact.phone_verification_key == verification_key:
                initial.update({'phone_verification': True})
        return initial

    def dispatch(self, request, *args, **kwargs):
        # We put the code inline instead of using method_decorator() otherwise
        # kwargs is interpreted as parameters in sensitive_post_parameters.
        request.sensitive_post_parameters = '__ALL__'
        response = super(ActivationView, self).dispatch(
            request, *args, **kwargs)
        add_never_cache_headers(response)
        return response

    def get(self, request, *args, **kwargs): # ActivationView
        context = None
        if not self.contact:
            # We return a custom 404 page such that a user has a chance
            # to see an explanation of why clicking an expired link
            # in an e-mail leads to a 404.
            status_code = 404
            context = self.get_context_data()
            context.update({'reason': _("Activation failed. You may have"\
                " already activated your account previously. In that case,"\
                " just login. Thank you.")})
            return self.render_to_response(context, status=status_code)

        try:
            self.run_pipeline()
            # We have an active user, so we are login them in directly.
            return HttpResponseRedirect(self.get_success_url())
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except OTPRequired:
            form = self.get_mfa_form()
            context = self.get_context_data(form=form)
        except AuthDisabled:
            context = {'disabled_authentication': True}
        except RegistrationDisabled:
            context = {'disabled_registration': True}
        except serializers.ValidationError:
            pass
        except exceptions.AuthenticationFailed:
            # Force registration
            pass

        if not context:
            context = self.get_context_data(form=self.get_form())
        return self.render_to_response(context)


    def post(self, request, *args, **kwargs): # ActivationView
        context = None
        try:
            self.run_pipeline()
            return HttpResponseRedirect(self.get_success_url())
        except serializers.ValidationError as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except OTPRequired as err:
            form = self.get_mfa_form()
            context = self.get_context_data(form=form)
        except AuthDisabled:
            context = {'disabled_authentication': True}
        except RegistrationDisabled:
            context = {'disabled_registration': True}

        if context is None:
            context = self.get_context_data(form=self.get_form())
        return self.render_to_response(context)


class PasswordResetConfirmView(PasswordResetConfirmMixin, ActivationView):
    """
    Specific view that will first reset a user's password so the form displays.
    """
    form_class = PasswordResetConfirmForm


class SigninView(LoginMixin, AuthResponseMixin, ProcessFormView):
    """
    Check credentials and sign in the authenticated user.
    """
    form_class = AuthenticationForm
    password_form_class = PasswordAuthForm
    template_name = 'accounts/login.html'

    def get_form_class(self):
        if ('code' in self.request.POST and
            not 'code' in self.form_class.base_fields):
            return self.mfa_code_form_class
        if ('password' in self.request.POST and
            not 'password' in self.form_class.base_fields):
            return self.password_form_class
        return self.form_class

    def get_form_kwargs(self):
        kwargs = super(SigninView, self).get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs

    def get_initial(self):
        initial = super(SigninView, self).get_initial()
        if not 'password' in self.form_class.base_fields:
            initial.update({'password': ""})
        return initial

    def get_password_form(self):
        form_class = self.get_form_class()
        if not 'password' in form_class.base_fields:
            form_class = self.password_form_class
            form = form_class(**self.get_form_kwargs())
            form._errors = ErrorDict() #pylint:disable=protected-access
        else:
            form = form_class(**self.get_form_kwargs())
        return form

    def get(self, request, *args, **kwargs):
        return self.render_to_response(self.get_context_data())

    def post(self, request, *args, **kwargs): # SigninView
        context = None
        try:
            self.run_pipeline()
            return HttpResponseRedirect(self.get_success_url())
        except serializers.ValidationError as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
            context.update({'email_verification_link': True})
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except OTPRequired as err:
            form = self.get_mfa_form()
            context = self.get_context_data(form=form)
        except PasswordRequired as err:
            form = self.get_password_form()
            context = self.get_context_data(form=form)
            context.update({
                'email_verification_link': reverse('password_reset')})
        except VerifyRequired as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
        except AuthDisabled:
            context = {'disabled_authentication': True}
        except exceptions.AuthenticationFailed as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
            disabled_registration = get_disabled_registration(self.request)
            context.update({'register_link': (reverse('registration_register')
                if not disabled_registration else None),})

        if not context:
            context = self.get_context_data()
        return self.render_to_response(context)


class SignoutView(AuthResponseMixin, View):
    """
    Log out the authenticated user.
    """
    template_name = 'accounts/logout.html'

    def get(self, request, *args, **kwargs): #pylint:disable=unused-argument
        LOGGER.info("%s signed out.", self.request.user,
            extra={'event': 'logout', 'request': request})
        auth_logout(request)
        next_url = self.get_success_url()
        response = HttpResponseRedirect(next_url)
        if settings.LOGOUT_CLEAR_COOKIES:
            for cookie in settings.LOGOUT_CLEAR_COOKIES:
                response.delete_cookie(cookie)
        return response
