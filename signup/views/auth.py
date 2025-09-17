# Copyright (c) 2025, Djaodjin Inc.
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

import re, logging

from django.contrib.auth import logout as auth_logout, REDIRECT_FIELD_NAME
from django.http import HttpResponseRedirect
from django.views.decorators.cache import add_never_cache_headers
from django.views.generic.base import TemplateResponseMixin, View
from django.views.generic.edit import FormMixin, ProcessFormView
from rest_framework import exceptions, serializers

from .. import settings
from ..auth import validate_redirect
from ..compat import gettext_lazy as _, reverse
from ..forms import (ActivationForm, CodeActivationForm,
    FrictionlessSignupForm, OTPCodeForm, PasswordAuthForm,
    PasswordResetConfirmForm, StartAuthenticationForm,
    VerifyEmailForm, VerifyPhoneForm)
from ..helpers import update_context_urls
from ..mixins import (LoginMixin, PasswordResetConfirmMixin,
    RegisterMixin, VerifyMixin, VerifyCompleteMixin, AuthDisabled,
    IncorrectUser, OTPRequired, PasswordRequired, RegistrationDisabled,
    SSORequired, VerifyEmailRequired, VerifyPhoneRequired)
from ..models import Contact
from ..utils import fill_form_errors, get_disabled_registration


LOGGER = logging.getLogger(__name__)


class AuthResponseMixin(TemplateResponseMixin, FormMixin):
    """
    Returns a *disabled* page regardless when get_disabled_authentication
    is True.
    """
    success_url = settings.LOGIN_REDIRECT_URL
    verify_email_form_class = VerifyEmailForm
    verify_phone_form_class = VerifyPhoneForm
    password_form_class = PasswordAuthForm
    otp_code_form_class = OTPCodeForm
    set_password_form_class = CodeActivationForm

    def get_form(self, form_class=None):
        """Return an instance of the form to be used in this view."""
        if form_class is None:
            form_class = self.get_form_class()
        kwargs = self.get_form_kwargs()
        return form_class(**kwargs)

    def get_verify_email_form(self):
        if settings.USE_VERIFICATION_LINKS:
            form = self.get_form()
        else:
            form = self.get_form(form_class=self.verify_email_form_class)
        return form

    def get_verify_phone_form(self):
        if settings.USE_VERIFICATION_LINKS:
            form = self.get_form()
        else:
            form = self.get_form(form_class=self.verify_phone_form_class)
        return form

    def get_password_form(self):
        form = self.get_form(form_class=self.password_form_class)
        return form

    def get_otp_form(self):
        form = self.get_form(form_class=self.otp_code_form_class)
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
        context.update({'disabled_registration': disabled_registration})
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


class ActivationView(VerifyCompleteMixin, AuthResponseMixin, ProcessFormView):
    """
    The user is now on the activation url that was sent in an email.
    It is time to complete the registration and activate the account.

    View that checks the hash in a password activation link and presents a
    form for entering a new password. We can activate the account for real
    once we know the email is valid and a password has been set.

    URL paths
    /activate/<verification_key>/
    """
    form_class = ActivationForm
    template_name = 'accounts/activate/verification_key.html'

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
            form = self.get_otp_form()
            context = self.get_context_data(form=form)
        except (exceptions.AuthenticationFailed,
                serializers.ValidationError):
            # Force registration
            pass
        except AuthDisabled:
            context = self.get_context_data()
            context.update({'disabled_authentication': True})
            return self.response_class(
                request=self.request,
                template=['accounts/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)
        except RegistrationDisabled:
            context = self.get_context_data()
            return self.response_class(
                request=request,
                template=['accounts/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)

        if context is None:
            context = self.get_context_data(form=self.get_form())
        return self.render_to_response(context)


    def post(self, request, *args, **kwargs): # ActivationView
        context = None
        try:
            self.run_pipeline()
            return HttpResponseRedirect(self.get_success_url())
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except OTPRequired:
            form = self.get_otp_form()
            context = self.get_context_data(form=form)
        except (exceptions.AuthenticationFailed,
                serializers.ValidationError) as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
        except AuthDisabled:
            context = self.get_context_data()
            context.update({'disabled_authentication': True})
            return self.response_class(
                request=self.request,
                template=['accounts/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)
        except RegistrationDisabled:
            context = self.get_context_data()
            return self.response_class(
                request=request,
                template=['accounts/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)

        if context is None:
            context = self.get_context_data(form=self.get_form())
        return self.render_to_response(context)


class PasswordResetConfirmView(PasswordResetConfirmMixin, ActivationView):
    """
    Specific view that will first reset a user's password so the form displays.

    URL paths
    `/reset/<verification_key>/`
    """
    password_form_class = PasswordResetConfirmForm

    def get_form_class(self):
        contact = self.contact
        if contact and contact.user:
            # Without this check, we might bypass the activation/registration
            # page expected to gather personal information (full_name,
            # phone, etc.)
            return self.password_form_class
        return self.form_class


class SigninView(LoginMixin, AuthResponseMixin, ProcessFormView):
    """
    Workflow page to authenticate a previously existing user,
    or create a new user.

    URL paths:
    `/activate/`
    `/login/`
    """
    form_class = StartAuthenticationForm
    template_name = 'accounts/login.html'

    def get_form_class(self):
        if 'new_password' in self.request.POST:
            return self.set_password_form_class
        if ('otp_code' in self.request.POST and
            not 'otp_code' in self.form_class.base_fields):
            return self.otp_code_form_class
        if ('email_code' in self.request.POST and
            not 'email_code' in self.form_class.base_fields):
            return self.verify_email_form_class
        if ('phone_code' in self.request.POST and
            not 'phone_code' in self.form_class.base_fields):
            return self.verify_phone_form_class
        if ('password' in self.request.POST and
            not 'password' in self.form_class.base_fields):
            return self.password_form_class
        return self.form_class

    def get_initial(self):
        initial = super(SigninView, self).get_initial()
        if not 'password' in self.form_class.base_fields:
            initial.update({'password': ""})
        return initial

    def get(self, request, *args, **kwargs):
        return self.render_to_response(self.get_context_data())

    def post(self, request, *args, **kwargs): # SigninView
        #pylint:disable=too-many-locals,protected-access
        context = None
        try:
            self.run_pipeline()
            return HttpResponseRedirect(self.get_success_url())
        except serializers.ValidationError as err:
            form = self.get_form()
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
            context.update({
                'email_verification_link': reverse('password_reset')})
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except OTPRequired as err:
            form = self.get_otp_form()
            fill_form_errors(form, err, aliases={
                'email': 'username', 'phone': 'username'})
            form._errors.pop('otp_code', None)
            context = self.get_context_data(form=form)
        except PasswordRequired as err:
            form = self.get_password_form()
            fill_form_errors(form, err, aliases={
                'email': 'username', 'phone': 'username'})
            form._errors.pop('password', None)
            form._errors.pop('new_password', None)
            form._errors.pop('new_password2', None)
            context = self.get_context_data(form=form)
            verification_link = self.request.path
            context.update({'email_verification_link': verification_link})
        except VerifyEmailRequired as err:
            # `verify_email` lands here.
            cleaned_data = self.validate_inputs(raise_exception=False)
            form = self.get_verify_email_form()
            fill_form_errors(form, err, aliases={'email': 'username'})
            form._errors.pop('email_code', None)
            if 'email_code' in form:
                username = cleaned_data.get('email')
                if not username:
                    username = _("your email address")
                form['email_code'].label = \
                _("Enter the code we sent to <strong>%(username)s</strong>") % {
                    'username': username}
            context = self.get_context_data(form=form)
        except VerifyPhoneRequired as err:
            # `verify_phone` lands here.
            form = self.get_verify_phone_form()
            fill_form_errors(form, err, aliases={'phone': 'username'})
            form._errors.pop('phone_code', None)
            if 'phone_code' in form:
                username = cleaned_data.get('phone')
                if not username:
                    username = _("your phone number")
                form['phone_code'].label = \
                _("Enter the code we sent to <strong>%(username)s</strong>") % {
                    'username': username}
            context = self.get_context_data(form=form)
        except IncorrectUser as err:
            # We couldn't find a user model, and most likely will have
            # to register a new user.
            cleaned_data = self.validate_inputs(raise_exception=False)
            form = self.get_form(form_class=self.set_password_form_class)
            form._errors = {}
            form.data = form.data.copy()
            email = cleaned_data.get('email')
            if email:
                form.data.setlist('email', [email])
            username = cleaned_data.get('username')
            if not re.match(r"^%s$" % settings.USERNAME_PAT, username):
                form.data.pop('username', None)
            context = self.get_context_data(form=form)
        except exceptions.AuthenticationFailed as err:
            cleaned_data = self.validate_inputs(raise_exception=False)
            email_verification_link = None
            phone_verification_link = None
            register_link = None
            form = self.get_form()
            if 'email' in cleaned_data and cleaned_data['email']:
                form.data = form.data.copy()
                form.data.setlist('check_email', [True])
                form.add_error('username',
            _("This e-mail address must be verified before going any further."))
                email_verification_link = self.request.path
            elif 'phone' in cleaned_data and cleaned_data['phone']:
                form.data = form.data.copy()
                form.data.setlist('check_phone', [True])
                phone_verification_link = self.request.path
            else:
                disabled_registration = get_disabled_registration(self.request)
                register_link = (reverse('registration_register')
                    if not disabled_registration else None)
            fill_form_errors(form, err)
            context = self.get_context_data(form=form)
            if email_verification_link:
                context.update({
                    'email_verification_link': email_verification_link})
            if phone_verification_link:
                context.update({
                    'phone_verification_link': phone_verification_link})
            if register_link:
                context.update({
                    'register_link': register_link})
        except AuthDisabled:
            context = self.get_context_data()
            context.update({'disabled_authentication': True})
            return self.response_class(
                request=request,
                template=['accounts/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)
        except RegistrationDisabled:
            context = self.get_context_data()
            return self.response_class(
                request=request,
                template=['accounts/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)

        if context is None:
            context = self.get_context_data()
        return self.render_to_response(context)


class RecoverView(VerifyMixin, SigninView):
    """
    Workflow page to authenticate by verifying an email address
    or phone number instead of a password, then reset password.

    URL paths:
    `/recover/`
    """
    template_name = 'accounts/recover.html'


class SignupView(RegisterMixin, SigninView):
    """
    Overrides the entry point to up-fron the full name and email
    address field, as well as not present any form in case registration
    has been disabled.

    URL paths:
    `/register/`
    `/register/<var>`
    `/register/frictionless/`
    """
    form_class = FrictionlessSignupForm
    template_name = 'accounts/register.html'

    def get(self, request, *args, **kwargs):
        disabled_registration = get_disabled_registration(request)
        if disabled_registration:
            return self.response_class(
                request=request,
                template=['accounts/disabled.html'],
                context=self.get_context_data(),
                using=self.template_engine,
                content_type=self.content_type)
        return self.render_to_response(self.get_context_data())


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


class VerificationView(AuthResponseMixin, ProcessFormView):
    """
    The user is now on the verification url. We are waiting for an e-mail code.
    """
    form_class = VerifyEmailForm
    template_name = 'accounts/verify.html'

    @property
    def contact(self):
        if not hasattr(self, '_contact'):
            #pylint:disable=attribute-defined-outside-init
            self._contact = Contact.objects.get_token(
                self.kwargs.get(self.key_url_kwarg))
        return self._contact

    @property
    def phone_code_expected(self):
        if not hasattr(self, '_phone_code_expected'):
            #pylint:disable=attribute-defined-outside-init
            self._phone_code_expected = (self.contact.phone_verification_key
                == self.kwargs.get(self.key_url_kwarg))
        return self._phone_code_expected

    def get_form_class(self):
        if self.phone_code_expected:
            return VerifyPhoneForm
        return self.form_class

    def get_initial(self):
        return {
            'email': self.contact.email,
            'phone': self.contact.phone
         }

    def form_valid(self, form):
        if self.phone_code_expected:
            try:
                Contact.objects.finalize_phone_verification(
                    form.cleaned_data['phone'], form.cleaned_data['phone_code'])
            except Contact.DoesNotExist:
                form.add_error('phone_code',
                    _("Phone verification code does not match."))
                return self.form_invalid(form)
            return HttpResponseRedirect(self.get_success_url())
        try:
            Contact.objects.finalize_email_verification(
                form.cleaned_data['email'], form.cleaned_data['email_code'])
        except Contact.DoesNotExist:
            form.add_error('email_code',
                _("Email verification code does not match."))
            return self.form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())
