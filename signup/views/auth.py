# Copyright (c) 2026, Djaodjin Inc.
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

from django import forms
from django.contrib.auth import logout as auth_logout, REDIRECT_FIELD_NAME
from django.http import HttpResponseRedirect
from django.views.decorators.cache import add_never_cache_headers
from django.views.generic.base import TemplateResponseMixin, RedirectView
from django.views.generic.edit import FormMixin, ProcessFormView
from rest_framework import exceptions, serializers

from .. import settings
from ..auth import validate_redirect
from ..compat import gettext_lazy as _, reverse
from ..forms import (ActivationForm, ActivationAuthForm, CodeActivationForm,
    OTPCodeForm, PasswordAuthForm, PasswordResetConfirmForm,
    StartAuthenticationForm, VerifyEmailForm, VerifyPhoneForm)
from ..helpers import has_invalid_password, update_context_urls
from ..mixins import (LoginMixin, RegisterMixin, VerifyCompleteMixin,
    AuthDisabled, IncorrectUser, OTPRequired, PasswordRequired,
    RegistrationDisabled, SSORequired, VerifyEmailFailed, VerifyEmailRequired,
    VerifyPhoneFailed, VerifyPhoneRequired)
from ..utils import fill_form_errors, get_disabled_registration
from ..validators import as_email_or_phone


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

    def _update_form_focus(self, form, field_focus):
        for field_name, field in form.fields.items():
            if field_name == field_focus:
                form.fields[field_name].widget.attrs['autofocus'] = True
            else:
                form.fields[field_name].widget.attrs['autofocus'] = False


    def _update_form_errors(self, form, err, aliases=None):
        fill_form_errors(form, err, aliases=aliases)
        if 'email_code' in form.fields:
            check_email = (form.data.get('check_email') and
                not form.data.get('email_code'))
            if check_email or 'email_code' in form.errors:
                self._update_form_focus(form, 'email_code')
            else:
                form.fields['email_code'].widget = forms.HiddenInput()
        if 'phone_code' in form.fields:
            check_phone = (form.data.get('check_phone') and
                not form.data.get('phone_code'))
            if check_phone or 'phone_code' in form.errors:
                self._update_form_focus(form, 'phone_code')
            else:
                form.fields['phone_code'].widget = forms.HiddenInput()

    def get_verify_email_form(self):
        form_class = self.get_form_class()
        if not settings.USE_VERIFICATION_LINKS:
            if 'email_code' not in form_class.base_fields:
                form_class = self.verify_email_form_class
        return self.get_form(form_class=form_class)

    def get_verify_phone_form(self):
        form_class = self.get_form_class()
        if not settings.USE_VERIFICATION_LINKS:
            if 'phone_code' not in form_class.base_fields:
                form_class = self.verify_phone_form_class
        return self.get_form(form_class=form_class)

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
        context = super(AuthResponseMixin, self).get_context_data(**kwargs)
        sep = ""
        query = ""
        next_url = validate_redirect(self.request)
        if next_url:
            query = "%s%s=%s" % (sep, REDIRECT_FIELD_NAME, next_url)
            sep = "&"
        if query:
            context.update({'query': query})

        # URLs for user
        disabled_registration = get_disabled_registration(self.request)
        context.update({'disabled_registration': disabled_registration})
        update_context_urls(context, {
            'api': {
                'login': reverse('api_login'),
                'register': (reverse('api_register')
                    if not disabled_registration else None),
            },
            'user': {
                'login': str(settings.LOGIN_URL),
        }})
        return context


class VerifyCompleteView(VerifyCompleteMixin, AuthResponseMixin,
                         ProcessFormView):
    """
    The user is now on the activation url that was sent in an email.
    It is time to complete the registration and activate the account.

    View that checks the hash in a password activation link and presents a
    form for entering a new password. We can activate the account for real
    once we know the email is valid and a password has been set.

    The email was marked verified on GET, but that creates lots of problems
    with email phishing detection software as they would trigger a GET request
    on a one-time link. We have introduced a page with a button to click
    in order to insure `run_pipeline` runs on POST only.

    URL paths
    /activate/<verification_key>/
    """
    form_class = ActivationForm
    password_form_class = ActivationAuthForm
    set_password_form_class = PasswordResetConfirmForm

    template_name = 'login/verification_key.html'

    def get_context_data(self, **kwargs):
        context = super(VerifyCompleteView, self).get_context_data(**kwargs)
        context.update({'object': self.contact})
        if self.contact and self.contact.extra:
            # XXX 'reason' might be best as a separate field.
            context.update({'reason': self.contact.extra})
        return context

    def get_form_class(self):
        contact = self.contact
        if contact and contact.user and not has_invalid_password(contact.user):
            # Without this check, we might bypass the activation/registration
            # page expected to gather personal information (full_name,
            # phone, etc.)
            return self.password_form_class
        return self.form_class

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
        response = super(VerifyCompleteView, self).dispatch(
            request, *args, **kwargs)
        add_never_cache_headers(response)
        return response

    def get(self, request, *args, **kwargs): # VerifyCompleteView
        context = None
        if not self.contact:
            # We return a custom 404 page such that a user has a chance
            # to see an explanation of why clicking an expired link
            # in an e-mail leads to a 404.
            status_code = 404
            context = self.get_context_data()
            context.update({'reason': _("This activation token is invalid"\
                " or has expired. You may have already activated your account"\
                " previously. In that case just login. Thank you.")})
            return self.render_to_response(context, status=status_code)

        try:
            self.pipeline_prefetch()
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except AuthDisabled:
            context = self.get_context_data()
            context.update({'disabled_authentication': True})
            return self.response_class(
                request=self.request,
                template=['login/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)

        if context is None:
            context = self.get_context_data(form=self.get_form())
        return self.render_to_response(context)


    def post(self, request, *args, **kwargs): # VerifyCompleteView
        context = None
        try:
            if self.request.POST.get('reset'):
                raise PasswordRequired(self.contact.user)
            self.run_pipeline()
            return HttpResponseRedirect(self.get_success_url())
        except OTPRequired:
            form = self.get_otp_form()
            context = self.get_context_data(form=form)
        except PasswordRequired:
            form = self.get_form(form_class=self.set_password_form_class)
            #pylint:disable=protected-access
            form._errors = {}
            context = self.get_context_data(form=form)
        except SSORequired as err:
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except (exceptions.AuthenticationFailed,
                serializers.ValidationError) as err:
            form = self.get_form()
            self._update_form_errors(form, err)
            context = self.get_context_data(form=form)
        except AuthDisabled:
            context = self.get_context_data()
            context.update({'disabled_authentication': True})
            return self.response_class(
                request=self.request,
                template=['login/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)
        except RegistrationDisabled:
            context = self.get_context_data()
            return self.response_class(
                request=request,
                template=['login/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)

        if context is None:
            context = self.get_context_data(form=self.get_form())
        return self.render_to_response(context)


class SigninView(LoginMixin, AuthResponseMixin, ProcessFormView):
    """
    Workflow page to authenticate a previously existing user,
    or create a new user.

    URL paths:
    `/activate/`
    `/login/`
    """
    form_class = StartAuthenticationForm
    template_name = 'login/index.html'
    landing_query_param = 'landing'


    def get_context_data(self, **kwargs):
        context = super(SigninView, self).get_context_data(**kwargs)
        sep = ""
        query = ""
        next_url = validate_redirect(self.request)
        if next_url:
            query = "%s%s=%s" % (sep, REDIRECT_FIELD_NAME, next_url)
            sep = "&"
        landing = self.get_landing()
        if landing:
            query = "%s%s=%s" % (sep, self.landing_query_param, landing)
            sep = "&"
        if query:
            context.update({'query': query})
        return context


    def get_form_class(self):
        form_class = self.form_class
        if 'new_password' in self.request.POST:
            form_class = self.set_password_form_class
        elif ('otp_code' in self.request.POST and
            not 'otp_code' in self.form_class.base_fields):
            form_class = self.otp_code_form_class
        elif ('email_code' in self.request.POST and
            not 'email_code' in self.form_class.base_fields):
            form_class = self.verify_email_form_class
        elif ('phone_code' in self.request.POST and
            not 'phone_code' in self.form_class.base_fields):
            form_class = self.verify_phone_form_class
        elif ('password' in self.request.POST and
            not 'password' in self.form_class.base_fields):
            form_class = self.password_form_class
        return form_class

    def get_initial(self):
        initial = super(SigninView, self).get_initial()
        if not 'password' in self.form_class.base_fields:
            initial.update({'password': ""})

        if self.request.method in ("POST", "PUT"):
            initial_data = self.request.POST
            if 'email' in initial_data:
                initial.update({'email': initial_data.get('email')})
            if 'phone' in initial_data:
                initial.update({'phone': initial_data.get('phone')})
            if 'email' not in initial_data and 'phone' not in initial_data:
                username = initial_data.get('username')
                if username:
                    email, phone = as_email_or_phone(username)
                    initial.update({'email': email, 'phone': phone})
            if 'phone' not in initial:
                email = initial.get('email')
                if email:
                    email, phone = as_email_or_phone(email)
                    initial.update({'email': email, 'phone': phone})

        return initial

    def get_landing(self):
        page_name = self.request.GET.get(self.landing_query_param, None)
        if page_name and re.match(r"^[a-zA-Z\-]+$", page_name):
            return page_name
        return None

    def get_template_names(self):
        candidates = super(SigninView, self).get_template_names()
        page_name = self.get_landing()
        if page_name:
            candidates = ["login/%s.html" % page_name] + candidates
        return candidates


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
            LOGGER.debug("[SigninView/ValidationError] %s form is %s",
                err, form.__class__)
            self._update_form_errors(form, err)
            context = self.get_context_data(form=form)
        except SSORequired as err:
            LOGGER.debug("[SigninView/SSORequired] %s", err)
            form = self.get_form()
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
        except OTPRequired as err:
            LOGGER.debug("[SigninView/OTPRequired] %s", err)
            form = self.get_otp_form()
            self._update_form_errors(form, err, aliases={
                'email': 'username', 'phone': 'username'})
            form._errors.pop('otp_code', None)
            context = self.get_context_data(form=form)
        except PasswordRequired as err:
            LOGGER.debug("[SigninView/PasswordRequired] %s", err)
            form = self.get_password_form()
            self._update_form_errors(form, err, aliases={
                'email': 'username', 'phone': 'username'})
            form._errors.pop('password', None)
            form._errors.pop('new_password', None)
            form._errors.pop('new_password2', None)
            context = self.get_context_data(form=form)
            context.update({'check_email': True})
        except VerifyEmailRequired as err:
            # `verify_email` lands here.
            LOGGER.debug("[SigninView/VerifyEmailRequired] %s", err)
            cleaned_data = self.validate_inputs(raise_exception=False)
            form = self.get_verify_email_form()
            self._update_form_errors(form, err, aliases={'email': 'username'})
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
            LOGGER.debug("[SigninView/VerifyPhoneRequired] %s", err)
            form = self.get_verify_phone_form()
            self._update_form_errors(form, err, aliases={'phone': 'username'})
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
            LOGGER.debug("[SigninView/IncorrectUser] %s", err)
            cleaned_data = self.validate_inputs(raise_exception=False)
            form = self.get_form(form_class=self.set_password_form_class)
            self._update_form_errors(form, err)
            form._errors = {}
            form.data = form.data.copy()
            email = cleaned_data.get('email')
            if email:
                form.data.setlist('email', [email])
            phone = cleaned_data.get('phone')
            if phone:
                form.data.setlist('phone', [phone])
            username = cleaned_data.get('username')
            if (username and
                not re.match(r"^%s$" % settings.USERNAME_PAT, username)):
                form.data.pop('username', None)
            context = self.get_context_data(form=form)
            context.update({'requires_registration': True})

        except VerifyEmailFailed as err:
            LOGGER.debug("[SigninView/VerifyEmailFailed] %s", err)
            form = self.get_form()
            cleaned_data = self.validate_inputs(raise_exception=False)
            aliases = {}
            check_email = (
                'email' in cleaned_data and cleaned_data['email'])
            if check_email:
                form.data = form.data.copy()
                form.data.setlist('check_email', [True])
                if 'email' not in form.fields:
                    aliases = {'email': 'username'}
            self._update_form_errors(form, err, aliases=aliases)
            context = self.get_context_data(form=form)
            if check_email:
                context.update({'check_email': check_email})

        except VerifyPhoneFailed as err:
            LOGGER.debug("[SigninView/VerifyPhoneFailed] %s", err)
            form = self.get_form()
            cleaned_data = self.validate_inputs(raise_exception=False)
            aliases = {}
            check_phone = (
                'phone' in cleaned_data and cleaned_data['phone'])
            if check_phone:
                form.data = form.data.copy()
                form.data.setlist('check_phone', [True])
                if 'phone' not in form.fields:
                    aliases = {'phone': 'username'}
            self._update_form_errors(form, err, aliases=aliases)
            context = self.get_context_data(form=form)
            if check_phone:
                context.update({'check_phone': check_phone})

        except exceptions.AuthenticationFailed as err:
            LOGGER.debug("[SigninView/AuthenticationFailed] %s", err)
            form = self.get_form()
            cleaned_data = self.validate_inputs(raise_exception=False)
            self._update_form_errors(form, err)
            #pylint:disable=too-many-nested-blocks
            if isinstance(form, ActivationForm):
                # We are trying to register a new user, while email, phone,
                # or username point to an already registered user.
                for field_name in ['email', 'phone', 'username']:
                    if field_name in form.fields:
                        field_value = cleaned_data.get(field_name)
                        if field_value:
                            try:
                                _unused = self.model.objects.find_user(
                                    field_value)
                                form.add_error(field_name,
                                    _("This %(field_name)s is already taken.")
                                    % {'field_name': field_name})
                                if field_name == 'phone':
                                    # reverts `CodeActivationForm.__init__`
                                    form.fields['phone'].widget.attrs[
                                        'readonly'] = False
                                    form.fields['phone_code'].widget = \
                                        forms.HiddenInput()
                            except self.model.DoesNotExist:
                                pass

            context = self.get_context_data(form=form)

        except AuthDisabled as err:
            LOGGER.debug("[SigninView/AuthDisabled] %s", err)
            context = self.get_context_data()
            context.update({'disabled_authentication': True})
            return self.response_class(
                request=request,
                template=['login/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)
        except RegistrationDisabled as err:
            LOGGER.debug("[SigninView/RegistrationDisabled] %s", err)
            context = self.get_context_data()
            return self.response_class(
                request=request,
                template=['login/disabled.html'],
                context=context,
                using=self.template_engine,
                content_type=self.content_type)

        if context is None:
            context = self.get_context_data()
        return self.render_to_response(context)


class SignupView(RegisterMixin, SigninView):
    """
    Overrides the entry point to up-fron the full name and email
    address field, as well as not present any form in case registration
    has been disabled.

    URL paths:
    `/register/`
    """

    def get(self, request, *args, **kwargs):
        disabled_registration = get_disabled_registration(request)
        if disabled_registration:
            return self.response_class(
                request=request,
                template=['login/disabled.html'],
                context=self.get_context_data(),
                using=self.template_engine,
                content_type=self.content_type)
        return self.render_to_response(self.get_context_data())


class SignoutView(AuthResponseMixin, RedirectView):
    """
    Log out the authenticated user.
    """
    url = settings.LOGIN_URL

    def get(self, request, *args, **kwargs): #pylint:disable=unused-argument
        LOGGER.info("%s signed out.", self.request.user,
            extra={'event': 'logout', 'request': request})
        auth_logout(request)
        resp = super(SignoutView, self).get(request, *args, **kwargs)
        if settings.LOGOUT_CLEAR_COOKIES:
            for cookie in settings.LOGOUT_CLEAR_COOKIES:
                resp.delete_cookie(cookie)
        return resp
