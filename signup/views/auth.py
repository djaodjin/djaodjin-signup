# Copyright (c) 2022, Djaodjin Inc.
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

import logging, re

from django.contrib import messages
from django.contrib.auth import (login as auth_login, logout as auth_logout,
    REDIRECT_FIELD_NAME, authenticate, get_user_model)
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import Http404, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.utils.http import urlencode, urlsafe_base64_decode
from django.views.decorators.cache import add_never_cache_headers
from django.views.generic.base import TemplateResponseMixin, View
from django.views.generic.edit import FormMixin, ProcessFormView, UpdateView
from rest_framework import serializers, exceptions

from .. import settings
from ..auth import validate_redirect
from ..compat import gettext_lazy as _, is_authenticated, reverse, six
from ..forms import (ActivationForm, AuthenticationForm, FrictionlessSignupForm,
    MFACodeForm, PasswordResetForm, PasswordResetConfirmForm, UserActivateForm)
from ..helpers import has_invalid_password
from ..mixins import (ActivateMixin, LoginMixin, RecoverMixin, RegisterMixin,
    SSORequired, UrlsMixin)
from ..models import Contact
from ..utils import (fill_form_errors, get_disabled_authentication,
    get_disabled_registration, get_password_reset_throttle)
from ..validators import as_email_or_phone


LOGGER = logging.getLogger(__name__)


def _login(request, user):
    """
    Attaches a session cookie to the request and
    generates an login event in the audit logs.
    """
    auth_login(request, user)
    LOGGER.info("%s signed in.", user,
        extra={'event': 'login', 'request': request})


class RedirectFormMixin(FormMixin):
    success_url = settings.LOGIN_REDIRECT_URL

    def get_success_url(self):
        next_url = validate_redirect(self.request)
        if not next_url:
            next_url = super(RedirectFormMixin, self).get_success_url()
        return next_url

    def get_context_data(self, **kwargs):
        context = super(RedirectFormMixin, self).get_context_data(**kwargs)
        next_url = validate_redirect(self.request)
        if next_url:
            context.update({REDIRECT_FIELD_NAME: next_url})
        return context


class AuthTemplateResponseMixin(UrlsMixin, TemplateResponseMixin):
    """
    Returns a *disabled* page regardless when get_disabled_authentication
    is True.
    """

    def get_context_data(self, **kwargs):
        context = super(AuthTemplateResponseMixin, self).get_context_data(
            **kwargs)
        # URLs for user
        disabled_registration = get_disabled_registration(self.request)
        self.update_context_urls(context, {
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

    def dispatch(self, request, *args, **kwargs):
        if request.method.lower() in self.http_method_names:
            if request.method.lower() == 'post':
                # The authentication URLs are anonymously accessible, hence
                # prime candidates for bots. These will POST to '/login/.' for
                # example because there is a `action="."` in the <form> tag
                # in login.html.
                # We cannot catch these by restricting the match pattern.
                # 1. '^login/$' will not match 'login/.' hence trigger the catch
                #    all pattern that might forward the HTTP request.
                # 2. 'login/(?P<extra>.*)' will through a missing argument
                #    exception in `reverse` calls.
                try:
                    pat = (r'(?P<expected_path>%s)(?P<extra>.*)' %
                        request.resolver_match.route)
                    look = re.match(pat, request.path.lstrip('/'))
                    if look:
                        expected_path = '/' + look.group('expected_path')
                        extra =  look.group('extra')
                        if extra:
                            return HttpResponseRedirect(
                                self.request.build_absolute_uri(expected_path))
                except AttributeError:
                    pass # Django<=1.11 ResolverMatch does not have
                         # a route attribute.
            if get_disabled_authentication(request):
                context = {'disabled_authentication': True}
                response_kwargs = {}
                response_kwargs.setdefault('content_type', self.content_type)
                return TemplateResponse(
                    request=request, template='accounts/disabled.html',
                    context=context, **response_kwargs)
        return super(AuthTemplateResponseMixin, self).dispatch(
            request, *args, **kwargs)


class RedirectFormView(RedirectFormMixin, ProcessFormView):
    """
    Redirects on form valid.
    """


class PasswordResetBaseView(RecoverMixin, RedirectFormMixin, ProcessFormView):
    """
    Enter email address or phone number to reset password.
    """
    model = get_user_model()
    form_class = PasswordResetForm
    token_generator = default_token_generator

    def check_user_throttles(self, request, user):
        throttle = get_password_reset_throttle()
        if throttle:
            throttle(request, self, user)

    def form_valid(self, form):
        username = form.cleaned_data.get('email', None)
        email, phone = as_email_or_phone(username)
        try:
            self.recover_user(**form.cleaned_data)
            if phone:
                messages.info(self.request,
                    _("Please follow the instructions in the phone message"\
                    " that has just been sent to you to reset"\
                    " your password."))
            elif email:
                messages.info(self.request,
                    _("Please follow the instructions"\
                    " in the email that has just been sent to you to reset"\
                    " your password."))
            return super(PasswordResetBaseView, self).form_valid(form)
        except serializers.ValidationError as err:
            fill_form_errors(form, err)

        except SSORequired as err:
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
            return self.render_to_response(context)

        except exceptions.PermissionDenied as err:
            pass

        return self.form_invalid(form)


class PasswordResetConfirmBaseView(RedirectFormMixin, ProcessFormView):
    """
    Clicked on the link sent in the reset e-mail.
    """
    model = get_user_model()
    form_class = PasswordResetConfirmForm
    token_generator = default_token_generator
    post_reset_login = True

    def form_valid(self, form):
        if self.post_reset_login:
            user = self.object
            user_with_backend = authenticate(self.request,
                username=user.username,
                password=form.cleaned_data['new_password'])
            _login(self.request, user_with_backend)
        return super(PasswordResetConfirmBaseView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(PasswordResetConfirmBaseView,
                        self).get_context_data(**kwargs)
        user = self.object
        if user is not None and self.token_generator.check_token(
                                    user, self.kwargs.get('token')):
            context.update({'validlink': True})
        return context

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests, instantiating a form instance with the passed
        POST variables and then checked for validity.
        """
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        user = self.object
        if user is not None and self.token_generator.check_token(
                                    user, self.kwargs.get('token')):
            if form.is_valid():
                form.save()
                LOGGER.info("%s reset her/his password.", user,
                    extra={'event': 'resetpassword', 'request': request})
                return self.form_valid(form)
        return self.form_invalid(form)

    def get_success_url(self):
        messages.info(self.request,
            _("Your password has been reset sucessfully."))
        return super(PasswordResetConfirmBaseView, self).get_success_url()

    def get_form_kwargs(self):
        """
        Returns the keyword arguments for instantiating the form.
        """
        kwargs = super(PasswordResetConfirmBaseView, self).get_form_kwargs()
        try:
            uid = urlsafe_base64_decode(self.kwargs.get('uidb64'))
            if not isinstance(uid, six.string_types):
                # See Django2.2 release notes
                uid = uid.decode()
            self.object = self.model.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, self.model.DoesNotExist):
            self.object = None
        kwargs.update({'instance': self.object})
        return kwargs


class SignupBaseView(RedirectFormMixin, RegisterMixin, ProcessFormView):
    """
    A frictionless registration backend With a full name and email
    address, the user is immediately signed up and logged in.
    """
    model = get_user_model()
    form_class = FrictionlessSignupForm
    fail_url = ('registration_register', (), {})

    def dispatch(self, request, *args, **kwargs):
        if request.method.lower() in self.http_method_names:
            if get_disabled_registration(request):
                context = {'disabled_registration': True}
                response_kwargs = {}
                response_kwargs.setdefault('content_type', self.content_type)
                return TemplateResponse(request=request,
                    template='accounts/disabled.html',
                    context=context, **response_kwargs)
        return super(SignupBaseView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        try:
            cleaned_data = {}
            for field_name in six.iterkeys(form.data):
                cleaned_data.update({
                    field_name: form.cleaned_data.get(
                        field_name, form.data[field_name])})
            new_user = self.register(**cleaned_data)
        except serializers.ValidationError as err:
            fill_form_errors(form, err)
            return self.form_invalid(form)
        except SSORequired as err:
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
            return self.render_to_response(context)
        if new_user:
            success_url = self.get_success_url()
        else:
            success_url = self.request.META['PATH_INFO']
        return HttpResponseRedirect(success_url)

    def get_initial(self):
        initial = super(SignupBaseView, self).get_initial()
        for key, value in six.iteritems(self.request.GET):
            initial.update({key: value})
        return initial

    def register(self, **cleaned_data):
        user = self.register_user(
            next_url=self.get_success_url(), **cleaned_data)
        _login(self.request, user)
        return user


class ActivationBaseView(RedirectFormMixin, ActivateMixin, UpdateView):
    """
    The user is now on the activation url that was sent in an email.
    It is time to complete the registration and activate the account.

    View that checks the hash in a password activation link and presents a
    form for entering a new password. We can activate the account for real
    once we know the email is valid and a password has been set.
    """
    form_class = ActivationForm
    http_method_names = ['get', 'post']

    def get_context_data(self, **kwargs):
        context = super(ActivationBaseView, self).get_context_data(**kwargs)
        user = self.object
        if user:
            contact = getattr(user, '_contact', None)
            if contact and contact.extra:
                # XXX 'reason' might be best as a separate field.
                context.update({'reason': contact.extra})
        return context

    def get_form_class(self):
        if self.object and not has_invalid_password(self.object):
            return UserActivateForm
        return super(ActivationBaseView, self).get_form_class()

    def get_initial(self):
        if self.object:
            return {
                'email': self.object.email,
                'full_name': self.object.get_full_name(),
                'username': self.object.username}
        return {}

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        if is_authenticated(request):
            if request.user != self.object:
                auth_logout(request)
        # We put the code inline instead of using method_decorator() otherwise
        # kwargs is interpreted as parameters in sensitive_post_parameters.
        request.sensitive_post_parameters = '__ALL__'
        response = super(ActivationBaseView, self).dispatch(
            request, *args, **kwargs)
        add_never_cache_headers(response)
        return response

    def form_valid(self, form):
        user_with_backend = None
        if isinstance(form, UserActivateForm):
            password = form.cleaned_data.get('password')
            user = self.object
            if user:
                user_with_backend = authenticate(self.request,
                    username=user.username, password=password)
                if not user_with_backend:
                    form.add_error('password', ValidationError(
                        _("Please enter a correct password.")))
                    return self.form_invalid(form)

        user = self.activate_user(**form.cleaned_data)
        if user.last_login:
            messages.info(
                self.request, _("Thank you. Your account is now active."))

        # Okay, security check complete. Log the user in.
        if not user_with_backend:
            password = form.cleaned_data.get(
                'password', form.cleaned_data.get('new_password'))
            user_with_backend = authenticate(
                self.request, username=user.username, password=password)

        # There is something really wrong if user_with_backend is `None`
        # at that point.
        _login(self.request, user_with_backend)
        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()
        return HttpResponseRedirect(self.get_success_url())

    def get(self, request, *args, **kwargs):
        # We return a custom 404 page such that a user has a chance
        # to see an explanation of why clicking an expired link
        # in an e-mail leads to a 404.
        status_code = 200
        next_url = validate_redirect(self.request)
        context = self.get_context_data(**kwargs)
        user = self.object
        if not user:
            status_code = 404
            messages.error(request, _("Activation failed. You may have"\
                " already activated your account previously. In that case,"\
                " just login. Thank you."))
            if next_url:
                return HttpResponseRedirect(next_url)
            return self.render_to_response(context, status=status_code)

        if is_authenticated(request) and self.request.user == user:
            user = self.activate_user()
            if user.last_login:
                messages.info(self.request,
                    _("Thank you for verifying your e-mail address."))
            return HttpResponseRedirect(self.get_success_url())

        email = user.email
        try:
            self.check_sso_required(email)
        except SSORequired as err:
            context.update({'sso_required': err})

        return self.render_to_response(context, status=status_code)

    def get_object(self, queryset=None):  #pylint:disable=unused-argument
        contact = Contact.objects.get_token(self.kwargs.get(self.key_url_kwarg))
        if not contact:
            raise Http404(_("Cannot find activation token '%(token)s'") % {
                'token': self.kwargs.get(self.key_url_kwarg)})
        user = contact.user
        if user:
            # Set the Contact instance that was used to identify the User.
            #pylint:disable=protected-access
            user._contact = contact
        return user


class SigninBaseView(LoginMixin, RedirectFormMixin, ProcessFormView):
    """
    Check credentials and sign in the authenticated user.
    """
    model = get_user_model()
    form_class = AuthenticationForm
    password_form_class = AuthenticationForm
    mfa_code_form_class = MFACodeForm

    def get_form_class(self):
        if ('code' in self.request.POST and
            not 'code' in self.form_class.base_fields):
            return self.mfa_code_form_class
        if ('password' in self.request.POST and
            not 'password' in self.form_class.base_fields):
            return self.password_form_class
        return self.form_class

    def get_form_kwargs(self):
        kwargs = super(SigninBaseView, self).get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs

    def get_password_form(self):
        form_class = self.form_class
        if not 'password' in self.form_class.base_fields:
            form_class = self.password_form_class
        form = form_class(**self.get_form_kwargs())
        return form

    def get_mfa_form(self):
        form = self.mfa_code_form_class(**self.get_form_kwargs())
        # We must pass the username and password back to the browser
        # as hidden fields, but prevent calls to `form.non_field_errors()`
        # in the templates to inadvertently trigger a call
        # to `MFACodeForm.clean()`.
        form._errors = {} #pylint:disable=protected-access
        return form

    def form_valid(self, form):
        try:
            user = self.login_user(**form.cleaned_data)
            _login(self.request, user)
            return super(SigninBaseView, self).form_valid(form)
        except serializers.ValidationError as err:
            for error in err.detail:
                if 'password' in error:
                    form = self.get_password_form()
                elif 'code' in error:
                    form = self.get_mfa_form()
            fill_form_errors(form, err)

        except SSORequired as err:
            context = self.get_context_data(form=form)
            context.update({'sso_required': err})
            return self.render_to_response(context)

        except exceptions.PermissionDenied as err:
            pass

        return self.form_invalid(form)

    def form_invalid(self, form):
        username = form.cleaned_data.get('username')
        # It is possible username should be interpreted as an e-mail address
        # and yet be entered incorrectly, in which case the `username` key
        # won't be present in the `cleaned_data`.
        if username:
            try:
                user = self.candidate_user(username)
            except SSORequired as err:
                form._errors = {} #pylint:disable=protected-access
                context = self.get_context_data(form=form)
                context.update({'sso_required': err})
                return self.render_to_response(context)

            except serializers.ValidationError as err:
                # We want to prevent duplicate error messages when the user
                # cannot be found in the database.
                form._errors = {} #pylint:disable=protected-access
                fill_form_errors(form, err)
                # Django takes extra steps to make sure an attacker finds
                # it difficult to distinguish between a non-existant user
                # and an incorrect password on login.
                # This is only useful when registration is disabled otherwise
                # an attacker could simply use the register end-point instead.
                if not get_disabled_registration(self.request):
                    # If we have attempted to login a user that is not yet
                    # registered, automatically redirect to the registration
                    # page and pre-populate the form fields.
                    try:
                        validate_email(username)
                        query_params = {'email': username}
                        messages.error(self.request, _("This email is not yet"\
                            " registered. Would you like to do so?"))
                    except ValidationError:
                        query_params = {'username': username}
                        messages.error(self.request, _(
                            "This username is not yet"\
                            " registered. Would you like to do so?"))
                    next_url = validate_redirect(self.request)
                    if next_url:
                        query_params.update({REDIRECT_FIELD_NAME: next_url})
                    redirect_to = reverse('registration_register')
                    if query_params:
                        redirect_to += '?%s' % urlencode(query_params)
                    return HttpResponseRedirect(redirect_to)
        return super(SigninBaseView, self).form_invalid(form)


class SignoutBaseView(RedirectFormMixin, View):
    """
    Log out the authenticated user.
    """

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


# Actual views to instantiate start here:

class ActivationView(AuthTemplateResponseMixin, ActivationBaseView):

    template_name = 'accounts/activate/verification_key.html'


class PasswordResetView(AuthTemplateResponseMixin, PasswordResetBaseView):

    template_name = 'accounts/recover.html'


class PasswordResetConfirmView(AuthTemplateResponseMixin,
                               PasswordResetConfirmBaseView):

    template_name = 'accounts/reset.html'


class SigninView(AuthTemplateResponseMixin, SigninBaseView):

    template_name = 'accounts/login.html'


class SignoutView(AuthTemplateResponseMixin, SignoutBaseView):

    template_name = 'accounts/logout.html'


class SignupView(AuthTemplateResponseMixin, SignupBaseView):

    template_name = 'accounts/register.html'
