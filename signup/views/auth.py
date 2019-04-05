# Copyright (c) 2019, Djaodjin Inc.
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

from django.contrib import messages
from django.contrib.auth import (login as auth_login, logout as auth_logout,
    REDIRECT_FIELD_NAME, authenticate)
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.utils import six
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.cache import add_never_cache_headers
from django.views.generic.base import TemplateResponseMixin, View
from django.views.generic.edit import FormMixin, ProcessFormView, UpdateView
from rest_framework.exceptions import ValidationError
from rest_framework.settings import api_settings

from .. import settings, signals
from ..auth import validate_redirect
from ..backends.auth import UsernameOrEmailAuthenticationForm
from ..compat import User, reverse, is_authenticated
from ..decorators import check_user_active
from ..forms import (ActivationForm, MFACodeForm, NameEmailForm,
    PasswordResetForm, PasswordResetConfirmForm)
from ..helpers import full_name_natural_split
from ..mixins import UrlsMixin
from ..models import Contact
from ..utils import (fill_form_errors, get_disabled_authentication,
    get_disabled_registration)


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
        user_urls = {}
        if not is_authenticated(self.request):
            disabled_registration = get_disabled_registration(self.request)
            self.update_context_urls(context, {'user': {
               'login': reverse('login'),
               'password_reset': reverse('password_reset'),
               'register': (reverse('registration_register')
                    if not disabled_registration else None),
            }})
        return context

    def dispatch(self, request, *args, **kwargs):
        if request.method.lower() in self.http_method_names:
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


class PasswordResetBaseView(RedirectFormMixin, ProcessFormView):
    """
    Enter email address to reset password.
    """
    form_class = PasswordResetForm
    token_generator = default_token_generator

    def form_valid(self, form):
        try:
            user = User.objects.get(
                email__iexact=form.cleaned_data['email'], is_active=True)
            next_url = validate_redirect(self.request)
            if check_user_active(self.request, user, next_url=next_url):
                # Make sure that a reset password email is sent to a user
                # that actually has an activated account.
                uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()
                token = self.token_generator.make_token(user)
                back_url = self.request.build_absolute_uri(
                    reverse('password_reset_confirm', args=(uid, token)))
                if next_url:
                    back_url += '?%s=%s' % (REDIRECT_FIELD_NAME, next_url)
                signals.user_reset_password.send(
                    sender=__name__, user=user, request=self.request,
                    back_url=back_url, expiration_days=settings.KEY_EXPIRATION)
                messages.info(self.request, _("Please follow the instructions"\
                    " in the email that has just been sent to you to reset"\
                    " your password."))
            else:
                messages.info(self.request, _(
"You should now secure and activate your account following the instructions"\
" we just emailed you. Thank you."))
            return super(PasswordResetBaseView, self).form_valid(form)
        except User.DoesNotExist:
            # We don't want to give a clue about registered users, yet
            # it already possible to do a straight register to get the same.
            messages.error(self.request, _("We cannot find an account"\
                " for this e-mail address. Please verify the spelling."))
        return super(PasswordResetBaseView, self).form_invalid(form)


class PasswordResetConfirmBaseView(RedirectFormMixin, ProcessFormView):
    """
    Clicked on the link sent in the reset e-mail.
    """
    form_class = PasswordResetConfirmForm
    token_generator = default_token_generator

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
                LOGGER.info("%s reset her/his password.", self.request.user,
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
            uid = urlsafe_base64_decode(self.kwargs.get('uidb64')).decode()
            self.object = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            self.object = None
        kwargs.update({'instance': self.object})
        return kwargs


class SignupBaseView(RedirectFormMixin, ProcessFormView):
    """
    A frictionless registration backend With a full name and email
    address, the user is immediately signed up and logged in.
    """

    form_class = NameEmailForm
    fail_url = ('registration_register', (), {})

    @staticmethod
    def first_and_last_names(**cleaned_data):
        first_name = cleaned_data.get('first_name', None)
        last_name = cleaned_data.get('last_name', None)
        if not first_name:
            # If the form does not contain a first_name/last_name pair,
            # we assume a full_name was passed instead.
            full_name = cleaned_data.get(
                'user_full_name', cleaned_data.get('full_name', None))
            first_name, _, last_name = full_name_natural_split(full_name)
        return first_name, last_name

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
                    field_name: form.cleaned_data.get(field_name, None)})
            new_user = self.register(**cleaned_data)
        except ValidationError as err:
            fill_form_errors(form, err)
            return self.form_invalid(form)
        if new_user:
            success_url = self.get_success_url()
        else:
            success_url = self.request.META['PATH_INFO']
        return HttpResponseRedirect(success_url)

    def register_user(self, **cleaned_data):
        #pylint: disable=maybe-no-member
        email = cleaned_data['email']
        users = User.objects.filter(email__iexact=email)
        if users.exists():
            user = users.get()
            if check_user_active(self.request, user,
                                 next_url=self.get_success_url()):
                raise ValidationError(
                    {'email':
                     _("A user with that e-mail address already exists."),
                     api_settings.NON_FIELD_ERRORS_KEY:
                     mark_safe(_(
                         "This email address has already been registered!"\
" Please <a href=\"%s\">login</a> with your credentials. Thank you.")
                        % reverse('login'))})
            else:
                raise ValidationError(
                    {'email':
                     _("A user with that e-mail address already exists."),
                    api_settings.NON_FIELD_ERRORS_KEY:
                     mark_safe(_(
                         "This email address has already been registered!"\
" You should now secure and activate your account following "\
" the instructions we just emailed you. Thank you."))})
            return None

        first_name, last_name = self.first_and_last_names(**cleaned_data)
        username = cleaned_data.get('username', None)
        password = cleaned_data.get('new_password',
            cleaned_data.get('password', None))
        user = User.objects.create_user(username,
            email=email, password=password,
            first_name=first_name, last_name=last_name)
        # Bypassing authentication here, we are doing frictionless registration
        # the first time around.
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        return user

    def register(self, **cleaned_data):
        user = self.register_user(**cleaned_data)
        _login(self.request, user)
        return user


class ActivationBaseView(RedirectFormMixin, UpdateView):
    """
    The user is now on the activation url that was sent in an email.
    It is time to complete the registration and activate the account.

    View that checks the hash in a password activation link and presents a
    form for entering a new password. We can activate the account for real
    once we know the email is valid and a password has been set.
    """
    form_class = ActivationForm
    key_url_kwarg = 'verification_key'
    http_method_names = ['get', 'post']

    def activate_user(self, form):
        # If we don't save the ``User`` model here,
        # we won't be able to authenticate later.
        first_name, last_name = self.first_and_last_names(**form.cleaned_data)
        verification_key = self.kwargs.get(self.key_url_kwarg)
        user = Contact.objects.activate_user(verification_key,
            username=form.cleaned_data['username'],
            password=form.cleaned_data['new_password'],
            first_name=first_name,
            last_name=last_name)
        return user

    @staticmethod
    def first_and_last_names(**cleaned_data):
        first_name = cleaned_data.get('first_name', None)
        last_name = cleaned_data.get('last_name', None)
        if not first_name:
            # If the form does not contain a first_name/last_name pair,
            # we assume a full_name was passed instead.
            full_name = cleaned_data.get('full_name', None)
            first_name, _, last_name = full_name_natural_split(full_name)
        return first_name, last_name

    @property
    def contact(self):
        if not hasattr(self, '_contact'):
            self._contact = Contact.objects.get_token(
                self.kwargs.get(self.key_url_kwarg))
        return self._contact

    def get_context_data(self, **kwargs):
        context = super(ActivationBaseView, self).get_context_data(**kwargs)
        if self.contact and self.contact.extra:
            # XXX might be best as a separate field.
            context.update({'reason': self.contact.extra})
        return context

    def get_initial(self):
        if self.object:
            return {
                'email': self.object.email,
                'full_name': self.object.get_full_name(),
                'username': self.object.username}
        return {}

    def dispatch(self, request, *args, **kwargs):
        if is_authenticated(request):
            auth_logout(request)
        # We put the code inline instead of using method_decorator() otherwise
        # kwargs is interpreted as parameters in sensitive_post_parameters.
        request.sensitive_post_parameters = '__ALL__'
        response = super(ActivationBaseView, self).dispatch(
            request, *args, **kwargs)
        add_never_cache_headers(response)
        return response

    def form_valid(self, form):
        verification_key = self.kwargs.get(self.key_url_kwarg)
        user = self.activate_user(form)
        if not user.last_login:
            # XXX copy/paste from models.ActivatedUserManager.create_user
            LOGGER.info("'%s %s <%s>' registered with username '%s'",
                user.first_name, user.last_name, user.email, user,
                extra={'event': 'register', 'user': user})
            signals.user_registered.send(sender=__name__, user=user)
        else:
            LOGGER.info("'%s %s <%s>' activated with username '%s'",
                user.first_name, user.last_name, user.email, user,
                extra={'event': 'activate', 'user': user})
            signals.user_activated.send(sender=__name__,
                user=user, verification_key=verification_key,
                request=self.request)
            messages.info(
                self.request, _("Thank you. Your account is now active."))

        # Okay, security check complete. Log the user in.
        user_with_backend = authenticate(
            username=user.username,
            password=form.cleaned_data.get('new_password'))
        _login(self.request, user_with_backend)
        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()
        return HttpResponseRedirect(self.get_success_url())

    def get(self, request, *args, **kwargs):
        # We return a custom 404 page such that a user has a chance
        # to see an explanation of why clicking an expired link
        # in an e-mail leads to a 404.
        self.object = self.get_object()
        if not self.object:
            messages.error(request, _("Activation failed. You may have"\
                " already activated your account previously. In that case,"\
                " just login. Thank you."))
            next_url = validate_redirect(self.request)
            return HttpResponseRedirect(next_url)
        return self.render_to_response(self.get_context_data(**kwargs))

    def get_object(self, queryset=None):  #pylint:disable=unused-argument
        token = self.contact
        return token.user if token else None


class SigninBaseView(RedirectFormMixin, ProcessFormView):
    """
    Check credentials and sign in the authenticated user.
    """

    form_class = UsernameOrEmailAuthenticationForm

    def get_form_class(self):
        username = self.request.POST.get('username', None)
        if username:
            contact = Contact.objects.filter(user__username=username).first()
            if contact and contact.mfa_backend and contact.mfa_priv_key:
                return MFACodeForm
        return self.form_class

    def get_mfa_form(self):
        form = MFACodeForm(**self.get_form_kwargs())
        # We must pass the username and password back to the browser
        # as hidden fields, but prevent calls to `form.non_field_errors()`
        # in the templates to inadvertently trigger a call
        # to `MFACodeForm.clean()`.
        form._errors = {} #pylint:disable=protected-access
        return form

    def form_valid(self, form):
        user = form.get_user()
        contact = Contact.objects.filter(user=user).first()
        if contact and contact.mfa_backend:
            if not contact.mfa_priv_key:
                form = self.get_mfa_form()
                contact.create_mfa_token()
                context = self.get_context_data(form=form)
                return self.render_to_response(context)
            # `get_form_class` will have returned `MFACodeForm`
            # if `mfa_priv_key` is not yet set, which in turn
            # will not make it this far is the code is incorrect.
            contact.clear_mfa_token()
        _login(self.request, user)
        return super(SigninBaseView, self).form_valid(form)

    def form_invalid(self, form):
        user = form.get_user()
        contact = Contact.objects.filter(user=user).first()
        if contact and contact.mfa_backend:
            if contact.mfa_nb_attempts >= settings.MFA_MAX_ATTEMPTS:
                contact.clear_mfa_token()
                form = self.get_form()
                form.add_error(None, _("You have exceeded the number"\
                " of attempts to enter the MFA code. Please start again."))
            else:
                contact.mfa_nb_attempts += 1
                contact.save()
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

    template_name = 'accounts/activate.html'


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
