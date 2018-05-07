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

"""Extra Forms and Views that might prove useful to register users."""

import logging

from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth import REDIRECT_FIELD_NAME, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.utils import six
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.cache import add_never_cache_headers
from django.views.generic.base import ContextMixin, TemplateResponseMixin, View
from django.views.generic.detail import BaseDetailView
from django.views.generic.edit import FormMixin, ProcessFormView, UpdateView

from .. import settings, signals
from ..auth import validate_redirect
from ..backends.auth import UsernameOrEmailAuthenticationForm
from ..compat import User, reverse
from ..decorators import check_user_active, send_verification_email
from ..forms import (NameEmailForm, PasswordChangeForm, PasswordResetForm,
    UserForm, UserNotificationsForm)
from ..models import Contact, Notification
from ..utils import full_name_natural_split, has_invalid_password


LOGGER = logging.getLogger(__name__)


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


class AuthTemplateResponseMixin(TemplateResponseMixin):
    """
    Returns a *disabled* page regardless when DISABLED_AUTHENTICATION
    is True.
    """

    def get_context_data(self, **kwargs):
        context = super(AuthTemplateResponseMixin, self).get_context_data(
            **kwargs)
        # URLs for user
        user_urls = {}
        if not self.request.user.is_authenticated():
            user_urls = {
               'login': reverse('login'),
               'password_reset': reverse('password_reset'),
               'register': reverse('registration_register'),
            }
        if 'urls' in context:
            if 'user' in context['urls']:
                context['urls']['user'].update(user_urls)
            else:
                context['urls'].update({'user': user_urls})
        else:
            context.update({'urls': {'user': user_urls}})
        return context

    def dispatch(self, request, *args, **kwargs):
        if request.method.lower() in self.http_method_names:
            if settings.DISABLED_AUTHENTICATION:
                context = {}
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
        users = User.objects.filter(email__iexact=form.cleaned_data['email'])
        if users.exists():
            user = users.get()
            if user.is_active and user.has_usable_password():
                # Make sure that no email is sent to a user that actually has
                # a password marked as unusable
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = self.token_generator.make_token(user)
                back_url = self.request.build_absolute_uri(
                    reverse('password_reset_confirm', args=(uid, token)))
                next_url = validate_redirect(self.request)
                if next_url:
                    back_url += '?%s=%s' % (REDIRECT_FIELD_NAME, next_url)
                signals.user_reset_password.send(
                    sender=__name__, user=user, request=self.request,
                    back_url=back_url, expiration_days=settings.KEY_EXPIRATION)
        return super(PasswordResetBaseView, self).form_valid(form)

    def get_success_url(self):
        messages.info(self.request, "Please follow the instructions "\
            "in the email that has just been sent to you to reset"\
            " your password.")
        return super(PasswordResetBaseView, self).get_success_url()


class PasswordResetConfirmBaseView(RedirectFormMixin, ProcessFormView):
    """
    Clicked on the link sent in the reset e-mail.
    """
    form_class = PasswordChangeForm
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
        messages.info(self.request, "Your password has been reset sucessfully.")
        return super(PasswordResetConfirmBaseView, self).get_success_url()

    def get_form_kwargs(self):
        """
        Returns the keyword arguments for instantiating the form.
        """
        kwargs = super(PasswordResetConfirmBaseView, self).get_form_kwargs()
        try:
            uid = urlsafe_base64_decode(self.kwargs.get('uidb64'))
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
            if settings.DISABLED_REGISTRATION:
                context = {}
                response_kwargs = {}
                response_kwargs.setdefault('content_type', self.content_type)
                return TemplateResponse(request=request,
                    template='accounts/disabled_registration.html',
                    context=context, **response_kwargs)
        return super(SignupBaseView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        new_user = self.register(**form.cleaned_data)
        if new_user:
            success_url = self.get_success_url()
        else:
            success_url = self.request.META['PATH_INFO']
        return HttpResponseRedirect(success_url)

    def register(self, **cleaned_data):
        #pylint: disable=maybe-no-member
        email = cleaned_data['email']
        users = User.objects.filter(email=email)
        if users.exists():
            user = users.get()
            if check_user_active(self.request, user,
                                 next_url=self.get_success_url()):
                messages.warning(self.request, mark_safe(_(
                    'This email address has already been registered!'\
' Please <a href="%s">login</a> with your credentials. Thank you.'
                    % reverse('login'))))
            else:
                messages.warning(self.request, mark_safe(_(
                    "This email address has already been registered!"\
" You should now secure and activate your account following "\
" the instructions we just emailed you. Thank you.")))
            return None

        first_name, last_name = self.first_and_last_names(**cleaned_data)
        username = cleaned_data.get('username', None)
        password = cleaned_data.get('new_password1', None)
        user = User.objects.create_user(username,
            email=email, password=password,
            first_name=first_name, last_name=last_name)

        # Bypassing authentication here, we are doing frictionless registration
        # the first time around.
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        auth_login(self.request, user)
        return user


class ActivationBaseView(ContextMixin, View):
    """
    The user is now on the activation url that was sent in an email.
    It is time to activate the account.
    """
    http_method_names = ['get']
    token_generator = default_token_generator
    key_url_kwarg = 'verification_key'

    def get(self, request, *args, **kwargs):
        #pylint:disable=unused-argument
        verification_key = self.kwargs.get(self.key_url_kwarg)
        #pylint: disable=maybe-no-member
        user = Contact.objects.find_user(verification_key)
        if user:
            if has_invalid_password(user):
                messages.info(self.request,
                    _("You are about to activate your account. Please set"\
                      " a password to secure it."))
                url = reverse('registration_password_confirm', args=(
                    verification_key, self.token_generator.make_token(user)))
            else:
                user = Contact.objects.activate_user(verification_key)
                # XXX Should we directly login user here?
                signals.user_activated.send(sender=__name__,
                    user=user, verification_key=verification_key,
                    request=self.request)
                messages.info(self.request,
                    _("Thank you. Your account is now active." \
                          " You can sign in at your convienience."))
                url = reverse('login')
            next_url = validate_redirect(self.request)
            if next_url:
                success_url = "%s?%s=%s" % (url, REDIRECT_FIELD_NAME, next_url)
            else:
                success_url = url
            return HttpResponseRedirect(success_url)
        context = self.get_context_data(**kwargs)
        return self.render_to_response(context)


class SendActivationView(BaseDetailView):
    """Send an account activation code to the user."""

    model = User
    slug_field = 'username'
    slug_url_kwarg = 'user'

    def get(self, request, *args, **kwargs):
        user = self.get_object()
        unverified_email = Contact.objects.unverified_for_user(
            self.get_object()).first()
        if unverified_email is not None:
            send_verification_email(unverified_email, request)
        else:
            messages.info(self.request,
                _("This email address has already been verified."))
        return HttpResponseRedirect(
            reverse('users_profile', args=(user,)))


class SigninBaseView(RedirectFormMixin, ProcessFormView):
    """
    Check credentials and sign in the authenticated user.
    """

    form_class = UsernameOrEmailAuthenticationForm

    def form_valid(self, form):
        auth_login(self.request, form.get_user())
        LOGGER.info("%s signed in.", self.request.user,
            extra={'event': 'login', 'request': self.request})
        return super(SigninBaseView, self).form_valid(form)


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

class UserProfileView(AuthTemplateResponseMixin, UpdateView):
    """
    If a user is manager for an Organization, she can access the Organization
    profile. If a user is manager for an Organization subscribed to another
    Organization, she can access the product provided by that organization.
    """

    model = User
    form_class = UserForm
    slug_field = 'username'
    slug_url_kwarg = 'user'
    template_name = 'users/user_form.html'

    def get_context_data(self, **kwargs):
        context = super(UserProfileView, self).get_context_data(**kwargs)
        # URLs for user
        if self.request.user.is_authenticated():
            user_urls = {
                'api_profile': reverse(
                    'api_user_profile', args=(self.object,)),
                'notifications': reverse(
                    'users_notifications', args=(self.object,)),
                'password_change': reverse(
                    'password_change', args=(self.object,)),
                'profile': reverse('users_profile', args=(self.object,)),
                'profile_redirect': reverse('accounts_profile')
            }
        if 'urls' in context:
            if 'user' in context['urls']:
                context['urls']['user'].update(user_urls)
            else:
                context['urls'].update({'user': user_urls})
        else:
            context.update({'urls': {'user': user_urls}})
        setattr(context['user'], 'full_name', context['user'].get_full_name())
        return context

    def get_success_url(self):
        messages.info(self.request, 'Profile Updated.')
        return reverse('users_profile', args=(self.object,))


class UserNotificationsView(AuthTemplateResponseMixin, UpdateView):
    """
    A view where a user can configure their notification settings
    """
    model = User
    form_class = UserNotificationsForm
    slug_field = 'username'
    slug_url_kwarg = 'user'
    template_name = 'users/user_notifications.html'

    def form_valid(self, form):
        with transaction.atomic():
            notifications = self.get_initial().get('notifications')
            self.object.notifications.clear()
            for notification_slug, enabled in six.iteritems(form.cleaned_data):
                if enabled:
                    self.object.notifications.add(
                        notifications.get(notification_slug)[0])
        return HttpResponseRedirect(self.get_success_url())

    def get_initial(self):
        notifications = {}
        enabled = self.request.user.notifications.all()
        for notification in Notification.objects.all():
            notifications.update({
                notification.slug: (notification, notification in enabled)})
        return {'notifications': notifications}

    def get_success_url(self):
        messages.info(self.request, 'Notifications Updated.')
        return reverse('users_notifications', args=(self.object,))


class PasswordChangeView(UserProfileView):
    """
    Update password for a User
    """

    form_class = PasswordChangeForm
    template_name = 'users/password_change_form.html'

    def get_success_url(self):
        LOGGER.info("%s updated password for %s.",
            self.request.user, self.object, extra={
            'event': 'update-password', 'request': self.request,
            'modified': self.object.username})
        messages.info(self.request, "Password has been updated successfuly.")
        return reverse('users_profile', args=(self.object,))


class RegistrationPasswordConfirmBaseView(RedirectFormMixin, ProcessFormView):
    """
    View that checks the hash in a password activation link and presents a
    form for entering a new password. We can activate the account for real
    once we know the email is valid and a password has been set.
    """
    form_class = PasswordChangeForm
    token_generator = default_token_generator
    key_url_kwarg = 'verification_key'

    def dispatch(self, request, *args, **kwargs):
        # We put the code inline instead of using method_decorator() otherwise
        # kwargs is interpreted as parameters in sensitive_post_parameters.
        request.sensitive_post_parameters = '__ALL__'
        response = super(RegistrationPasswordConfirmBaseView, self).dispatch(
            request, *args, **kwargs)
        add_never_cache_headers(response)
        return response

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests, instantiating a form instance with the passed
        POST variables and then checked for validity.
        """
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        # We use *find_user* instead of *activate_user* because we want
        # to make sure both the *verification_key* and *token* are valid
        # before doing any modification of the underlying models.
        #pylint: disable=maybe-no-member
        user = self.object
        if (user is not None
            and self.token_generator.check_token(
                user, self.kwargs.get('token'))):
            if form.is_valid():
                return self.form_valid(form)
        return self.form_invalid(form)

    def form_valid(self, form):
        #pylint: disable=maybe-no-member
        self.object = form.save() # If we don't save the ``User`` model here,
                                  # we won't be able to authenticate later.
        verification_key = self.kwargs.get('verification_key')
        user = Contact.objects.activate_user(verification_key)
        signals.user_activated.send(sender=__name__,
            user=user, verification_key=verification_key, request=self.request)
        messages.info(self.request,
                      _("Thank you. Your account is now active."))

        # Okay, security check complete. Log the user in.
        user_with_backend = authenticate(
            username=user.username,
            password=form.cleaned_data.get('new_password1'))
        auth_login(self.request, user_with_backend)
        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()
        return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        context = super(RegistrationPasswordConfirmBaseView,
                        self).get_context_data(**kwargs)
        user = self.object
        if user is not None and self.token_generator.check_token(
                                    user, self.kwargs.get('token')):
            context.update({'validlink': True})
        return context

    def get_form_kwargs(self):
        """
        Returns the keyword arguments for instantiating the form.
        """
        kwargs = super(
            RegistrationPasswordConfirmBaseView, self).get_form_kwargs()
        #pylint: disable=no-member
        self.object = Contact.objects.find_user(
            self.kwargs.get(self.key_url_kwarg))
        kwargs.update({'instance': self.object})
        return kwargs


class ActivationView(AuthTemplateResponseMixin, ActivationBaseView):

    template_name = 'accounts/activate.html'


class PasswordResetView(AuthTemplateResponseMixin, PasswordResetBaseView):

    template_name = 'accounts/recover.html'


class PasswordResetConfirmView(AuthTemplateResponseMixin,
                               PasswordResetConfirmBaseView):

    template_name = 'accounts/reset.html'


class RegistrationPasswordConfirmView(AuthTemplateResponseMixin,
                                      RegistrationPasswordConfirmBaseView):

    template_name = 'accounts/reset.html'


class SigninView(AuthTemplateResponseMixin, SigninBaseView):

    template_name = 'accounts/login.html'


class SignoutView(AuthTemplateResponseMixin, SignoutBaseView):

    template_name = 'accounts/logout.html'


class SignupView(AuthTemplateResponseMixin, SignupBaseView):

    template_name = 'accounts/register.html'


@login_required
def redirect_to_user_profile(request):
    return redirect(reverse('users_profile', args=(request.user,)))
