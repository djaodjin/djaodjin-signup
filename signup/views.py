# Copyright (c) 2014, Djaodjin Inc.
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

from django.core.urlresolvers import reverse
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout

from django.contrib.auth import REDIRECT_FIELD_NAME, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.generic.base import ContextMixin, TemplateResponseMixin, View
from django.views.generic.detail import BaseDetailView
from django.views.generic.edit import FormMixin, ProcessFormView, UpdateView

from signup.auth import validate_redirect
from signup.backends import get_email_backend
from signup.decorators import check_user_active, _send_verification_email
from signup.compat import User
from signup.forms import NameEmailForm, PasswordChangeForm, UserForm
from signup.backends.auth import UsernameOrEmailAuthenticationForm
from signup import signals
from signup import settings


def _redirect_to(url):
    try:
        to_url, args, kwargs = url #(cast to tuple) pylint: disable=star-args
        return redirect(to_url, *args, **kwargs) #pylint: disable=star-args
    except ValueError:
        return redirect(url)


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
                site = get_current_site(self.request)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = self.token_generator.make_token(user)
                back_url = self.request.build_absolute_uri(
                    reverse('password_reset_confirm', args=(uid, token)))
                get_email_backend().send([user.email],
                    'accounts/password_reset.eml',
                    {'user': user, 'site': site,
                     'back_url': back_url,
                     'expiration_days': settings.KEY_EXPIRATION,
                     # XXX Reason for a redirect after password reset?
                     # redirect_field_name: next_url
                     })
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
    token_generator = default_token_generator

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests, instantiating a form instance with the passed
        POST variables and then checked for validity.
        """
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        try:
            uid = urlsafe_base64_decode(self.kwargs.get('uidb64'))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and self.token_generator.check_token(
                                    user, self.kwargs.get('token')):
            if form.is_valid():
                return self.form_valid(form)
        return self.form_invalid(form)

    def get_success_url(self):
        messages.info(self.request, "Your password has been reset sucessfully.")
        return super(PasswordResetConfirmBaseView, self).get_success_url()


class SignupBaseView(RedirectFormMixin, ProcessFormView):
    """
    A frictionless registration backend With a full name and email
    address, the user is immediately signed up and logged in.
    """

    form_class = NameEmailForm
    fail_url = ('registration_register', (), {})

    def form_valid(self, form):
        new_user = self.register(**form.cleaned_data)
        if new_user:
            success_url = self.get_success_url()
        else:
            success_url = self.request.META['PATH_INFO']
        return _redirect_to(success_url)

    def register(self, **cleaned_data):
        #pylint: disable=maybe-no-member
        full_name, email = cleaned_data['full_name'], cleaned_data['email']
        users = User.objects.filter(email=email)
        if users.exists():
            user = users.get()
            if check_user_active(self.request, user,
                                 next_url=self.get_success_url()):
                messages.info(self.request, mark_safe(_(
                    'This email address has already been registered!'\
' Please <a href="%s">login</a> with your credentials. Thank you.'
                    % reverse('login'))))
            else:
                messages.info(self.request, mark_safe(_(
                    "This email address has already been registered!"\
" You should now secure and activate your account following "\
" the instructions we just emailed you. Thank you.")))
            return None

        name_parts = full_name.split(' ')
        if len(name_parts) > 0:
            first_name = name_parts[0]
            last_name = ' '.join(name_parts[1:])
        else:
            first_name = full_name
            last_name = ''
        username = None
        if cleaned_data.has_key('username'):
            username = cleaned_data['username']
        if username and cleaned_data.has_key('password'):
            user = User.objects.create_user(
                username=username, password=cleaned_data['password'],
                email=email, first_name=first_name, last_name=last_name)
        else:
            user = User.objects.create_inactive_user(email,
                username=username, first_name=first_name, last_name=last_name)
        signals.user_registered.send(
            sender=__name__, user=user, request=self.request)

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

    def get(self, request, *args, **kwargs):
        verification_key = kwargs['verification_key']
        #pylint: disable=maybe-no-member
        user = User.objects.find_user(verification_key)
        if user:
            if user.has_invalid_password:
                messages.info(self.request,
                    _("Please set a password to protect your account."))
                url = reverse('registration_password_confirm',
                              args=(user.email_verification_key,
                                    self.token_generator.make_token(user)))
            else:
                user = User.objects.activate_user(verification_key)
                signals.user_activated.send(
                    sender=__name__, user=user, request=self.request)
                messages.info(self.request,
                    _("Thank you. Your account is now active." \
                          " You can sign in at your convienience."))
                url = reverse('login')
            next_url = validate_redirect(self.request)
            if next_url:
                success_url = "%s?%s=%s" % (url, REDIRECT_FIELD_NAME, next_url)
            else:
                success_url = url
            return _redirect_to(success_url)
        return super(ActivationBaseView, self).get(request, *args, **kwargs)


class SendActivationView(BaseDetailView):
    """Send an account activation code to the user."""

    model = User
    slug_field = 'username'
    slug_url_kwarg = 'user'

    def get(self, request, *args, **kwargs):
        user = self.get_object()
        site = get_current_site(request)
        _send_verification_email(user, site)
        messages.info(self.request, "Activation e-mail sent.")
        return HttpResponseRedirect(
            reverse('users_profile', args=(self.object,)))


class SigninBaseView(RedirectFormMixin, ProcessFormView):
    """
    Check credentials and sign in the authenticated user.
    """

    form_class = UsernameOrEmailAuthenticationForm

    def form_valid(self, form):
        auth_login(self.request, form.get_user())
        return super(SigninBaseView, self).form_valid(form)


class SignoutBaseView(RedirectFormMixin, View):
    """
    Log out the authenticated user.
    """

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        next_url = self.get_success_url()
        if next_url:
            return HttpResponseRedirect(next_url)
        return super(SignoutBaseView, self).get(request, *args, **kwargs)


class UserProfileView(UpdateView):
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

    def get_success_url(self):
        messages.info(self.request, 'Profile Updated.')
        return reverse('users_profile', args=(self.object,))


class PasswordChangeView(UserProfileView):
    """
    Update password for a User
    """

    form_class = PasswordChangeForm
    template_name = 'users/password_change_form.html'

    def get_success_url(self):
        messages.info(self.request, "Password has been updated successfuly.")
        return reverse('users_profile', args=(self.object,))


class RegistrationPasswordConfirmBaseView(RedirectFormMixin, ProcessFormView):
    """
    View that checks the hash in a password activation link and presents a
    form for entering a new password. We can activate the account for real
    once we know the email is valid and a password has been set.
    """
    token_generator = default_token_generator
    form_class = SetPasswordForm

    @method_decorator(sensitive_post_parameters)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(RegistrationPasswordConfirmBaseView, self).dispatch(
            request, *args, **kwargs)

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
        user = User.objects.find_user(self.kwargs.get('verification_key'))
        if user is not None and self.token_generator.check_token(user,
                                                   self.kwargs.get('token')):
            if form.is_valid():
                return self.form_valid(form)
        return self.form_invalid(form)

    def form_valid(self, form):
        #pylint: disable=maybe-no-member
        user = User.objects.activate_user(self.kwargs.get('verification_key'))
        signals.user_activated.send(
            sender=__name__, user=user, request=self.request)
        messages.info(self.request,
                      _("Thank you. Your account is now active."))

        # Okay, security check complete. Log the user in.
        user_with_backend = authenticate(
            username=user.username,
            password=form.cleaned_data.get('new_password1'))
        auth_login(self.request, user_with_backend)
        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()

        return super(RegistrationPasswordConfirmBaseView, self).form_valid(form)


class PasswordResetView(TemplateResponseMixin, PasswordResetBaseView):

    template_name = 'accounts/recover.html'


class PasswordResetConfirmView(TemplateResponseMixin,
                               PasswordResetConfirmBaseView):

    template_name = 'accounts/reset.html'


class SignupView(TemplateResponseMixin, SignupBaseView):

    template_name = 'accounts/register.html'


class ActivationView(TemplateResponseMixin, ActivationBaseView):

    template_name = 'accounts/activate.html'


class SigninView(TemplateResponseMixin, SigninBaseView):

    template_name = 'accounts/login.html'


class SignoutView(TemplateResponseMixin, SignoutBaseView):

    template_name = 'accounts/logout.html'


class RegistrationPasswordConfirmView(TemplateResponseMixin,
                                      RegistrationPasswordConfirmBaseView):

    template_name = 'accounts/reset.html'


@login_required
def redirect_to_user_profile(request):
    return redirect(request.user.get_absolute_url())
