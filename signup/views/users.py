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

"""Views to update login credentials and display information about a User."""

import logging

from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.utils import six
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_protect
from django.views.generic.detail import BaseDetailView
from django.views.generic.edit import UpdateView

from .. import settings
from ..compat import User, reverse, is_authenticated
from ..decorators import send_verification_email
from ..forms import (PasswordChangeForm, PublicKeyForm, UserForm,
    UserNotificationsForm)
from ..mixins import UserMixin
from ..models import Contact, Notification
from ..utils import has_invalid_password, update_db_row


LOGGER = logging.getLogger(__name__)


class UserProfileView(UserMixin, UpdateView):
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

    def form_valid(self, form):
        form.save(commit=False)
        if update_db_row(self.object, form):
            return self.form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        context = super(UserProfileView, self).get_context_data(**kwargs)
        setattr(context['user'], 'full_name', context['user'].get_full_name())
        # URLs for user
        if is_authenticated(self.request):
#XXX            contact, _ = Contact.objects.update_or_create_token(self.object)
            self.update_context_urls(context, {'user': {
                'api_generate_keys': reverse(
                    'api_generate_keys', args=(self.object,)),
                'api_profile': reverse(
                    'api_user_profile', args=(self.object,)),
                'api_password_change': reverse(
                    'api_user_password_change', args=(self.object,)),
                'api_contact': reverse(
                    'api_contact', args=(self.object.username,)), #XXX
                'api_pubkey': reverse(
                    'api_pubkey', args=(self.object,)),
                'password_change': reverse(
                    'password_change', args=(self.object,)),
            }})
            if has_invalid_password(self.object):
                self.update_context_urls(context, {'user': {
                    'api_activate': reverse(
                        'api_user_activate', args=(self.object,)),
                }})
        return context

    def get_success_url(self):
        messages.info(self.request, _("Profile updated."))
        return reverse('users_profile', args=(self.object,))


class UserNotificationsView(UserMixin, UpdateView):
    """
    A view where a user can configure their notification settings
    """
    model = User
    form_class = UserNotificationsForm
    slug_field = 'username'
    slug_url_kwarg = 'user'
    template_name = 'users/notifications.html'

    @staticmethod
    def get_notifications():
        return Notification.objects.all()

    def form_valid(self, form):
        with transaction.atomic():
            notifications = self.get_initial().get('notifications')
            self.object.notifications.clear()
            for notification_slug, enabled in six.iteritems(form.cleaned_data):
                if settings.NOTIFICATIONS_OPT_OUT:
                    if not enabled:
                        self.object.notifications.add(
                            notifications.get(notification_slug)[0])
                else:
                    if enabled:
                        self.object.notifications.add(
                            notifications.get(notification_slug)[0])
        return HttpResponseRedirect(self.get_success_url())

    def get_initial(self):
        notifications = {}
        enabled = self.user.notifications.all()
        if settings.NOTIFICATIONS_OPT_OUT:
            for notification in self.get_notifications():
                notifications.update({
                    notification.slug: (
                        notification, notification not in enabled)})
        else:
            for notification in self.get_notifications():
                notifications.update({
                    notification.slug: (
                        notification, notification in enabled)})
        return {'notifications': notifications}

    def get_success_url(self):
        messages.info(self.request, _("Notifications updated."))
        return reverse('users_notifications', args=(self.object,))


class PasswordChangeView(UserProfileView):
    """
    Update password for a User
    """

    form_class = PasswordChangeForm
    template_name = 'users/password_change_form.html'

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(PasswordChangeView, self).dispatch(
            request, *args, **kwargs)

    def form_valid(self, form):
        password = form.cleaned_data['password']
        pwd_correct = self.request.user.check_password(password)
        if not pwd_correct:
            form.add_error(None, _("Your password is incorrect."))
            return self.form_invalid(form)
        return super(PasswordChangeView, self).form_valid(form)

    def get_success_url(self):
        LOGGER.info("%s updated password for %s.",
            self.request.user, self.object, extra={
            'event': 'update-password', 'request': self.request,
            'modified': self.object.username})
        if self.request.user == self.object:
            # Updating the password logs out all other sessions for the user
            # except the current one.
            update_session_auth_hash(self.request, self.object)
        messages.info(self.request, _("Password has been updated successfuly."))
        return reverse('users_profile', args=(self.object,))


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
            messages.info(self.request, _("Please follow the instructions"\
                " in the email that has just been sent to you to verify"\
                " the e-mail address."))
        else:
            messages.info(self.request,
                _("This email address has already been verified."))
        return HttpResponseRedirect(
            reverse('users_profile', args=(user,)))


class UserPublicKeyUpdateView(UserProfileView):
    """
    Update password for a User
    """
    form_class = PublicKeyForm
    template_name = 'users/pubkey_change_form.html'

    def form_valid(self, form):
        """
        If the form is valid, save the associated model.
        """
        password = form.cleaned_data['password']
        pwd_correct = self.request.user.check_password(password)
        if not pwd_correct:
            form.add_error(None, _("Your password is incorrect."))
            return self.form_invalid(form)
        try:
            self.user.set_pubkey(form.cleaned_data['pubkey'],
                bind_password=form.cleaned_data['password'])
            LOGGER.info("%s updated pubkey for %s.",
                self.request.user, self.object, extra={
                'event': 'update-pubkey', 'request': self.request,
                'modified': self.object.username})
            self.object = self.user
        except AttributeError:
            form.add_error(None, "Cannot store public key in the User model.")
            return super(UserPublicKeyUpdateView, self).form_invalid(form)
        except PermissionDenied as err:
            form.add_error(None, str(err))
            return super(UserPublicKeyUpdateView, self).form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        messages.info(self.request,
            _("Public Key has been updated successfuly."))
        return reverse('users_profile', args=(self.user,))


@login_required
def redirect_to_user_profile(request):
    return redirect(reverse('users_profile', args=(request.user,)))
