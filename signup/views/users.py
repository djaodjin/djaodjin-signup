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

"""Views to update login credentials and display information about a User."""

import logging

from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.generic.edit import UpdateView

from .. import settings
from ..compat import gettext_lazy as _, is_authenticated, reverse, six
from ..forms import (PasswordChangeForm, PublicKeyForm, UserForm,
    UserNotificationsForm)
from ..helpers import has_invalid_password
from ..mixins import UserMixin
from ..models import Contact, Notification
from ..utils import update_db_row


LOGGER = logging.getLogger(__name__)


class UserProfileView(UserMixin, UpdateView):
    """
    If a user is manager for an Organization, she can access the Organization
    profile. If a user is manager for an Organization subscribed to another
    Organization, she can access the product provided by that organization.
    """
    form_class = UserForm
    template_name = 'users/index.html'

    def form_valid(self, form):
        contact = self.object.contacts.filter(email=self.object.email).first()
        if not contact:
            contact = self.object.contacts.order_by('pk').first()
        failed = False
        with transaction.atomic():
            # `form.save(commit=False)` will copy the form fields values
            # to the instance without committing to the database.
            # `update_db_row` will commit to the database.
            form.save(commit=False)
            if update_db_row(self.object, form):
                failed = True
            else:
                if contact:
                    contact.slug = form.cleaned_data['username']
                    contact.full_name = form.cleaned_data['full_name']
                    contact.nick_name = form.cleaned_data['nick_name']
                    contact.lang = form.cleaned_data['lang']
                    if contact.email != form.cleaned_data['email']:
                        contact.email = form.cleaned_data['email']
                        contact.email_verified_at = None
                    if contact.phone != form.cleaned_data['phone']:
                        contact.phone = form.cleaned_data['phone']
                        contact.phone_verified_at = None
                    if update_db_row(contact, form):
                        failed = True
                else:
                    contact = Contact.objects.create(
                        user=self.object,
                        slug=form.cleaned_data['username'],
                        full_name=form.cleaned_data['full_name'],
                        nick_name=form.cleaned_data['nick_name'],
                        lang=form.cleaned_data['lang'],
                        email=form.cleaned_data['email'],
                        phone=form.cleaned_data['phone'])
        if failed:
            return self.form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())

    def get_initial(self):
        initial = super(UserProfileView, self).get_initial()
        if self.object:
            initial.update({'full_name': self.object.get_full_name()})
        return initial

    def get_context_data(self, **kwargs):
        context = super(UserProfileView, self).get_context_data(**kwargs)
        setattr(context['user'], 'full_name', context['user'].get_full_name())
        contact = context['user'].contacts.filter(
            picture__isnull=False).order_by('created_at').first()
        if contact:
            setattr(context['user'], 'picture', contact.picture)
        # URLs for user
        if is_authenticated(self.request):
            self.update_context_urls(context, {'user': {
                'api_generate_keys': reverse(
                    'api_generate_keys', args=(self.object,)),
                'api_profile': reverse(
                    'api_user_profile', args=(self.object,)),
                'api_password_change': reverse(
                    'api_user_password_change', args=(self.object,)),
                'api_user_picture': reverse(
                    'api_user_picture', args=(self.object,)),
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
    form_class = UserNotificationsForm
    template_name = 'users/notifications.html'

    @staticmethod
    def get_notifications(user=None):#pylint:disable=unused-argument
        return {}

    def form_valid(self, form):
        with transaction.atomic():
            notifications = self.get_initial().get('notifications')
            self.object.notifications.clear()
            for notification_slug, enabled in six.iteritems(form.cleaned_data):
                if not notification_slug in notifications:
                    continue
                #pylint:disable=unused-variable
                notification, notused = Notification.objects.get_or_create(
                    slug=notification_slug)
                if settings.NOTIFICATIONS_OPT_OUT:
                    if not enabled:
                        self.object.notifications.add(notification)
                else:
                    if enabled:
                        self.object.notifications.add(notification)
        return HttpResponseRedirect(self.get_success_url())

    def get_initial(self):
        notifications = {}
        enabled = list(self.user.notifications.all().values_list(
            'slug', flat=True))
        if settings.NOTIFICATIONS_OPT_OUT:
            for notification_slug, notification_data in six.iteritems(
                    self.get_notifications(self.user)):
                notifications.update({
                    notification_slug: (
                        notification_data, notification_slug not in enabled)})
        else:
            for notification_slug, notification_data in six.iteritems(
                    self.get_notifications(self.user)):
                notifications.update({
                    notification_slug: (
                        notification_data, notification_slug in enabled)})
        return {'notifications': notifications}

    def get_success_url(self):
        messages.info(self.request, _("Notifications updated."))
        return reverse('users_notifications', args=(self.object,))


class PasswordChangeView(UserProfileView):
    """
    Update password for a User
    """
    form_class = PasswordChangeForm
    template_name = 'users/password.html'

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


class UserPublicKeyUpdateView(UserProfileView):
    """
    Update password for a User
    """
    form_class = PublicKeyForm
    template_name = 'users/pubkey.html'

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
