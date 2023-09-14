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
from rest_framework.exceptions import AuthenticationFailed

from .. import settings
from ..compat import gettext_lazy as _, reverse, six
from ..forms import (PasswordChangeForm, PublicKeyForm, UserForm,
    UserNotificationsForm)
from ..helpers import has_invalid_password, update_context_urls
from ..mixins import AuthenticatedUserPasswordMixin, UserMixin
from ..models import Contact, Notification, OTPGenerator
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
        contact = self.user.contacts.filter(
            email__iexact=self.user.email).first()
        if not contact:
            contact = self.user.contacts.order_by('pk').first()
        failed = False
        with transaction.atomic():
            # `form.save(commit=False)` will copy the form fields values
            # to the instance without committing to the database.
            # `update_db_row` will commit to the database.
            form.save(commit=False)
            if update_db_row(self.user, form):
                failed = True
            else:
                if form.cleaned_data['phone']:
                    validated_phone = form.cleaned_data['phone']
                else:
                    validated_phone = None
                if contact:
                    contact.slug = form.cleaned_data['username']
                    contact.full_name = form.cleaned_data['full_name']
                    contact.nick_name = form.cleaned_data['nick_name']
                    contact.lang = form.cleaned_data['lang']
                    if contact.email != form.cleaned_data['email']:
                        contact.email = form.cleaned_data['email']
                        contact.email_verified_at = None
                    if contact.phone != validated_phone:
                        contact.phone = validated_phone
                        contact.phone_verified_at = None
                    if update_db_row(contact, form):
                        failed = True
                else:
                    contact = Contact.objects.create(
                        user=self.user,
                        slug=form.cleaned_data['username'],
                        full_name=form.cleaned_data['full_name'],
                        nick_name=form.cleaned_data['nick_name'],
                        lang=form.cleaned_data['lang'],
                        email=form.cleaned_data['email'],
                        phone=validated_phone)
        if failed:
            return self.form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())

    def get_initial(self):
        initial = super(UserProfileView, self).get_initial()
        if self.user:
            initial.update({'full_name': self.user.get_full_name()})
        return initial


    def get_context_data(self, **kwargs):
        context = super(UserProfileView, self).get_context_data(**kwargs)
        setattr(self.user, 'full_name', self.user.get_full_name())
        primary_contact = self.user.contacts.filter(
            email__iexact=self.user.email).order_by('created_at').first()
        if primary_contact:
            context.update({
                'email_verified_at': primary_contact.email_verified_at,
                'phone_verified_at': primary_contact.phone_verified_at
            })
        if primary_contact and primary_contact.picture:
            setattr(self.user, 'picture', primary_contact.picture)
        else:
            picture_candidate = self.user.contacts.filter(
                picture__isnull=False).order_by('created_at').first()
            if picture_candidate:
                setattr(self.user, 'picture', picture_candidate.picture)
        # URLs for user
        update_context_urls(context, {
            'api_recover': reverse('api_recover'),
            'user': {
                'api_generate_keys': reverse(
                    'api_generate_keys', args=(self.user,)),
                'api_profile': reverse(
                    'api_user_profile', args=(self.user,)),
                'api_password_change': reverse(
                    'api_user_password_change', args=(self.user,)),
                'api_otp_change': reverse(
                    'api_user_otp_change', args=(self.user,)),
                'api_profile_picture': reverse(
                    'api_user_picture', args=(self.user,)),
                'api_contact': reverse(
                    'api_contact', args=(self.user.username,)), #XXX
                'api_pubkey': reverse(
                    'api_pubkey', args=(self.user,)),
                'password_change': reverse(
                    'password_change', args=(self.user,)),
                'keys_update': reverse(
                    'pubkey_update', args=(self.user,)),
        }})
        if has_invalid_password(self.user):
            update_context_urls(context, {'user': {
                'api_activate': reverse(
                    'api_user_activate', args=(self.user,)),
            }})
        context.update({
            'otp_enabled': OTPGenerator.objects.filter(
                user=self.user).exists()})
        return context

    def get_success_url(self):
        messages.info(self.request, _("Profile updated."))
        return reverse('users_profile', args=(self.user,))


class UserNotificationsView(UserMixin, UpdateView):
    """
    A view where a user can configure their notification settings
    """
    form_class = UserNotificationsForm
    template_name = 'users/notifications.html'

    def form_valid(self, form):
        with transaction.atomic():
            notifications = self.get_initial().get('notifications')
            self.user.notifications.clear()
            for notification_slug, enabled in six.iteritems(form.cleaned_data):
                if not notification_slug in notifications:
                    continue
                #pylint:disable=unused-variable
                notification, notused = Notification.objects.get_or_create(
                    slug=notification_slug)
                if settings.NOTIFICATIONS_OPT_OUT:
                    if not enabled:
                        self.user.notifications.add(notification)
                else:
                    if enabled:
                        self.user.notifications.add(notification)
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
        return reverse('users_notifications', args=(self.user,))


class PasswordChangeView(AuthenticatedUserPasswordMixin, UserProfileView):
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
        try:
            self.re_auth(self.request, form.cleaned_data)
        except AuthenticationFailed:
            form.add_error(None, _("Your password is incorrect."))
            return self.form_invalid(form)
        return super(PasswordChangeView, self).form_valid(form)

    def get_success_url(self):
        LOGGER.info("%s updated password for %s.",
            self.request.user, self.user, extra={
            'event': 'update-password', 'request': self.request,
            'modified': self.user.username})
        if self.request.user == self.user:
            # Updating the password logs out all other sessions for the user
            # except the current one.
            update_session_auth_hash(self.request, self.user)
        messages.info(self.request, _("Password has been updated successfuly."))
        return reverse('users_profile', args=(self.user,))


class UserPublicKeyUpdateView(AuthenticatedUserPasswordMixin, UserProfileView):
    """
    Update password for a User
    """
    form_class = PublicKeyForm
    template_name = 'users/pubkey.html'

    def form_valid(self, form):
        """
        If the form is valid, save the associated model.
        """
        try:
            self.re_auth(self.request, form.cleaned_data)
        except AuthenticationFailed:
            form.add_error(None, _("Your password is incorrect."))
            return self.form_invalid(form)
        try:
            self.user.set_pubkey(form.cleaned_data['pubkey'],
                bind_password=form.cleaned_data['password'])
            LOGGER.info("%s updated pubkey for %s.",
                self.request.user, self.user, extra={
                'event': 'update-pubkey', 'request': self.request,
                'modified': self.user.username})
            #pylint:disable=attribute-defined-outside-init
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
