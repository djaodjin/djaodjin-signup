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

"""Views about contact activities"""

from django.views.generic import DetailView, TemplateView

from .. import settings
from ..compat import reverse
from ..helpers import update_context_urls
from ..mixins import AccountMixin, ContactMixin
from ..models import Contact
from ..utils import get_account_model


class AccountDetailView(AccountMixin, DetailView):

    template_name = 'activities/accounts/account.html'
    model = get_account_model()

    def get_object(self, queryset=None):
        return self.account

    def get_context_data(self, **kwargs):
        context = super(AccountDetailView, self).get_context_data(**kwargs)
        context.update({'account': self.account})
        update_context_urls(context, {
            'api_activities': reverse('api_profile_activities', args=(
                self.get_object(),)),
            'api_contacts': reverse('api_contacts')
        })
        return context


class AccountListMixin(settings.EXTRA_MIXIN):
    """
    Mixin such that EXTRA_MIXIN can defaults to `object`.
    """


class AccountListView(AccountListMixin, TemplateView):

    template_name = 'activities/accounts/index.html'

    def get_context_data(self, **kwargs):
        context = super(AccountListView, self).get_context_data(**kwargs)
        update_context_urls(context, {
            'api_contacts': reverse('api_contacts'),
        })
        return context


class ContactDetailView(ContactMixin, DetailView):

    template_name = 'activities/contacts/contact.html'
    model = Contact

    def get_object(self):
        return self.contact

    def get_context_data(self, **kwargs):
        context = super(ContactDetailView, self).get_context_data(**kwargs)
        context.update({'contact': self.contact})
        update_context_urls(context, {
            'api_activities': reverse('api_activities', args=(self.contact,)),
            'api_contact': reverse('api_contact', args=(self.contact,)),
            'api_contacts': reverse('api_contacts')
        })
        return context


class ContactListMixin(settings.EXTRA_MIXIN):
    """
    Mixin such that EXTRA_MIXIN can defaults to `object`.
    """


class ContactListView(ContactListMixin, TemplateView):

    template_name = 'activities/contacts/index.html'

    def get_context_data(self, **kwargs):
        context = super(ContactListView, self).get_context_data(**kwargs)
        update_context_urls(context, {
            'api_contacts': reverse('api_contacts'),
            'contacts': reverse('signup_contacts')
        })
        return context
