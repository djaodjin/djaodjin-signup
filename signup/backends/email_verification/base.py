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
import logging

from django.core.mail import send_mail
from django.utils import translation

from ..base import load_backend
from ... import settings, signals
from ...compat import gettext_lazy as _

LOGGER = logging.getLogger(__name__)


class EmailVerificationBackend(object):

    def send(self, email, email_code,
             back_url=None, expiration_days=settings.KEY_EXPIRATION):
        """
        Send an e-mail message to the user to verify her e-mail address.
        """
        send_mail(
            _("E-mail verification code"),
            _("%(back_url)s\nE-mail verification code: %(code)s\n"\
              "Expires in %(expiration_days)d days.") % {
                  'back_url': back_url,
                  'code': "{:0>6}".format(email_code) if email_code else None,
                  'expiration_days': expiration_days
              },
            settings.DEFAULT_FROM_EMAIL, [email])


def send_verification_email(contact, request, back_url=None):
    """
    Send an email to the user to verify her email address.

    The email embed a link to a verification url and a redirect to the page
    the verification email was sent from so that the user stays on her
    workflow once verification is completed.
    """
    backend = load_backend(settings.EMAIL_VERIFICATION_BACKEND)
    with translation.override(contact.lang):
        backend.send(contact.email, contact.email_code, back_url=back_url)

    LOGGER.info("email verification code or link to %s", contact.email)
    signals.user_email_verification.send(
        sender=__name__, contact=contact, request=request)
