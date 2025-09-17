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

from django.core.exceptions import ImproperlyConfigured
from django.utils import translation

from ... import settings, signals
from ..base import load_backend

LOGGER = logging.getLogger(__name__)


def send_verification_phone(contact, request, back_url=None):
    """
    Send a text message to the user to verify her phone number.

    The email embed a link to a verification url and a redirect to the page
    the verification email was sent from so that the user stays on her
    workflow once verification is completed.
    """
    phone = str(contact.phone) # insures we pass a string to the backend.
    if not settings.PHONE_VERIFICATION_BACKEND:
        LOGGER.error("Attempting to verify phone number '%s',"\
            " yet no PHONE_VERIFICATION_BACKEND was specified.", phone)
        raise ImproperlyConfigured("Attempting to verify phone number '%s',"\
            " yet no PHONE_VERIFICATION_BACKEND was specified." % phone)

    backend = load_backend(settings.PHONE_VERIFICATION_BACKEND)
    with translation.override(contact.lang):
        backend.send(phone, contact.phone_code, back_url=back_url)

    LOGGER.info("text verification code or link to %s", phone)
    signals.user_phone_verification.send(
        sender=__name__, contact=contact, request=request)
