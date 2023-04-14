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

"""
Backends to send one-time authentication codes
"""
from __future__ import unicode_literals

from .. import signals
from ..utils import generate_random_code


class EmailOTCBackend(object):
    """
    Backend to authenticate a user through a code sent to an email address.
    """

    def create_token(self, user, request=None):
        user.one_time_code = generate_random_code()
        user.otc_backend = user.EMAIL_BACKEND
        user.save()
        signals.user_mfa_code.send(
            sender=__name__, user=user, code=user.one_time_code,
            request=request)


class PhoneOTCBackend(object):
    """
    Backend to authenticate a user through a code sent to a phone number.
    """

    def create_token(self, user, request=None):
        user.one_time_code = generate_random_code()
        user.otc_backend = user.PHONE_BACKEND
        user.save()
        signals.user_mfa_code.send(
            sender=__name__, user=user, code=user.one_time_code,
            request=request)
