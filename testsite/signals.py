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

from django.conf import settings
from django.core.mail import send_mail
from django.dispatch import receiver
from signup.signals import user_registered, user_activated

#pylint: disable=unused-argument
SEND_EMAIL = False

@receiver(user_registered, dispatch_uid="user_registered_notice")
def user_registered_notice(sender, user, request=None, **kwargs):
    if SEND_EMAIL:
        send_mail("user registered", "%s has registered.",
                  settings.DEFAULT_FROM_EMAIL,
                  [admin[1] for admin in settings.ADMINS],
                  fail_silently=False)


@receiver(user_activated, dispatch_uid="user_activated_notice")
def user_activated_notice(sender, user, request, **kwargs):
    if SEND_EMAIL:
        send_mail("user activated", "%s has been activated.",
              settings.DEFAULT_FROM_EMAIL,
              [admin[1] for admin in settings.ADMINS],
              fail_silently=False)
