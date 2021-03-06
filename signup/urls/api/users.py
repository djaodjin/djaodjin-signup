# Copyright (c) 2020, Djaodjin Inc.
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

from django.conf.urls import url

from ...settings import USERNAME_PAT
from ...api.users import (PasswordChangeAPIView, UserDetailAPIView,
    UserListCreateAPIView, UserNotificationsAPIView, UserPictureAPIView)

urlpatterns = [
    url(r'^users/(?P<user>%s)/notifications/' % USERNAME_PAT,
        UserNotificationsAPIView.as_view(), name='api_user_notifications'),
    url(r'^users/(?P<user>%s)/picture/' % USERNAME_PAT,
        UserPictureAPIView.as_view(), name='api_user_picture'),
    url(r'^users/(?P<user>%s)/password/' % USERNAME_PAT,
        PasswordChangeAPIView.as_view(), name='api_user_password_change'),
    url(r'^users/(?P<user>%s)/' % USERNAME_PAT,
        UserDetailAPIView.as_view(), name='api_user_profile'),
    url(r'^users/?', UserListCreateAPIView.as_view(), name='saas_api_users'),
]
