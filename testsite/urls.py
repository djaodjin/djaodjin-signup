# Copyright (c) 2026, Djaodjin Inc.
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
from django.conf.urls.static import static
from django.contrib.auth.decorators import login_required
from django.contrib.staticfiles.views import serve as django_static_serve
from django.views.generic.base import RedirectView, TemplateView
from signup.compat import reverse_lazy, include, path, re_path
from signup.api.activities import (ActivityByAccountAPIView,
    ActivityListAPIView)
from signup.api.contacts import (ActivityListCreateAPIView,

    ContactDetailAPIView, ContactListAPIView, ContactPictureAPIView)
from signup.api.keys import (ListCreateAPIKeysAPIView, PublicKeyAPIView,
    DestroyAPIKeyAPIView)
from signup.api.tokens import JWTRefresh, JWTVerify
from signup.api.users import (ActivityByAccountContactAPIView,
    OTPChangeAPIView, PasswordChangeAPIView,
    UserDetailAPIView, UserListCreateAPIView, UserNotificationsAPIView,
    UserPictureAPIView)
from signup.decorators import active_required
from signup.views.contacts import (AccountDetailView, AccountListView,
    ContactListView, ContactDetailView)
from signup.views.users import (PasswordChangeView,
    UserPublicKeyUpdateView, UserProfileView, UserNotificationsView,
    redirect_to_user_profile)


urlpatterns = \
    static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + [
    re_path(r'(?P<path>favicon.ico)', django_static_serve),
    # signup.urls.api.dashboard.activities
    path('api/activities/<slug:profile>/contacts',
        login_required(ActivityByAccountContactAPIView.as_view()),
        name='api_profile_activities_contacts'),
    path('api/activities/<slug:profile>',
        login_required(ActivityByAccountAPIView.as_view(
            lookup_field='username')),
        name='api_profile_activities'),
    path('api/activities',
        login_required(ActivityListAPIView.as_view()),
        name='api_profile_activities_index'),
    # signup.urls.api.dashboard.contacts
    path('api/contacts/<slug:user>/activities',
         login_required(ActivityListCreateAPIView.as_view()),
         name='api_activities'),
    path('api/contacts/<slug:user>/picture',
         login_required(ContactPictureAPIView.as_view()),
         name='api_contact_picture'),
    path('api/contacts/<slug:user>',
         login_required(ContactDetailAPIView.as_view()),
         name='api_contact'),
    path('api/contacts',
         login_required(ContactListAPIView.as_view()),
         name='api_contacts'),
    # signup.urls.api.dashboard.keys
    path('api/users/<slug:user>/ssh-keys',
         login_required(PublicKeyAPIView.as_view()),
         name='api_pubkey'),
    path('api/users/<slug:user>/api-keys',
         login_required(ListCreateAPIKeysAPIView.as_view()),
         name='api_generate_keys'),
    path('api/users/<slug:user>/api-keys/<slug:key>',
         login_required(DestroyAPIKeyAPIView.as_view()),
         name='api_destroy_key'),
    # signup.urls.api.dashboard.users
    path('api/users/<slug:user>/notifications',
         login_required(UserNotificationsAPIView.as_view()),
         name='api_user_notifications'),
    path('api/users/<slug:user>/picture',
         login_required(UserPictureAPIView.as_view()),
         name='api_user_picture'),
    path('api/users/<slug:user>/otp',
         login_required(OTPChangeAPIView.as_view()),
         name='api_user_otp_change'),
    path('api/users/<slug:user>/password',
         login_required(PasswordChangeAPIView.as_view()),
         name='api_user_password_change'),
    path('api/users/<slug:user>',
         login_required(UserDetailAPIView.as_view()),
         name='api_user_profile'),
    path('api/users',
         login_required(UserListCreateAPIView.as_view()),
         name='saas_api_users'),
    # signup.urls.api.tokens
    path('api/auth/tokens/verify',
         login_required(JWTVerify.as_view()),
         name='api_verify_token'),
    path('api/auth/tokens',
         login_required(JWTRefresh.as_view()),
         name='api_refresh_token'),

    path('api/',
        include('signup.urls.api.dashboard.activate')),
    path('api/',
        include('signup.urls.api.auth')),

    # Views
    # signup.urls.views.dashboard.contacts
    path('activities/accounts/<slug:profile>/',
         login_required(AccountDetailView.as_view(lookup_field='username')),
         name='signup_account_activities'),
    path('activities/accounts/',
         login_required(AccountListView.as_view()),
         name='signup_accounts'),
    path('activities/contacts/<slug:user>/',
         login_required(ContactDetailView.as_view()),
         name='signup_contact'),
    path('activities/contacts/',
         login_required(ContactListView.as_view()),
         name='signup_contacts'),
    # signup.urls.views.dashboard.users
    path('users/<slug:user>/password/',
         login_required(PasswordChangeView.as_view()),
         name='password_change'),
    path('users/<slug:user>/pubkey/',
         login_required(UserPublicKeyUpdateView.as_view()),
         name='pubkey_update'),
    path('users/<slug:user>/notifications/',
         login_required(UserNotificationsView.as_view()),
         name='users_notifications'),
    path('users/<slug:user>/',
         login_required(UserProfileView.as_view()),
         name='users_profile'),
    path('users/',
         redirect_to_user_profile,
         name='accounts_profile'),

    # signup.urls.views.auth
    path('', include('signup.urls.views.auth')),

    # testsite application views
    path('app/<slug:user>/',
         active_required(TemplateView.as_view(template_name='app.html'))),
    path('app/',
         login_required(TemplateView.as_view(template_name='app.html'))),
    path('', RedirectView.as_view(url=reverse_lazy('login')),
        name='homepage'),
]
