# Copyright (c) 2014, DjaoDjin inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from django.core.exceptions import ValidationError
from django.db.models import Q
from django.http import Http404
from rest_framework import serializers
from rest_framework.generics import ListAPIView

from signup.compat import User


class UserSerializer(serializers.ModelSerializer):
    #pylint: disable=no-init,old-style-class

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def full_clean(self, instance):
        # Implementation Note:
        # We only want to make sure we get a correctly formatted username
        # without validating the User is unique in the database. rest_framework
        # does not propagate the flag here so we override the method.
        try:
            instance.full_clean(exclude=self.get_validation_exclusions(),
                                validate_unique=False)
        except ValidationError as err:
            self._errors = err.message_dict
            return None
        return instance


class UserListAPIView(ListAPIView):

    model = User
    serializer_class = UserSerializer

    def get_queryset(self):
        queryset = super(UserListAPIView, self).get_queryset()
        startswith = self.request.GET.get('q', None)
        if not startswith:
            raise Http404
        return queryset.filter(Q(username__startswith=startswith)
            | Q(email__startswith=startswith))
