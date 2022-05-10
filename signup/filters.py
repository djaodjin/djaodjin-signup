# Copyright (c) 2022, DjaoDjin inc.
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
from __future__ import unicode_literals

import operator
from functools import reduce

from django.db import models
from rest_framework.compat import distinct
from rest_framework.filters import (OrderingFilter as BaseOrderingFilter,
    SearchFilter as BaseSearchFilter)

from .compat import force_str, six


class SearchFilter(BaseSearchFilter):

    @staticmethod
    def get_valid_fields(queryset, view, context=None):
        #pylint:disable=protected-access,unused-argument
        model_fields = {
            field.name for field in queryset.model._meta.get_fields()}
        base_fields = getattr(view, 'search_fields', [])
        valid_fields = tuple([
            field for field in base_fields if field in model_fields])
        return valid_fields

    def filter_queryset(self, request, queryset, view):
        search_fields = self.get_valid_fields(queryset, view)
        search_terms = self.get_search_terms(request)

        if not search_fields or not search_terms:
            return queryset

        orm_lookups = [
            self.construct_search(six.text_type(search_field))
            for search_field in search_fields
        ]

        base = queryset
        conditions = []
        for search_term in search_terms:
            queries = [
                models.Q(**{orm_lookup: search_term})
                for orm_lookup in orm_lookups
            ]
            conditions.append(reduce(operator.or_, queries))
        queryset = queryset.filter(reduce(operator.and_, conditions))

        if self.must_call_distinct(queryset, search_fields):
            # Filtering against a many-to-many field requires us to
            # call queryset.distinct() in order to avoid duplicate items
            # in the resulting queryset.
            # We try to avoid this if possible, for performance reasons.
            queryset = distinct(queryset, base)
        return queryset

    def get_schema_operation_parameters(self, view):
        search_fields = getattr(view, 'search_fields', [])
        search_fields_description = "search for matching text in %s"  % (
            ', '.join(search_fields))
        return [
            {
                'name': self.search_param,
                'required': False,
                'in': 'query',
                'description': force_str(search_fields_description),
                'schema': {
                    'type': 'string',
                },
            },
        ]


class OrderingFilter(BaseOrderingFilter):

    def get_valid_fields(self, queryset, view, context=None):
        #pylint:disable=protected-access
        model_fields = {
            field.name for field in queryset.model._meta.get_fields()}
        base_fields = super(OrderingFilter, self).get_valid_fields(
            queryset, view, context=context if context else {})
        valid_fields = tuple([
            field for field in base_fields if field[0] in model_fields])
        return valid_fields

    def get_ordering(self, request, queryset, view):
        #pylint:disable=protected-access
        ordering = None
        params = request.query_params.get(self.ordering_param)
        if params:
            fields = [param.strip() for param in params.split(',')]
            if 'created_at' in fields or '-created_at' in fields:
                model_fields = {
                    field.name for field in queryset.model._meta.get_fields()}
                if 'date_joined' in model_fields:
                    fields = ['date_joined' if field == 'created_at' else (
                        '-date_joined' if field == '-created_at' else field)
                        for field in fields]
            ordering = self.remove_invalid_fields(
                queryset, fields, view, request)
        if not ordering:
            # We use an alternate ordering if the fields are not present
            # in the second model.
            # (ex: Organization.full_name vs. User.first_name)
            ordering = self.remove_invalid_fields(
                queryset, self.get_default_ordering(view), view, request)
        if not ordering:
            ordering = view.alternate_ordering
        return ordering

    def get_schema_operation_parameters(self, view):
        # validating presence of coreapi and coreschema
        super(OrderingFilter, self).get_schema_fields(view)
        ordering_fields = getattr(view, 'ordering_fields', [])
        sort_fields_description = "sort by %s. If a field is preceded by"\
            " a minus sign ('-'), the order will be reversed. Multiple 'o'"\
            " parameters can be specified to produce a stable"\
            " result." % ', '.join([field[1] for field in ordering_fields])
        return [
            {
                'name': self.ordering_param,
                'required': False,
                'in': 'query',
                'description': force_str(sort_fields_description),
                'schema': {
                    'type': 'string',
                },
            },
        ]


class SortableSearchableFilterBackend(object):

    def __init__(self, sort_fields, search_fields):
        self.sort_fields = sort_fields
        self.search_fields = search_fields

    def __call__(self):
        return self

    def filter_queryset(self, request, queryset, view):
        #pylint:disable=no-self-use,unused-argument
        return queryset

    def get_schema_operation_parameters(self, view):
        search_fields = getattr(view, 'search_fields', [])
        search_fields_description = "search for matching text in %s"  % (
            ', '.join(search_fields))
        ordering_fields = getattr(view, 'ordering_fields', [])
        sort_fields_description = "sort by %s. If a field is preceded by"\
            "a minus sign ('-'), the order will be reversed. Multiple 'o'"\
            " parameters can be specified to produce a stable"\
            " result." % ', '.join([field[1] for field in ordering_fields])
        return [
            {
                'name': self.search_param,
                'required': False,
                'in': 'query',
                'description': force_str(search_fields_description),
                'schema': {
                    'type': 'string',
                },
            },
            {
                'name': self.ordering_param,
                'required': False,
                'in': 'query',
                'description': force_str(sort_fields_description),
                'schema': {
                    'type': 'string',
                },
            }
        ]


class SortableDateRangeSearchableFilterBackend(SortableSearchableFilterBackend):

#    def __init__(self, sort_fields, search_fields):
#        super(SortableDateRangeSearchableFilterBackend, self).__init__(
#            sort_fields, search_fields)

    def get_schema_operation_parameters(self, view):
        fields = super(SortableDateRangeSearchableFilterBackend,
            self).get_schema_operation_parameters(view)
        fields += [
            {
                'name': 'start_at',
                'required': False,
                'in': 'query',
                'description': force_str("date/time in ISO format"\
                        " after which records were created."),
                'schema': {
                    'type': 'string',
                },
            },
            {
                'name': 'ends_at',
                'required': False,
                'in': 'query',
                'description': force_str("date/time in ISO format"\
                        " before which records were created."),
                'schema': {
                    'type': 'string',
                },
            }
        ]
        return fields
