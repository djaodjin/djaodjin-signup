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
import logging

from django.core.exceptions import FieldDoesNotExist
from django.db import models
from rest_framework.compat import distinct
from rest_framework.filters import (OrderingFilter as BaseOrderingFilter,
    SearchFilter as BaseSearchFilter)

from . import settings
from .compat import force_str, six


LOGGER = logging.getLogger(__name__)


class SearchFilter(BaseSearchFilter):

    search_field_param = settings.SEARCH_FIELDS_PARAM


    def filter_queryset(self, request, queryset, view):
        search_fields = self.get_valid_fields(request, queryset, view)
        search_terms = self.get_search_terms(request)
        LOGGER.debug("[SearchFilter.filter_queryset] search_terms=%s, "\
            "search_fields=%s", search_terms, search_fields)

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
        queryset = queryset.filter(reduce(operator.or_, conditions))

        if self.must_call_distinct(queryset, search_fields):
            # Filtering against a many-to-many field requires us to
            # call queryset.distinct() in order to avoid duplicate items
            # in the resulting queryset.
            # We try to avoid this if possible, for performance reasons.
            queryset = distinct(queryset, base)
        return queryset


    @staticmethod
    def filter_valid_fields(queryset, fields, view):
        #pylint:disable=protected-access
        model_fields = {
            field.name for field in queryset.model._meta.get_fields()}
        # We add all the fields that could be aliases then filter out the ones
        # which are not present in the model.
        alternate_fields = getattr(view, 'alternate_fields', {})
        for field in fields:
            alternate_field = alternate_fields.get(field, None)
            if alternate_field:
                if isinstance(alternate_field, (list, tuple)):
                    fields += tuple(alternate_field)
                else:
                    fields += tuple([alternate_field])

        valid_fields = []
        for field in fields:
            if '__' in field:
                relation, rel_field = field.split('__')
                try:
                    # check if the field is a relation
                    rel = queryset.model._meta.get_field(relation).remote_field
                    if rel:
                        # if the field doesn't exist the
                        # call will throw an exception
                        rel.model._meta.get_field(rel_field)
                        valid_fields.append(field)
                except FieldDoesNotExist:
                    pass
            elif field in model_fields:
                valid_fields.append(field)

        return tuple(valid_fields)


    def get_query_fields(self, request):
        return request.query_params.getlist(self.search_field_param)


    def get_search_terms(self, request):
        """
        Search terms are set by a ?search=... query parameter,
        and may be comma and/or whitespace delimited.
        """
        params = request.query_params.get(self.search_param, '')
        params = params.replace('\x00', '')  # strip null characters
        params = params.replace(',', ' ')
        results = []
        inside = False
        first = 0
        for last, letter in enumerate(params):
            if inside:
                if letter == '"':
                    if first < last:
                        results += [params[first:last]]
                    first = last + 1
                    inside = False
            else:
                if letter in (' ', '\t'):
                    if first < last:
                        results += [params[first:last]]
                    first = last + 1
                elif letter == '"':
                    inside = True
                    first = last + 1
        if first < len(params):
            results += [params[first:len(params)]]
        return results


    def get_valid_fields(self, request, queryset, view, context=None):
        #pylint:disable=protected-access,unused-argument
        if context is None:
            context = {}

        fields = self.get_query_fields(request)
        # client-supplied fields take precedence
        if fields:
            fields = self.filter_valid_fields(queryset, fields, view)
        # if there are no fields (due to empty query params or wrong
        # fields we fallback to fields specified in the view
        if not fields:
            fields = getattr(view, 'search_fields', [])
            fields = self.filter_valid_fields(queryset, fields, view)
        return fields


    def get_schema_operation_parameters(self, view):
        search_fields = getattr(view, 'search_fields', [])
        search_fields_description = (
            "restrict searches to one or more fields in: %s."\
            " searches all fields when unspecified."  % (
            ', '.join(search_fields)))
        return [
            {
                'name': self.search_param,
                'required': False,
                'in': 'query',
                'description': force_str(
                    "value to search for in the fields specified by %s" %
                    self.search_field_param),
                'schema': {
                    'type': 'string',
                },
            },
            {
                'name': self.search_field_param,
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
        valid_fields = tuple(
            field for field in base_fields if field[0] in model_fields)
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

    search_param = 'q'
    ordering_param = 'o'

    def __init__(self, sort_fields, search_fields):
        self.sort_fields = sort_fields
        self.search_fields = search_fields

    def __call__(self):
        return self

    def filter_queryset(self, request, queryset, view):
        #pylint:disable=unused-argument
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
