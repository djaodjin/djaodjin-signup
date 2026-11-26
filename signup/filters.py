# Copyright (c) 2026, DjaoDjin inc.
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
from django.db.models.expressions import RawSQL
from django.db.models.functions import Cast
from rest_framework.filters import (OrderingFilter as BaseOrderingFilter,
    SearchFilter as BaseSearchFilter)

from . import settings
from .compat import force_str, six


LOGGER = logging.getLogger(__name__)


def search_terms_as_list(params):
    """
    Search terms are set by a ?q=... query parameter.
    When multiple search terms must be matched, they can be delimited
    by a comma.
    """
    params = params.replace('\x00', '')  # strip null characters
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
            if letter in (',',):
                if first < last:
                    results += [params[first:last]]
                first = last + 1
            elif letter == '"':
                inside = True
                first = last + 1
    if first < len(params):
        results += [params[first:len(params)]]
    return results


class SearchFilter(BaseSearchFilter):

    search_field_param = settings.SEARCH_FIELDS_PARAM

    def filter_queryset(self, request, queryset, view):
        #pylint:disable=too-many-locals
        search_fields = self.get_valid_fields(request, queryset, view)
        search_terms = self.get_search_terms(request)
        LOGGER.debug("[SearchFilter.filter_queryset] search_terms=%s, "\
            "search_fields=%s", search_terms, search_fields)

        if not search_fields or not search_terms:
            return queryset

        json_field = self.get_json_field(view)
        json_field_as_json = '%s_json' % (json_field if json_field else "")
        model_search_fields = []
        json_search_fields = []
        for field in search_fields:
            field_name = field
            lookup = self.lookup_prefixes.get(field_name[0])
            if lookup:
                field_name = field_name[1:]
            if json_field and field_name.startswith('%s__' % json_field):
                json_field_name = field_name.replace(
                    json_field, json_field_as_json)
                json_search_fields += [
                    (lookup + json_field_name) if lookup else json_field_name]
            else:
                model_search_fields += [field]
        if json_search_fields:
            json_field_valid = "%s_valid" % json_field_as_json
            if settings.IS_JSON_SQL_FEATURE_AVAILABLE:
                queryset = queryset.annotate(
                    **{json_field_valid: RawSQL("%s IS JSON" % json_field, [])})
            else:
                # sqlite3 defines a `JSON_VALID` function.
                # PostgresQL < 16 requires to create a database function.
                queryset = queryset.annotate(**{json_field_valid: models.Func(
                    json_field, function='JSON_VALID',
                    output_field=models.BooleanField())})
            queryset = queryset.annotate(
                    **{json_field_as_json: models.Case(
                    models.When(models.Q(**{json_field_valid: True}),
                    then=Cast(json_field, output_field=models.JSONField())))})

        try:
            # djangorestframework>=3.15
            orm_lookups = [
                self.construct_search(six.text_type(search_field), queryset)
                for search_field in (model_search_fields + json_search_fields)
            ]
        except TypeError:
            # djangorestframework<=3.14
            #pylint:disable=no-value-for-parameter
            orm_lookups = [
                self.construct_search(six.text_type(search_field))
                for search_field in (model_search_fields + json_search_fields)
            ]

        conditions = []
        for search_term in search_terms:
            queries = [
                self.build_search_query(orm_lookup, search_term)
                for orm_lookup in orm_lookups
            ]
            conditions.append(reduce(operator.or_, queries))
        queryset = queryset.filter(reduce(operator.or_, conditions))

        if self.must_call_distinct(queryset, model_search_fields):
            # Filtering against a many-to-many field requires us to
            # call queryset.distinct() in order to avoid duplicate items
            # in the resulting queryset.
            # We try to avoid this if possible, for performance reasons.
            queryset = queryset.distinct()
        return queryset


    def build_search_query(self, orm_lookup, search_term):
        return models.Q(**{orm_lookup: search_term})


    def filter_valid_fields(self, queryset, fields, view):
        #pylint:disable=too-many-locals,protected-access
        model_fields = {
            field.name for field in queryset.model._meta.get_fields()}
        annotations = getattr(
            getattr(queryset, 'query', None), 'annotations', None)
        if annotations:
            model_fields |= set(annotations.keys())
        # We add all the fields that could be aliases then filter out the ones
        # which are not present in the model.
        alternate_fields = getattr(view, 'alternate_fields', {})
        for field in fields:
            field_lookup = field[0]
            lookup = self.lookup_prefixes.get(field_lookup)
            if lookup:
                field = field[1:]
            alternate_field = alternate_fields.get(field, None)
            if alternate_field:
                if lookup:
                    alternate_field = field_lookup + alternate_field
                if isinstance(alternate_field, (list, tuple)):
                    fields += tuple(alternate_field)
                else:
                    fields += tuple([alternate_field])

        search_fields = getattr(view, 'search_fields', [])
        json_field = self.get_json_field(view)
        valid_fields = []
        for field in fields:
            field_name = field
            lookup = self.lookup_prefixes.get(field_name[0])
            if lookup:
                field_name = field_name[1:]
            if json_field and field_name.startswith('%s__' % json_field):
                if json_field in model_fields:
                    valid_fields.append(field)
            elif field in search_fields:
                if '__' in field_name:
                    relation, rel_field = field_name.split('__')
                    try:
                        # check if the field is a relation
                        rel = queryset.model._meta.get_field(
                            relation).remote_field
                        if rel:
                            # if the field doesn't exist the
                            # call will throw an exception
                            rel.model._meta.get_field(rel_field)
                            valid_fields.append(field)
                    except FieldDoesNotExist:
                        pass
                elif field_name in model_fields:
                    try:
                        rel = queryset.model._meta.get_field(
                            field_name).remote_field
                    except FieldDoesNotExist:
                        rel = None
                    if not rel:
                        # if it is a relation fields (as a result valid),
                        # we don't want to end-up with a problem later on
                        # when we are trying `field__icontains=`.
                        valid_fields.append(field)

        return tuple(valid_fields)


    def get_json_field(self, view):
        json_field = getattr(view, 'json_field', None)
        if json_field and json_field in getattr(view, 'search_fields', []):
            return json_field
        return None


    def get_query_param(self, request, key, default_value=None):
        try:
            return request.query_params.get(key, default_value)
        except AttributeError:
            pass
        return request.GET.get(key, default_value)


    def get_query_param_list(self, request, key, default_value=None):
        try:
            return request.query_params.getlist(key, default_value)
        except AttributeError:
            pass
        return request.GET.getlist(key, default_value)


    def get_query_fields(self, request):
        return self.get_query_param_list(request, self.search_field_param)


    def get_search_terms(self, request):
        """
        Search terms are set by a ?q=... query parameter.
        When multiple search terms must be matched, they can be delimited
        by a comma.
        """
        return search_terms_as_list(
            self.get_query_param(request, self.search_param, ''))


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
        search_fields = getattr(view, 'search_fields', None)
        json_field = self.get_json_field(view)
        search_field_names = []
        if search_fields:
            for search_field in search_fields:
                if isinstance(search_field, tuple):
                    search_field_names += [search_field[1]]
                else:
                    search_field_names += [search_field]
        search_fields_description = (
            "restrict searches to one or more fields in: %(search_fields)s."\
            " searches all fields when unspecified.")
        if json_field:
            search_fields_description += (
            " If %(json_field)s is valid JSON, using target keys works"\
            " by adding a '__' between %(json_field)s and the target key"\
            " (example: '%(json_field)s__birth_date').")
        search_fields_description = search_fields_description % {
            'json_field': json_field,
            'search_fields': ', '.join(search_field_names)}
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
