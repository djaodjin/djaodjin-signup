# Copyright (c) 2015, Djaodjin Inc.
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

import datetime, base64, hashlib, hmac, json, logging

import boto.sts

from signup import settings


LOGGER = logging.getLogger(__name__)


def temporary_security_token(request, aws_upload_role=None, aws_region=None):
    """
    Create temporary security credentials on AWS. This typically needed
    to allow uploads from the browser directly to S3.
    """
    if (request.user.is_authenticated()
        and not request.session.has_key('access_key')):
        if not aws_upload_role:
            aws_upload_role = settings.AWS_UPLOAD_ROLE
        if not aws_region:
            aws_region = settings.AWS_REGION
        conn = boto.sts.connect_to_region(aws_region)
        assumed_role = conn.assume_role(
            aws_upload_role, request.session.session_key)
        request.session['access_key'] = assumed_role.credentials.access_key
        request.session['secret_key'] = assumed_role.credentials.secret_key
        request.session['security_token'] \
            = assumed_role.credentials.session_token
        LOGGER.info('AWS temporary credentials for %s to assume role %s {'\
            '"aws_access_key": "%s"}', request.user, aws_upload_role,
            request.session['access_key'])


class AWSContextMixin(object):


    @staticmethod
    def _signed_policy(region, service, requested_at,
                       access_key, secret_key, security_token,
                       bucket=None):
        #pylint:disable=too-many-arguments,too-many-locals
        signature_date = requested_at.strftime("%Y%m%d")
        x_amz_credential = '/'.join([
            access_key, signature_date, region, service, 'aws4_request'])
        x_amz_date = '%sT000000Z' % signature_date
        policy = json.dumps({
            "expiration": (requested_at + datetime.timedelta(
                hours=24)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "conditions":[
                {"bucket": bucket},
                {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
                {"x-amz-credential": x_amz_credential},
                {"x-amz-date": x_amz_date},
                {"x-amz-security-token": security_token},
                ["starts-with", "$key", ""]
            ]
        }).encode("utf-8")
        policy_base64 = base64.b64encode(policy).replace('\n', '')
        date_key = hmac.new(("AWS4%s" % secret_key).encode("utf-8"),
            signature_date.encode("utf-8"),
            hashlib.sha256).digest()
        date_region_key = hmac.new(
            date_key, region.encode("utf-8"),
            hashlib.sha256).digest()
        date_region_service_key = hmac.new(
            date_region_key, service.encode("utf-8"),
            hashlib.sha256).digest()
        signing_key = hmac.new(
            date_region_service_key, "aws4_request".encode("utf-8"),
            hashlib.sha256).digest()
        policy_signature = hmac.new(
            signing_key, policy_base64,
            hashlib.sha256).hexdigest()
        return {
            'access_key': access_key,
            'security_token': security_token,
            'aws_policy': policy_base64,
            'aws_policy_signature': policy_signature,
            'x_amz_credential': x_amz_credential,
            'x_amz_date': x_amz_date}

    def get_context_data(self, *args, **kwargs):
        #pylint: disable=unused-argument
        context = {}
        if self.request.user.is_authenticated():
            aws_region = kwargs.get('aws_region', settings.AWS_REGION)
            if not 'access_key' in self.request.session:
                # Lazy creation of temporary credentials.
                temporary_security_token(self.request,
                    kwargs.get('aws_upload_role', settings.AWS_UPLOAD_ROLE),
                    aws_region)
            context.update(self._signed_policy(
                aws_region, "s3",
                datetime.datetime.now(),
                self.request.session['access_key'],
                self.request.session['secret_key'],
                security_token=self.request.session['security_token'],
                bucket=kwargs.get('bucket', None)))
        return context
