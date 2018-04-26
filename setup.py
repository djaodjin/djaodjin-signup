# Copyright (c) 2018, Djaodjin Inc.
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

from distutils.core import setup
import signup

setup(
    name='djaodjin-signup',
    version=signup.__version__,
    author='The DjaoDjin Team',
    author_email='support@djaodjin.com',
    packages=['signup',
              'signup.api',
              'signup.backends',
              'signup.migrations',
              'signup.views',
              'signup.urls',
              'signup.urls.api',
              ],
    package_data={'signup': ['templates/accounts/*.html',
                             'templates/notification/*.eml',
                             'templates/users/*.html',
                             'static/js/*.js']},
    url='https://github.com/djaodjin/djaodjin-signup/',
    download_url='https://github.com/djaodjin/djaodjin-signup/tarball/%s' \
        % signup.__version__,
    license='BSD',
    description="DjaoDjin's Implementation of Frictionless Sign Up",
    long_description=open('README.md').read(),
)
