# Copyright (c) 2025, Djaodjin Inc.
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

import logging, re

from django.http import Http404
from django.contrib.auth import (REDIRECT_FIELD_NAME, authenticate,
    get_user_model, login as auth_login)
from django.core.exceptions import ImproperlyConfigured
from django.core.validators import validate_email as validate_email_base
from django.db import IntegrityError, router, transaction
from django.utils import translation
from django.utils.http import urlencode
from rest_framework import exceptions, serializers
from rest_framework.generics import get_object_or_404

from . import signals, settings
from .auth import validate_path_pattern, validate_redirect
from .backends.email_verification import send_verification_email
from .backends.phone_verification import send_verification_phone
from .compat import gettext_lazy as _, is_authenticated, reverse, six
from .helpers import (full_name_natural_split, has_invalid_password,
    update_context_urls)
from .models import Contact, DelegateAuth, Notification, OTPGenerator
from .utils import (generate_random_slug, get_disabled_authentication,
    get_disabled_registration, get_email_dynamic_validator,
    get_login_throttle, get_phone_dynamic_validator, handle_uniq_error)
from .validators import as_email_or_phone, validate_phone

LOGGER = logging.getLogger(__name__)


class SSORequired(exceptions.AuthenticationFailed):

    sso_providers = settings.SSO_PROVIDERS

    def __init__(self, delegate_auth, detail=None, code=None):
        self.delegate_auth = delegate_auth
        super(SSORequired, self).__init__(detail=detail, code=code)

    @property
    def url(self):
        back_url = reverse('social:begin', args=(self.delegate_auth.provider,))
        if self.delegate_auth.provider == 'saml':
            back_url += "?" + urlencode({
                'next': settings.LOGIN_REDIRECT_URL,
                'idp': self.delegate_auth.domain
            })
        return back_url

    @property
    def provider_info(self):
        return self.sso_providers.get(self.delegate_auth.provider, {
            'name': str(self.delegate_auth.provider)
        })

    @property
    def printable_name(self):
        return self.provider_info.get('name', str(self.delegate_auth.provider))


class IncorrectUser(exceptions.AuthenticationFailed):
    """
    Cannot find user or contact
    """


class VerifyEmailRequired(exceptions.AuthenticationFailed):
    """
    break workflow because we are waiting for a link/code
    that was sent to an e-mail address to continue.
    """

class VerifyPhoneRequired(exceptions.AuthenticationFailed):
    """
    break workflow because we are waiting for a link/code
    that was sent to a phone number to continue.
    """


class OTPRequired(exceptions.AuthenticationFailed):
    """
    break workflow because we require the user to enter an OTP
    """


class PasswordRequired(exceptions.AuthenticationFailed):
    """
    break workflow because we require the user to enter a password
    """
    def __init__(self, user, detail=None, code=None):
        self.user = user
        super(PasswordRequired, self).__init__(detail=detail, code=code)


class AuthDisabled(exceptions.PermissionDenied):
    """
    Authentication is disabled
    """


class RegistrationDisabled(exceptions.PermissionDenied):
    """
    Registration is disabled
    """


class AuthMixin(object):
    """
    Steps used in authentication workflows:
     - login with password
     - login with e-mail verification
     - login with phone verification
     - login with OTP code,
     - login through any combination of the above.
     - registration, either pre-populated or not.
    """
    backend_path = 'signup.backends.auth.UsernameOrEmailPhoneModelBackend'
    default_check_email = False
    default_check_phone = False
    form_class = None
    model = get_user_model()
    registration_fields = (
        'country',
        'email',
        'full_name',
        'first_name',
        'last_name',
        'nick_name',
        'get_nick_name',
        'lang',
        'get_lang',
        'locality',
        'postal_code',
        'new_password',
        'new_password2',
        'password',
        'phone',
        'get_phone',
        'region',
        'street_address',
        'username',
    )
    renames = {}
    serializer_class = None


    def email_verification_required(self, user, **cleaned_data):
        cleaned_email = cleaned_data.get('email')
        email = cleaned_email
        if not email and user:
            email = user.email

        if Contact.objects.email_verification_required(email):
            return True

        cleaned_phone = cleaned_data.get('phone')
        if (user and has_invalid_password(user) and
            email and not cleaned_phone):
            # When we have a user with no password set, we will
            # verify the email address unless we will verify
            # the phone number instead.
            return True

        if not user and cleaned_email:
            # XXX `and not Contact.objects.is_email_verified(cleaned_email)`
            # If we are going to register a new user
            # through the authentication workflow,
            # we must verify the e-mail address when provided.
            return True

        return False


    def get_query_param(self, request, key, default_value=None):
        try:
            return request.query_params.get(key, default_value)
        except AttributeError:
            pass
        return request.GET.get(key, default_value)


    def phone_verification_required(self, user, **cleaned_data):
        cleaned_phone = cleaned_data.get('phone')
        phone = cleaned_phone
        if not phone and user:
            contact = user.contacts.exclude(phone__isnull=False).first()
            if contact:
                phone = contact.phone

        if Contact.objects.phone_verification_required(phone):
            return True

        cleaned_email = cleaned_data.get('email')
        if (user and has_invalid_password(user) and
            phone and not cleaned_email):
            # When we have a user with no password set, we will
            # verify the phone number unless we will verify
            # the email address instead.
            return True

        if not user and cleaned_phone:
            # If we are going to register a new user
            # through the authentication workflow,
            # we must verify the phone number when provided.
            return True

        return False


    def prefetch_contact_info(self):
        return None


    def validate_inputs(self, contact=None, raise_exception=True):
        initial_data = {}
        if contact:
            fields = []
            if self.form_class is not None:
                fields = six.iterkeys(self.get_initial())
            elif self.serializer_class is not None and hasattr(
                    self.serializer_class, 'Meta'):
                # We want to pre-populate all fields except write-only
                # fields obviously (ex: email_code), or read-only fields
                # (ex: 'created_at').
                #pylint:disable=protected-access
                fields = [field_name
                    for field_name, field_obj in six.iteritems(
                        self.serializer_class._declared_fields) if not (
                        field_obj.write_only or field_obj.read_only)]
                LOGGER.debug("[prefetch_contact_info] fields=%s", str(fields))
            for field_name in fields:
                field_value = None
                if contact.user:
                    field_value = getattr(contact.user, field_name, None)
                if not field_value:
                    field_value = getattr(contact, field_name, None)
                if field_value:
                    initial_data.update({field_name: field_value})

        # merges data from form fields or json serializer
        cleaned_data = {}
        if initial_data:
            cleaned_data = initial_data.copy()
        if self.form_class is not None:
            form = self.get_form()
            if self.request.method.lower() in ('post',):
                if not form.is_valid() and raise_exception:
                    raise serializers.ValidationError()
                for field_name in six.iterkeys(form.data):
                    cleaned_data.update({
                        field_name: form.cleaned_data.get(
                            field_name, form.data[field_name])})
            next_url = validate_redirect(self.request)
            if next_url:
                cleaned_data.update({'next_url': next_url})
        elif self.serializer_class is not None:
            data = initial_data.copy()
            data.update(self.request.data)
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=raise_exception)
            for field_name in six.iterkeys(data):
                if field_name == 'phone':
                    # See serializers_overrides.py:UserDetailSerializer
                    field_value = serializer.validated_data.get('get_phone',
                        serializer.validated_data.get(
                            field_name, data[field_name]))
                else:
                    field_value = serializer.validated_data.get(
                        field_name, data[field_name])
                cleaned_data.update({field_name: field_value})

        if 'email' not in cleaned_data and 'phone' not in cleaned_data:
            username = cleaned_data.get('username')
            email, phone = as_email_or_phone(username)
            cleaned_data.update({'email': email, 'phone': phone})
        if 'phone' not in cleaned_data:
            email = cleaned_data.get('email')
            email, phone = as_email_or_phone(email)
            cleaned_data.update({'email': email, 'phone': phone})

        return cleaned_data


    def find_candidate(self, **cleaned_data):
        username = cleaned_data.get('username')
        email = cleaned_data.get('email')
        phone = cleaned_data.get('phone')

        user = None
        if username:
            try:
                user = self.model.objects.find_user(username)
                if not email:
                    email = user.email
            except self.model.DoesNotExist:
                user = None

        if not user and email:
            try:
                user = self.model.objects.find_user(email)
            except self.model.DoesNotExist:
                user = None

        if not user and phone:
            try:
                user = self.model.objects.find_user(phone)
                if not email:
                    email = user.email
            except self.model.DoesNotExist:
                user = None

        return user, email


    def auth_check_disabled(self, user):
        auth_disabled = get_disabled_authentication(self.request, user)
        if auth_disabled:
            raise AuthDisabled(
                {'detail': _("Authentication is disabled")})

    def get_verification_back_url(self, verification_key):
        if settings.USE_VERIFICATION_LINKS:
            return self.request.build_absolute_uri(reverse(
                'registration_activate', args=(verification_key,)))
        return None

    def verify_email(self, user, **cleaned_data):
        email = cleaned_data.get('email')
        if not email and user:
            email = user.email

        email_code = cleaned_data.get('email_code')

        # send link through e-mail
        if email and not email_code:
            force_verification = cleaned_data.get('check_email',
                self.default_check_email)
            requires_verification = self.email_verification_required(
                user, **cleaned_data)
            if not user:
                # If the email is not connected to a user, we will check
                # the e-mail pass bot-prevention tests.
                dynamic_validator = get_email_dynamic_validator()
                if dynamic_validator:
                    dynamic_validator(email)

                # If we do not have a candidate user, we first must give
                # a chance to the visitor to verify the e-mail address.
                if not force_verification and requires_verification:
                    raise exceptions.AuthenticationFailed()

            if force_verification or requires_verification:

                #pylint:disable=unused-variable
                contact, unused = Contact.objects.prepare_email_verification(
                    email, user=user)
                #pylint:disable=assignment-from-none
                back_url = self.get_verification_back_url(
                    contact.email_verification_key)
                next_url = cleaned_data.get('next_url')
                if back_url and next_url:
                    back_url += '?%s=%s' % (REDIRECT_FIELD_NAME, next_url)
                send_verification_email(contact, self.request,
                    back_url=back_url)
                raise VerifyEmailRequired({'email': (
                    _("We sent a one-time link to your e-mail address.")
                    if back_url else
                    _("We sent a one-time code to your e-mail address."))})

        return user


    def check_email_verified(self, user, **cleaned_data):
        email = cleaned_data.get('email')
        if not email and user:
            email = user.email

        email_code = cleaned_data.get('email_code')
        if email_code:
            try:
                commit = (user or cleaned_data.get('new_password'))
                Contact.objects.finalize_email_verification(
                    email, email_code, commit=commit)
                if user and has_invalid_password(user):
                    # Bypassing authentication here, we are doing frictionless
                    # registration the first time around.
                    user.backend = self.backend_path
            except Contact.DoesNotExist:
                raise serializers.ValidationError({'email_code':
                    _("E-mail verification code does not match.")})

        return user


    def verify_phone(self, user, **cleaned_data):
        phone = cleaned_data.get('phone')
        if not phone and user:
            contact = user.contacts.exclude(phone__isnull=False).first()
            if contact:
                phone = contact.phone

        phone_code = cleaned_data.get('phone_code')

        # send link through phone
        if phone and not phone_code:
            force_verification = cleaned_data.get('check_phone',
                self.default_check_phone)
            requires_verification = self.phone_verification_required(
                user, **cleaned_data)
            if not user:
                # If the phone is not connected to a user, we will check
                # the e-mail pass bot-prevention tests.
                dynamic_validator = get_phone_dynamic_validator()
                if dynamic_validator:
                    dynamic_validator(phone)

                # If we do not have a candidate user, we first must give
                # a chance to the visitor to verify the e-mail address.
                if not force_verification and requires_verification:
                    raise exceptions.AuthenticationFailed()

            if force_verification or requires_verification:
                #pylint:disable=unused-variable
                contact, unused = Contact.objects.prepare_phone_verification(
                    phone, user=user)
                #pylint:disable=assignment-from-none
                back_url = self.get_verification_back_url(
                    contact.phone_verification_key)
                next_url = cleaned_data.get('next_url')
                if back_url and next_url:
                    back_url += '?%s=%s' % (REDIRECT_FIELD_NAME, next_url)
                try:
                    send_verification_phone(contact, self.request,
                        back_url=back_url)
                    raise VerifyPhoneRequired({'phone': (
                        _("We sent a one-time link to your phone.")
                        if back_url else
                        _("We sent a one-time code to your phone."))})
                except ImproperlyConfigured:
                    # Cannot send phone verification if we don't have a backend,
                    # so we fall through and will attempt to send an e-mail
                    # verification.
                    pass

        return user


    def check_phone_verified(self, user, **cleaned_data):
        phone = cleaned_data.get('phone')
        if not phone and user:
            contact = user.contacts.exclude(phone__isnull=False).first()
            if contact:
                phone = contact.phone

        phone_code = cleaned_data.get('phone_code')
        if phone_code:
            try:
                commit = (user or cleaned_data.get('new_password'))
                Contact.objects.finalize_phone_verification(
                    phone, phone_code, commit=commit)
                if user and has_invalid_password(user):
                    # Bypassing authentication here, we are doing frictionless
                    # registration the first time around.
                    user.backend = self.backend_path
            except Contact.DoesNotExist:
                raise serializers.ValidationError({'phone_code':
                    _("Phone verification code does not match.")})

        return user


    def check_password(self, user, **cleaned_data):
        #pylint:disable=unused-argument
        user_with_backend = None
        if user:
            # If we have already logged in the user by verifying an e-mail
            # address or phone number, a password is optional.
            backend = getattr(user, 'backend', None)
            if backend:
                user_with_backend = user

            password = cleaned_data.get('password')
            if password:
                user_with_backend = authenticate(self.request,
                    username=user.username, password=password)
            if not user_with_backend:
                if not password and not cleaned_data.get('new_password'):
                    field_name = (
                        'new_password' if 'new_password' in cleaned_data
                        else 'password')
                    raise PasswordRequired(user, detail={
                        field_name: _("Password is required.")})
                raise exceptions.AuthenticationFailed()

        else:
            # We are going to register a user, let's give the opportunity
            # to the created user to set a password.
            if not cleaned_data.get('new_password'):
                raise IncorrectUser({'detail':
                    _("Please enter a few information about yourself.")})

        return user_with_backend


    def check_user_throttles(self, request, user):
        """
        Rate-limit based on the user.
        """
        throttle = get_login_throttle()
        if throttle:
            throttle(request, self, user)


    def check_sso_required(self, email):
        # If the user cannot be found and we are not login
        # with an e-mail address, we cannot tell if we should
        # redirect to an SSO provider or not.
        if email:
            try:
                delegate_auth = DelegateAuth.objects.get_from_email(email)
                raise SSORequired(delegate_auth)
            except DelegateAuth.DoesNotExist:
                pass


    def check_otp(self, user, **cleaned_data):
        otp_code = cleaned_data.get('otp_code')
        if OTPGenerator.objects.filter(user=user).exists():
            if not otp_code:
                raise OTPRequired({
                    'otp_code': _("OTP code is required.")})
            nb_attempts = OTPGenerator.objects.verify(user, otp_code)
            if nb_attempts >= settings.MFA_MAX_ATTEMPTS:
                raise exceptions.PermissionDenied({'otp_code': _(
            "You have exceeded the number of attempts to enter the OTP code."\
                    " Please start again.")})
            if nb_attempts > 0:
                raise serializers.ValidationError({
                    'code': _("OTP code does not match.")})


    @staticmethod
    def first_and_last_names(**cleaned_data):
        first_name = cleaned_data.get('first_name', "")
        last_name = cleaned_data.get('last_name', "")
        if not first_name:
            # If the form does not contain a first_name/last_name pair,
            # we assume a full_name was passed instead.
            full_name = cleaned_data.get(
                'user_full_name', cleaned_data.get('full_name', None))
            if full_name:
                first_name, _, last_name = full_name_natural_split(full_name)
        return first_name, last_name


    def create_models(self, *args, **cleaned_data):
        user_extra = {}
        for field_name, field_value in six.iteritems(cleaned_data):
            if field_name not in self.registration_fields:
                if field_name.startswith('user_'):
                    user_extra.update({field_name[5:]: field_value})
        if not user_extra:
            user_extra = None
        email = cleaned_data.get('email')
        phone = cleaned_data.get('phone')
        password = cleaned_data.get('password')
        first_name = cleaned_data.get('first_name')
        last_name = cleaned_data.get('last_name')
        lang = cleaned_data.get('lang')
        return self.model.objects.create_user(*args, email=email,
            password=password, phone=phone, first_name=first_name,
            last_name=last_name, lang=lang, extra=user_extra)


    def create_user(self, contact, **cleaned_data):
        #pylint:disable=too-many-locals
        cleaned_data.pop('check_email', None)
        cleaned_data.pop('check_phone', None)

        self.register_check_data(contact, **cleaned_data)

        first_name, last_name = self.first_and_last_names(**cleaned_data)
        full_name = cleaned_data.get('full_name', None)
        if not full_name:
            full_name = (first_name + ' ' + last_name).strip()

        email = cleaned_data.get('email')
        if not email and contact:
            email = contact.email
        phone = cleaned_data.get('phone')
        if not phone and contact:
            phone = contact.phone
        username = cleaned_data.get('username')
        #pylint:disable=too-many-nested-blocks
        if username:
            if not re.match(r"^%s$" % settings.USERNAME_PAT, username):
                if not contact:
                    contact_kwargs = {}
                    try:
                        validate_email_base(username)
                        if not email:
                            email = username
                        contact_kwargs = {'email__iexact': username}
                    except serializers.ValidationError:
                        pass
                    if not contact_kwargs:
                        try:
                            contact_kwargs = {
                                'phone__iexact': validate_phone(username)
                            }
                            if not phone:
                                phone = username
                        except serializers.ValidationError:
                            pass
                    contact = Contact.objects.filter(**contact_kwargs).first()
                if contact:
                    username = contact.slug
                else:
                    username = generate_random_slug()

        password = cleaned_data.get('new_password',
            cleaned_data.get('password'))
        lang = cleaned_data.get('lang', cleaned_data.get('get_lang',
            translation.get_language_from_request(self.request)))

        if settings.DISABLED_USER_UPDATE:
            raise exceptions.AuthenticationFailed({
                'detail': _("Update of credentials (password, etc.)"\
                            " has been disabled.")})

        user = None
        previously_inactive = False
        if contact:
            try:
                # If we don't save the ``User`` model here,
                # we won't be able to authenticate later.
                # `activate_user` will reset the password.
                user, previously_inactive = contact.activate_user(
                    username=username,
                    password=cleaned_data.get('new_password'),
                    full_name=full_name)
            except IntegrityError as err:
                handle_uniq_error(err)

        if not user:
            disabled_registration = get_disabled_registration(self.request)
            if disabled_registration:
                raise RegistrationDisabled(
                    {'detail': _("Registration is disabled")})

            try:
                create_models_kwargs = cleaned_data.copy()
                create_models_kwargs.update({
                    'email': email,
                    'password': password,
                    'phone': phone,
                    'first_name': first_name,
                    'last_name': last_name,
                    'lang': lang
                })
                user = self.create_models(username, **create_models_kwargs)
            except IntegrityError as err:
                handle_uniq_error(err, renames=self.renames)

        if user:
            if not user.last_login:
                phone = user.get_phone()
                lang = user.get_lang()
                LOGGER.info("'%s <%s>' registered with username '%s'%s%s",
                    user.get_full_name(), user.email, user,
                    (" and phone %s" % str(phone)) if phone else "",
                    (" and preferred language %s" % str(lang)) if lang else "",
                    extra={'event': 'register', 'user': user})
                signals.user_registered.send(sender=__name__, user=user,
                        request=self.request)
            elif previously_inactive:
                LOGGER.info("'%s <%s>' activated with username '%s'",
                    user.get_full_name(), user.email, user,
                    extra={'event': 'activate', 'user': user})
                signals.user_activated.send(sender=__name__, user=user,
                    request=self.request)
            else:
                LOGGER.info("%s password reset", user)
                signals.user_reset_password.send(
                    sender=__name__, user=user, request=self.request)

            # Bypassing authentication here, we are doing frictionless
            # registration the first time around.
            user.backend = self.backend_path

        return user


    def create_session(self, user_with_backend):
        """
        Attaches a session cookie to the request and
        generates an login event in the audit logs.
        """
        if self.form_class or self.request.query_params.get('cookie', False):
            auth_login(self.request, user_with_backend)
        LOGGER.info("%s signed in.", user_with_backend,
            extra={'event': 'login', 'request': self.request})


    def register_check_data(self, contact, **cleaned_data):
        # Override to check the registration data (ex: signed agreements)
        errors = {}

        email = cleaned_data.get('email')
        if not email and contact:
            email = contact.email
        phone = cleaned_data.get('phone')
        if not phone and contact:
            phone = contact.phone

        if not email and not phone:
            errors.update({
                'email': _("At least one of email or phone is required."),
                'phone': _("At least one of email or phone is required.")})

        if errors:
            raise serializers.ValidationError(errors)

    def run_pipeline(self):
        # Login, Verify, Register:
        # Bot prevention
        # - no extra characters on URL path
        # - validate fields through regex
        # - optional Captcha

        # The authentication URLs are anonymously accessible, hence
        # prime candidates for bots. These will POST to '/login/.' for
        # example because there is a `action="."` in the <form> tag
        # in login.html.
        validate_path_pattern(self.request)

        # `ActivationView` will run the pipeline in GET HTTP requests
        # (uses `verification_key` in URL path), while other views will
        # solely do so in POST HTTP requests.
        #pylint:disable=assignment-from-none
        contact = self.prefetch_contact_info()
        LOGGER.debug("[run_pipeline] prefetched contact=%s", str(contact))
        cleaned_data = self.validate_inputs(contact)
        LOGGER.debug("[run_pipeline] cleaned_data=%s", str(cleaned_data))
        # Login, Verify: Find candidate User or Contact
        if contact:
            user = contact.user
            email = contact.email
            if user:
                email = user.email
        else:
            user, email = self.find_candidate(**cleaned_data)
        LOGGER.debug("[run_pipeline] found_candidate user=%s, email=%s",
            user, email)
        # Login, Verify: Check if auth is disabled for User, or
        # auth disabled globally if we only have a Contact
        self.auth_check_disabled(user)
        LOGGER.debug("[run_pipeline] auth_check_disabled(user=%s)", user)

        # Login, Verify: Auth rate-limiter
        self.check_user_throttles(self.request, user)
        LOGGER.debug("[run_pipeline] check_user_throttles(user=%s)", user)

        # Login, Verify, Register:
        # Redirects if email requires SSO
        self.check_sso_required(email)
        LOGGER.debug("[run_pipeline] check_sso_required(email=%s)", email)

        user = self.verify_phone(user, **cleaned_data)
        LOGGER.debug("[run_pipeline] verify_phone(user=%s,"\
            " cleaned_data=%s) returned user.backend=%s", user,
            cleaned_data, getattr(user, 'backend', None))

        user = self.verify_email(user, **cleaned_data)
        LOGGER.debug("[run_pipeline] verify_email(user=%s,"\
            " cleaned_data=%s) returned user._backend=%s", user,
            cleaned_data, getattr(user, 'backend', None))

        with transaction.atomic(using=router.db_for_write(Contact)):
            user = self.check_phone_verified(user, **cleaned_data)
            LOGGER.debug("[run_pipeline] check_phone_verified(user=%s,"\
                " cleaned_data=%s) returned user.backend=%s", user,
                cleaned_data, getattr(user, 'backend', None))

            user = self.check_email_verified(user, **cleaned_data)
            LOGGER.debug("[run_pipeline] check_email_verified(user=%s,"\
                " cleaned_data=%s) returned user._backend=%s", user,
                cleaned_data, getattr(user, 'backend', None))

            # Login: If login by verifying e-mail or phone, send code
            #        Else check password
            user = self.check_password(user, **cleaned_data)
            LOGGER.debug("[run_pipeline] check_password(user=%s,"\
                " cleaned_data=%s) returned user.backend=%s", user,
                cleaned_data, getattr(user, 'backend', None))

            # Login, Verify: If required, check 2FA
            self.check_otp(user, **cleaned_data)

            # Verify: If does not exist, create User from Contact
            # Register: Create User
            if not user and self.request.method.lower() in ['post']:
                # Some e-mail spam prevention tools like
                # 'Barracuda Sentinel (EE)'
                # will generate HEAD requests on one-time e-mail links. We don't
                # want those to fall through `check_password`, end up here
                # and render the link unusable before someone can click on it.
                #pylint:disable=assignment-from-none
                LOGGER.debug("[run_pipeline] create_user("
                    "contact=%s, cleaned_data=%s)", contact, cleaned_data)
                user = self.create_user(contact, **cleaned_data)

            if not getattr(user, 'backend', None):
                # If for any reasons we don't have a user with an auth backend
                # at this point, we can't continue.
                raise exceptions.AuthenticationFailed()

            # Login, Verify, Register: Create session
            LOGGER.debug("[run_pipeline] create session for user=%s", user)
            self.create_session(user)

        return user


class VerifyMixin(AuthMixin):
    """
    Authenticate by verifying e-mail address or phone number
    """
    pattern_name = 'registration_activate'
    default_check_email = True
    default_check_phone = True

    def get_verification_back_url(self, verification_key):
        back_url = None
        if settings.USE_VERIFICATION_LINKS:
            back_url = self.request.build_absolute_uri(reverse(
                'password_reset_confirm', args=(verification_key,)))
        return back_url

    def email_verification_required(self, user, **cleaned_data):
        email = cleaned_data.get('email')
        if not email and user:
            email = user.email
        return bool(email)

    def phone_verification_required(self, user, **cleaned_data):
        phone = cleaned_data.get('phone')
        if not phone and user:
            contact = user.contacts.exclude(phone__isnull=False).first()
            if contact:
                phone = contact.phone
        return bool(phone) if cleaned_data.get('phone') else False


class LoginMixin(AuthMixin):
    """
    Workflow for authentication (login/sign-in) either through an HTML page
    view or an API call.
    """


class RegisterMixin(AuthMixin):
    """
    workflow for registration
    """

    def email_verification_required(self, user, **cleaned_data):
        return False

    def phone_verification_required(self, user, **cleaned_data):
        return False

    def check_password(self, user, **cleaned_data):
        #pylint:disable=unused-argument
        return None


class VerifyCompleteMixin(RegisterMixin):
    """
    Overrides the `check_password` step in URL `/activate/{verification_key}/`
    and `/api/auth/activate/{verification_key}` to raise `IncorrectUser`
    if the user has no password set.
    """
    key_url_kwarg = 'verification_key'

    @property
    def contact(self):
        if not hasattr(self, '_contact'):
            #pylint:disable=attribute-defined-outside-init
            verification_key = self.kwargs.get(self.key_url_kwarg)
            self._contact = Contact.objects.get_token(verification_key)
            if not self._contact:
                raise Http404("Contact could not be found from"\
                    " verification_key '%s'" % str())
        return self._contact

    def prefetch_contact_info(self):
        return self.contact


class PasswordResetConfirmMixin(VerifyCompleteMixin):
    """
    Overrides the `check_password` step in URL `/reset/{verification_key}/`
    and `/api/auth/reset/{verification_key}/` such that it resets the password
    for the identified user.
    """


# ------------------------

class AuthenticatedUserPasswordMixin(object):

    def re_auth(self, request, validated_data):
        password = validated_data.get('password')

        if settings.DISABLED_USER_UPDATE:
            raise exceptions.AuthenticationFailed({
                'detail': _("Update of credentials (password, etc.)"\
                            " has been disabled.")})

        if not request.user.check_password(password):
            raise exceptions.AuthenticationFailed()


class ContactMixin(settings.EXTRA_MIXIN):

    lookup_field = 'slug'
    lookup_url_kwarg = 'user'
    user_queryset = get_user_model().objects.filter(is_active=True)

    @property
    def contact(self):
        if not hasattr(self, '_contact'):
            kwargs = {self.lookup_field: self.kwargs.get(self.lookup_url_kwarg)}
            self._contact = get_object_or_404(Contact.objects.all(), **kwargs)
        return self._contact

    @staticmethod
    def as_contact(user):
        return Contact(slug=user.username, email=user.email,
            full_name=user.get_full_name(), nick_name=user.first_name,
            created_at=user.date_joined, user=user)

    def get_object(self):
        try:
            obj = super(ContactMixin, self).get_object()
        except Http404:
            # We might still have a `User` model that matches.
            lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
            filter_kwargs = {'username': self.kwargs[lookup_url_kwarg]}
            user = get_object_or_404(self.user_queryset, **filter_kwargs)
            obj = self.as_contact(user)
        return obj


class UserMixin(settings.EXTRA_MIXIN):

    user_field = 'username'
    user_url_kwarg = 'user'
    user_queryset = get_user_model().objects.filter(is_active=True)
    user_model = get_user_model()

    # django-restframework
    lookup_field = 'username'
    lookup_url_kwarg = 'user'
    queryset = get_user_model().objects.filter(is_active=True)
    model = get_user_model()

    # Django
    slug_field = 'username'
    slug_url_kwarg = 'user'

    @property
    def user(self):
        if not hasattr(self, '_user'):
            slug = self.kwargs.get(self.user_url_kwarg)
            if getattr(self.request.user, self.user_field) == slug:
                # Not only do we avoid one database query, we also
                # make sure the user is the actual wrapper object.
                self._user = self.request.user
            else:
                kwargs = {self.user_field: slug}
                try:
                    self._user = get_object_or_404(self.user_queryset, **kwargs)
                except Http404:
                    # We might still have a `User` model that matches.
                    lookup_url_kwarg = (
                        self.lookup_url_kwarg or self.lookup_field)
                    filter_kwargs = {'slug': self.kwargs[lookup_url_kwarg]}
                    contact = get_object_or_404(Contact.objects.all(),
                        **filter_kwargs)
                    self._user = self.as_user(contact)
        return self._user

    def as_user(self, contact):
        #pylint:disable=unused-variable
        first_name, unused, last_name = full_name_natural_split(
            contact.full_name)
        return self.queryset.model(username=contact.slug, email=contact.email,
            first_name=first_name, last_name=last_name)

    def get_context_data(self, **kwargs):
        context = super(UserMixin, self).get_context_data(**kwargs)
        # URLs for user
        if is_authenticated(self.request):
            update_context_urls(context, {
                'profile_redirect': reverse('accounts_profile'),
                'user': {
                    'notifications': reverse(
                        'users_notifications', args=(self.user,)),
                    'profile': reverse('users_profile', args=(self.user,)),
                }
            })
        return context

    @staticmethod
    def get_notifications(user=None):#pylint:disable=unused-argument
        return {obj.slug: {
            'summary': obj.title,
            'description': obj.description}
                for obj in Notification.objects.all()}

    def get_object(self):
        return self.user
