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

import logging

from django.http import Http404
from django.contrib.auth import (REDIRECT_FIELD_NAME, authenticate,
    get_user_model, login as auth_login)
from django.db import IntegrityError
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
from .utils import (get_disabled_authentication, get_disabled_registration,
    get_email_dynamic_validator, get_login_throttle, handle_uniq_error)
from .validators import as_email_or_phone

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


class VerifyRequired(exceptions.AuthenticationFailed):
    """
    break workflow because we are waiting for a link/code to continue.
    """

class OTPRequired(exceptions.AuthenticationFailed):
    """
    break workflow because we require the user to enter an OTP
    """

class PasswordRequired(exceptions.AuthenticationFailed):
    """
    break workflow because we require the user to enter a password
    """

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
    Steps used in authentiction workflows, either login through a password
    or through an e-mail link.
    """
    backend_path = 'signup.backends.auth.UsernameOrEmailPhoneModelBackend'
    model = get_user_model()
    form_class = None
    serializer_class = None

    def prefetch_contact_info(self):
        return {}

    def validate_inputs(self, initial_data=None):
        # The authentication URLs are anonymously accessible, hence
        # prime candidates for bots. These will POST to '/login/.' for
        # example because there is a `action="."` in the <form> tag
        # in login.html.
        validate_path_pattern(self.request)

        cleaned_data = {}
        if initial_data:
            cleaned_data = initial_data.copy()
        if self.form_class is not None:
            form = self.get_form()
            if self.request.method.lower() in ('post',):
                if not form.is_valid():
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
            serializer.is_valid(raise_exception=True)
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

    def register_check_disabled(self):
        pass

    def register_check_data(self, **cleaned_data):
        pass

    def find_candidate(self, **cleaned_data):
        username = cleaned_data.get('username')
        email = cleaned_data.get('email')
        phone = cleaned_data.get('phone')
        if not username:
            username = email
        if not username:
            username = phone
        try:
            user = self.model.objects.find_user(username)

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

    def auth_check_mfa(self, user, **cleaned_data):
        code = cleaned_data.get('code')
        if OTPGenerator.objects.filter(user=user).exists():
            if not code:
                raise OTPRequired({
                    'code': _("OTP code is required.")})
            if not user.otp.verify(code):
                if user.otp.nb_attempts >= settings.MFA_MAX_ATTEMPTS:
                    user.otp.clear_attempts()
                    raise exceptions.PermissionDenied({'detail': _(
            "You have exceeded the number of attempts to enter the OTP code."\
                        " Please start again.")})
                user.otp.nb_attempts += 1
                user.otp.save()
                raise serializers.ValidationError({
                    'code': _("OTP code does not match.")})
            user.otp.clear_attempts()

    def create_user(self, **cleaned_data):
        #pylint:disable=unused-argument
        return None

    def check_password(self, user, **cleaned_data):
        #pylint:disable=unused-argument
        return None

    def create_session(self, user_with_backend):
        """
        Attaches a session cookie to the request and
        generates an login event in the audit logs.
        """
        if self.form_class or self.request.query_params.get('cookie', False):
            auth_login(self.request, user_with_backend)
        LOGGER.info("%s signed in.", user_with_backend,
            extra={'event': 'login', 'request': self.request})

    def run_pipeline(self):
        # Register: Check if registration or auth is disabled
        self.register_check_disabled()
        # Login, Verify, Register:
        # Bot prevention
        # - no extra characters on URL path
        # - validate fields through regex
        # - optional Captcha

        # `ActivationView` will run the pipeline in GET HTTP requests
        # (uses `verification_key` in URL path), while other views will
        # solely do so in POST HTTP requests.
        initial_data = self.prefetch_contact_info()
        LOGGER.debug("[run_pipeline] initial_data=%s", str(initial_data))
        cleaned_data = self.validate_inputs(initial_data)
        LOGGER.debug("[run_pipeline] cleaned_data=%s", str(cleaned_data))
        # Login, Verify: Find candidate User or Contact
        user, email = self.find_candidate(**cleaned_data)
        LOGGER.debug("[run_pipeline] found_candidate user=%s, email=%s",
            user, email)
        # Login, Verify: Check if auth is disabled for User, or
        # auth disabled globally if we only have a Contact
        self.auth_check_disabled(user)
        # Login, Verify: Auth rate-limiter
        self.check_user_throttles(self.request, user)
        # Login, Verify, Register:
        # Redirects if email requires SSO
        self.check_sso_required(email)
        # Login: If login by verifying e-mail or phone, send code
        #        Else check password
        #pylint:disable=assignment-from-none
        user_with_backend = self.check_password(user, **cleaned_data)

        # Login, Verify: If required, check 2FA
        self.auth_check_mfa(user, **cleaned_data)

        # Register: Bot prevention verify e-mail if it looks suspicious.
        self.register_check_data(**cleaned_data)
        # Verify: If does not exist, create User from Contact
        # Register: Create User
        if not user_with_backend:
            #pylint:disable=assignment-from-none
            user_with_backend = self.create_user(**cleaned_data)
        # Login, Verify, Register: Create session
        LOGGER.debug("[run_pipeline] create session for user_with_backend=%s",
            user_with_backend)

        self.create_session(user_with_backend)
        return user_with_backend


class LoginMixin(AuthMixin):
    """
    Workflow for authentication (login/sign-in) either through an HTML page
    view or an API call.
    """
    def check_password(self, user, **cleaned_data):
        user_with_backend = None
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')
        user_with_backend = authenticate(self.request,
            username=username, password=password)
        if user_with_backend:
            return user_with_backend

        disabled_registration = get_disabled_registration(self.request)
        if not disabled_registration:
            if not user:
                phone = email = None # XXX call find_candidate again?
                if phone:
                    raise IncorrectUser({'phone': _("Not found.")})
                if email:
                    raise IncorrectUser({'email': _("Not found.")})
                raise IncorrectUser({'username': _("Not found.")})
        if not password:
            raise PasswordRequired({
                'password': _("Password is required.")})

        raise serializers.ValidationError({
            'detail': _("Credentials do not match.")})


class VerifyMixin(AuthMixin):
    """
    Authenticate by verifying e-mail address
    """
    pattern_name = 'registration_activate'

    def get_query_param(self, request, key, default_value=None):
        try:
            return request.query_params.get(key, default_value)
        except AttributeError:
            pass
        return request.GET.get(key, default_value)

    def send_notification_email(self, contact, next_url=None):
        request = self.request
        if self.get_query_param(request, 'noreset'):
            send_verification_email(contact, request, next_url=next_url)
        else:
            back_url = request.build_absolute_uri(
                reverse('password_reset_confirm', args=(
                    contact.email_verification_key,)))
            if next_url:
                back_url += '?%s=%s' % (REDIRECT_FIELD_NAME, next_url)
            signals.user_reset_password.send(
                sender=__name__, user=contact, request=request,
                back_url=back_url, expiration_days=settings.KEY_EXPIRATION)


    def check_password(self, user, **cleaned_data):
        next_url = cleaned_data.get('next_url')
        email = cleaned_data.get('email')
        if not email and user:
            email = user.email
        # send link through e-mail
        if email:
            #pylint:disable=unused-variable
            contact, unused = Contact.objects.prepare_email_verification(
                email, user=user)
            self.send_notification_email(contact, next_url=next_url)
            raise VerifyRequired({'detail': _(
                    "We sent a one-time link to your e-mail address.")})

        raise serializers.ValidationError({
            'detail': _("Credentials do not match.")})


class VerifyPhoneMixin(AuthMixin):
    """
    Authenticate by verifying phone
    """
    def check_password(self, user, **cleaned_data):
        next_url = cleaned_data.get('next_url')

        phone = cleaned_data.get('phone')
        # send link through phone
        if phone:
            #pylint:disable=unused-variable
            contact, unused = Contact.objects.prepare_phone_verification(
                phone, user=user)
            send_verification_phone(contact, self.request, next_url=next_url)
            raise VerifyRequired({'detail': _(
                    "We sent a one-time code to your phone.")})

        raise serializers.ValidationError({
            'detail': _("Credentials do not match.")})


class RegisterMixin(AuthMixin):

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

    def register_check_disabled(self):
        disabled_registration = get_disabled_registration(self.request)
        if disabled_registration:
            raise RegistrationDisabled(
                {'detail': _("Registration is disabled")})

    def register_check_data(self, **cleaned_data):
        email = cleaned_data.get('email')
        if email:
            dynamic_validator = get_email_dynamic_validator()
            if dynamic_validator:
                dynamic_validator(email)

    @staticmethod
    def first_and_last_names(**cleaned_data):
        first_name = cleaned_data.get('first_name', None)
        last_name = cleaned_data.get('last_name', None)
        if not first_name:
            # If the form does not contain a first_name/last_name pair,
            # we assume a full_name was passed instead.
            full_name = cleaned_data.get(
                'user_full_name', cleaned_data.get('full_name', None))
            first_name, _, last_name = full_name_natural_split(full_name)
        return first_name, last_name

    def create_user(self, **cleaned_data):
        first_name, last_name = self.first_and_last_names(**cleaned_data)
        email = cleaned_data.get('email')
        phone = cleaned_data.get('phone')
        username = cleaned_data.get('username')
        password = cleaned_data.get('new_password',
            cleaned_data.get('password'))
        lang = cleaned_data.get('lang', cleaned_data.get('get_lang',
            translation.get_language_from_request(self.request)))
        user_extra = {}
        for field_name, field_value in six.iteritems(cleaned_data):
            if field_name not in self.registration_fields:
                if field_name.startswith('user_'):
                    user_extra.update({field_name[5:]: field_value})
        if not user_extra:
            user_extra = None
        try:
            user = self.model.objects.create_user(username,
                email=email, password=password, phone=phone,
                first_name=first_name, last_name=last_name,
                lang=lang, extra=user_extra)
        except IntegrityError as err:
            handle_uniq_error(err)

        LOGGER.info("'%s <%s>' registered with username '%s'%s%s",
            user.get_full_name(), user.email, user,
            (" and phone %s" % str(phone)) if phone else "",
            (" and preferred language %s" % str(lang)) if lang else "",
            extra={'event': 'register', 'user': user})
        signals.user_registered.send(sender=__name__, user=user)

        # Bypassing authentication here, we are doing frictionless registration
        # the first time around.
        user.backend = self.backend_path
        return user


class VerifyCompleteMixin(AuthMixin):

    key_url_kwarg = 'verification_key'

    def prefetch_contact_info(self):
        data = {}
        verification_key = self.kwargs.get(self.key_url_kwarg)
        contact = Contact.objects.get_token(verification_key)
        if contact:
            fields = []
            if self.form_class is not None:
                fields = six.iterkeys(self.get_initial())
            elif self.serializer_class is not None:
                fields = self.serializer_class.Meta.fields
            for field_name in fields:
                field_value = None
                if contact.user:
                    field_value = getattr(contact.user, field_name, None)
                if not field_value:
                    field_value = getattr(contact, field_name, None)
                if field_value:
                    data.update({field_name: field_value})
        return data

    def find_candidate(self, **cleaned_data):
        verification_key = self.kwargs.get(self.key_url_kwarg)
        contact = Contact.objects.get_token(verification_key)
        if not contact:
            raise serializers.ValidationError({
                'detail': _("verification key not found")})

        if contact.user:
            email = contact.user.email
        else:
            email = contact.email

        return contact.user, email


    def check_password(self, user, **cleaned_data):
        #pylint:disable=unused-argument
        if (self.request.method.lower() == 'get' and
            (not user or has_invalid_password(user))):
            raise IncorrectUser({'email': _("Not found.")})
        return super(VerifyCompleteMixin, self).check_password(
            user, **cleaned_data)

    def create_user(self, **cleaned_data):
        verification_key = self.kwargs.get(self.key_url_kwarg)
        full_name = cleaned_data.get('full_name', None)
        if not full_name:
            first_name = cleaned_data.get('first_name', "")
            last_name = cleaned_data.get('last_name', "")
            full_name = (first_name + ' ' + last_name).strip()
        # If we don't save the ``User`` model here,
        # we won't be able to authenticate later.
        try:
            user, previously_inactive = Contact.objects.activate_user(
                verification_key,
                username=cleaned_data.get('username'),
                password=cleaned_data.get('new_password'),
                full_name=full_name)
        except IntegrityError as err:
            handle_uniq_error(err)

        if user:
            if not user.last_login:
                phone = user.get_phone()
                lang = user.get_lang()
                LOGGER.info("'%s <%s>' registered with username '%s'%s%s",
                    user.get_full_name(), user.email, user,
                    (" and phone %s" % str(phone)) if phone else "",
                    (" and preferred language %s" % str(lang)) if lang else "",
                    extra={'event': 'register', 'user': user})
                signals.user_registered.send(sender=__name__, user=user)
            elif previously_inactive:
                LOGGER.info("'%s <%s>' activated with username '%s'",
                    user.get_full_name(), user.email, user,
                    extra={'event': 'activate', 'user': user})
                signals.user_activated.send(sender=__name__, user=user,
                    verification_key=self.kwargs.get(self.key_url_kwarg),
                    request=self.request)

        # Bypassing authentication here, we are doing frictionless registration
        # the first time around.
        user.backend = self.backend_path
        return user


class PasswordResetConfirmMixin(VerifyCompleteMixin):

    def check_password(self, user, **cleaned_data):
        #pylint:disable=unused-argument
        if self.request.method.lower() == 'get':
            if user:
                user.password = '!'
                user.save()
            if not user or has_invalid_password(user):
                raise IncorrectUser({'email': _("Not found.")})
        return super(PasswordResetConfirmMixin, self).check_password(
            user, **cleaned_data)


class AuthenticatedUserPasswordMixin(object):

    def re_auth(self, request, validated_data):
        password = validated_data.get('password')
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
