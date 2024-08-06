from django.test import TestCase
from django.contrib.auth import get_user_model
from django.test.utils import override_settings

from otp_rest_auth.app_settings import app_settings
from otp_rest_auth.auth_backends import AuthenticationBackend


class AuthenticationBackendTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create(
            is_active=True,
            email="john@example.com",
            username="john",
            phone="+2348076048994",
        )
        user.set_password(user.username)
        user.save()
        self.user = user

    @override_settings(
        OTP_REST_AUTH={
            "AUTHENTICATION_METHODS": [app_settings.AuthenticationMethods.USERNAME]
        }
    )
    def test_auth_by_username(self):
        user = self.user
        backend = AuthenticationBackend()
        self.assertEqual(
            backend.authenticate(
                request=None, username=user.username, password=user.username
            ).pk,
            user.pk,
        )
        self.assertEqual(
            backend.authenticate(
                request=None, username=user.email, password=user.username
            ),
            None,
        )

    @override_settings(
        OTP_REST_AUTH={
            "AUTHENTICATION_METHODS": [app_settings.AuthenticationMethods.EMAIL]
        }
    )
    def test_auth_by_email(self):
        user = self.user
        backend = AuthenticationBackend()
        self.assertEqual(
            backend.authenticate(
                request=None, email=user.email, password=user.username
            ).pk,
            user.pk,
        )
        self.assertEqual(
            backend.authenticate(
                request=None, email=user.username, password=user.username
            ),
            None,
        )

    @override_settings(
        OTP_REST_AUTH={
            "AUTHENTICATION_METHODS": [app_settings.AuthenticationMethods.PHONE]
        }
    )
    def test_auth_by_phone(self):
        user = self.user
        backend = AuthenticationBackend()
        self.assertEqual(
            backend.authenticate(
                request=None, phone=user.phone, password=user.username
            ).pk,
            user.pk,
        )
        self.assertEqual(
            backend.authenticate(
                request=None, phone=user.username, password=user.username
            ),
            None,
        )

    @override_settings(
        OTP_REST_AUTH={
            "AUTHENTICATION_METHODS": [
                app_settings.AuthenticationMethods.PHONE,
                app_settings.AuthenticationMethods.EMAIL,
                app_settings.AuthenticationMethods.USERNAME,
            ]
        }
    )
    def test_auth_by_all_methods(self):
        user = self.user
        backend = AuthenticationBackend()
        self.assertEqual(
            backend.authenticate(
                request=None, username=user.username, password=user.username
            ).pk,
            user.pk,
        )
        self.assertEqual(
            backend.authenticate(
                request=None, email=user.email, password=user.username
            ).pk,
            user.pk,
        )
        self.assertEqual(
            backend.authenticate(
                request=None, phone=user.phone, password=user.username
            ).pk,
            user.pk,
        )
