from django.test import TestCase, RequestFactory
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch
from unittest import skip
from django.test.utils import override_settings

from otp_rest_auth.models import Account
from otp_rest_auth.views import LoginView
from otp_rest_auth.app_settings import app_settings


User = get_user_model()


class LoginViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.view = LoginView.as_view()
        self.url = reverse("otp_rest_login")
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            phone="+2348145640915",
            password="password",
        )

        self.account = Account.objects.get(user=self.user)
        self.account.is_verified = True
        self.account.save()

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.ACCOUNT,
        }
    )
    def test_post_valid_credentials(self):
        data = {"username": "testuser", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_post_invalid_credentials(self):
        data = {"username": "testuser", "password": "wrongpassword"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("non_field_errors", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.ACCOUNT,
        }
    )
    @patch("otp_rest_auth.views.get_login_response_data")
    @patch("otp_rest_auth.views.set_jwt_cookies")
    def test_jwt_cookies_set(self, mock_set_jwt_cookies, mock_get_login_response_data):
        mock_get_login_response_data.return_value = {
            "user": {"username": "testuser"},
            "access": "access_token",
            "refresh": "refresh_token",
        }

        data = {"username": "testuser", "password": "password"}
        request = self.factory.post(self.url, data, format="json")
        response = self.view(request)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_set_jwt_cookies.assert_called_once_with(
            response, "access_token", "refresh_token"
        )

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.ACCOUNT,
        }
    )
    def test_phone_login_with_account_verification_type(self):
        data = {"phone": "+2348145640915", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.ACCOUNT,
        }
    )
    def test_email_login_with_account_verification_type(self):
        data = {"email": self.user.email, "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.PHONE,
        }
    )
    def test_phone_login_with_phone_verification_type_verified(self):
        self.account.phone_verified = True
        self.account.save()

        data = {"phone": "+2348145640915", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.PHONE,
        }
    )
    def test_phone_login_with_phone_verification_type_unverified(self):
        data = {"phone": "+2348145640915", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.EMAIL,
        }
    )
    def test_email_login_with_account_verification_type_verified(self):
        self.account.email_verified = True
        self.account.save()

        data = {"email": self.user.email, "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.EMAIL,
        }
    )
    def test_email_login_with_account_verification_type_unverified(self):
        data = {"email": self.user.email, "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.PHONE,
        }
    )
    @skip("resolve later")
    def test_phone_login_without_phone_field(self):
        self.account.phone_verified = True
        self.account.save()

        data = {"email": self.user.email, "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.EMAIL,
        }
    )
    @skip("resolve later")
    def test_email_login_without_email_field(self):
        self.account.email_verified = True
        self.account.save()

        data = {"phone": "+2348145640915", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    def test_post_inactive_user(self):
        self.user.is_active = False
        self.user.save()

        data = {"username": "testuser", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("non_field_errors", response.data)
        self.assertEqual(
            response.data["non_field_errors"][0], "User account is disabled."
        )

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": True,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.ACCOUNT,
        }
    )
    def test_post_unverified_account(self):
        self.account.is_verified = False
        self.account.save()

        data = {"username": "testuser", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("non_field_errors", response.data)
        self.assertEqual(
            response.data["non_field_errors"][0], "Account is not verified."
        )

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": False,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.ACCOUNT,
        }
    )
    def test_post_unverified_account_with_verification_not_required(self):
        self.account.is_verified = False
        self.account.save()

        data = {"username": "testuser", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "VERIFICATION_REQUIRED": False,
            "VERIFICATION_METHOD": app_settings.AccountVerificationMethod.ACCOUNT,
            "AUTHENTICATION_METHODS": (
                app_settings.AuthenticationMethods.EMAIL,
                app_settings.AuthenticationMethods.USERNAME,
            ),
        }
    )
    def test_login_with_unavailable_authentication_type(self):
        data = {"phone": "+2348145640915", "password": "password"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)
