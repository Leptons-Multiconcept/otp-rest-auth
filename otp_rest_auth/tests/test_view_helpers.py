from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.test import TestCase, RequestFactory
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from otp_rest_auth.models import Account, TOTP
from otp_rest_auth.serializers import JWTSerializer
from otp_rest_auth.app_settings import app_settings
from otp_rest_auth.views import get_login_response_data, verify

User = get_user_model()


class GetLoginResponseDataTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser", password="12345")
        self.context = {"request": self.factory.get("/")}

    @patch("otp_rest_auth.jwt_auth.get_tokens_for_user")
    @override_settings(OTP_REST_AUTH={"JWT_AUTH_RETURN_EXPIRATION": True})
    def test_get_login_response_data_with_expiration(self, mock_get_tokens):
        mock_get_tokens.return_value = ("access_token", "refresh_token")

        # with patch.object(app_settings, "JWT_AUTH_RETURN_EXPIRATION", True):
        data = get_login_response_data(self.user, self.context)

        self.assertIn("access", data)
        self.assertIn("refresh", data)
        self.assertIn("access_expiration", data)
        self.assertIn("refresh_expiration", data)

    @patch("otp_rest_auth.jwt_auth.get_tokens_for_user")
    @override_settings(OTP_REST_AUTH={"JWT_AUTH_RETURN_EXPIRATION": False})
    def test_get_login_response_data_without_expiration(self, mock_get_tokens):
        mock_get_tokens.return_value = ("access_token", "refresh_token")

        data = get_login_response_data(self.user, self.context)

        self.assertIn("access", data)
        self.assertIn("refresh", data)
        self.assertNotIn("access_expiration", data)
        self.assertNotIn("refresh_expiration", data)

    @patch("otp_rest_auth.jwt_auth.get_tokens_for_user")
    @override_settings(OTP_REST_AUTH={"JWT_AUTH_HTTPONLY": True})
    def test_get_login_response_data_with_httponly(self, mock_get_tokens):
        mock_get_tokens.return_value = ("access_token", "refresh_token")

        data = get_login_response_data(self.user, self.context)

        self.assertIn("access", data)
        self.assertIn("refresh", data)
        self.assertEqual(data["refresh"], "")

    @patch("otp_rest_auth.jwt_auth.get_tokens_for_user")
    @override_settings(OTP_REST_AUTH={"JWT_AUTH_HTTPONLY": False})
    def test_get_login_response_data_without_httponly(self, mock_get_tokens):
        mock_get_tokens.return_value = ("access_token", "refresh_token")

        data = get_login_response_data(self.user, self.context)

        self.assertIn("access", data)
        self.assertIn("refresh", data)
        self.assertNotEqual(data["refresh"], "")

    @patch("otp_rest_auth.jwt_auth.get_tokens_for_user")
    @override_settings(
        OTP_REST_AUTH={
            "JWT_AUTH_HTTPONLY": False,
            "JWT_AUTH_RETURN_EXPIRATION": True,
            "JWT_SERIALIZER": JWTSerializer,
        }
    )
    def test_get_login_response_data_serializer(self, mock_get_tokens):
        mock_get_tokens.return_value = ("access_token", "refresh_token")

        data = get_login_response_data(self.user, self.context)

        self.assertIsInstance(data, dict)
        self.assertIn("user", data)
        self.assertIn("access", data)
        self.assertIn("refresh", data)


class VerifyTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser", password="12345")
        self.account = Account.objects.get(user=self.user)

    def test_verify_success(self):
        totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )
        serializer = MagicMock()
        serializer.validated_data = {"otp": totp.otp}

        response = verify(
            serializer, self.factory.get("/"), TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.account.refresh_from_db()
        self.assertTrue(self.account.is_verified)
        self.assertTrue(self.user.is_active)

    def test_verify_invalid_otp(self):
        serializer = MagicMock()
        serializer.validated_data = {"otp": None}

        response = verify(
            serializer, self.factory.get("/"), TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Invalid OTP.")

    @override_settings(OTP_REST_AUTH={"LOGIN_UPON_VERIFICATION": True})
    def test_verify_login_upon_verification(self):
        totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )
        serializer = MagicMock()
        serializer.validated_data = {"otp": totp.otp}

        response = verify(
            serializer,
            self.factory.get("/"),
            TOTP.PURPOSE_ACCOUNT_VERIFICATION,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @override_settings(OTP_REST_AUTH={"LOGIN_UPON_VERIFICATION": False})
    def test_verify_no_login_upon_verification(self):
        totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )
        serializer = MagicMock()
        serializer.validated_data = {"otp": totp.otp}

        response = verify(
            serializer,
            self.factory.get("/"),
            TOTP.PURPOSE_ACCOUNT_VERIFICATION,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data)
