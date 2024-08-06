from django.test import TestCase, RequestFactory
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.utils.translation import gettext_lazy as _

from otp_rest_auth.views import RegisterView
from otp_rest_auth.app_settings import app_settings

User = get_user_model()


class RegisterViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = RequestFactory()

    @patch("otp_rest_auth.otp_ops.send_verification_otp")
    @override_settings(
        OTP_REST_AUTH={"VERIFICATION_METHOD": app_settings.AccountVerificationMethod.NONE}
    )
    def test_create_user_without_verification(self, mock_send_verification_otp):
        """
        Test creating a user without verification disabled.
        """
        request_data = {
            "username": "testuser",
            "email": "test@example.com",
            "phone": "+2348145640915",
            "password1": "testPassword123!",
            "password2": "testPassword123!",
        }
        request = self.factory.post("/api/register/", request_data)

        view = RegisterView.as_view()
        response = view(request)

        self.assertFalse(mock_send_verification_otp.called)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("user", response.data)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    @patch("otp_rest_auth.otp_ops.send_verification_otp")
    @patch("otp_rest_auth.models.TOTP.objects.create")
    @override_settings(
        OTP_REST_AUTH={"VERIFICATION_METHOD": app_settings.AccountVerificationMethod.EMAIL}
    )
    def test_create_user_with_verification(
        self, mock_create_totp, mock_send_verification_otp
    ):
        """
        Test creating a user with verification enabled.
        """
        request_data = {
            "username": "testuser",
            "email": "test@example.com",
            "phone": "+2348145640915",
            "password1": "testPassword123!",
            "password2": "testPassword123!",
        }
        request = self.factory.post("/api/register/", request_data)

        view = RegisterView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("detail", response.data)
        self.assertEqual(response.data["detail"], _("Verification OTP sent."))

        # self.assertTrue(mock_create_totp.called)
        # self.assertTrue(mock_send_verification_otp.called)

    def test_invalid_data(self):
        """
        Test creating a user with invalid data.
        """
        request_data = {
            "username": "testuser",
            "email": "test@example.com",
            # Missing password fields
        }
        request = self.factory.post("/api/register/", request_data)

        view = RegisterView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password1", response.data)
        self.assertIn("password2", response.data)
