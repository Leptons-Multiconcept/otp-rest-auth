from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from unittest.mock import patch, ANY

from otp_rest_auth.models import TOTP
from otp_rest_auth.app_settings import app_settings

User = get_user_model()


class ResetPasswordViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="testPassword123!",
            email="testuser@example.com",
            phone="+2348145640915",
        )
        self.url = reverse("otp_rest_password_reset")

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_reset_password_success(self, mock_send_verification_otp):
        data = {"email": self.user.email}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Verification OTP sent.")
        totp = TOTP.objects.filter(
            user=self.user, purpose=TOTP.PURPOSE_PASSWORD_RESET
        ).first()
        self.assertIsNotNone(totp)
        mock_send_verification_otp.assert_called_once_with(totp, ANY)

    def test_reset_password_no_user(self):
        data = {"email": "nonexistent@example.com"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Verification OTP sent.")

    def test_reset_password_phone_no_user(self):
        data = {"phone": "+2348145640000"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("detail", response.data)

    def test_reset_password_invalid_data(self):
        data = {"email": "invalid_email"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_reset_password_phone_success(self, mock_send_verification_otp):
        data = {"phone": "+2348145640915"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Verification OTP sent.")
        totp = TOTP.objects.filter(
            user=self.user, purpose=TOTP.PURPOSE_PASSWORD_RESET
        ).first()
        self.assertIsNotNone(totp)
        mock_send_verification_otp.assert_called_once_with(totp, ANY)

    def test_reset_password_phone_invalid_data(self):
        data = {"phone": "invalid_phone"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("phone", response.data)

    @override_settings(
        OTP_REST_AUTH={
            "AUTHENTICATION_METHODS": (
                app_settings.AuthenticationMethods.PHONE,
                app_settings.AuthenticationMethods.USERNAME,
            ),
        }
    )
    def test_reset_password_unavailable_authentication_type(self):
        data = {"email": "nonexistent@example.com"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
