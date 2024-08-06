from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from unittest.mock import patch, MagicMock
from otp_rest_auth.models import TOTP
from otp_rest_auth import app_settings
from otp_rest_auth.otp_ops import verify_otp, validate_otp

User = get_user_model()


class PasswordResetConfirmViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="old_password",
            email="testuser@example.com",
            phone="+2348145640915",
        )
        self.totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_PASSWORD_RESET
        )
        self.url = reverse("otp_rest_password_reset_confirm")

    @patch("otp_rest_auth.serializers.verify_otp")
    @patch("otp_rest_auth.serializers.validate_otp")
    @patch("django.contrib.auth.forms.SetPasswordForm.is_valid", return_value=True)
    @patch("django.contrib.auth.forms.SetPasswordForm.save")
    def test_password_reset_confirm_success(
        self, mock_save, mock_is_valid, mock_validate_otp, mock_verify_otp
    ):
        mock_validate_otp.return_value = (True, self.totp)
        data = {
            "otp": self.totp.otp,
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["detail"], "Password has been reset with the new password."
        )
        mock_validate_otp.assert_called_once_with(
            data["otp"], TOTP.PURPOSE_PASSWORD_RESET
        )
        mock_verify_otp.assert_called_once_with(
            self.totp.otp, TOTP.PURPOSE_PASSWORD_RESET
        )
        mock_save.assert_called_once()

    @patch("otp_rest_auth.serializers.validate_otp")
    def test_password_reset_confirm_invalid_otp(self, mock_validate_otp):
        mock_validate_otp.side_effect = TOTP.DoesNotExist
        data = {
            "otp": "000000",
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("otp", response.data)

    def test_password_reset_confirm_invalid_passwords(self):
        data = {
            "otp": self.totp.otp,
            "new_password1": "short",
            "new_password2": "short",
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("new_password2", response.data)
