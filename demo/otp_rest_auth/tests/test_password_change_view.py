from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.test.utils import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch, MagicMock
from otp_rest_auth.app_settings import app_settings

User = get_user_model()


class PasswordChangeViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="old_password",
            email="testuser@example.com",
            phone="+2348145640915",
        )

        self.client.force_authenticate(user=self.user)
        self.url = reverse("otp_rest_password_change")

    @override_settings(OTP_REST_AUTH={"OLD_PASSWORD_FIELD_ENABLED": False})
    @patch("django.contrib.auth.forms.SetPasswordForm.is_valid", return_value=True)
    @patch("django.contrib.auth.forms.SetPasswordForm.save")
    def test_password_change_no_old_password_success(self, mock_save, mock_is_valid):
        data = {
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "New password has been saved.")
        mock_is_valid.assert_called_once()
        mock_save.assert_called_once()

    @override_settings(OTP_REST_AUTH={"OLD_PASSWORD_FIELD_ENABLED": True})
    @patch("django.contrib.auth.forms.SetPasswordForm.is_valid", return_value=True)
    @patch("django.contrib.auth.forms.SetPasswordForm.save")
    def test_password_change_with_old_password_success(self, mock_save, mock_is_valid):
        data = {
            "old_password": "old_password",
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "New password has been saved.")
        mock_is_valid.assert_called_once()
        mock_save.assert_called_once()

    @patch("django.contrib.auth.forms.SetPasswordForm.is_valid", return_value=False)
    def test_password_change_invalid_passwords(self, mock_is_valid):
        data = {
            "old_password": "old_password",
            "new_password1": "short",
            "new_password2": "short",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("new_password2", response.data)

    @override_settings(OTP_REST_AUTH={"OLD_PASSWORD_FIELD_ENABLED": True})
    def test_password_change_invalid_old_password(self):
        data = {
            "old_password": "wrong_old_password",
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("old_password", response.data)

    @override_settings(OTP_REST_AUTH={"LOGOUT_ON_PASSWORD_CHANGE": True})
    def test_logout_on_password_change(self):
        refresh = RefreshToken.for_user(self.user)

        data = {
            "refresh": str(refresh),
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "New password has been saved.")
        self.assertIn("logout_detail", response.data)

    @override_settings(OTP_REST_AUTH={"LOGOUT_ON_PASSWORD_CHANGE": True})
    def test_logout_on_password_change_no_refresh(self):
        data = {
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(OTP_REST_AUTH={"LOGOUT_ON_PASSWORD_CHANGE": True})
    def test_logout_on_password_change_invalid_refresh(self):
        data = {
            "refresh": "not_refresh",
            "new_password1": "new_secure_password",
            "new_password2": "new_secure_password",
        }
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "New password has been saved.")
        self.assertIn("logout_detail", response.data)
