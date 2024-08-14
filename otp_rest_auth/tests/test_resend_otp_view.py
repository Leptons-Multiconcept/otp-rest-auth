from django.test import TestCase, RequestFactory
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from rest_framework.exceptions import MethodNotAllowed
from unittest.mock import patch, MagicMock
from otp_rest_auth.views import ResendOTPView
from otp_rest_auth.models import Account, TOTP
from otp_rest_auth.serializers import ResendOTPSerializer
from otp_rest_auth import app_settings

User = get_user_model()


class ResendOTPViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = RequestFactory()
        self.view = ResendOTPView.as_view()
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            phone="+2348145640915",
            password="testPassword123!",
        )
        self.account = Account.objects.get(user=self.user)
        self.totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )

    def test_get_not_allowed(self):
        request = self.factory.get("/resend-otp/")
        response = self.view(request)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_post_valid_data(self, mock_send_verification_otp):
        data = {
            "purpose": TOTP.PURPOSE_ACCOUNT_VERIFICATION,
            "email": self.user.email,
            "phone": "+2348145640915",
        }
        request = self.factory.post("/resend-otp/", data, format="json")

        serializer = ResendOTPSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        with patch.object(ResendOTPView, "get_serializer", return_value=serializer):
            response = self.view(request)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mock_send_verification_otp.assert_called_once()

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_post_invalid_data(self, mock_send_verification_otp):
        data = {
            "purpose": TOTP.PURPOSE_ACCOUNT_VERIFICATION,
            "email": "wrong@example.com",
            "phone": "+2348145640915",
        }
        request = self.factory.post("/resend-otp/", data, format="json")

        serializer = ResendOTPSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        with patch.object(ResendOTPView, "get_serializer", return_value=serializer):
            response = self.view(request)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data, {"detail": "Incorrect email or phone."})
            mock_send_verification_otp.assert_not_called()

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_post_resend_otp_with_verified_account(self, mock_send_verification_otp):
        self.account.is_verified = True
        self.account.save()

        data = {
            "purpose": TOTP.PURPOSE_ACCOUNT_VERIFICATION,
            "email": self.user.email,
            "phone": "+2348145640915",
        }
        request = self.factory.post("/resend-otp/", data, format="json")

        serializer = ResendOTPSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        with patch.object(ResendOTPView, "get_serializer", return_value=serializer):
            response = self.view(request)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            mock_send_verification_otp.assert_not_called()

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_post_resend_otp_with_unverified_account(self, mock_send_verification_otp):
        data = {
            "purpose": TOTP.PURPOSE_ACCOUNT_VERIFICATION,
            "email": self.user.email,
            "phone": "+2348145640915",
        }
        request = self.factory.post("/resend-otp/", data, format="json")

        serializer = ResendOTPSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        with patch.object(ResendOTPView, "get_serializer", return_value=serializer):
            response = self.view(request)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mock_send_verification_otp.assert_called_once()

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_post_resend_otp_with_invalid_otp(self, mock_send_verification_otp):
        self.totp.is_valid = False
        self.totp.save()

        data = {
            "purpose": TOTP.PURPOSE_ACCOUNT_VERIFICATION,
            "email": self.user.email,
            "phone": "+2348145640915",
        }
        request = self.factory.post("/resend-otp/", data, format="json")

        serializer = ResendOTPSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        with patch.object(ResendOTPView, "get_serializer", return_value=serializer):
            response = self.view(request)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mock_send_verification_otp.assert_called_once()

    @patch("otp_rest_auth.views.send_verification_otp")
    def test_post_resend_otp_invalidates_existing_otp(self, mock_send_verification_otp):
        self.totp.is_valid = True
        self.totp.save()

        data = {
            "purpose": TOTP.PURPOSE_ACCOUNT_VERIFICATION,
            "email": self.user.email,
            "phone": "+2348145640915",
        }
        request = self.factory.post("/resend-otp/", data, format="json")

        serializer = ResendOTPSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        with patch.object(ResendOTPView, "get_serializer", return_value=serializer):
            response = self.view(request)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.totp.refresh_from_db()

        self.assertFalse(self.totp.is_valid)

        mock_send_verification_otp.assert_called_once()
        new_totp = TOTP.objects.filter(
            user=self.user, purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION
        ).latest("created_at")
        self.assertNotEqual(self.totp, new_totp)
        self.assertTrue(new_totp.is_valid)
