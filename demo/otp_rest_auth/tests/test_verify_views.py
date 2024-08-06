from django.test import TestCase, RequestFactory
from rest_framework.test import APIClient
from unittest.mock import patch
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.test.utils import override_settings

from otp_rest_auth.app_settings import app_settings
from otp_rest_auth.models import TOTP
from otp_rest_auth.serializers import OTPSerializer
from otp_rest_auth.views import VerifyAccountView, VerifyEmailView, VerifyPhoneView

User = get_user_model()


class VerifyAccountViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = RequestFactory()
        self.view = VerifyAccountView.as_view()
        self.user = User.objects.create_user(username="testuser", password="12345")
        self.totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )

    def test_get_not_allowed(self):
        request = self.factory.get("/verify-account/")
        response = self.view(request)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch("otp_rest_auth.views.verify")
    @override_settings(OTP_REST_AUTH={"OTP_SERIALIZER": OTPSerializer})
    def test_post_valid_data(self, mock_verify):
        data = {"otp": self.totp.otp}
        request = self.factory.post("/verify-account/", data, format="json")

        mock_response = Response(
            {"detail": "Verification successful."}, status=status.HTTP_200_OK
        )
        mock_verify.return_value = mock_response

        response = self.view(request)
        mock_verify.assert_called_once
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"detail": "Verification successful."})

    @patch("otp_rest_auth.views.verify")
    @override_settings(OTP_REST_AUTH={"OTP_SERIALIZER": OTPSerializer})
    def test_post_invalid_data(self, mock_verify):
        data = {"otp": "wrong_otp"}
        request = self.factory.post("/verify-account/", data, format="json")

        serializer = app_settings.OTP_SERIALIZER(data=data)
        self.assertFalse(serializer.is_valid())

        response = self.view(request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_verify.assert_not_called()


class VerifyEmailViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = RequestFactory()
        self.view = VerifyAccountView.as_view()
        self.user = User.objects.create_user(username="testuser", password="12345")
        self.totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_PHONE_VERIFICATION
        )

    def test_get_not_allowed(self):
        request = self.factory.get("/verify-account/")
        response = self.view(request)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch("otp_rest_auth.views.verify")
    @override_settings(OTP_REST_AUTH={"OTP_SERIALIZER": OTPSerializer})
    def test_post_valid_data(self, mock_verify):
        data = {"otp": self.totp.otp}
        request = self.factory.post("/verify-account/", data, format="json")

        mock_response = Response(
            {"detail": "Verification successful."}, status=status.HTTP_200_OK
        )
        mock_verify.return_value = mock_response

        response = self.view(request)
        mock_verify.assert_called_once
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"detail": "Verification successful."})

    @patch("otp_rest_auth.views.verify")
    @override_settings(OTP_REST_AUTH={"OTP_SERIALIZER": OTPSerializer})
    def test_post_invalid_data(self, mock_verify):
        data = {"otp": "wrong_otp"}
        request = self.factory.post("/verify-account/", data, format="json")

        serializer = app_settings.OTP_SERIALIZER(data=data)
        self.assertFalse(serializer.is_valid())

        response = self.view(request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_verify.assert_not_called()


class VerifyPhoneViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = RequestFactory()
        self.view = VerifyAccountView.as_view()
        self.user = User.objects.create_user(username="testuser", password="12345")
        self.totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_PHONE_VERIFICATION
        )

    def test_get_not_allowed(self):
        request = self.factory.get("/verify-account/")
        response = self.view(request)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch("otp_rest_auth.views.verify")
    @override_settings(OTP_REST_AUTH={"OTP_SERIALIZER": OTPSerializer})
    def test_post_valid_data(self, mock_verify):
        data = {"otp": self.totp.otp}
        request = self.factory.post("/verify-account/", data, format="json")

        mock_response = Response(
            {"detail": "Verification successful."}, status=status.HTTP_200_OK
        )
        mock_verify.return_value = mock_response

        response = self.view(request)
        mock_verify.assert_called_once
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"detail": "Verification successful."})

    @patch("otp_rest_auth.views.verify")
    @override_settings(OTP_REST_AUTH={"OTP_SERIALIZER": OTPSerializer})
    def test_post_invalid_data(self, mock_verify):
        data = {"otp": "wrong_otp"}
        request = self.factory.post("/verify-account/", data, format="json")

        serializer = app_settings.OTP_SERIALIZER(data=data)
        self.assertFalse(serializer.is_valid())

        response = self.view(request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_verify.assert_not_called()
