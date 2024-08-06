from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from otp_rest_auth.app_settings import app_settings

User = get_user_model()


class LogoutViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="password",
            email="testuser@example.com",
            phone="+2348145640915",
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)
        self.refresh_token = str(self.refresh)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.access_token)
        self.url = reverse("otp_rest_logout")

    def test_logout_success(self):
        data = {"refresh": self.refresh_token}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Successfully logged out.")

    def test_logout_no_refresh_token(self):
        response = self.client.post(self.url, {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_invalid_refresh_token(self):
        data = {"refresh": "invalid_token"}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["detail"], "Token is invalid or expired")

    def test_logout_token_blacklisted(self):
        self.refresh.blacklist()
        data = {"refresh": self.refresh_token}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["detail"], "Token is blacklisted")

    def test_logout_no_authentication(self):
        self.client.credentials()
        response = self.client.post(
            self.url, {"refresh": self.refresh_token}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_unsets_cookies(self):
        data = {"refresh": self.refresh_token}
        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.cookies[app_settings.JWT_AUTH_COOKIE].value == "")
        self.assertTrue(
            response.cookies[app_settings.JWT_AUTH_REFRESH_COOKIE].value == ""
        )
