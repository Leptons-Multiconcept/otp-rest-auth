from django.core import mail
from django.test import TestCase
from unittest.mock import patch, Mock
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.core.exceptions import ValidationError

from account.models import Account, TOTP
from account.app_settings import app_settings
from account.adapter import DefaultAccountAdapter

User = get_user_model()


class DefaultAccountAdapterTests(TestCase):
    def setUp(self):
        self.adapter = DefaultAccountAdapter()
        self.user = User.objects.create_user(
            username="testuser", email="test@example.com", phone="+2341234567890"
        )
        self.account = Account.objects.create(user=self.user, is_verified=True)
        self.totp = TOTP.objects.create(
            user=self.user, purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION
        )

    def test_new_user(self):
        user = self.adapter.new_user(None)
        self.assertIsInstance(user, User)

    @patch("account.adapter.slugify")
    @patch("account.adapter.get_user_model")
    def test_generate_unique_username(self, mock_get_user_model, mock_slugify):
        mock_slugify.side_effect = lambda x: x
        User = mock_get_user_model.return_value
        User.objects.filter.return_value.exists.side_effect = [True, False]

        components = ["John", "Doe", "john.doe@example.com", "john.doe"]
        username = self.adapter.generate_unique_username(components)
        self.assertEqual(username, "john.doe1")

    @patch("account.utils.user_username")
    def test_populate_username(self, mock_user_username):
        mock_user = Mock()
        mock_user.username = ""
        self.adapter.populate_username(None, mock_user)
        mock_user_username.assert_called()

    def test_save_user(self):
        request = Mock()
        user = Mock()
        form = Mock()
        form.cleaned_data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "phone": "+2340987654321",
            "username": "johndoe",
            "password1": "secret",
        }

        saved_user = self.adapter.save_user(request, user, form, commit=True)
        self.assertEqual(saved_user, user)

    @patch("account.adapter.get_user_model")
    def test_clean_username(self, mock_get_user_model):
        mock_get_user_model.return_value = User
        username = "newuser"
        cleaned_username = self.adapter.clean_username(username)
        self.assertEqual(cleaned_username, "newuser")

    def test_clean_email(self):
        email = "test@example.com"
        cleaned_email = self.adapter.clean_email(email)
        self.assertEqual(cleaned_email, "test@example.com")

    def test_clean_phone(self):
        with patch(
            "phonenumber_field.validators.validate_international_phonenumber"
        ) as val_int_phnum:
            phone = "+2341234567890"
            cleaned_phone = self.adapter.clean_phone(phone)

            val_int_phnum.assert_called_once()
            self.assertEqual(cleaned_phone, "+2341234567890")

    @patch("django.contrib.auth.password_validation.validate_password")
    def test_clean_password(self, mock_validate_password):
        password = "password123"
        try:
            self.adapter.clean_password(password)
            mock_validate_password.assert_called_once_with(password)
        except ValidationError:
            pass
        # self.assertEqual(cleaned_password, "password123")

    @override_settings(OTP_REST_AUTH={"EMAIL_SUBJECT_PREFIX": "Test"})
    def test_format_email_subject(self):
        subject = "Subject"
        formatted_subject = self.adapter.format_email_subject(subject)
        self.assertEqual(formatted_subject, "Test Subject")

    def test_render_mail(self):
        with patch.object(self.adapter, "render_to_string") as mock_render_to_string:
            mock_render_to_string.side_effect = ["Test Subject", "Test Body"]
            email = "test@example.com"
            context = {}
            message = self.adapter.render_mail("account/email/test", email, context)
            self.assertEqual(
                message.subject, f"{app_settings.EMAIL_SUBJECT_PREFIX} Test Subject"
            )
            self.assertEqual(message.body, "Test Body")

    @patch("account.adapter.render_mail")
    @patch("account.adapter.EmailMultiAlternatives.send")
    def test_send_mail(self, mock_send, mock_render_mail):
        email = "test@example.com"
        context = {}
        mock_render_mail.return_value = mail.EmailMultiAlternatives()
        self.adapter.send_mail("account/email/test", email, context)
        mock_send.assert_called()

    @patch("account.adapter.send_mail")
    def test_send_otp_to_email(self, mock_send_mail):
        self.adapter.send_otp_to_email(self.totp)
        mock_send_mail.assert_called()

    @patch("account.adapter.Client")
    def test_send_otp_to_phone(self, mock_client):
        self.adapter.send_otp_to_phone(self.totp)
        mock_client.return_value.messages.create.assert_called()
