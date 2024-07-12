from datetime import timedelta
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.utils import timezone
from django.core.exceptions import ValidationError

from otp_rest_auth.models import Account, TOTP
from otp_rest_auth.app_settings import app_settings


User = get_user_model()


class AccountModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="password")
        self.account = Account.objects.get(user=self.user)

    def test_initial_account_creation(self):
        account = Account.objects.get(user=self.user)
        self.assertFalse(account.is_verified)
        self.assertFalse(account.phone_verified)
        self.assertFalse(account.email_verified)
        self.assertIsNone(account.verified_at)
        self.assertIsNone(account.phone_verified_at)
        self.assertIsNone(account.email_verified_at)

    def test_phone_verified_sets_is_verified(self):
        self.account.phone_verified = True
        self.account.save()
        self.account.refresh_from_db()

        self.assertTrue(self.account.is_verified)
        self.assertIsNotNone(self.account.verified_at)
        self.assertIsNotNone(self.account.phone_verified_at)
        self.assertIsNone(self.account.email_verified_at)

    def test_email_verified_sets_is_verified(self):
        self.account.email_verified = True
        self.account.save()
        self.account.refresh_from_db()

        self.assertTrue(self.account.is_verified)
        self.assertIsNotNone(self.account.verified_at)
        self.assertIsNotNone(self.account.email_verified_at)
        self.assertIsNone(self.account.phone_verified_at)

    def test_phone_and_email_verified(self):
        self.account.phone_verified = True
        self.account.email_verified = True
        self.account.save()
        self.account.refresh_from_db()

        self.assertTrue(self.account.is_verified)
        self.assertIsNotNone(self.account.verified_at)
        self.assertIsNotNone(self.account.phone_verified_at)
        self.assertIsNotNone(self.account.email_verified_at)

    def test_is_verified_set_does_not_override(self):
        self.account.is_verified = True
        self.account.save()
        initial_verified_at = self.account.verified_at

        self.account.save()
        self.account.refresh_from_db()

        self.assertTrue(self.account.is_verified)
        self.assertEqual(self.account.verified_at, initial_verified_at)

    def test_unverified_phone_and_email_does_not_set_is_verified(self):
        self.account.phone_verified = False
        self.account.email_verified = False
        self.account.save()
        self.account.refresh_from_db()

        self.assertFalse(self.account.is_verified)
        self.assertIsNone(self.account.verified_at)
        self.assertIsNone(self.account.phone_verified_at)
        self.assertIsNone(self.account.email_verified_at)


class TOTPModelTests(TestCase):
    @override_settings(
        OTP_REST_AUTH={
            "OTP_LENGTH": 4,
            "OTP_EXPIRY_TIME": 60,
            "PASSWORD_RESET_OTP_EXPIRY_TIME ": 90,
        }
    )
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="password")
        self.totp = TOTP.objects.create(
            user=self.user,
            purpose=TOTP.PURPOSE_EMAIL_VERIFICATION,
        )

    def test_initial_totp_creation(self):
        totp = TOTP.objects.create(
            user=self.user,
            purpose=TOTP.PURPOSE_PASSWORD_RESET,
        )
        self.assertEqual(totp.user, self.user)
        self.assertTrue(totp.is_valid)
        self.assertIsNone(totp.invalidated_at)
        self.assertEqual(totp.purpose, TOTP.PURPOSE_PASSWORD_RESET)
        self.assertIsNotNone(totp.expiration_time)
        self.assertIsNotNone(totp.created_at)

    @override_settings(OTP_REST_AUTH={"OTP_LENGTH": 9})
    def test_otp_generation(self):
        totp = TOTP.objects.create(
            user=self.user,
            purpose=TOTP.PURPOSE_EMAIL_VERIFICATION,
        )
        self.assertNotEqual(self.totp.otp, totp.otp)
        self.assertEqual(len(str(totp.otp)), app_settings.OTP_LENGTH)

    def test_is_valid_reset_to_true(self):
        totp = TOTP.objects.create(
            user=self.user,
            purpose=TOTP.PURPOSE_PHONE_VERIFICATION,
            is_valid=False,
        )
        totp.is_valid = True
        with self.assertRaises(ValidationError):
            totp.clean()

    def test_otp_update(self):
        totp = TOTP.objects.create(
            user=self.user,
            purpose=TOTP.PURPOSE_ACCOUNT_VERIFICATION,
        )
        totp.otp = 123456
        with self.assertRaises(ValidationError):
            totp.clean()

    def test_invalidated_at_set(self):
        totp = TOTP.objects.create(
            user=self.user,
            purpose=TOTP.PURPOSE_PHONE_VERIFICATION,
            is_valid=False,
        )
        self.assertIsNotNone(totp.invalidated_at)

    def test_is_expired(self):
        totp_password_reset = TOTP.objects.create(
            user=self.user,
            is_valid=True,
            purpose=TOTP.PURPOSE_PASSWORD_RESET,
            expiration_time=timezone.now() + timedelta(seconds=3600),  # 1 hour from now
        )
        totp_email_verification = TOTP.objects.create(
            user=self.user,
            is_valid=True,
            purpose=TOTP.PURPOSE_EMAIL_VERIFICATION,
            expiration_time=timezone.now() + timedelta(seconds=3600),  # 1 hour from now
        )

        self.assertFalse(totp_password_reset.is_expired)
        self.assertFalse(totp_email_verification.is_expired)

        expired_totp = TOTP.objects.create(
            user=self.user,
            is_valid=True,
            purpose=TOTP.PURPOSE_PHONE_VERIFICATION,
            expiration_time=timezone.now() - timedelta(seconds=3600),  # 1 hour ago
        )
        self.assertTrue(expired_totp.is_expired)

    @override_settings(
        OTP_REST_AUTH={"OTP_EXPIRY_TIME": 60, "PASSWORD_RESET_OTP_EXPIRY_TIME": 120}
    )
    def test_expiration_time_calculation(self):
        # Test Password Reset OTP expiration time calculation
        password_reset_otp = TOTP.objects.create(
            user=self.user,
            is_valid=True,
            purpose=TOTP.PURPOSE_PASSWORD_RESET,
        )
        prt = timezone.now() + timedelta(
            seconds=app_settings.PASSWORD_RESET_OTP_EXPIRY_TIME
        )
        self.assertEqual(password_reset_otp.expiration_time.second, prt.second)

        # Test Email Verification OTP expiration time calculation
        email_verification_otp = TOTP.objects.create(
            user=self.user,
            is_valid=True,
            purpose=TOTP.PURPOSE_EMAIL_VERIFICATION,
        )
        evt = timezone.now() + timedelta(seconds=app_settings.OTP_EXPIRY_TIME)
        self.assertEqual(email_verification_otp.expiration_time.second, evt.second)

        self.assertNotEqual(prt.minute, evt.minute)
