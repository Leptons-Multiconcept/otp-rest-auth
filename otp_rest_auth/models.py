import random
from django.db import models
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from phonenumber_field.modelfields import PhoneNumberField

from .app_settings import app_settings


adapter = app_settings.ADAPTER()


class Account(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    is_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)

    verified_at = models.DateTimeField(null=True, blank=True)
    phone_verified_at = models.DateTimeField(null=True, blank=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.phone_verified or self.email_verified and not self.is_verified:
            self.is_verified = True

        if self.is_verified and not self.verified_at:
            self.verified_at = timezone.now()

        if self.phone_verified and not self.phone_verified_at:
            self.phone_verified_at = timezone.now()

        if self.email_verified and not self.email_verified_at:
            self.email_verified_at = timezone.now()

        return super().save(*args, **kwargs)


class TOTP(models.Model):
    PURPOSE_PASSWORD_RESET = "PasswordReset"
    PURPOSE_EMAIL_VERIFICATION = "EmailVerification"
    PURPOSE_PHONE_VERIFICATION = "PhoneVerification"
    PURPOSE_ACCOUNT_VERIFICATION = "AccountVerification"

    PURPOSE_CHOICES = [
        (PURPOSE_PASSWORD_RESET, "Password Reset"),
        (PURPOSE_EMAIL_VERIFICATION, "Email Verification"),
        (PURPOSE_PHONE_VERIFICATION, "Phone Verification"),
        (PURPOSE_ACCOUNT_VERIFICATION, "Account Verification"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    otp = models.IntegerField()
    is_valid = models.BooleanField(default=True)
    invalidated_at = models.DateTimeField(null=True, blank=True)
    purpose = models.CharField(max_length=100, choices=PURPOSE_CHOICES)
    expiration_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_expired(self):
        return timezone.now() > self.expiration_time

    def clean(self):
        if self.pk:
            original_state = TOTP.objects.get(pk=self.pk)
            if original_state.is_valid is False:
                raise ValidationError(
                    "is_valid cannot be reset to True once set to False."
                )
            if original_state.otp != self.otp:
                raise ValidationError("otp cannot be updated.")

        return super().clean()

    def save(self, *args, **kwargs):
        self.clean()

        # set `otp``
        otp_len = app_settings.OTP_LENGTH
        first_digit = str(random.randint(1, 9))
        digits = "".join([str(random.randint(0, 9)) for _ in range(otp_len - 1)])
        self.otp = int(first_digit + digits)

        # set `invalidated_at``
        if not self.is_valid and not self.invalidated_at:
            self.invalidated_at = timezone.now()

        # set `expiration_time`
        if not self.expiration_time:
            if self.purpose == self.PURPOSE_PASSWORD_RESET:
                self.expiration_time = timezone.now() + timedelta(
                    seconds=app_settings.PASSWORD_RESET_OTP_EXPIRY_TIME
                )
            else:
                self.expiration_time = timezone.now() + timedelta(
                    seconds=app_settings.OTP_EXPIRY_TIME
                )

        super().save(*args, **kwargs)

class TOTPMetadata(models.Model):
    totp = models.OneToOneField(TOTP, on_delete=models.CASCADE, related_name='metadata')
    new_phone = PhoneNumberField(null=True)
    new_email = models.EmailField(null=True)