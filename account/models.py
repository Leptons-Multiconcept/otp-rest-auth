import random
from django.db import models
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError

from .app_settings import app_settings
from .adapter import DefaultAccountAdapter

adapter = DefaultAccountAdapter()


class Account(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

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

    _otp = models.IntegerField()
    is_valid = models.BooleanField(default=True)
    invalidated_at = models.DateTimeField(null=True, blank=True)
    purpose = models.CharField(max_length=100, choices=PURPOSE_CHOICES)
    expiration_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def otp(self):
        return self._otp

    @property
    def is_expired(self):
        return self.created_at < self.expiration_time

    def clean(self):
        if self.pk:
            original_state = TOTP.objects.get(pk=self.pk)
            if original_state.is_valid is False:
                raise ValidationError(
                    "is_valid cannot be reset to True once set to False."
                )

        return super().clean()

    def save(self, *args, **kwargs):
        self.clean()

        # set `_otp``
        otp_len = app_settings.OTP_LENGTH
        otp = "".join([str(random.randint(0, 9)) for _ in range(otp_len)])
        self._otp = int(otp)

        # set `invalidated_at``
        if not self.is_valid and not self.invalidated_at:
            self.invalidated_at = timezone.now()

        # set `expiration_time`
        if not self.expiration_time:
            if self.purpose == self.PURPOSE_PASSWORD_RESET:
                self.expiration_time = timezone.now() - timedelta(
                    seconds=app_settings.PASSWORD_RESET_OTP_EXPIRY_TIME
                )
        else:
            self.expiration_time = timezone.now() - timedelta(
                seconds=app_settings.OTP_EXPIRY_TIME
            )

        super().save(*args, **kwargs)
