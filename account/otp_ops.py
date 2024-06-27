from django.utils import timezone

from . import signals
from .models import TOTP, Account
from .app_settings import app_settings
from .adapter import DefaultAccountAdapter

adapter = DefaultAccountAdapter()


def verify_otp(otp: int, purpose: str):
    totp = TOTP.objects.filter(_otp=otp, purpose=purpose).first()
    if not totp:
        print(f"token: {otp}, purpose: {purpose}")
        return False, None
    if totp.is_expired() or not totp.is_valid:
        return False, None

    # Confirm OTP
    totp.is_valid = False
    totp.invalidated_at = timezone.now()
    totp.save()
    return True, totp


def send_verification_otp(totp: TOTP, request=None, signup=False):
    def signal_email_confirmation_sent():
        signals.email_confirmation_sent.send(
            sender=send_verification_otp,
            request=request,
            signup=signup,
        )

    def signal_phone_confirmation_sent():
        signals.phone_confirmation_sent.send(
            sender=send_verification_otp,
            request=request,
            signup=signup,
        )

    if totp.purpose == TOTP.PURPOSE_ACCOUNT_VERIFICATION:
        adapter.send_otp_to_email(totp)
        adapter.send_otp_to_phone(totp)

        signal_email_confirmation_sent()
        signal_phone_confirmation_sent()

    elif totp.purpose == TOTP.PURPOSE_EMAIL_VERIFICATION:
        adapter.send_otp_to_email(totp)
        signal_email_confirmation_sent()

    elif totp.purpose == TOTP.PURPOSE_PHONE_VERIFICATION:
        adapter.send_otp_to_phone(totp)
        signal_phone_confirmation_sent()

    elif totp.purpose == TOTP.PURPOSE_PASSWORD_RESET:
        medium = app_settings.PWD_RESET_OTP_RECIPIENTS
        if "phone" in medium:
            adapter.send_otp_to_phone(totp)
        if "email" in medium:
            adapter.send_otp_to_email(totp)
