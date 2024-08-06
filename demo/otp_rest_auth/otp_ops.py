from django.utils import timezone

from . import signals
from .models import TOTP
from .app_settings import app_settings

adapter = app_settings.ADAPTER()


def validate_otp(otp: int, purpose: str):
    totp = TOTP.objects.filter(otp=otp, purpose=purpose).first()
    if not totp:
        return False, None
    if totp.is_expired or not totp.is_valid:
        return False, None

    return True, totp


def verify_otp(otp: int, purpose: str):
    is_valid, totp = validate_otp(otp, purpose)
    if not is_valid:
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
        adapter.send_otp_to_user_email(totp)
        adapter.send_otp_to_user_phone(totp)

        signal_email_confirmation_sent()
        signal_phone_confirmation_sent()

    elif totp.purpose == TOTP.PURPOSE_EMAIL_VERIFICATION:
        adapter.send_otp_to_user_email(totp)
        signal_email_confirmation_sent()

    elif totp.purpose == TOTP.PURPOSE_PHONE_VERIFICATION:
        adapter.send_otp_to_user_phone(totp)
        signal_phone_confirmation_sent()

    elif totp.purpose == TOTP.PURPOSE_PASSWORD_RESET:
        medium = app_settings.PASSWORD_RESET_OTP_RECIPIENTS
        if "phone" in medium:
            adapter.send_otp_to_user_phone(totp)
        if "email" in medium:
            adapter.send_otp_to_user_email(totp)
