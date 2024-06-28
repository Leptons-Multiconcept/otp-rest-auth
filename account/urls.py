from django.urls import path

from .views import (
    RegisterView,
    ResendOTPView,
    ResetPasswordView,
    LoginView,
    LogoutView,
    VerifyAccountView,
    VerifyEmailView,
    VerifyPhoneView,
    PasswordResetConfirmView,
)

urlpatterns = [
    path("", RegisterView.as_view(), name="otp_rest_register"),
    path("login/", LoginView.as_view(), name="otp_rest_login"),
    path("logout/", LogoutView.as_view(), name="otp_rest_logout"),
    path("resend_otp/", ResendOTPView.as_view(), name="otp_rest_resend_otp"),
    path("verify/phone", VerifyPhoneView.as_view(), name="otp_rest_verify_phone"),
    path("verify/email", VerifyEmailView.as_view(), name="otp_rest_verify_email"),
    path("verify/account", VerifyAccountView.as_view(), name="otp_rest_verify_account"),
    path(
        "password/reset/", ResetPasswordView.as_view(), name="otp_rest_password_reset"
    ),
    path(
        "password/reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="otp_rest_password_reset_confirm",
    ),
]
