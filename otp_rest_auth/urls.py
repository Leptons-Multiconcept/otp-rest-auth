from django.urls import path, include

from .views import (
    RegisterView,
    ResendOTPView,
    ResetPasswordView,
    LoginView,
    LogoutView,
    UserDetailsView,
    VerifyAccountView,
    VerifyEmailView,
    VerifyPhoneView,
    PasswordChangeView,
    PasswordResetConfirmView,
    InvokeChangeEmailOTPView,
    InvokeChangePhoneOTPView,
    ChangeEmailConfrimationView,
    ChangePhoneConfirmationView,
)
from rest_framework_simplejwt.views import TokenVerifyView
from otp_rest_auth.jwt_auth import get_refresh_view

urlpatterns = [
    path("login/", LoginView.as_view(), name="otp_rest_login"),
    path("logout/", LogoutView.as_view(), name="otp_rest_logout"),
    path("register/", RegisterView.as_view(), name="otp_rest_register"),
    path("user/", UserDetailsView.as_view(), name="otp_rest_user_details"),
    path("resend_otp/", ResendOTPView.as_view(), name="otp_rest_resend_otp"),
    path(
        "phone/change/",
        InvokeChangePhoneOTPView.as_view(),
        name="otp_rest_change_phone",
    ),
    path(
        "email/change/",
        InvokeChangeEmailOTPView.as_view(),
        name="otp_rest_change_email",
    ),
    path(
        "phone/change/confirm/",
        ChangePhoneConfirmationView.as_view(),
        name="otp_rest_change_phone_set",
    ),
    path(
        "email/change/confirm/",
        ChangeEmailConfrimationView.as_view(),
        name="otp_rest_change_email_set",
    ),
    path("verify/phone/", VerifyPhoneView.as_view(), name="otp_rest_verify_phone"),
    path("verify/email/", VerifyEmailView.as_view(), name="otp_rest_verify_email"),
    path(
        "verify/account/", VerifyAccountView.as_view(), name="otp_rest_verify_account"
    ),
    path(
        "password/reset/", ResetPasswordView.as_view(), name="otp_rest_password_reset"
    ),
    path(
        "password/reset/confirm/",
        PasswordResetConfirmView.as_view(),
        name="otp_rest_password_reset_confirm",
    ),
    path(
        "password/change/",
        PasswordChangeView.as_view(),
        name="otp_rest_password_change",
    ),
    path("token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("token/refresh/", get_refresh_view().as_view(), name="token_refresh"),
]
