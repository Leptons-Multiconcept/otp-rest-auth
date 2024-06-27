from django.urls import path

from .views import (
    RegisterView,
    ResendOTPView,
    LoginView,
    LogoutView,
    VerifyAccountView,
    VerifyEmailView,
    VerifyPhoneView,
)

urlpatterns = [
    path("", RegisterView.as_view(), name="rest_register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("resend_otp/", ResendOTPView.as_view(), name="resend_otp"),
    path("verify/phone", VerifyPhoneView.as_view(), name="verify_phone"),
    path("verify/email", VerifyEmailView.as_view(), name="verify_email"),
    path("verify/account", VerifyAccountView.as_view(), name="verify_account"),
]
