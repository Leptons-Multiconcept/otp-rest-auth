from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework import status, views
from rest_framework.response import Response
from rest_framework.exceptions import MethodNotAllowed
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.generics import CreateAPIView, GenericAPIView, RetrieveUpdateAPIView

from .app_settings import app_settings
from . import signals
from .utils import get_throttle_scope
from .models import Account, TOTP, TOTPMetadata
from .otp_ops import send_verification_otp, verify_otp
from .serializers import (
    ResendOTPSerializer,
    LogoutSerializer,
    ChangeEmailSerializer,
    ChangePhoneSerializer,
    ChangeEmailConfirmSerializer,
    ChangePhoneConfirmSerializer,
)
from .jwt_auth import get_tokens_for_user, set_jwt_cookies, unset_jwt_cookies


UserModel = get_user_model()
adapter = app_settings.ADAPTER()
sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters("password1", "password2"),
)


def get_login_response_data(user, context):
    from rest_framework_simplejwt.settings import (
        api_settings as jwt_settings,
    )

    serializer_class = app_settings.JWT_SERIALIZER
    if app_settings.JWT_AUTH_RETURN_EXPIRATION:
        serializer_class = app_settings.JWT_SERIALIZER_WITH_EXPIRATION

    access_token_expiration = timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME
    refresh_token_expiration = timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME
    return_expiration_times = app_settings.JWT_AUTH_RETURN_EXPIRATION
    auth_httponly = app_settings.JWT_AUTH_HTTPONLY

    access_token, refresh_token = get_tokens_for_user(user)

    data = {
        "user": user,
        "access": access_token,
    }

    if not auth_httponly:
        data["refresh"] = refresh_token
    else:
        # Wasnt sure if the serializer needed this
        data["refresh"] = ""

    if return_expiration_times:
        data["access_expiration"] = access_token_expiration
        data["refresh_expiration"] = refresh_token_expiration

    serializer = serializer_class(
        instance=data,
        context=context,
    )

    return serializer.data


def verify(serializer, request, totp_purpose, login=True) -> Response:
    """
    If OTP is valid set user.is_active and the respective
    app_settings.VERIFICATION_METHOD of the user account to True.
    """
    otp = serializer.validated_data["otp"]
    success, totp = verify_otp(otp, totp_purpose)
    if not success:
        return Response({"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

    user_account = Account.objects.get(user=totp.user)
    if totp_purpose == TOTP.PURPOSE_ACCOUNT_VERIFICATION:
        user_account.is_verified = True
    elif totp_purpose == TOTP.PURPOSE_EMAIL_VERIFICATION:
        user_account.email_verified = True
    elif totp_purpose == TOTP.PURPOSE_PHONE_VERIFICATION:
        user_account.phone_verified = True

    totp.user.is_active = True

    totp.user.save()
    user_account.save()

    response = Response(status=status.HTTP_200_OK)
    if login and app_settings.LOGIN_UPON_VERIFICATION:
        data = get_login_response_data(totp.user, {"request": request})
        response.data = data

        set_jwt_cookies(response, data["access"], data["refresh"])

    return response


class RegisterView(CreateAPIView):
    serializer_class = app_settings.REGISTER_SERIALIZER
    permission_classes = app_settings.REGISTER_PERMISSION_CLASSES

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_register")
        return super().get_throttles()

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_response_data(self, user):
        if (
            app_settings.VERIFICATION_METHOD
            != app_settings.AccountVerificationMethod.NONE
        ):
            return {"detail": _("Verification OTP sent.")}

        return get_login_response_data(user, self.get_serializer_context())

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        data = self.get_response_data(user)

        if data:
            response = Response(
                data,
                status=status.HTTP_201_CREATED,
                headers=headers,
            )
        else:
            response = Response(status=status.HTTP_204_NO_CONTENT, headers=headers)

        if app_settings.VERIFICATION_REQUIRED is False:
            user.is_active = True
            user.save()

        return response

    def perform_create(self, serializer):
        user = serializer.save(self.request)

        signal_kwargs = {}
        signals.user_signed_up.send(
            sender=user.__class__,
            request=self.request._request,
            user=user,
            **signal_kwargs,
        )

        # send OTP
        if (
            app_settings.VERIFICATION_METHOD
            == app_settings.AccountVerificationMethod.ACCOUNT
        ):
            purpose = TOTP.PURPOSE_ACCOUNT_VERIFICATION
        elif (
            app_settings.VERIFICATION_METHOD
            == app_settings.AccountVerificationMethod.EMAIL
        ):
            purpose = TOTP.PURPOSE_EMAIL_VERIFICATION
        elif (
            app_settings.VERIFICATION_METHOD
            == app_settings.AccountVerificationMethod.PHONE
        ):
            purpose = TOTP.PURPOSE_PHONE_VERIFICATION

        if (
            app_settings.VERIFICATION_METHOD
            != app_settings.AccountVerificationMethod.NONE
        ):
            totp = TOTP.objects.create(user=user, purpose=purpose)
            send_verification_otp(totp, signup=True)

        return user


class VerifyAccountView(views.APIView):
    permission_classes = (AllowAny,)
    allowed_methods = ("POST", "OPTIONS", "HEAD")

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_verify_account")
        return super().get_throttles()

    def get_serializer(self, *args, **kwargs):
        return app_settings.OTP_SERIALIZER(*args, **kwargs)

    def get(self, *args, **kwargs):
        raise MethodNotAllowed("GET")

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return verify(serializer, request, TOTP.PURPOSE_ACCOUNT_VERIFICATION)


class VerifyEmailView(views.APIView):
    throttle_scope = "otp_auth_v_email"
    permission_classes = (AllowAny,)
    allowed_methods = ("POST", "OPTIONS", "HEAD")

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_verify_email")
        return super().get_throttles()

    def get_serializer(self, *args, **kwargs):
        return app_settings.OTP_SERIALIZER(*args, **kwargs)

    def get(self, *args, **kwargs):
        raise MethodNotAllowed("GET")

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return verify(serializer, request, TOTP.PURPOSE_EMAIL_VERIFICATION)


class VerifyPhoneView(views.APIView):
    permission_classes = (AllowAny,)
    allowed_methods = ("POST", "OPTIONS", "HEAD")

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_verify_phone")
        return super().get_throttles()

    def get_serializer(self, *args, **kwargs):
        return app_settings.OTP_SERIALIZER(*args, **kwargs)

    def get(self, *args, **kwargs):
        raise MethodNotAllowed("GET")

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return verify(serializer, request, TOTP.PURPOSE_PHONE_VERIFICATION)


class ResendOTPView(views.APIView):
    permission_classes = (AllowAny,)
    allowed_methods = ("POST", "OPTIONS", "HEAD")

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_otp_resend")
        return super().get_throttles()

    def get_serializer(self, *args, **kwargs):
        return ResendOTPSerializer(*args, **kwargs)

    def get(self, *args, **kwargs):
        raise MethodNotAllowed("GET")

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if data["purpose"] == TOTP.PURPOSE_ACCOUNT_VERIFICATION:
            email, phone = data.get("email"), data.get("phone")
            filter = {app_settings.USER_MODEL_EMAIL_FIELD: email} if email else {}
            if phone:
                filter[app_settings.USER_MODEL_PHONE_FIELD] = phone

        elif data["purpose"] == TOTP.PURPOSE_EMAIL_VERIFICATION:
            filter = {app_settings.USER_MODEL_EMAIL_FIELD: data["email"]}
        elif data["purpose"] == TOTP.PURPOSE_PHONE_VERIFICATION:
            filter = {app_settings.USER_MODEL_PHONE_FIELD: data["phone"]}
        elif data["purpose"] == TOTP.PURPOSE_PASSWORD_RESET:
            email, phone = data.get("email"), data.get("phone")
            filter = {app_settings.USER_MODEL_EMAIL_FIELD: email} if email else {}
            if phone:
                filter[app_settings.USER_MODEL_PHONE_FIELD] = phone

        user = UserModel.objects.filter(**filter).first()
        if not user:
            return Response(
                {"detail": "Incorrect email or phone."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        purpose = data["purpose"]
        account = Account.objects.filter(user=user).first()

        if purpose == TOTP.PURPOSE_ACCOUNT_VERIFICATION and account.is_verified:
            msg = "Account already verified."
            return Response({"detail": msg}, status=status.HTTP_400_BAD_REQUEST)
        elif purpose == TOTP.PURPOSE_EMAIL_VERIFICATION and account.email_verified:
            msg = "Email address already verified."
            return Response({"detail": msg}, status=status.HTTP_400_BAD_REQUEST)
        elif purpose == TOTP.PURPOSE_PHONE_VERIFICATION and account.phone_verified:
            msg = "Phone number already verified."
            return Response({"detail": msg}, status=status.HTTP_400_BAD_REQUEST)

        # invalidate existing otp
        old_totp = TOTP.objects.filter(user=user, purpose=data["purpose"]).first()
        if old_totp and old_totp.is_valid:
            old_totp.is_valid = False
            old_totp.save()

        new_totp = TOTP.objects.create(user=user, purpose=data["purpose"])
        send_verification_otp(new_totp, request=request)

        return Response({"detail": "ok"}, status=status.HTTP_200_OK)


class LoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = app_settings.LOGIN_SERIALIZER

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_login")
        return super().get_throttles()

    user = None
    access_token = None
    token = None

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        user = self.serializer.validated_data["user"]
        data = get_login_response_data(user, {"request": request})

        response = Response(data, status=status.HTTP_200_OK)
        set_jwt_cookies(response, data["access"], data["refresh"])

        return response


class LogoutView(GenericAPIView):
    """
    Delete the Token object assigned to the current User object.
    Accepts/Returns nothing.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_logout")
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        return self.logout(request)

    def logout(self, request):
        response = Response(
            {"detail": _("Successfully logged out.")},
            status=status.HTTP_200_OK,
        )

        cookie_name = app_settings.JWT_AUTH_COOKIE
        unset_jwt_cookies(response)

        if "rest_framework_simplejwt.token_blacklist" in settings.INSTALLED_APPS:
            # add refresh token to blacklist
            try:
                token = RefreshToken(request.data["refresh"])
                token.blacklist()
            except KeyError:
                response.data = {
                    "detail": _("Refresh token was not included in request data.")
                }
                response.status_code = status.HTTP_401_UNAUTHORIZED
            except (TokenError, AttributeError, TypeError) as error:
                if hasattr(error, "args"):
                    if (
                        "Token is blacklisted" in error.args
                        or "Token is invalid or expired" in error.args
                    ):
                        response.data = {"detail": _(error.args[0])}
                        response.status_code = status.HTTP_401_UNAUTHORIZED
                    else:
                        response.data = {"detail": _("An error has occurred.")}
                        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

                else:
                    response.data = {"detail": _("An error has occurred.")}
                    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        elif not cookie_name:
            message = _(
                "Neither cookies or blacklist are enabled, so the token "
                "has not been deleted server side. Please make sure the token is deleted client side.",
            )
            response.data = {"detail": message}
            response.status_code = status.HTTP_200_OK

        return response


class ResetPasswordView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = app_settings.PASSWORD_RESET_SERIALIZER

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_password_reset")
        return super().get_throttles()

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        user = self.serializer.validated_data["user"]
        if user:
            totp = TOTP.objects.create(user=user, purpose=TOTP.PURPOSE_PASSWORD_RESET)
            send_verification_otp(totp, request)

        return Response(
            {"detail": _("Verification OTP sent.")}, status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(GenericAPIView):
    serializer_class = app_settings.PASSWORD_RESET_CONFIRM_SERIALIZER
    permission_classes = (AllowAny,)

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_password_reset_confirm")
        return super().get_throttles()

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": _("Password has been reset with the new password.")},
        )


class PasswordChangeView(GenericAPIView):
    serializer_class = app_settings.PASSWORD_CHANGE_SERIALIZER
    permission_classes = (IsAuthenticated,)

    def get_throttles(self):
        self.throttle_scope = get_throttle_scope("otp_auth_password_change")
        return super().get_throttles()

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        resp_detail = {"detail": "New password has been saved."}

        if app_settings.LOGOUT_ON_PASSWORD_CHANGE:
            logout_view = LogoutView()
            response = logout_view.logout(request)

            resp_detail["logout_detail"] = response.data["detail"]

        return Response(resp_detail)


class UserDetailsView(RetrieveUpdateAPIView):
    """
    Reads and updates UserModel fields
    Accepts GET, PUT, PATCH methods.

    Default accepted fields: username, first_name, last_name
    Default display fields: pk, username, email, first_name, last_name
    Read-only fields: pk, email

    Returns UserModel fields.
    """

    serializer_class = app_settings.USER_DETAILS_SERIALIZER
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user

    def get_queryset(self):
        """
        Adding this method since it is sometimes called when using
        django-rest-swagger
        """
        return get_user_model().objects.none()


class InvokeChangeEmailOTPView(GenericAPIView):
    serializer_class = ChangeEmailSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["new_email"]
        user = request.user

        totp = TOTP.objects.create(user=user, purpose=TOTP.PURPOSE_EMAIL_VERIFICATION)
        TOTPMetadata.objects.create(totp=totp, new_email=email)

        adapter.send_otp_to_email(totp, email)

        return Response({"detail": _("Verification OTP sent.")})


class InvokeChangePhoneOTPView(GenericAPIView):
    serializer_class = ChangePhoneSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data["new_phone"]
        user = request.user

        totp = TOTP.objects.create(user=user, purpose=TOTP.PURPOSE_PHONE_VERIFICATION)
        TOTPMetadata.objects.create(totp=totp, new_phone=phone)

        adapter.send_otp_to_phone(totp, phone)

        return Response({"detail": _("Verification OTP sent.")})


class ChangeEmailConfrimationView(GenericAPIView):
    serializer_class = ChangeEmailConfirmSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data["otp"]
        success, totp = verify_otp(otp, TOTP.PURPOSE_EMAIL_VERIFICATION)
        if not success or totp.user != request.user:
            return Response(
                {"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
            )

        totp_metadata = TOTPMetadata.objects.filter(totp=totp).first()
        if not totp_metadata or not totp_metadata.new_email:
            return Response(
                {"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
            )

        if app_settings.UNIQUE_EMAIL:
            # Ensure the new email address isn't used by another user
            email_field = app_settings.USER_MODEL_EMAIL_FIELD
            if UserModel.objects.filter(
                **{email_field: totp_metadata.new_email}
            ).exists():
                return Response(
                    {"detail": "Email address already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        user_account = Account.objects.filter(user=totp.user).first()
        if totp.user and not user_account:
            # Create account for user. The user may have logged in via some social auth.
            user_account = Account.objects.create(user=totp.user)

        if not user_account.email_verified:
            user_account.email_verified = True

        totp.user.is_active = True
        new_email = totp_metadata.new_email
        setattr(totp.user, app_settings.USER_MODEL_EMAIL_FIELD, new_email)

        totp.user.save()
        user_account.save()

        return Response(status=status.HTTP_200_OK)


class ChangePhoneConfirmationView(GenericAPIView):
    serializer_class = ChangeEmailConfirmSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data["otp"]
        success, totp = verify_otp(otp, TOTP.PURPOSE_PHONE_VERIFICATION)
        if not success or totp.user != request.user:
            return Response(
                {"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
            )

        totp_metadata = TOTPMetadata.objects.filter(totp=totp).first()
        if not totp_metadata or not totp_metadata.new_phone:
            return Response(
                {"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
            )

        if app_settings.UNIQUE_PHONE:
            # Ensure the new phone number isn't used by another user
            phone_field = app_settings.USER_MODEL_PHONE_FIELD
            if UserModel.objects.filter(
                **{phone_field: totp_metadata.new_phone}
            ).exists():
                return Response(
                    {"detail": "Phone number already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        user_account = Account.objects.filter(user=totp.user).first()
        if totp.user and not user_account:
            # Create account for user. The user may have logged in via some social auth.
            user_account = Account.objects.create(user=totp.user)

        if not user_account.phone_verified:
            user_account.phone_verified = True

        totp.user.is_active = True
        new_phone = totp_metadata.new_phone
        setattr(totp.user, app_settings.USER_MODEL_PHONE_FIELD, new_phone)

        totp.user.save()
        user_account.save()
        return Response(status=status.HTTP_200_OK)
