from django.conf import settings
from django.utils.module_loading import import_string


class AppSettings(object):
    """
    test: AccountType can't be NONE and Verification be required
    test: Serializers passed are serializers
    test: If VerificationType is Account then PHONE and EMAIL must be required and unique
        - If VerificationType is Phone then Phone must be required and unique
        - Same for EMAIL
    """

    def __init__(self):
        if self.VERIFICATION_METHOD is self.AccountVerificationMethod.NONE:
            assert (
                self.VERIFICATION_REQUIRED is False
            ), "VERIFICATION_REQUIRED must be False when VERIFICATION_METHOD is set to None"

        if self.VERIFICATION_METHOD == self.AccountVerificationMethod.ACCOUNT:
            assert (
                self.PHONE_REQUIRED and self.EMAIL_REQUIRED
            ), "Both PHONE and EMAIL must be required for Account verification"
            assert (
                self.UNIQUE_PHONE and self.UNIQUE_EMAIL
            ), "Both PHONE and EMAIL must be unique for Account verification"

        if self.VERIFICATION_METHOD == "Phone":
            assert self.PHONE_REQUIRED, "PHONE must be required for Phone verification"
            assert self.UNIQUE_PHONE, "PHONE must be unique for Phone verification"

        if self.VERIFICATION_METHOD == "Email":
            assert self.EMAIL_REQUIRED, "EMAIL must be required for Email verification"
            assert self.EMAIL_UNIQUE, "EMAIL must be unique for Email verification"

    class AccountVerificationMethod:
        # After signing up, keep the user account inactive until the account
        # is verified. An account can be verified and Email and Phone will be
        # unverified. But if either Email or Phone is verified, Account will be
        # verified.

        # Send verification OTP to email and phone.
        ACCOUNT = "account"
        # Send verification OTP to email only
        EMAIL = "email"
        # Send verification OTP to phone only
        PHONE = "phone"
        # Don't send verification OTP
        NONE = "none"

    class AuthenticationMethods:
        PHONE = "phone"
        EMAIL = "email"
        USERNAME = "username"

    def _import_string(self, input):
        if isinstance(input, str):
            return import_string(input)
        return input

    def _setting(self, attr, default):
        otp_rest_auth_settings = getattr(settings, "OTP_REST_AUTH", {})
        return otp_rest_auth_settings.get(attr, default)

    @property
    def VERIFICATION_METHOD(self):
        """
        Account verification method.
        """
        return self._setting(
            "VERIFICATION_METHOD", self.AccountVerificationMethod.ACCOUNT
        )

    @property
    def VERIFICATION_REQUIRED(self):
        """
        True:
            - Keep the user account inactive until the account is verified
            - Don't allow login with unverified account
        False:
            - Activate user account upon registration
            - Allow login with unverified account
        """
        legacy = self.VERIFICATION_METHOD != self.AccountVerificationMethod.NONE

        return self._setting("VERIFICATION_REQUIRED", legacy)

    @property
    def AUTHENTICATION_METHODS(self):
        """Fields a user can sign in with."""
        return self._setting(
            "AUTHENTICATION_METHODS",
            (
                self.AuthenticationMethods.PHONE,
                self.AuthenticationMethods.EMAIL,
                self.AuthenticationMethods.USERNAME,
            ),
        )

    @property
    def ADAPTER(self):
        default_adapter = "otp_rest_auth.adapter.DefaultAccountAdapter"
        adapter_import_str = self._setting("ADAPTER", default_adapter)

        return self._import_string(adapter_import_str)

    @property
    def PASSWORD_RESET_OTP_RECIPIENTS(self):
        """
        Where to send password reset OTP to. Phone, Email, or both.
        """
        return self._setting("PASSWORD_RESET_OTP_RECIPIENTS", ("phone", "email"))

    @property
    def PASSWORD_RESET_OTP_EXPIRY_TIME(self):
        return self._setting("PASSWORD_RESET_OTP_EXPIRY_TIME", 90)

    @property
    def PASSWORD_RESET_CONFIRM_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.PasswordResetConfirmSerializer"
        serializer = self._setting(
            "PASSWORD_RESET_CONFIRM_SERIALIZER", default_serializer
        )

        return self._import_string(serializer)

    @property
    def PASSWORD_RESET_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.PasswordResetSerializer"
        serializer = self._setting("PASSWORD_RESET_SERIALIZER", default_serializer)

        return self._import_string(serializer)

    @property
    def PASSWORD_CHANGE_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.PasswordChangeSerializer"
        serializer = self._setting("PASSWORD_CHANGE_SERIALIZER", default_serializer)

        return self._import_string(serializer)

    @property
    def OLD_PASSWORD_FIELD_ENABLED(self):
        return self._setting("OLD_PASSWORD_FIELD_ENABLED", False)

    @property
    def JWT_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.JWTSerializer"
        serializer = self._setting("JWT_SERIALIZER", default_serializer)

        return self._import_string(serializer)

    @property
    def LOGIN_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.LoginSerializer"
        serializer = self._setting("LOGIN_SERIALIZER", default_serializer)

        return self._import_string(serializer)

    @property
    def UNIQUE_PHONE(self):
        """
        Enforce uniqueness of phone numbers
        """
        return self._setting("UNIQUE_PHONE", True)

    @property
    def UNIQUE_EMAIL(self):
        """
        Enforce uniqueness of email addresses
        """
        return self._setting("UNIQUE_EMAIL", True)

    @property
    def EMAIL_REQUIRED(self):
        """
        The user is required to hand over an email address when signing up
        """
        return self._setting("EMAIL_REQUIRED", True)

    @property
    def PHONE_REQUIRED(self):
        """
        The user is required to hand over a phone number when signing up
        """
        return self._setting("PHONE_REQUIRED", True)

    @property
    def USERNAME_REQUIRED(self):
        """
        The user is required to enter a username when signing up
        """
        return self._setting("USERNAME_REQUIRED", False)

    @property
    def USERNAME_BLACKLIST(self):
        """
        List of usernames that are not allowed
        """
        return self._setting("USERNAME_BLACKLIST", [])

    @property
    def USERNAME_MIN_LENGTH(self):
        """
        Minimum username Length
        """
        return self._setting("USERNAME_MIN_LENGTH", 3)

    @property
    def USERNAME_MAX_LENGTH(self):
        """
        Maximum username Length
        """
        return self._setting("USERNAME_MAX_LENGTH", 15)

    @property
    def PRESERVE_USERNAME_CASING(self):
        return self._setting("PRESERVE_USERNAME_CASING", False)

    @property
    def USERNAME_VALIDATORS(self):
        return []

    @property
    def USER_MODEL_USERNAME_FIELD(self):
        return self._setting("USER_MODEL_USERNAME_FIELD", "username")

    @property
    def USER_MODEL_EMAIL_FIELD(self):
        return self._setting("USER_MODEL_EMAIL_FIELD", "email")

    @property
    def USER_MODEL_PHONE_FIELD(self):
        return self._setting("USER_MODEL_PHONE_FIELD", "phone")

    @property
    def REGISTER_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.RegisterSerializer"
        serializer = self._setting("REGISTER_SERIALIZER", default_serializer)

        return self._import_string(serializer)

    @property
    def OTP_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.OTPSerializer"
        serializer = self._setting("OTP_SERIALIZER", default_serializer)

        return self._import_string(serializer)

    @property
    def REGISTER_PERMISSION_CLASSES(self):
        return self._setting("REGISTER_PERMISSION_CLASSES", [])

    @property
    def SITE_NAME(self):
        return self._setting("SITE_NAME", "DjangoApp")

    @property
    def TEMPLATE_EXTENSION(self):
        """
        A string defining the template extension to use, defaults to `html`.
        """
        return self._setting("TEMPLATE_EXTENSION", "html")

    @property
    def EMAIL_SUBJECT_PREFIX(self):
        """
        Subject-line prefix to use for email messages sent
        """
        return self._setting("EMAIL_SUBJECT_PREFIX", None)

    @property
    def OTP_LENGTH(self):
        """
        Number of digits in OTP.
        """
        return self._setting("OTP_LENGTH", 6)

    @property
    def OTP_EXPIRY_TIME(self):
        return self._setting("OTP_EXPIRY_TIME", 90)

    @property
    def PASSWORD_MIN_LENGTH(self):
        return self._setting("PASSWORD_MIN_LENGTH", 4)

    @property
    def PASSWORD_MAX_LENGTH(self):
        return self._setting("PASSWORD_MAX_LENGTH", 50)

    @property
    def USER_DETAILS_SERIALIZER(self):
        default_serializer = "otp_rest_auth.serializers.UserDetailsSerializer"
        serializer = self._setting("USER_DETAILS_SERIALIZER", default_serializer)

        return self._import_string(serializer)

    @property
    def JWT_SERIALIZER_WITH_EXPIRATION(self):
        default_serializer = "otp_rest_auth.serializers.JWTSerializerWithExpiration"
        serializer = self._setting("JWT_SERIALIZER_WITH_EXPIRATION", default_serializer)

        return self._import_string(serializer)

    @property
    def LOGIN_UPON_VERIFICATION(self):
        """
        Send JWT to client upon verification
        """
        return self._setting("LOGIN_UPON_VERIFICATION", False)

    @property
    def LOGIN_ATTEMPTS_LIMIT(self):
        """
        Number of failed login attempts. When this number is
        exceeded, the user is prohibited from logging in for the
        specified `LOGIN_ATTEMPTS_TIMEOUT`
        """
        return self._setting("LOGIN_ATTEMPTS_LIMIT", 5)

    @property
    def LOGIN_ATTEMPTS_TIMEOUT(self):
        """
        Time period from last unsuccessful login attempt, during
        which the user is prohibited from trying to log in.  Defaults to
        5 minutes.
        """
        return self._setting("LOGIN_ATTEMPTS_TIMEOUT", 60 * 5)

    @property
    def RATE_LIMITS(self):
        dflt = {
            # Change password view (for users already logged in)
            "change_password": "5/m",
            # Email management (e.g. add, remove, change primary)
            "manage_email": "10/m",
            # Request a password reset, global rate limit per IP
            "reset_password": "20/m",
            # Rate limit measured per individual email address
            "reset_password_email": "5/m",
            # Reauthentication for users already logged in)
            "reauthenticate": "10/m",
            # Password reset (the view the password reset email links to).
            "reset_password_from_key": "20/m",
            # Signups.
            "signup": "20/m",
            # NOTE: Login is already protected via `LOGIN_ATTEMPTS_LIMIT`
        }
        return self._setting("RATE_LIMITS", dflt)

    @property
    def LOGOUT_ON_PASSWORD_CHANGE(self):
        return self._setting("LOGOUT_ON_PASSWORD_CHANGE", False)

    @property
    def SIGNUP_PASSWORD_VERIFICATION(self):
        """
        Signup password verification
        """
        return self._setting("SIGNUP_PASSWORD_VERIFICATION", True)

    @property
    def SIGNUP_PASSWORD_ENTER_TWICE(self):
        legacy = self._setting("SIGNUP_PASSWORD_VERIFICATION", True)
        return self._setting("SIGNUP_PASSWORD_ENTER_TWICE", legacy)

    @property
    def JWT_AUTH_COOKIE(self):
        return self._setting("JWT_AUTH_COOKIE", "jwt-auth")

    @property
    def JWT_AUTH_SECURE(self):
        return self._setting("JWT_AUTH_SECURE", False)

    @property
    def JWT_AUTH_SAMESITE(self):
        return self._setting("JWT_AUTH_SAMESITE", "Lax")

    @property
    def JWT_AUTH_COOKIE_DOMAIN(self):
        return self._setting("JWT_AUTH_COOKIE_DOMAIN", None)

    @property
    def JWT_AUTH_REFRESH_COOKIE(self):
        return self._setting("JWT_AUTH_REFRESH_COOKIE", "jwt-refresh")

    @property
    def JWT_AUTH_REFRESH_COOKIE_PATH(self):
        return self._setting("JWT_AUTH_REFRESH_COOKIE_PATH", "/")

    @property
    def JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED(self):
        return self._setting("JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED", False)

    @property
    def JWT_AUTH_COOKIE_USE_CSRF(self):
        return self._setting("JWT_AUTH_COOKIE_USE_CSRF", False)

    @property
    def JWT_AUTH_RETURN_EXPIRATION(self):
        return self._setting("JWT_AUTH_RETURN_EXPIRATION", True)

    @property
    def JWT_AUTH_HTTPONLY(self):
        return self._setting("JWT_AUTH_HTTPONLY", False)

    @property
    def TWILIO_ACCOUNT_SID(self):
        return self._setting("TWILIO_ACCOUNT_SID", None)

    @property
    def TWILIO_AUTH_TOKEN(self):
        return self._setting("TWILIO_AUTH_TOKEN", None)

    @property
    def TWILIO_PHONE_NUMBER(self):
        return self._setting("TWILIO_PHONE_NUMBER", None)

    @property
    def DEV_PRINT_SMS(self):
        return self._setting("DEV_PRINT_SMS", True)

    @property
    def SMS_VERIFICATION_MESSAGE(self):
        default_msg = f"Your {self.SITE_NAME} verification OTP is: <otp_code>"
        return self._setting("SMS_VERIFICATION_MESSAGE", default_msg)

    @property
    def SMS_PASSWORD_RESET_MESSAGE(self):
        default_msg = f"Your {self.SITE_NAME} password reset OTP is: <otp_code>"
        return self._setting("SMS_PASSWORD_RESET_MESSAGE", default_msg)


app_settings = AppSettings()
