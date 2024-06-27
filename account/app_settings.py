from django.conf import settings


class AppSettings(object):
    """
    test: AccountType can't be NONE and Verification be required
    test: Serializers passed are serializers
    test: If VerificationType is Account then PHONE and EMAIL must be required and unique
        - If VerificationType is Phone then Phone must be required and unique
        - Same for EMAIL
    """

    class AccountVerificationType:
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

    def _setting(self, attr, default):
        return getattr(settings, attr, default)

    @property
    def VERIFICATION_TYPE(self):
        """
        Account verification method.
        """
        return self._setting("VERIFICATION_TYPE", self.AccountVerificationType.ACCOUNT)

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
        legacy = self.VERIFICATION_TYPE != self.AccountVerificationType.NONE

        return self._setting("VERIFICATION_REQUIRED", legacy)

    @property
    def AUTHENTICATION_METHODS(self):
        return self._setting(
            "AUTHENTICATION_METHOD",
            (
                self.AuthenticationMethods.PHONE,
                self.AuthenticationMethods.EMAIL,
                self.AuthenticationMethods.USERNAME,
            ),
        )

    @property
    def PWD_RESET_OTP_RECIPIENTS(self):
        """
        Where to send password reset OTP to. Phone, Email, or both.
        """
        return self._setting("PWD_RESET_OTP_RECIPIENTS", ("phone", "email"))

    @property
    def JWT_SERIALIZER(self):
        from .serializers import JWTSerializer

        return self._setting("JWT_SERIALIZER", JWTSerializer)

    @property
    def LOGIN_SERIALIZER(self):
        from .serializers import LoginSerializer

        return self._setting("LOGIN_SERIALIZER", LoginSerializer)

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
        from .serializers import RegisterSerializer

        return self._setting("REGISTER_SERIALIZER", RegisterSerializer)

    @property
    def OTP_SERIALIZER(self):
        from .serializers import OTPSerializer

        return self._setting("OTP_SERIALIZER", OTPSerializer)

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
        return self._setting("OTP_EXPIRY_TIME", 3360)

    @property
    def PASSWORD_MIN_LENGTH(self):
        return self._setting("PASSWORD_MIN_LENGTH", 4)

    @property
    def PASSWORD_MAX_LENGTH(self):
        return self._setting("PASSWORD_MAX_LENGTH", 50)

    @property
    def USER_DETAILS_SERIALIZER(self):
        from .serializers import UserDetailsSerializer

        return self._setting("USER_DETAILS_SERIALIZER", UserDetailsSerializer)

    @property
    def JWT_SERIALIZER_WITH_EXPIRATION(self):
        from .serializers import JWTSerializerWithExpiration

        return self._setting(
            "JWT_SERIALIZER_WITH_EXPIRATION", JWTSerializerWithExpiration
        )

    @property
    def LOGIN_UPON_VERIFICATION(self):
        """
        Send JWT to client upon verification
        """
        return self._setting("LOGIN_UPON_VERIFICATION", True)

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


app_settings = AppSettings()
