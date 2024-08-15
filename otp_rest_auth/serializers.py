from rest_framework import serializers
from django.contrib.auth.forms import SetPasswordForm
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model, authenticate
from django.core.exceptions import ObjectDoesNotExist
from phonenumber_field.serializerfields import PhoneNumberField
from django.core.exceptions import ValidationError as DjangoValidationError

from .app_settings import app_settings
from .models import Account, TOTP
from .otp_ops import verify_otp, validate_otp
from .utils import (
    get_user_by_phone,
    get_user_by_email,
    get_user_by_username,
    get_auth_method_field,
)


UserModel = get_user_model()
adapter = app_settings.ADAPTER()


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=app_settings.USERNAME_MAX_LENGTH,
        min_length=app_settings.USERNAME_MIN_LENGTH,
        required=app_settings.USERNAME_REQUIRED,
    )
    phone = serializers.CharField()
    email = serializers.EmailField(required=app_settings.PHONE_REQUIRED)
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not app_settings.SIGNUP_PASSWORD_ENTER_TWICE:
            self.fields.pop("password1")
            self.fields.pop("password2")
            self.fields["password"] = serializers.CharField(write_only=True)

        if (
            app_settings.AuthenticationMethods.PHONE
            not in app_settings.AUTHENTICATION_METHODS
        ):
            self.fields.pop("phone")

        if (
            app_settings.AuthenticationMethods.EMAIL
            not in app_settings.AUTHENTICATION_METHODS
        ):
            self.fields.pop("email")

        if (
            app_settings.AuthenticationMethods.USERNAME
            not in app_settings.AUTHENTICATION_METHODS
        ):
            self.fields.pop("username")

    def validate_username(self, username):
        username = adapter.clean_username(username)
        return username

    def validate_phone(self, phone):
        phone = adapter.clean_phone(phone)
        if app_settings.UNIQUE_PHONE:
            user = get_user_by_phone(phone)
            account = Account.objects.filter(user=user).first()

            if (
                account
                and not account.is_verified
                and app_settings.VERIFICATION_METHOD
                == app_settings.AccountVerificationMethod.PHONE
            ):
                raise serializers.ValidationError(
                    _(
                        "Phone number is not verified. A verification code was sent to your phone. "
                        "Please verify your number or request a new code."
                    )
                )
            elif account and account.is_verified:
                raise serializers.ValidationError(
                    _("A user is already registered with this phone number."),
                )

        return phone

    def validate_email(self, email):
        email = adapter.clean_email(email)
        if app_settings.UNIQUE_EMAIL:
            user = get_user_by_email(email)
            account = Account.objects.filter(user=user).first()

            if (
                account
                and not account.is_verified
                and app_settings.VERIFICATION_METHOD
                == app_settings.AccountVerificationMethod.EMAIL
            ):
                raise serializers.ValidationError(
                    _(
                        "Email address is not verified. A verification code was sent to your email. "
                        "Please verify your email or request a new code."
                    )
                )
            elif account and account.is_verified:
                raise serializers.ValidationError(
                    _("A user is already registered with this e-mail address."),
                )

        return email

    def validate_password1(self, password):
        if app_settings.SIGNUP_PASSWORD_VERIFICATION:
            return adapter.clean_password(password)

    def validate(self, data):
        if app_settings.SIGNUP_PASSWORD_ENTER_TWICE:
            if data["password1"] != data["password2"]:
                raise serializers.ValidationError(
                    _("The two password fields didn't match.")
                )

        if (
            app_settings.VERIFICATION_METHOD
            == app_settings.AccountVerificationMethod.ACCOUNT
        ):
            user_from_email = get_user_by_email(data.get("email"))
            user_from_phone = get_user_by_phone(data.get("phone"))
            if user_from_email or user_from_phone:
                raise serializers.ValidationError(
                    _(
                        "An account already exists with the provided email or phone number. "
                        "Please verify your account or use a different email or phone number."
                    )
                )

        return data

    def get_cleaned_data(self):
        return {
            "username": self.validated_data.get("username", ""),
            "password1": self.validated_data.get("password1", ""),
            "email": self.validated_data.get("email", ""),
            "phone": self.validated_data.get("phone", ""),
        }

    def save(self, request):
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        user = adapter.save_user(request, user, self, commit=False)
        if "password1" in self.cleaned_data:
            try:
                adapter.clean_password(self.cleaned_data["password1"], user=user)
            except DjangoValidationError as exc:
                raise serializers.ValidationError(
                    detail=serializers.as_serializer_error(exc)
                )

        if app_settings.VERIFICATION_REQUIRED:
            user.is_active = False

        user.save()
        return user


class OTPSerializer(serializers.Serializer):
    otp = serializers.IntegerField()


class ResendOTPSerializer(serializers.Serializer):
    phone = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    purpose = serializers.ChoiceField(choices=TOTP.PURPOSE_CHOICES, required=True)

    def validate_phone(self, phone):
        return adapter.clean_phone(phone)

    def validate(self, data):
        if data["purpose"] == TOTP.PURPOSE_ACCOUNT_VERIFICATION:
            if "phone" not in data and "email" not in data:
                raise serializers.ValidationError(
                    _("Either 'phone' or 'email' field is required.")
                )

        if data["purpose"] == TOTP.PURPOSE_EMAIL_VERIFICATION:
            if "email" not in data:
                raise serializers.ValidationError(_('"email" field is required.'))

        if data["purpose"] == TOTP.PURPOSE_PHONE_VERIFICATION:
            if "phone" not in data:
                raise serializers.ValidationError(_('"phone" field is required.'))

        if data["purpose"] == TOTP.PURPOSE_PASSWORD_RESET:
            if (
                "phone" in app_settings.PASSWORD_RESET_OTP_RECIPIENTS
                and "email" in app_settings.PASSWORD_RESET_OTP_RECIPIENTS
            ):
                if "phone" not in data and "email" not in data:
                    raise serializers.ValidationError(
                        _("Either 'phone' or 'email' field is required.")
                    )
            elif "phone" in app_settings.PASSWORD_RESET_OTP_RECIPIENTS:
                if "phone" not in data:
                    raise serializers.ValidationError(_("'phone' field is required."))
            elif "email" in app_settings.PASSWORD_RESET_OTP_RECIPIENTS:
                if "email" not in data:
                    raise serializers.ValidationError(_("'email' field is required."))

        return super().validate(data)


class UserDetailsSerializer(serializers.ModelSerializer):
    """
    User model w/o password
    """

    @staticmethod
    def validate_username(username):
        username = adapter.clean_username(username)
        return username

    class Meta:
        extra_fields = []
        # see https://github.com/iMerica/dj-rest-auth/issues/181
        # UserModel.XYZ causing attribute error while importing other
        # classes from `serializers.py`. So, we need to check whether the auth model has
        # the attribute or not
        if hasattr(UserModel, "USERNAME_FIELD"):
            extra_fields.append(UserModel.USERNAME_FIELD)
        if hasattr(UserModel, "EMAIL_FIELD"):
            extra_fields.append(UserModel.EMAIL_FIELD)
        if hasattr(UserModel, app_settings.USER_MODEL_PHONE_FIELD):
            extra_fields.append(app_settings.USER_MODEL_PHONE_FIELD)
        if hasattr(UserModel, "first_name"):
            extra_fields.append("first_name")
        if hasattr(UserModel, "last_name"):
            extra_fields.append("last_name")
        model = UserModel
        fields = ("pk", *extra_fields)
        read_only_fields = ("email", "phone")


class JWTSerializer(serializers.Serializer):
    """
    Serializer for JWT authentication.
    """

    access = serializers.CharField()
    refresh = serializers.CharField()
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
        """
        Required to allow using custom USER_DETAILS_SERIALIZER in
        JWTSerializer. Defining it here to avoid circular imports
        """
        JWTUserDetailsSerializer = app_settings.USER_DETAILS_SERIALIZER

        user_data = JWTUserDetailsSerializer(obj["user"], context=self.context).data
        return user_data


class JWTSerializerWithExpiration(JWTSerializer):
    """
    Serializer for JWT authentication with expiration times.
    """

    access_expiration = serializers.DateTimeField()
    refresh_expiration = serializers.DateTimeField()


class LoginSerializer(serializers.Serializer):
    phone = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(style={"input_type": "password"})

    def __init__(self, instance=None, data=..., **kwargs):
        super().__init__(instance, data, **kwargs)

        if (
            app_settings.AuthenticationMethods.USERNAME
            not in app_settings.AUTHENTICATION_METHODS
        ):
            self.fields.pop("username")
        if (
            app_settings.AuthenticationMethods.PHONE
            not in app_settings.AUTHENTICATION_METHODS
        ):
            self.fields.pop("phone")
        if (
            app_settings.AuthenticationMethods.EMAIL
            not in app_settings.AUTHENTICATION_METHODS
        ):
            self.fields.pop("email")

    def authenticate(self, **kwargs):
        return authenticate(self.context["request"], **kwargs)

    def validate_phone(self, phone):
        return adapter.clean_phone(phone)

    def get_user(self, data):
        auth_methods = app_settings.AUTHENTICATION_METHODS
        credentials = {}

        for method in auth_methods:
            if data.get(method) and data.get("password"):
                credentials[method] = data.get(method)
                credentials["password"] = data.get("password")
                break

        if not credentials:
            if len(auth_methods) == 1:
                msg = _(f'Must include "{auth_methods[0]}" and "password".')
            else:
                auth_methods_str = (
                    '", "'.join(auth_methods[:-1]) + f'", or "{auth_methods[-1]}"'
                )
                auth_methods_str = f'"{auth_methods_str}'
                msg = _(f'Must include either {auth_methods_str} and "password".')
            raise serializers.ValidationError(msg)

        user = self.authenticate(**credentials)
        return user

    @staticmethod
    def validate_auth_user_status(user):
        if not user.is_active:
            msg = _("User account is disabled.")
            raise serializers.ValidationError(msg)

    @staticmethod
    def validate_verification_type_status(user):
        user_account = Account.objects.filter(user=user).first()
        if not user_account:
            raise ObjectDoesNotExist(
                "The related Account instance for this user does not exist."
            )

        if app_settings.VERIFICATION_REQUIRED:
            verification_type = app_settings.VERIFICATION_METHOD
            if (
                verification_type == app_settings.AccountVerificationMethod.ACCOUNT
                and not user_account.is_verified
            ):
                raise serializers.ValidationError(_("Account is not verified."))
            if (
                verification_type == app_settings.AccountVerificationMethod.EMAIL
                and not user_account.email_verified
            ):
                raise serializers.ValidationError(_("E-mail is not verified."))
            if (
                verification_type == app_settings.AccountVerificationMethod.PHONE
                and not user_account.phone_verified
            ):
                raise serializers.ValidationError(_("Phone number is not verified."))

    def validate(self, attrs):
        user = self.get_user(attrs)
        if not user:
            msg = _("Unable to log in with provided credentials.")
            raise serializers.ValidationError(msg)

        self.validate_verification_type_status(user)
        self.validate_auth_user_status(user)

        attrs["user"] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class PasswordResetSerializer(serializers.Serializer):
    phone = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)

    def get_user(self, data):
        user = None
        requried_auth_method_provided = False

        auth_methods = app_settings.AUTHENTICATION_METHODS
        for method in auth_methods:
            if data.get(method):
                method_value = data.get(method)
                if method_value:
                    requried_auth_method_provided = True
                else:
                    continue

                method_field = get_auth_method_field(method)

                if method_field == app_settings.USER_MODEL_USERNAME_FIELD:
                    user = get_user_by_username(method_value)
                elif method_field == app_settings.USER_MODEL_EMAIL_FIELD:
                    user = get_user_by_email(method_value)
                elif method_field == app_settings.USER_MODEL_PHONE_FIELD:
                    user = get_user_by_phone(method_value)

                if user:
                    break

        if not requried_auth_method_provided:
            if len(auth_methods) == 1:
                msg = _(f'Must include "{auth_methods[0]}".')
            else:
                auth_methods_str = (
                    '", "'.join(auth_methods[:-1]) + f'", or "{auth_methods[-1]}"'
                )
                auth_methods_str = f'"{auth_methods_str}'
                msg = _(f"Must include either {auth_methods_str}.")
            raise serializers.ValidationError(msg)

        return user

    def validate_phone(self, phone):
        return adapter.clean_phone(phone)

    def validate(self, attrs):
        user = self.get_user(attrs)
        attrs["user"] = user

        return attrs


class PasswordResetConfirmSerializer(serializers.Serializer):
    otp = serializers.IntegerField()
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    totp = None
    set_password_form = None

    def validate_otp(self, otp):
        try:
            is_valid, self.totp = validate_otp(otp, TOTP.PURPOSE_PASSWORD_RESET)
            if not is_valid:
                raise serializers.ValidationError(_("Invalid OTP."))

        except TOTP.DoesNotExist:
            raise serializers.ValidationError(_("Invalid OTP."))

    def validate(self, data):
        self.set_password_form = SetPasswordForm(
            user=self.totp.user,
            data=data,
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)

        return data

    def save(self):
        verify_otp(self.totp.otp, TOTP.PURPOSE_PASSWORD_RESET)
        return self.set_password_form.save()


class PasswordChangeSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    set_password_form = None

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = app_settings.OLD_PASSWORD_FIELD_ENABLED
        self.logout_on_password_change = app_settings.LOGOUT_ON_PASSWORD_CHANGE
        super().__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop("old_password")

        if not self.logout_on_password_change:
            self.fields.pop("refresh")

        self.request = self.context.get("request")
        self.user = getattr(self.request, "user", None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value),
        )

        if all(invalid_password_conditions):
            err_msg = _(
                "Your old password was entered incorrectly. Please enter it again."
            )
            raise serializers.ValidationError(err_msg)
        return value

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(
            user=self.user,
            data=attrs,
        )

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        self.set_password_form.save()


class ChangeEmailSerializer(serializers.Serializer):
    new_email = serializers.EmailField()

    def validate_new_email(self, new_email):
        email_field = app_settings.USER_MODEL_EMAIL_FIELD
        if app_settings.UNIQUE_EMAIL:
            if UserModel.objects.filter(**{email_field: new_email}).exists():
                raise serializers.ValidationError("Email address already exists.")
        return new_email


class ChangePhoneSerializer(serializers.Serializer):
    new_phone = PhoneNumberField()

    def validate_new_email(self, new_phone):
        phone_field = app_settings.USER_MODEL_PHONE_FIELD
        if app_settings.UNIQUE_PHONE:
            if UserModel.objects.filter(**{phone_field: new_phone}).exists():
                raise serializers.ValidationError("Phone number already exists.")
        return new_phone


class ChangeEmailConfirmSerializer(serializers.Serializer):
    otp = serializers.IntegerField()


class ChangePhoneConfirmSerializer(serializers.Serializer):
    otp = serializers.IntegerField()
