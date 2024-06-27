from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model, authenticate
from django.core.exceptions import ValidationError as DjangoValidationError
from phonenumber_field.serializerfields import PhoneNumberField

from .app_settings import app_settings
from .adapter import DefaultAccountAdapter
from .models import Account, TOTP
from .utils import get_user_by_phone, get_user_by_email


UserModel = get_user_model()
adapter = DefaultAccountAdapter()


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=app_settings.USERNAME_MAX_LENGTH,
        min_length=app_settings.USERNAME_MIN_LENGTH,
        required=app_settings.USERNAME_REQUIRED,
    )
    phone = serializers.CharField(required=app_settings.EMAIL_REQUIRED)
    email = serializers.EmailField(required=app_settings.PHONE_REQUIRED)
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(
        write_only=True, required=app_settings.SIGNUP_PASSWORD_ENTER_TWICE
    )

    def validate_username(self, username):
        username = adapter.clean_username(username)
        return username

    def validate_phone(self, phone):
        phone = adapter.clean_phone(phone)
        if app_settings.UNIQUE_PHONE:
            user = get_user_by_phone(phone)
            if user:
                account = Account.objects.filter(user=user).first()
                if (
                    account
                    and account.is_verified
                    or app_settings.VERIFICATION_TYPE
                    == app_settings.AccountVerificationType.NONE
                ):
                    raise serializers.ValidationError(
                        _("A user is already registered with this phone number."),
                    )
        return phone

    def validate_email(self, email):
        email = adapter.clean_email(email)
        if app_settings.UNIQUE_EMAIL:
            user = get_user_by_email(email)
            if user:
                account = Account.objects.filter(user=user).first()
                if (
                    account
                    and account.is_verified
                    or app_settings.VERIFICATION_TYPE
                    == app_settings.AccountVerificationType.NONE
                ):
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
            if "phone" not in data:
                raise serializers.ValidationError(_('"phone" field is required.'))
            if "email" not in data:
                raise serializers.ValidationError(_('"email" field is required.'))

        if data["purpose"] == TOTP.PURPOSE_EMAIL_VERIFICATION:
            if "email" not in data:
                raise serializers.ValidationError(_('"email" field is required.'))

        if data["purpose"] == TOTP.PURPOSE_PHONE_VERIFICATION:
            if "phone" not in data:
                raise serializers.ValidationError(_('"phone" field is required.'))

        if data["purpose"] == TOTP.PURPOSE_PASSWORD_RESET:
            if "phone" in app_settings.PWD_RESET_OTP_RECIPIENTS:
                if "phone" not in data:
                    raise serializers.ValidationError(_("'phone' field is required."))
            if "email" in app_settings.PWD_RESET_OTP_RECIPIENTS:
                if "email" not in data:
                    raise serializers.ValidationError(_('"email" field is required.'))

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
        if hasattr(UserModel, "PHONE_FIELD"):
            extra_fields.append(UserModel.PHONE_FIELD)
        if hasattr(UserModel, "first_name"):
            extra_fields.append("first_name")
        if hasattr(UserModel, "last_name"):
            extra_fields.append("last_name")
        model = UserModel
        fields = ("pk", *extra_fields)
        read_only_fields = ("email",)


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

        print("USER USER: ", obj)
        user_data = JWTUserDetailsSerializer(obj["user"], context=self.context).data
        return user_data


class JWTSerializerWithExpiration(JWTSerializer):
    """
    Serializer for JWT authentication with expiration times.
    """

    access_expiration = serializers.DateTimeField()
    refresh_expiration = serializers.DateTimeField()


class LoginSerializer(serializers.Serializer):
    phone = PhoneNumberField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(style={"input_type": "password"})

    def authenticate(self, **kwargs):
        return authenticate(self.context["request"], **kwargs)

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
                msg = _(f'Must include "{method}" and "password".')
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
        if app_settings.VERIFICATION_REQUIRED:
            verification_type = app_settings.VERIFICATION_TYPE
            if (
                verification_type == app_settings.AccountVerificationType.ACCOUNT
                and not user_account.is_verified
            ):
                raise serializers.ValidationError(_("Account is not verified."))
            if (
                verification_type == app_settings.AccountVerificationType.EMAIL
                and not user_account.email_verified
            ):
                raise serializers.ValidationError(_("E-mail is not verified."))
            if (
                verification_type == app_settings.AccountVerificationType.PHONE
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
