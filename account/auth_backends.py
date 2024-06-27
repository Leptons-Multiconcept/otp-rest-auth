from django.contrib.auth.backends import ModelBackend

from .app_settings import app_settings
from .utils import (
    get_auth_method_field,
    get_user_by_email,
    get_user_by_phone,
    get_user_by_username,
)


class AuthenticationBackend(ModelBackend):
    def authenticate(self, request, **credentials):
        user = None

        auth_methods = app_settings.AUTHENTICATION_METHODS
        for method in auth_methods:
            if not credentials.get(method):
                continue

            method_value = credentials.get(method)
            auth_method_field = get_auth_method_field(method)
            if auth_method_field == app_settings.USER_MODEL_USERNAME_FIELD:
                # username query is case sensitive if app_settings.PRESERVE_USERNAME_CASING
                # is set to True
                user = get_user_by_username(method_value)
            elif auth_method_field == app_settings.USER_MODEL_EMAIL_FIELD:
                user = get_user_by_email(method_value)
            elif auth_method_field == app_settings.USER_MODEL_PHONE_FIELD:
                user = get_user_by_phone(method_value)

            if not user or not user.check_password(credentials["password"]):
                return None

            return user
