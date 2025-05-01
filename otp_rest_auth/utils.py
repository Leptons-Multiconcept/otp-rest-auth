from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import FieldDoesNotExist

from .app_settings import app_settings


def user_field(user, field, *args, commit=False):
    """
    Gets or sets (optional) user model fields. No-op if fields do not exist.
    """
    if not field:
        return
    User = get_user_model()
    try:
        field_meta = User._meta.get_field(field)
        max_length = field_meta.max_length
    except FieldDoesNotExist:
        if not hasattr(user, field):
            return
        max_length = None
    if args:
        # Setter
        v = args[0]
        if v:
            v = v[0:max_length]
        setattr(user, field, v)
        if commit:
            user.save(update_fields=[field])
    else:
        # Getter
        return getattr(user, field)


def user_username(user, *args, commit=False):
    if args and not app_settings.PRESERVE_USERNAME_CASING and args[0]:
        args = [args[0].lower()]
    return user_field(user, app_settings.USER_MODEL_USERNAME_FIELD, *args)


def user_email(user, *args, commit=False):
    return user_field(user, app_settings.USER_MODEL_EMAIL_FIELD, *args, commit=commit)


def user_phone(user, *args, commit=False):
    return user_field(user, app_settings.USER_MODEL_PHONE_FIELD, *args, commit=commit)


def get_user_by_phone(phone: str, extra: dict):
    """
    Get user by phone number and other unique constriant fields.
    :param phone: Phone number
    :param extra: Dict containing unique constraint fields, if any.
    :return: User object if found, else None
    """
    if not app_settings.UNIQUE_EMAIL:
        return None

    User = get_user_model()

    filter_fields = {}
    const_fields = app_settings.get_user_unique_constraint_fields()
    if "phone" in const_fields:
        [
            filter_fields.update({field: extra[field]})
            for field in const_fields
            if field != "phone" and extra.get(field)
        ]

    phone_field = app_settings.USER_MODEL_PHONE_FIELD
    res = User.objects.filter(**{phone_field: phone, **filter_fields})

    return res.first()


def get_user_by_email(email: str, extra: dict):
    """
    Get user by email and other unique constriant fields.
    :param email: Email
    :param extra: Dict containing unique constraint fields, if any.
    :return: User object or None
    """
    if not app_settings.UNIQUE_EMAIL:
        return None

    User = get_user_model()

    filter_fields = {}
    const_fields = app_settings.get_user_unique_constraint_fields()
    if "email" in const_fields:
        [
            filter_fields.update({field: extra[field]})
            for field in const_fields
            if field != "email" and extra.get(field)
        ]

    email_field = app_settings.USER_MODEL_EMAIL_FIELD
    res = User.objects.filter(**{email_field: email, **filter_fields})

    return res.first()


def get_user_by_username(username: str, extra: dict):
    """
    Get user by username and other unique constriant fields.
    :param username: Username
    :param extra: Dict containing unique constraint fields, if any.
    :return: User object or None
    """
    if not app_settings.UNIQUE_EMAIL:
        return None

    User = get_user_model()

    filter_fields = {}
    const_fields = app_settings.get_user_unique_constraint_fields()
    if "username" in const_fields:
        [
            filter_fields.update({field: extra[field]})
            for field in const_fields
            if field.lower() != "username" and extra.get(field)
        ]

    username_field = app_settings.USER_MODEL_USERNAME_FIELD
    if app_settings.PRESERVE_USERNAME_CASING:
        res = User.objects.filter(**{username_field: username, **filter_fields})
    else:
        res = User.objects.filter(
            **{username_field + "__iexact": username.lower(), **filter_fields}
        )

    return res.first()


def get_auth_method_field(auth_method):
    auth_methods = {}
    for method in app_settings.AUTHENTICATION_METHODS:
        if method == app_settings.AuthenticationMethods.PHONE:
            phone = app_settings.AuthenticationMethods.PHONE
            auth_methods[phone] = app_settings.USER_MODEL_PHONE_FIELD

        if method == app_settings.AuthenticationMethods.EMAIL:
            email = app_settings.AuthenticationMethods.EMAIL
            auth_methods[email] = app_settings.USER_MODEL_EMAIL_FIELD

        if method == app_settings.AuthenticationMethods.USERNAME:
            username = phone = app_settings.AuthenticationMethods.USERNAME
            auth_methods[username] = app_settings.USER_MODEL_USERNAME_FIELD

    return auth_methods.get(auth_method)


def get_throttle_scope(throttle_key):
    rest_config = getattr(settings, "REST_FRAMEWORK", None)
    if rest_config:
        throttle_rates = rest_config.get("DEFAULT_THROTTLE_RATES", {})
        scope = throttle_rates.get(throttle_key, None)
        return throttle_key if scope else ""

    return ""
