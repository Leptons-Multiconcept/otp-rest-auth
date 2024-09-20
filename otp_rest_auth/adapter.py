from django import forms
from django.conf import settings
from django.utils.text import slugify
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from django.template import TemplateDoesNotExist
from django.core.validators import RegexValidator
from django.template.loader import render_to_string
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.contrib.auth.password_validation import validate_password

from .app_settings import app_settings


class DefaultAccountAdapter(object):
    error_messages = {
        "username_blacklisted": _(
            "Username can not be used. Please use other username."
        ),
        "username_taken": AbstractUser._meta.get_field("username").error_messages[
            "unique"
        ],
        "too_many_login_attempts": _(
            "Too many failed login attempts. Try again later."
        ),
        "email_taken": _("A user is already registered with this email address."),
        "enter_current_password": _("Please type your current password."),
        "incorrect_password": _("Incorrect password."),
        "password_min_length": _("Password must be a minimum of {0} characters."),
        "unknown_email": _("The email address is not assigned to any user account"),
    }

    def new_user(self, request):
        """
        Instantiates a new User instance.
        """
        user = get_user_model()()
        return user

    def generate_unique_username(self, components):
        User = get_user_model()
        base_username = components[-1]  # Last element as fallback

        # Generate a base username from components
        if components[3]:  # Check if username is provided
            base_username = components[3]
        elif components[2]:  # Check if email is provided
            base_username = components[2].split("@")[0]
        elif (
            components[0] and components[1]
        ):  # Check if first_name and last_name are provided
            base_username = slugify(components[0][:30] + " " + components[1][:30])
        elif components[0]:  # Check if only first_name is provided
            base_username = slugify(components[0][:30])
        elif components[1]:  # Check if only last_name is provided
            base_username = slugify(components[1][:30])

        # Ensure uniqueness of username
        username = base_username
        suffix = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{suffix}"
            suffix += 1

        return username

    def populate_username(self, request, user):
        """
        Fills in a valid username, if required and missing.  If the
        username is already present it is assumed to be valid
        (unique).
        """
        from .utils import user_email, user_field, user_username

        first_name = user_field(user, "first_name")
        last_name = user_field(user, "last_name")
        email = user_email(user)
        username = user_username(user)
        if app_settings.USER_MODEL_USERNAME_FIELD:
            user_username(
                user,
                username
                or self.generate_unique_username(
                    [first_name, last_name, email, username, "user"]
                ),
            )

    def save_user(self, request, user, form, commit=True):
        """
        Saves a new `User` instance using information provided in the
        signup form.
        """
        from .utils import user_email, user_field, user_username, user_phone

        data = form.cleaned_data
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        email = data.get("email")
        phone = data.get("phone")
        username = data.get("username")
        user_email(user, email)
        user_phone(user, phone)
        user_username(user, username)
        if first_name:
            user_field(user, "first_name", first_name)
        if last_name:
            user_field(user, "last_name", last_name)
        if "password1" in data:
            user.set_password(data["password1"])
        else:
            user.set_unusable_password()
        self.populate_username(request, user)
        if commit:
            # Ability not to commit makes it easier to derive from
            # this adapter by adding
            user.save()
        return user

    def clean_username(self, username, shallow=False):
        """
        Validates the username. This method allows for dynamic restrictions on
        username selection.
        """
        # Apply all validators from settings
        for validator in app_settings.USERNAME_VALIDATORS:
            validator(username)

        # Check against blacklisted usernames
        username_blacklist_lower = [
            ub.lower() for ub in app_settings.USERNAME_BLACKLIST
        ]
        if username.lower() in username_blacklist_lower:
            raise forms.ValidationError(self.error_messages["username_blacklisted"])

        # If shallow validation, skip database lookup
        if not shallow:
            user_model = get_user_model()
            username_field = app_settings.USER_MODEL_USERNAME_FIELD

            # Filtering users by username
            filter_kwargs = {username_field + "__iexact": username}
            if user_model.objects.filter(**filter_kwargs).exists():
                error_message = user_model._meta.get_field(
                    username_field
                ).error_messages.get("unique")

                if not error_message:
                    error_message = self.error_messages["username_taken"]

                raise forms.ValidationError(
                    error_message,
                    params={
                        "model_name": user_model.__name__,
                        "field_label": username_field,
                    },
                )

        return username

    def clean_email(self, email):
        """
        Validates an email value. You can hook into this if you want to
        (dynamically) restrict what email addresses can be chosen.
        """
        return email

    def clean_phone(self, phone):
        """
        Validates a phone value.
        """
        from django.core.exceptions import ValidationError
        from phonenumber_field.serializerfields import PhoneNumber
        from phonenumbers.phonenumberutil import NumberParseException
        from phonenumber_field.validators import validate_international_phonenumber

        try:
            phone_number = PhoneNumber.from_string(phone)
            validate_international_phonenumber(phone_number)
        except NumberParseException:
            raise ValidationError(
                _("The phone number entered is not valid."), code="invalid_phone_number"
            )

        return phone

    def clean_password(self, password, user=None):
        """
        Validates a password. You can hook into this if you want to
        restric the allowed password choices.
        """
        min_length = app_settings.PASSWORD_MIN_LENGTH
        if min_length and len(password) < min_length:
            raise forms.ValidationError(
                self.error_message["password_min_length"].format(min_length)
            )
        validate_password(password, user)
        return password

    def format_email_subject(self, subject):
        prefix = app_settings.EMAIL_SUBJECT_PREFIX
        if prefix is None:
            return subject

        prefix = f"{prefix} "
        return prefix + force_str(subject)

    def render_mail(self, template_prefix, email, context, headers=None):
        """
        Renders an email to `email`.  `template_prefix` identifies the
        email that is to be sent, e.g. "account/email/email_confirmation"
        """
        to = [email] if isinstance(email, str) else email
        subject = render_to_string("{0}_subject.txt".format(template_prefix), context)
        # remove superfluous line breaks
        subject = " ".join(subject.splitlines()).strip()
        subject = self.format_email_subject(subject)

        from_email = settings.DEFAULT_FROM_EMAIL

        bodies = {}
        html_ext = app_settings.TEMPLATE_EXTENSION
        for ext in [html_ext, "txt"]:
            try:
                template_name = "{0}_message.{1}".format(template_prefix, ext)
                bodies[ext] = render_to_string(
                    template_name,
                    context,
                ).strip()
            except TemplateDoesNotExist:
                if ext == "txt" and not bodies:
                    # We need at least one body
                    raise
        if "txt" in bodies:
            msg = EmailMultiAlternatives(
                subject, bodies["txt"], from_email, to, headers=headers
            )
            if html_ext in bodies:
                msg.attach_alternative(bodies[html_ext], "text/html")
        else:
            msg = EmailMessage(
                subject, bodies[html_ext], from_email, to, headers=headers
            )
            msg.content_subtype = "html"  # Main content is now text/html
        return msg

    def send_mail(self, template_prefix, email, context):
        msg = self.render_mail(template_prefix, email, context)
        msg.send()

    def send_otp_to_email(self, totp, email):
        from .models import TOTP

        ctx = {
            "user": totp.user,
            "otp_code": totp.otp,
            "site_name": app_settings.SITE_NAME,
        }

        if totp.purpose == TOTP.PURPOSE_EMAIL_VERIFICATION:
            email_template = "account/email/email_confirmation"
        if totp.purpose == TOTP.PURPOSE_ACCOUNT_VERIFICATION:
            email_template = "account/email/account_confirmation"
        if totp.purpose == TOTP.PURPOSE_PASSWORD_RESET:
            email_template = "account/email/password_reset"

        self.send_mail(email_template, email, ctx)

    def send_otp_to_user_email(self, totp):
        email = getattr(totp.user, app_settings.USER_MODEL_EMAIL_FIELD)
        return self.send_otp_to_email(totp, email)

    def send_otp_to_phone(self, totp, phone):
        from twilio.rest import Client
        from .models import TOTP

        sms_msg = app_settings.SMS_VERIFICATION_MESSAGE
        if totp.purpose == TOTP.PURPOSE_PASSWORD_RESET:
            sms_msg = app_settings.SMS_PASSWORD_RESET_MESSAGE

        if "<otp_code>" in sms_msg:
            sms_msg = sms_msg.replace("<otp_code>", str(totp.otp))
        else:
            sms_msg = f"{sms_msg} {totp.otp}"

        if app_settings.DEV_PRINT_SMS:
            print(f"[SMS] {sms_msg}")
            return

        client = Client(app_settings.TWILIO_ACCOUNT_SID, app_settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=sms_msg,
            from_=app_settings.TWILIO_PHONE_NUMBER,
            to=phone,
        )
        return message.sid

    def send_otp_to_user_phone(self, totp):
        phone = getattr(totp.user, app_settings.USER_MODEL_PHONE_FIELD)
        return self.send_otp_to_phone(totp, phone)
