from django.apps import AppConfig


class OtpRestAuthConfig(AppConfig):
    name = "otp_rest_auth"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        import otp_rest_auth.signals
