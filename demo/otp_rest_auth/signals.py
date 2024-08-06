from django.dispatch import receiver, Signal
from django.db.models.signals import post_save
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_out  # noqa


User = get_user_model()


@receiver(post_save, sender=User)
def create_user_account(sender, instance, created, **kwargs):
    if created:
        from .models import Account

        acc = Account.objects.create(user=instance)
        acc.save()


# Provides the arguments "request", "user"
user_logged_in = Signal()

# Typically followed by `user_logged_in` (unless, email verification kicks in)
# Provides the arguments "request", "user"
user_signed_up = Signal()

# Provides the arguments "request", "user"
password_set = Signal()
# Provides the arguments "request", "user"
password_changed = Signal()
# Provides the arguments "request", "user"
password_reset = Signal()

# Provides the arguments "request", "user"
account_confirmed = Signal()
# Provides the arguments "request", "confirmation", "signup"
account_confirmation_sent = Signal()

# Provides the arguments "request", "phone_number"
phone_confirmed = Signal()
# Provides the arguments "request", "confirmation", "signup"
phone_confirmation_sent = Signal()

# Provides the arguments "request", "email_address"
email_confirmed = Signal()
# Provides the arguments "request", "confirmation", "signup"
email_confirmation_sent = Signal()

# Provides the arguments "request", "user", "from_email_address",
# "to_email_address"
email_changed = Signal()
# Provides the arguments "request", "user", "email_address"
email_added = Signal()
# Provides the arguments "request", "user", "email_address"
email_removed = Signal()

# Internal/private signal.
_add_email = Signal()
