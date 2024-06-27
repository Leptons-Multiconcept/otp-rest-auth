# Generated by Django 5.0.6 on 2024-06-24 08:57

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='totp',
            name='account',
        ),
        migrations.AddField(
            model_name='totp',
            name='_otp',
            field=models.IntegerField(default=2135),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='totp',
            name='user',
            field=models.ForeignKey(default=1235, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
    ]