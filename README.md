# Django OTP REST Auth

Welcome to the OTP Authentication App for Django. This app provides a seamless way to integrate One-Time Password (OTP) based authentication into your Django projects. Built specifically to complement Django Rest Framework and Django Allauth, which lack native OTP authentication support, this app fills the gap by offering robust and secure OTP functionalities.

## Requirements ⛓️
Django 3, 4 and 5  
Python >= 3.8

## Quick Setup 🏃‍♂️‍➡️
1. Install the package:
```
pip install django_otp_rest_auth
```
2. Add `otp_rest_auth` app to INSTALLED_APPS in your django settings.py:
```
NSTALLED_APPS = (
    ...,
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    ...,
    'otp_rest_auth'
)
```
Note: You don't need to install the apps listed above separately, as they are installed automatically
when `otp_rest_auth` is installed. However, it's important to add them to INSTALLED_APPS since `otp_rest_auth` requires them.

3. Add app backend to AUTHENTICATION_BACKENDS:
```
AUTHENTICATION_BACKENDS = [
    ...
    'django.contrib.auth.backends.ModelBackend',
    ...,
    'otp_rest_auth.auth_backends.AuthenticationBackend',
    ...
]
```
4. Add Add otp_rest_aut` urls:
```
urlpatterns = [
    ...,
    path('otp-rest-auth/', include('otp_rest_auth.urls'))
]
```
5. Migrate your database:
```
python manage.py migrate
```
Now, you're good to go!

## Features

🔑 **Comprehensive Account Management**  
Offers versatile account functionality, supporting multiple authentication methods (e.g., login by username, email, or phone) and flexible account verification strategies, from optional to mandatory account, email, or phone verification.  

🔒 **Enhanced Privacy**  
Prevents information leaks common on many sites. For instance, where many platforms allow users to check if an email is registered through password reset or signup forms, this solution includes account enumeration prevention, ensuring privacy by making it impossible to determine if an account exists.

🧩 **Fully Customizable**  
Provides developers with extensive flexibility to adapt core functionalities to meet specific needs. Using the adapter pattern, you can easily introduce modifications at targeted points, enabling precise customization that aligns with unique requirements.
