Installation
============

1. Install the package:
```
pip install otp_rest_auth
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
    # `otp-rest-auth` specific authentication methods, such as login by email, phone, and username
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
