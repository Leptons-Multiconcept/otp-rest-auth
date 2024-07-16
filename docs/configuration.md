# Configuration
Place the following configuration options in your settings.py under the `OTP_REST_AUTH dictionary.

***`ADAPTER` (default: `"otp_rest_auth.adapter.DefaultAccountAdapter"`)***  
Specifies the adapter class to use, enabling you to modify certain default behaviors.

***`VERIFICATION_TYPE` (default: `"account"` alternatives: `"email"` or `"phone"`)***  
Specifies the method to verify a user. If set to `account`, verification OTP is sent to the user's email and phone number.

***`VERIFICATION_REQUIRED` (default: `True`)***  
By setting this to `True`, a user will remain inactive and unable to log in until verified.

***`AUTHENTICATION_METHODS` (default: `('phone', 'email', 'username')`)***  
A tuple/list specifying the fields a user can use to log in.

***`PASSWORD_RESET_OTP_RECIPIENTS` (default: `('phone', 'email')`)***  
A tuple/list specifying the device(s) to which the password reset OTP will be sent.

***`PASSWORD_RESET_OTP_EXPIRY_TIME` (default: `90`)***  
Specifies the expiration time in seconds for the password reset OTP.

***`PASSWORD_RESET_CONFIRM_SERIALIZER` (default: `otp_rest_auth.serializers.PasswordResetConfirmSerializer`)***  
Specifies the path to the serializer class for the password reset confirmation view.

***`PASSWORD_RESET_SERIALIZER` (default: `otp_rest_auth.serializers.PasswordResetSerializer`)***  
Specifies the path to the serializer class for the password reset view.

***`PASSWORD_CHANGE_SERIALIZER` (default: `otp_rest_auth.serializers.PasswordChangeSerializer`)***  
Specifies the path to the serializer class for the password change view.

***`OLD_PASSWORD_FIELD_ENABLED` (default: `False`)***  
Sets the requirement for a user to enter their previous password when changing their password.

***`JWT_SERIALIZER` (default: `otp_rest_auth.serializers.JWTSerializer`)***  
Specifies the path to the serializer class for the JWT serializer.

***`LOGIN_SERIALIZER` (default: `otp_rest_auth.serializers.LoginSerializer`)***  
Specifies the path to the serializer class for the login view.

***`UNIQUE_PHONE` (default: `True`)***  
Enforces the uniqueness of phone numbers.

***`UNIQUE_EMAIL` (default: `True`)***  
Enforces the uniqueness of email addresses.

***`EMAIL_REQUIRED` (default: `True`)***  
Requires the user to provide an email address when signing up.

***`PHONE_REQUIRED` (default: `True`)***  
Requires the user to provide a phone number when signing up.

***`USERNAME_REQUIRED` (default: `False`)***  
Specifies whether a username is required when signing up.

***`USERNAME_BLACKLIST` (default: `[]`)***  
A list of usernames that are not allowed.

***`USERNAME_MIN_LENGTH` (default: `3`)***  
Specifies the minimum length for usernames.

***`USERNAME_MAX_LENGTH` (default: `15`)***  
Specifies the maximum length for usernames.

***`PRESERVE_USERNAME_CASING` (default: `False`)***  
Specifies whether to preserve the casing of usernames.

***`USERNAME_VALIDATORS` (default: `[]`)***  
A list of validators for usernames.

***`USER_MODEL_USERNAME_FIELD` (default: `username`)***  
Specifies the username field in the user model.

***`USER_MODEL_EMAIL_FIELD` (default: `email`)***  
Specifies the email field in the user model.

***`USER_MODEL_PHONE_FIELD` (default: `phone`)***  
Specifies the phone field in the user model.

***`REGISTER_SERIALIZER` (default: `otp_rest_auth.serializers.RegisterSerializer`)***  
Specifies the path to the serializer class for the registration view.

***`OTP_SERIALIZER` (default: `otp_rest_auth.serializers.OTPSerializer`)***  
Specifies the path to the serializer class for OTP handling.

***`REGISTER_PERMISSION_CLASSES` (default: `[]`)***  
Specifies the permission classes for the registration view.

***`SITE_NAME` (default: `DjangoApp`)***  
Specifies the name of the site.

***`TEMPLATE_EXTENSION` (default: `html`)***  
Specifies the template extension to use.

***`EMAIL_SUBJECT_PREFIX` (default: `None`)***  
Specifies the subject-line prefix to use for email messages sent.

***`OTP_LENGTH` (default: `6`)***  
Specifies the number of digits in OTP.

***`OTP_EXPIRY_TIME` (default: `90`)***  
Specifies the expiration time for OTP in seconds.

***`PASSWORD_MIN_LENGTH` (default: `4`)***  
Specifies the minimum length for passwords.

***`PASSWORD_MAX_LENGTH` (default: `50`)***  
Specifies the maximum length for passwords.

***`USER_DETAILS_SERIALIZER` (default: `otp_rest_auth.serializers.UserDetailsSerializer`)***  
Specifies the path to the serializer class for user details.

***`JWT_SERIALIZER_WITH_EXPIRATION` (default: `otp_rest_auth.serializers.JWTSerializerWithExpiration`)***  
Specifies the path to the serializer class for JWT with expiration.

***`LOGIN_UPON_VERIFICATION` (default: `False`)***  
Specifies whether to log in the user upon verification.

***`LOGOUT_ON_PASSWORD_CHANGE` (default: `False`)***  
Specifies whether to log out the user upon password change.

***`SIGNUP_PASSWORD_VERIFICATION` (default: `True`)***  
Specifies whether to verify the password during signup.

***`SIGNUP_PASSWORD_ENTER_TWICE` (default: `True`)***  
Specifies whether to enter the password twice during signup.

***`JWT_AUTH_COOKIE` (default: `jwt-auth`)***  
Specifies the name of the JWT auth cookie.

***`JWT_AUTH_SECURE` (default: `False`)***  
Specifies whether the JWT auth cookie is secure.

***`JWT_AUTH_SAMESITE` (default: `Lax`)***  
Specifies the SameSite attribute of the JWT auth cookie.

***`JWT_AUTH_COOKIE_DOMAIN` (default: `None`)***  
Specifies the domain for the JWT auth cookie.

***`JWT_AUTH_REFRESH_COOKIE` (default: `jwt-refresh`)***  
Specifies the name of the JWT refresh cookie.

***`JWT_AUTH_REFRESH_COOKIE_PATH` (default: `/`)***  
Specifies the path for the JWT refresh cookie.

***`JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED` (default: `False`)***  
Specifies whether to enforce CSRF on unauthenticated requests.

***`JWT_AUTH_COOKIE_USE_CSRF` (default: `False`)***  
Specifies whether to use CSRF with the JWT auth cookie.

***`JWT_AUTH_RETURN_EXPIRATION` (default: `True`)***  
Specifies whether to include the expiration time in the login response.

***`JWT_AUTH_HTTPONLY` (default: `False`)***  
Specifies whether the JWT auth cookie is HTTP-only.

***`TWILIO_ACCOUNT_SID` (default: `None`)***  
Specifies the Twilio account SID.

***`TWILIO_AUTH_TOKEN` (default: `None`)***  
Specifies the Twilio auth token.

***`TWILIO_PHONE_NUMBER` (default: `None`)***  
Specifies the Twilio phone number.

***`DEV_PRINT_SMS` (default: `True`)***  
Specifies whether to print SMS in development.

***`SMS_VERIFICATION_MESSAGE` (default: `"Your DjangoApp verification code is: <otp_code>"`)***  
Specifies the SMS verification message.

***`SMS_PASSWORD_RESET_MESSAGE` (default: `"Your DjangoApp security code to reset password is: <otp_code>"`)***  
Specifies the SMS password reset message.

```python
OTP_REST_AUTH = {
    'ADAPTER': 'otp_rest_auth.adapter.DefaultAccountAdapter',
    'VERIFICATION_TYPE': 'account',
    'VERIFICATION_REQUIRED': True,
    'AUTHENTICATION_METHODS': ('phone', 'email', 'username'),
    'PASSWORD_RESET_OTP_RECIPIENTS': ('phone', 'email'),
    'PASSWORD_RESET_OTP_EXPIRY_TIME': 90,
    'PASSWORD_RESET_CONFIRM_SERIALIZER': 'otp_rest_auth.serializers.PasswordResetConfirmSerializer'
    'PASSWORD_RESET_SERIALIZER': 'otp_rest_auth.serializers.PasswordResetSerializer',
    'PASSWORD_CHANGE_SERIALIZER': 'otp_rest_auth.serializers.PasswordChangeSerializer',
    'OLD_PASSWORD_FIELD_ENABLED': False,
    'JWT_SERIALIZER': 'otp_rest_auth.serializers.JWTSerializer',
    'LOGIN_SERIALIZER': 'otp_rest_auth.serializers.LoginSerializer',
    'UNIQUE_PHONE': True,
    'UNIQUE_EMAIL': True,
    'EMAIL_REQUIRED': True,
    'PHONE_REQUIRED': True,
    'USERNAME_REQUIRED': False,
    'USERNAME_BLACKLIST': [],
    'USERNAME_MIN_LENGTH': 3,
    'USERNAME_MAX_LENGTH': 15,
    'PRESERVE_USERNAME_CASING': False,
    'USERNAME_VALIDATORS': [],
    'USER_MODEL_USERNAME_FIELD': 'username',
    'USER_MODEL_EMAIL_FIELD': 'email',
    'USER_MODEL_PHONE_FIELD': 'phone',
    'REGISTER_SERIALIZER': 'otp_rest_auth.serializers.RegisterSerializer',
    'OTP_SERIALIZER': 'otp_rest_auth.serializers.OTPSerializer',
    'REGISTER_PERMISSION_CLASSES': [],
    'SITE_NAME': 'DjangoApp',
    'TEMPLATE_EXTENSION': 'html',
    'EMAIL_SUBJECT_PREFIX': None,
    'OTP_LENGTH': 6,
    'OTP_EXPIRY_TIME': 90,
    'PASSWORD_MIN_LENGTH': 4,
    'PASSWORD_MAX_LENGTH': 50,
    'USER_DETAILS_SERIALIZER': 'otp_rest_auth.serializers.UserDetailsSerializer',
    'JWT_SERIALIZER_WITH_EXPIRATION': 'otp_rest_auth.serializers.JWTSerializerWithExpiration',
    'LOGIN_UPON_VERIFICATION': False,
    'LOGOUT_ON_PASSWORD_CHANGE': False,
    'SIGNUP_PASSWORD_VERIFICATION': True,
    'SIGNUP_PASSWORD_ENTER_TWICE': True,
    'JWT_AUTH_COOKIE': 'jwt-auth',
    'JWT_AUTH_SECURE': False,
    'JWT_AUTH_SAMESITE': 'Lax',
    'JWT_AUTH_COOKIE_DOMAIN': None,
    'JWT_AUTH_REFRESH_COOKIE': 'jwt-refresh',
    'JWT_AUTH_REFRESH_COOKIE_PATH': '/',
    'JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED': False,
    'JWT_AUTH_COOKIE_USE_CSRF': False,
    'JWT_AUTH_RETURN_EXPIRATION': True,
    'JWT_AUTH_HTTPONLY': False,
    'TWILIO_ACCOUNT_SID': None,
    'TWILIO_AUTH_TOKEN': None,
    'TWILIO_PHONE_NUMBER': None,
    'DEV_PRINT_SMS': True,
    'SMS_VERIFICATION_MESSAGE': "Your DjangoApp verification code is: <otp_code>"
    'SMS_PASSWORD_RESET_MESSAGE': "Your <SITE_NAME> security code to reset password is: <otp_code>",
}
```
