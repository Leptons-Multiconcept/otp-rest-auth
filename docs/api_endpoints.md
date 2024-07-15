# API Endpoints

### Register Endpoint
---

**URL:** `/api/register/` (POST)

**Description:** Allows a new user to register by providing their username, phone number, email address, and password.
Depending on the configuration settings, the user may need to verify their account via OTP sent to their email or phone number.

**Parameters:** 
- `username` (string, optional, configurable via `USERNAME_REQUIRED`)
- `phone` (string, required if `VERIFICATION_TYPE` is `phone` or `account`)
- `email` (string, required if `VERIFICATION_TYPE` is `email` or `account`)
- `password1` (string, required if `SIGNUP_PASSWORD_ENTER_TWICE` is `True`)
- `password2` (string, required if `SIGNUP_PASSWORD_ENTER_TWICE` is `True`)
- `password` (string, required if `SIGNUP_PASSWORD_ENTER_TWICE` is `False`): The desired password for the new user.

**Return:**
- `201 Created`:
  - User has been successfully registered and, if verification is required, an OTP has been sent.
  - If VERIFICATION_REQUIRED is False, the user is logged in immediately and the JWT tokens are returned.
- `204 No Content`: User has been successfully registered, no additional data is returned.
- `400 Bad Request`: Validation errors with the provided data.

### Verify Account Endpoint
---

**URL:** `/api/verify-account/` (POST)

**Description:** Verifies a user's account using an OTP (One-Time Password) sent to their email or phone.
If the OTP is valid, the user's account is activated. If `LOGIN_UPON_VERIFICATION` is enabled, the user is also logged in and JWT tokens are returned.

**Parameters:**
- `otp` (int, required): The One-Time Password sent to the user's email or phone for account verification.

**Return:**
- `200 OK`: 
  - Account verification successful. 
  - If `LOGIN_UPON_VERIFICATION` is `True`, returns login response data to the user and sets the necessary cookies for authentication.
- `400 Bad Request`: Invalid OTP provided.


## Verify Account Endpoint
---

**URL:** `/api/verify-account/` (POST)
**Description:** Verifies a user's account using an OTP (One-Time Password) sent to their email or phone.
If the OTP is valid, the user's account is activated. If `LOGIN_UPON_VERIFICATION` is enabled, the user is also logged in and JWT tokens are returned.
**Parameters:**
- `otp` (int, required): The One-Time Password sent to the user's email or phone for account verification.
**Return:**
- `200 OK`: Account verification successful. 
- `400 Bad Request`: Invalid OTP provided.

### Verify Email Endpoint
---
**URL:** `/api/verify-email/` (POST)
**Description:** Verifies a user's email using an OTP (One-Time Password) sent to their email.
If the OTP is valid, the user's account is activated. If `LOGIN_UPON_VERIFICATION` is enabled, the user is also logged in and login response data is returned.
**Parameters:**
- `otp` (int, required): The One-Time Password sent to the user's email.
**Return:**
- `200 OK`: Email verification successful. 
- `400 Bad Request`: Invalid OTP provided.

### Verify Phone Endpoint
---
**URL:** `/api/verify-email/` (POST)
**Description:** Verifies a user's phone using an OTP (One-Time Password) sent to their phone.
If the OTP is valid, the user's account is activated. If `LOGIN_UPON_VERIFICATION` is enabled, the user is also logged in and login response data is returned.
**Parameters:**
- `otp` (int, required): The One-Time Password sent to the user's phone.
**Return:**
- `200 OK`: Email verification successful. 
- `400 Bad Request`: Invalid OTP provided.

### Resend OTP Endpoint Documentation
---
**URL:** `/api/resend-otp/` (POST)
**Description:** Resends an OTP (One-Time Password) for account verification or password reset to the user's email or phone based on the specified purpose.
**Parameters:** 
- `phone` (string, required if purpose is `phone` or `account`): The user's phone number.
- `purpose` (string, required): Specifies the purpose of OTP resend. Choices are:
  - `account_verification`: Resend OTP for account verification.
  - `email_verification`: Resend OTP for email verification.
  - `phone_verification`: Resend OTP for phone verification.
  - `password_reset`: Resend OTP for password reset.

**Return:**
- `200 OK`: OTP has been successfully resent.
- `400 Bad Request`: Invalid request parameters or user not found.

### User Details Endpoint Documentation
---
**URL:** `/api/user-details/` (GET, PUT, PATCH)
**Description:** Retrieves and updates the details of the authenticated user.

### Login Endpoint Documentation

**URL:** `/api/login/` (POST)
**Description:** Authenticates a user based on provided credentials (username, email, phone, password). Returns JWT tokens upon successful authentication.
**Parameters:**
- `username` (string, optional): The username of the user.
- `email` (string, optional): The email address of the user.
- `phone` (string, optional): The phone number of the user.
- `password` (string): The password associated with the user account.
**Return:**
- `200 OK`: Successful login. Returns login response data. If `auth_httponly` is `False`.
- `400 Bad Request`: Invalid credentials or account verification status.
- `401 Unauthorized`: Authentication credentials were not provided or are invalid.

### Logout Endpoint Documentation
---

**URL:** `/api/logout/` (POST)
**Description:** Logs out the currently authenticated user by deleting the JWT tokens associated with their session. Optionally, blacklists the refresh token to prevent reuse.
**Parameters:**
- `refresh` (string): The refresh token associated with the user's session.
**Return:**
- `200 OK`: Successfully logged out. JWT tokens are invalidated. If configured, refresh token is blacklisted.
- `400 Bad Request`: Refresh token is invalid or missing, blacklisted, or expired.

### Reset Password Endpoint Documentation
---
**URL:** `/api/reset-password/` (POST)
**Description:** Initiates the password reset process by sending a verification OTP to the user via their preferred authentication method (email, phone, or username).
**Parameters:**
- `phone` (string, optional): The user's phone number if provided.
- `email` (string, optional): The user's email address if provided.
- `username` (string, optional): The user's username if provided.
**Return:**
- `200 OK`: Verification OTP has been successfully sent.
- `400 Bad Request`: Missing or invalid authentication method provided.

### Password Reset Confirmation Endpoint Documentation
---
**URL:** `/api/reset-password/confirm/` (POST)
**Description:** Resets the user's password after verifying the OTP provided for password reset confirmation.
**Parameters:**
- `otp` (integer): The OTP (One-Time Password) received by the user for verification.
- `new_password1` (string): The new password to be set.
- `new_password2` (string): Confirmation of the new password.
**Return:**
- `200 OK`: Password has been successfully reset with the new password.
- `400 Bad Request`: Invalid OTP or password confirmation failed.


### Password Change Endpoint Documentation
---
**URL:** `/api/password/change/` (POST)
**Description:** Allows authenticated users to change their password by providing the old password and confirming the new one.
**Parameters:**
- `old_password` (string, required if `OLD_PASSWORD_FIELD_ENABLED` is `True`): The current password of the user.
- `new_password1` (string): The new password to be set.
- `new_password2` (string): Confirmation of the new password.

**Return:**
- `200 OK`: New password has been successfully saved. If configured (`LOGOUT_ON_PASSWORD_CHANGE` is `True`), the user will be automatically logged out.
- `400 Bad Request`: Invalid old password or validation errors with the new password data.

login response data:
```json
    {
      "access": "access_token", // only if HTTP_ONLY is `False`
      "refresh": "refresh_token", // only if HTTP_ONLY is `False`
      "user": {
        ...
      }
      "access_expiration": "access_token_expiration_time",  // only if `JWT_AUTH_RETURN_EXPIRATION` is `True`
      "refresh_expiration": "refresh_token_expiration_time" // only if `JWT_AUTH_RETURN_EXPIRATION` is `True`
    }
 ```
