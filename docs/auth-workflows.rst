Authentication workflows
------------------------

The authentication workflows are particularly important because they transition
HTTP requests from anonymous visitors to authenticated users.

There are three authentication workflows:

- Login (and its weak form: Password Recovery)
- Register
- Verify communication channel

These authentication workflows are best describe as a single
pipeline for a POST HTTP request with custom steps at specific points.

+-------------------------+-------------------------+-------------------------+
| Login                   | Verify                  | Register                |
| (/login/, /activate/,   | (/activate/{key},       | (/register/,            |
| /recover/, /api/auth)   | /api/auth/activate/{key}| /register/{form}/,      |
|                         | )                       | /api/auth/register)     |
+=========================+=========================+=========================+
| Generic HTTP Rate-limiter                                                   |
|   This rate-limiter is intended to prevent brute-force attempts. It is      |
|   generally implemented in the gateway and out-of-scope of this project.    |
+-------------------------+-------------------------+-------------------------+
|                         |                         | Check if registration   |
|                         |                         | or auth is disabled     |
+-------------------------+-------------------------+-------------------------+
| Bot prevention                                                              |
|   - no extra characters on URL path                                         |
|   - validate fields through regex                                           |
|   - optional Captcha                                                        |
+-------------------------+-------------------------+-------------------------+
| Find candidate User or Contact                    |                         |
+-------------------------+-------------------------+-------------------------+
| Check if auth is disabled for User, or            |                         |
| auth disabled globally if we only have a Contact  |                         |
+-------------------------+-------------------------+-------------------------+
| Auth rate-limiter                                 |                         |
+-------------------------+-------------------------+-------------------------+
| Redirects if email requires SSO                                             |
+-------------------------+-------------------------+-------------------------+
|                         |                         | Bot prevention          |
|                         |                         |   verify e-mail if it   |
|                         |                         |   looks suspicious.     |
+-------------------------+-------------------------+-------------------------+
| If recover password,    |                         |                         |
| reset password          |                         |                         |
+-------------------------+-------------------------+-------------------------+
| If no password,         |                                                   |
| verify e-mail or phone  |                                                   |
+-------------------------+-------------------------+-------------------------+
| If required, check 2FA                            |                         |
+-------------------------+-------------------------+-------------------------+
|                         | If does not exist,      | Create User             |
|                         | create User from Contact|                         |
+-------------------------+-------------------------+-------------------------+
| Check password          |                         |                         |
+-------------------------+-------------------------+-------------------------+
|                         | If no password,         |                         |
|                         | set new password        |                         |
+-------------------------+-------------------------+-------------------------+
| Create session                                                              |
+-------------------------+-------------------------+-------------------------+





Views
=====

ActivationView GET, POST
  /activate/<verification_key>/

SignupView GET, POST
  /register/
  /register/<page>/

SigninView GET, POST
  /activate/ (different template)
  /login/

PasswordResetView GET, POST
  /recover/

PasswordResetConfirmView GET, POST
  /reset/<uidb64>/<token>/

/logout/ ??

APIs
====

/api/auth/
/api/auth/activate/<verification_key>/
/api/auth/logout/
/api/auth/recover/
/api/auth/register/
/api/auth/reset/<uidb64>/<token>/
/api/auth/tokens/
/api/auth/tokens/verify/


/var/www/djaodjin/reps/djaodjin/scripts/djaoapp-urls.txt

