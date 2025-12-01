# Flask 2FA System

A simple Flask application that demonstrates user authentication with optional two-factor authentication (2FA) using TOTP and backup codes. This project provides user registration, login with optional 2FA, QR code provisioning, backup code generation/consumption, and a small user dashboard.

## Key features

- User registration and login (Flask-Login)
- Optional TOTP-based 2FA (pyotp)
- QR code provisioning for authenticator apps (qrcode + Pillow)
- Single-use backup codes for account recovery
- SQLite database (Flask-SQLAlchemy)
- Simple forms and validation (Flask-WTF / WTForms)

## Requirements

- Python 3.8+
- The following packages (install below):
  - Flask
  - flask-login
  - flask-wtf
  - flask-sqlalchemy
  - pyotp
  - qrcode
  - pillow

## Quick start (Windows PowerShell)

1) Create and activate a virtual environment:

```powershell
python -m venv .\venv
.\venv\Scripts\Activate.ps1
```

If activation is blocked, allow the session for this process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
```

2) Install dependencies:

```powershell
pip install --upgrade pip
pip install Flask flask-login flask-wtf flask-sqlalchemy pyotp qrcode pillow
```

3) Run the app:

```powershell
python .\app.py
```

Open http://127.0.0.1:5000 in your browser.

## Configuration

- `config.py` contains basic configuration including `SECRET_KEY` and the SQLite URI (`sqlite:///users.db`).
- For production, set a secure `SECRET_KEY` environment variable and enable HTTPS.

## Project layout

- `app.py` — main Flask application, routes and 2FA flow
- `models.py` — SQLAlchemy `User` model, password hashing, TOTP and backup code helpers
- `forms.py` — WTForms definitions for registration, login, and 2FA verification
- `templates/` — HTML templates for pages (register, login, dashboard, 2FA setup/verify, backup codes)
- `static/` — static assets (CSS)

## Security notes

- The project stores backup codes as hashed values, but in production you should review storage and rotation policies.
- Use HTTPS in production and set `SESSION_COOKIE_SECURE = True`.
- Replace the default `SECRET_KEY` before deploying.

## Contributing

Contributions are welcome. Suggested steps:

1) Fork the repo and create a feature branch.
2) Add tests for new behavior.
3) Open a pull request describing your changes.

## License

Specify a license for your project (e.g., MIT) or replace this section with your chosen license.

---

If you want, I can:
- Add a `requirements.txt` (from the current venv),
- Commit and push the README for you,
- Or shorten / expand any sections in this README. Tell me which.
