# Flask Golf

Web application for the **80 Yard Bombs Cup**, a fantasy golf league. Users authenticate via magic link email, submit golfer picks for active tournaments, and view leaderboards and player standings. Scores are pulled from the Slash Golf API (RapidAPI).

## Tech Stack

- **Python 3.10** / **Flask 3.0.3** — single-file app (`app.py`)
- **Turso** (hosted libSQL) — database via `libsql_experimental`
- **Resend** — transactional email (magic links, notifications)
- **Slash Golf API** (RapidAPI) — live golf scores and tournament data
- **Argon2** — token hashing for magic link auth
- **Tailwind CSS** (CDN) — dark-themed responsive UI
- **Gunicorn** — production WSGI server (2 workers, port 8080)
- **Flask-Compress** + Brotli — response compression

## Features

- **Magic link authentication** — passwordless login with Argon2-hashed tokens and SHA-256 session cookies
- **Invite-only registration** — access request workflow with admin approval and email notifications
- **Pick submission** — tiered golfer selection (by OWGR rank) with duplicate/validation checks
- **Leaderboard** — ranked fantasy entries with per-golfer score breakdowns
- **Player standings** — individual golfer scores with "selected by" info
- **Admin dashboard** — tournament CRUD, golfer refresh, pick lock/unlock, user management, registration toggle
- **Automated score refresh** — `POST /api/auto-refresh` endpoint for external cron/schedulers
- **Security** — CSRF protection, rate limiting, security headers (CSP, HSTS), audit logging

## Setup

```bash
# Install dependencies (using uv)
uv pip install -r requirements.txt

# Initialize the database
uv run flask init-db

# Run dev server
PYTHONUNBUFFERED=1 uv run python app.py
```

## Environment Variables

Configure in `.env` for local dev, or as secrets in the deployment dashboard.

| Variable | Required | Description |
|----------|----------|-------------|
| `TURSO_DATABASE_URL` | Yes | Turso libSQL connection URL |
| `TURSO_AUTH_TOKEN` | Yes (prod) | Turso auth token |
| `FLASK_SECRET_KEY` | Yes (prod) | Secret key for sessions/CSRF — app fails fast if missing in production |
| `RESEND_API_KEY` | No | Resend API key — omit to print magic links to console |
| `EMAIL_FROM` | No | Sender address (default: `picks@updates.cullin.link`) |
| `GOLF_API_KEY` | No | RapidAPI key for Slash Golf API |
| `ADMIN_EMAILS` | No | Comma-separated admin email addresses |

## Deployment

Deployed on **DigitalOcean App Platform**. Auto-deploys from `main`.

- Deploy spec: `.do/app.yaml`
- Health check: `GET /health`
- Run command: `gunicorn --worker-tmp-dir /dev/shm --config gunicorn_config.py app:app`

## Testing

```bash
uv run pytest tests/
```

78 tests covering auth, picks, leaderboard scoring, admin routes, and utility functions.

## License

MIT
