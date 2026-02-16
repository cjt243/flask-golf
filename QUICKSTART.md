# Quick Start Guide

Reference for runtime environments, configuration, and deployment.

## Configuration Files

| File | Tracked | Purpose | Loaded By |
|------|---------|---------|-----------|
| `.env` | No (gitignored) | **Primary local dev config** — all env vars | `python-dotenv` (auto-loaded by Flask) |
| `config.py` | No (gitignored) | Legacy local dev config — sets `os.environ` | `from config import *` in `app.py` |
| `.do/app.yaml` | Yes | DigitalOcean App Platform deploy spec | DO dashboard import |
| `.do/deploy.template.yaml` | Yes | DO deploy template (alternative format) | DO dashboard import |
| `gunicorn_config.py` | Yes | Gunicorn settings (port 8080, 2 workers) | `gunicorn --config` flag |
| `runtime.txt` | Yes | Python version for platform builds | Heroku/DO buildpack |
| `Procfile.txt` | Yes | Heroku process definition | Heroku |

**Load order**: Flask auto-loads `.env` via `python-dotenv`, then `app.py` imports `config.py` (if present). Values in `config.py` can override `.env` since they set `os.environ` directly after `.env` is already loaded.

## Environment Variables

All env vars for local dev go in `.env` at the project root:

```
TURSO_DATABASE_URL=libsql://flask-golf-cjt243.aws-us-east-1.turso.io
TURSO_AUTH_TOKEN=<turso-jwt-token>
FLASK_SECRET_KEY=<random-hex-string>
RESEND_API_KEY=<resend-api-key>
EMAIL_FROM=picks@updates.cullin.link
GOLF_API_KEY=<rapidapi-key>
ADMIN_EMAILS=user@example.com
```

### Email (Resend) Configuration

- **Verified domain**: `updates.cullin.link` (verified in [Resend dashboard](https://resend.com/domains))
- **EMAIL_FROM must use**: `picks@updates.cullin.link` (or any address `@updates.cullin.link`)
- **NOT** `picks@cullin.link` — the root domain `cullin.link` is **not** verified; using it causes "domain not verified" errors
- Without `RESEND_API_KEY`, magic links print to console instead of sending email

## Runtime Environments

### Local Development

- **Python**: 3.12 (installed in `.venv/`)
- **Package runner**: [uv](https://docs.astral.sh/uv/) — use `uv run` to execute commands within the venv
- **Database**: Turso hosted libSQL (same instance as production, or `file:local.db` for offline)
- **Server**: Flask dev server with debug mode (`python app.py`)
- **Email**: Set `RESEND_API_KEY` to send real emails, or omit it to print magic links to console
- **Run with**: `PYTHONUNBUFFERED=1 uv run python app.py` (unbuffered so magic links print immediately)

```bash
# Install dependencies
uv pip install -r requirements.txt

# Run dev server
PYTHONUNBUFFERED=1 uv run python app.py
# App runs on http://127.0.0.1:5000
```

### Production (DigitalOcean App Platform)

- **Python**: 3.10.14 (per `runtime.txt`)
- **Database**: Turso hosted libSQL at `libsql://flask-golf-cjt243.aws-us-east-1.turso.io`
- **Server**: Gunicorn with 2 workers, port 8080
- **Email**: Resend API with `picks@updates.cullin.link`
- **Instance**: `basic-xxs`
- **Env vars**: Set as secrets in DO App Platform dashboard (not auto-synced from `.do/` configs after initial setup)

**Important**: Changing `.do/app.yaml` or `.do/deploy.template.yaml` does **not** update env vars already configured in the DO dashboard. You must update them manually in the dashboard.

## Database

- **Production URL**: `libsql://flask-golf-cjt243.aws-us-east-1.turso.io`
- **Provider**: [Turso](https://turso.tech/) (hosted libSQL, AWS us-east-1)
- **Schema**: `schema.sql` — initialize with `flask init-db`
- **Driver**: `libsql_experimental` — requires tuple params (the `LibSQLConnectionWrapper` in `get_db()` handles this)
- **Migrations**: No migration framework. `CREATE TABLE IF NOT EXISTS` won't add new columns. Use `ALTER TABLE` manually for schema changes.

## External Services

| Service | Dashboard | Used For |
|---------|-----------|----------|
| **Turso** | [turso.tech](https://turso.tech/) | libSQL database hosting |
| **Resend** | [resend.com](https://resend.com/) | Magic link email delivery |
| **RapidAPI** (Slash Golf) | [rapidapi.com](https://rapidapi.com/) | Golf scores and tournament data |
| **DigitalOcean** | [cloud.digitalocean.com](https://cloud.digitalocean.com/) | App Platform hosting |

## Common Tasks

| Task | Command / Action |
|------|-----------------|
| Run locally | `PYTHONUNBUFFERED=1 uv run python app.py` |
| Initialize DB | `uv run flask init-db` |
| Clean expired sessions | `uv run flask cleanup-sessions` |
| Install dependencies | `uv pip install -r requirements.txt` |
| Refresh golfer scores | Admin panel -> "Refresh Golfers" button |
| Activate a tournament | Admin panel -> "Activate" button |
| Check app health | `GET /health` |
| Clear data cache | `GET /clear_cache` |
