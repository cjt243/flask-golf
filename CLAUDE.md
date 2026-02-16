# CLAUDE.md

## Start Here

**You MUST read these two files at the start of every session:**

1. **[`QUICKSTART.md`](QUICKSTART.md)** — Runtime environments, env vars, config files, service dashboards, deployment. This is your operational reference.
2. **[`PRODUCTION_PLAN.md`](PRODUCTION_PLAN.md)** — Master implementation plan with prioritized work items (P0-P3), UI/UX review, and phased execution order. **Update its Progress Tracker after completing each phase.**

## Project Overview

Flask Golf is a single-file Flask web app for a fantasy golf league ("80 Yard Bombs Cup"). Users authenticate via magic link email, submit golfer picks for active tournaments, and view leaderboards/standings.

**Stack**: Python 3.12 / Flask 3.0.3 / Turso (libSQL) / Resend / Tailwind CSS (CDN) / Gunicorn
**Deploy**: DigitalOcean App Platform, auto-deploys from `main`
**Branch**: `feature/turso-migration-magic-auth` — active dev branch, merges to `main` for deploy

## Architecture

**Single-file app** — all routes, helpers, and config live in `app.py`. No package structure, no `__init__.py`.

| File | Purpose |
|------|---------|
| `app.py` | Entire application |
| `schema.sql` | Database schema (Turso/libSQL) |
| `templates/base.html` | Shared layout: nav, footer, Tailwind config, typography |
| `templates/*.html` | 11 Jinja2 templates — all extend `base.html` |
| `gunicorn_config.py` | Production server config (port 8080, 2 workers) |
| `requirements.txt` | Pinned Python dependencies |
| `.env` | Local dev env vars (gitignored) |
| `PRODUCTION_PLAN.md` | Master plan — bugs, features, UI refresh, phased implementation |

### Routes

| Route | Auth | Purpose |
|-------|------|---------|
| `/` | Login | Leaderboard |
| `/players` | Login | Player standings |
| `/make_picks` | Login | Pick submission form |
| `/submit_picks` | Login+CSRF | Process pick submission |
| `/auth/login` | Public | Magic link login |
| `/auth/request-link` | CSRF | Send magic link email |
| `/auth/verify` | Public | Verify magic link token |
| `/auth/logout` | CSRF | Destroy session |
| `/auth/request-access` | Public | Invite-only registration form |
| `/auth/submit-access-request` | CSRF | Submit access request |
| `/admin` + sub-routes | Admin | Tournament management, user approval |
| `/health` | Public | Health check JSON |
| `/clear_cache` | Admin | Clear in-memory cache |
| `/api/auto-refresh` | API Key/Admin | Automated golfer score refresh (POST) |
| `/favicon.ico` | Public | SVG favicon (7-day cache) |

### Auth

Magic link email → Argon2-hashed tokens → SHA-256 session cookies (7-day expiry). Sessions in `sessions` table. Decorators: `@login_required`, `@admin_required`, `@csrf_required`. Admin status from `ADMIN_EMAILS` env var.

### Database

Turso/libSQL via `libsql_experimental`. The `LibSQLConnectionWrapper` auto-converts list params to tuples. All queries use parameterized SQL (no ORM).

**Tables**: `users`, `auth_tokens`, `sessions`, `tournaments`, `entries`, `golfers`, `tournament_metadata`, `rate_limits`, `security_events`, `access_requests`, `app_settings`, `failed_logins`

**User names**: `users` and `access_requests` tables have `first_name` + `last_name` columns (split from legacy `display_name`). Leaderboard shows "First L." under entry names.

**Migrations**: `_run_migrations()` runs on every app startup (at module level, not just via CLI). It handles ALTER TABLE additions. `CREATE TABLE IF NOT EXISTS` won't add columns — use the migration list for schema changes.

### Golf API

Slash Golf API via RapidAPI (`live-golf-data.p.rapidapi.com`). Endpoints: `/schedule`, `/leaderboard` (key: `leaderboardRows`), `/tournament` (key: `players`). Some fields use MongoDB-style `{"$numberInt": "4"}` — handled by `_api_int()`. Refresh via admin panel or `POST /api/auto-refresh` (X-API-Key header auth, reuses GOLF_API_KEY).

### Caching

In-memory dict, 5-minute TTL, per-worker (not shared). Cleared on pick submission, tournament activation, golfer refresh.

## Key Conventions

- Single-file app — keep it that way unless there's a strong reason to split
- DB params as lists — wrapper converts to tuples
- All POST routes require CSRF
- Timestamps: ISO UTC in DB, US/Eastern for display
- `g.user` populated every request via `load_user()`, includes `first_name`, `last_name`, passed to templates as `user`
- Logging via Python `logging` module (`logger = logging.getLogger('flask_golf')`)
- Security events logged to `security_events` table
- Templates extend `base.html` — nav, footer, Tailwind config are shared. Use `{% set show_nav = true %}` and `{% set active_tab = '...' %}` for authenticated pages
- Session cleanup is probabilistic (~1% of authenticated requests)

## Testing

### Critical: Use `uv run` for ALL Python commands

**Never use bare `python`, `python3`, or `source .venv/bin/activate`.** Always prefix with `uv run`:
```bash
uv run python app.py          # Run the app
uv run python /tmp/script.py   # Run any script
uv run flask init-db           # Flask CLI commands
uv pip install -r requirements.txt  # Install deps
```

### Testing authenticated routes

The app connects to **production Turso DB** even in local dev (same instance). Key implications:

- **Session cookie name**: `golf_session` (not `session_token`)
- **Only registered user**: `cullin.tripp@gmail.com` (admin)
- **Magic links sent via email** when `RESEND_API_KEY` is set (which it is in `.env`). They only print to console when the key is **not** set.
- **To test authenticated routes in Playwright**, create a session directly in the DB:
  ```python
  import hashlib, secrets
  raw_token = secrets.token_hex(32)
  token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
  db.execute("INSERT INTO sessions (id, user_id, session_token_hash, expires_at) VALUES (?, ?, ?, ?)",
             (session_id, user_id, token_hash, expires_at))
  # Then set cookie: {"name": "golf_session", "value": raw_token, "domain": "127.0.0.1", "path": "/"}
  ```
- **Clean up test sessions** after tests to avoid DB clutter.
- **CSRF tokens** are Flask session-bound. The `requests` library doesn't maintain Flask sessions properly — use Playwright for any flow involving CSRF forms.

### Server startup for tests

- Use `with_server.py` helper for simple page screenshots: `uv run python scripts/with_server.py --server "uv run flask run" --port 5000 -- uv run python test.py`
- For authenticated tests that need DB access, start the server via `subprocess.Popen` and use `requests` to poll `/health` until ready.
- **Kill port 5000** between test runs: `lsof -ti:5000 | xargs -r kill -9`
- `config.py` (gitignored) overrides env vars set by `.env` — removing a var from subprocess env won't help if `config.py` re-sets it.

## Workflow

- **After every phase**: Update Progress Tracker in `PRODUCTION_PLAN.md`, commit changes
- **Commits**: Descriptive messages, reference the phase (e.g., "Phase 1: Secure /clear_cache route")
- **No linter/formatter configured** — match existing code style
