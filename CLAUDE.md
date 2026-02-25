# CLAUDE.md

## Project Overview

Flask Golf is a single-file Flask web app for a fantasy golf league ("80 Yard Bombs Cup"). Users authenticate via magic link email, submit golfer picks for active tournaments, and view leaderboards/standings.

**Stack**: Python 3.12 / Flask 3.0.3 / Turso (libSQL) / Resend / Tailwind CSS (static build) / Gunicorn
**Deploy**: DigitalOcean App Platform, auto-deploys from `main`
**Operational reference**: [`QUICKSTART.md`](QUICKSTART.md) — env vars, config files, service dashboards, deployment

## Architecture

**Single-file app** — all routes, helpers, and config live in `app.py`. No package structure.

| File / Dir | Purpose |
|------------|---------|
| `app.py` | Entire application (~2300 lines) |
| `schema.sql` | Database schema (Turso/libSQL) |
| `templates/*.html` | 12 Jinja2 page templates — all extend `base.html`; `macros.html` has shared macros |
| `templates/emails/*.html` | 3 email templates (magic_link, admin_notification, approval) |
| `static/css/styles.css` | Tailwind CSS output (28KB minified) |
| `static/src/input.css` | Tailwind CSS source |
| `tailwind.config.js` | Tailwind build config with custom golf colors |
| `tests/` | 72 pytest tests (auth, picks, leaderboard, admin, utils) |
| `.github/workflows/` | CI (test.yml) + auto-refresh cron (auto-refresh.yml) |
| `gunicorn_config.py` | Production server config (port 8080, 2 workers) |
| `requirements.txt` | Pinned Python dependencies |
| `.env` | Local dev env vars (gitignored) |

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
| `/admin` + sub-routes | Admin | Tournament management, user approval, tiers, refresh schedule |
| `/health` | Public | Health check JSON |
| `/clear_cache` | Admin | Clear in-memory cache |
| `/api/auto-refresh` | API Key/Admin | Automated golfer score refresh (POST) |
| `/favicon.ico` | Public | SVG favicon (7-day cache) |

### Auth

Magic link email → Argon2-hashed tokens → SHA-256 session cookies (7-day expiry). Sessions in `sessions` table. Decorators: `@login_required`, `@admin_required`, `@csrf_required`. Admin status from `ADMIN_EMAILS` env var.

### Database

Turso/libSQL via `libsql_experimental`. The `LibSQLConnectionWrapper` auto-converts list params to tuples. All queries use parameterized SQL (no ORM).

**Tables**: `users`, `auth_tokens`, `sessions`, `tournaments`, `entries`, `golfers`, `tournament_metadata`, `rate_limits`, `security_events`, `access_requests`, `app_settings`, `failed_logins`

**User names**: `users` and `access_requests` tables have `first_name` + `last_name` columns. Leaderboard shows "First L." under entry names.

**Migrations**: `_run_migrations()` runs on every app startup. It handles ALTER TABLE additions and `CREATE INDEX IF NOT EXISTS` for performance indexes. `CREATE TABLE IF NOT EXISTS` won't add columns — use the migration list for schema changes.

### Golf API

Slash Golf API via RapidAPI (`live-golf-data.p.rapidapi.com`). Endpoints: `/schedule`, `/leaderboard` (key: `leaderboardRows`), `/tournament` (key: `players`). Some fields use MongoDB-style `{"$numberInt": "4"}` — handled by `_api_int()`. Refresh via admin panel or `POST /api/auto-refresh` (X-API-Key header auth, reuses GOLF_API_KEY).

### Caching

In-memory dict, 5-minute TTL, per-worker (not shared). Use `clear_tournament_cache(tournament_id)` to clear specific caches, or `clear_tournament_cache()` to clear all. Called on pick submission, tournament activation, golfer refresh, and tier changes.

### Tailwind CSS

Static build via Tailwind CLI v3.4. Custom colors: golf-green, golf-gold, turf (mapped from Tailwind green/amber defaults). `admin_tiers.html` and `macros.html` use dynamic Tailwind classes — all safelisted in `tailwind.config.js`.

```bash
npm run build:css                    # Rebuild after template changes
# Requires Node.js via fnm:
export PATH="$HOME/.local/share/fnm:$PATH" && eval "$(fnm env)"
```

## Conventions

- Single-file app — keep it that way unless there's a strong reason to split
- DB params as lists — wrapper converts to tuples
- All POST routes require CSRF
- Timestamps: ISO UTC in DB, US/Eastern for display
- `g.user` populated every request via `load_user()`, includes `first_name`, `last_name`, passed to templates as `user`
- Logging via `logging.getLogger('flask_golf')`
- Security events logged to `security_events` table
- Templates extend `base.html` — nav, footer, Tailwind config are shared. Use `{% set show_nav = true %}` and `{% set active_tab = '...' %}` for authenticated pages
- `templates/macros.html` provides `form_button()` (admin action forms) and `empty_state()` (no-data cards) macros — import with `{% from "macros.html" import form_button, empty_state %}`
- Shared helpers reduce duplication: `format_last_updated()`, `clear_tournament_cache()`, `get_tournament_external_info()`, `compute_tier()` with `TIER_BOUNDARIES` constant
- Rate limiting uses `INSERT ... ON CONFLICT DO UPDATE` upsert pattern
- Token verification logic lives in `_verify_magic_token()`, API schedule parsing in `_parse_api_schedule()`, player name extraction in `_extract_player_name()`
- Session cleanup is probabilistic (~1% of authenticated requests)
- No linter/formatter configured — match existing code style
- Commits: descriptive messages summarizing the change

## Development

### Critical: Use `uv run` for ALL Python commands

**Never use bare `python`, `python3`, or `source .venv/bin/activate`.** Always prefix with `uv run`:
```bash
uv run python app.py                 # Run the app
uv run python /tmp/script.py         # Run any script
uv run flask init-db                 # Flask CLI commands
uv pip install -r requirements.txt   # Install deps
uv run pytest tests/                 # Run tests
```

### Running locally

```bash
PYTHONUNBUFFERED=1 uv run python app.py   # http://127.0.0.1:5000
```

### Testing

The app connects to **production Turso DB** even in local dev (same instance).

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
  # Set cookie: {"name": "golf_session", "value": raw_token, "domain": "127.0.0.1", "path": "/"}
  ```
- **Clean up test sessions** after tests to avoid DB clutter
- **CSRF tokens** are Flask session-bound — use Playwright for flows involving CSRF forms, not `requests`
- **Kill port 5000** between test runs: `lsof -ti:5000 | xargs -r kill -9`

### CI

GitHub Actions runs pytest on push/PR to `main` (`.github/workflows/test.yml`). Auto-refresh cron runs hourly during tournament windows (`.github/workflows/auto-refresh.yml`).
