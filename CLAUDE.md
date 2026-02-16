# CLAUDE.md

## Project Overview

Flask Golf is a web application for a fantasy golf league ("80 Yard Bombs Cup"). Users authenticate via magic link email, submit golfer picks for active tournaments, and view leaderboards and player standings. Data is stored in Turso (libSQL) and golfer scores are fetched from the Slash Golf API (via RapidAPI). The frontend uses Tailwind CSS with a dark theme.

## Tech Stack

- **Python 3.10** (see `runtime.txt`)
- **Flask 3.0.3** with Jinja2 templates
- **Turso/libSQL** via `libsql-experimental` for database
- **Resend** for transactional email (magic link delivery)
- **Argon2** (`argon2-cffi`) for token hashing
- **email-validator** for email input validation
- **Requests** for HTTP calls to the Golf API
- **Tailwind CSS** (CDN) for frontend styling
- **Choices.js** (CDN) for dropdown components
- **Gunicorn** for production WSGI serving
- **Flask-Compress** + **Brotli** for HTTP response compression
- **pytz** for timezone conversion (UTC to US/Eastern)

## Repository Structure

```
flask-golf/
├── app.py                  # Main Flask application (all routes + helpers)
├── schema.sql              # Turso/libSQL database schema
├── gunicorn_config.py      # Gunicorn production config (port 8080, 2 workers)
├── requirements.txt        # Pinned Python dependencies
├── runtime.txt             # Python version (3.10.14)
├── Procfile.txt            # Heroku deployment entry point
├── .do/                    # DigitalOcean App Platform deployment configs
│   ├── app.yaml
│   └── deploy.template.yaml
├── templates/              # Jinja2 HTML templates
│   ├── leaderboard.html    # Entry-focused leaderboard (main page)
│   ├── player_standings.html # Individual golfer standings
│   ├── pick_form.html      # Golfer pick submission form (login required)
│   ├── submit_success.html # Post-submission confirmation
│   ├── login.html          # Magic link login form
│   ├── check_email.html    # "Check your email" confirmation page
│   ├── error.html          # Generic error page
│   └── admin.html          # Admin dashboard (tournament management)
├── .gitignore
├── LICENSE                 # MIT
└── README.md
```

This is a single-file Flask app — all routes, helpers, and configuration live in `app.py`. There is no package structure, no `__init__.py`, and no separate modules.

## Architecture

### Application Entry Point

`app.py` is both the module and the application. The Flask app instance is `app`. Run locally with `python app.py` (debug mode) or in production with gunicorn via `gunicorn --config gunicorn_config.py app:app`.

### Routes

| Route | Method | Function | Auth | Description |
|-------|--------|----------|------|-------------|
| `/` | GET | `leaderboard()` | Public | Main leaderboard showing fantasy league entry standings |
| `/players` | GET | `player_standings()` | Public | Individual golfer performance table |
| `/make_picks` | GET | `make_picks()` | Login | Pick submission form with tiered golfer dropdowns |
| `/submit_picks` | POST | `submit_picks()` | Login + CSRF | Processes pick submissions, writes to Turso |
| `/auth/login` | GET | `auth_login()` | Public | Magic link login page |
| `/auth/request-link` | POST | `auth_request_link()` | CSRF | Sends magic link email via Resend |
| `/auth/verify` | GET | `auth_verify()` | Public | Verifies magic link token, creates session |
| `/auth/logout` | POST | `auth_logout()` | CSRF | Destroys session, clears cookie |
| `/admin` | GET | `admin_dashboard()` | Admin | Tournament management dashboard |
| `/admin/create-tournament` | POST | `admin_create_tournament()` | Admin + CSRF | Create tournament from API schedule |
| `/admin/activate-tournament` | POST | `admin_activate_tournament()` | Admin + CSRF | Set active tournament (deactivates others) |
| `/admin/toggle-picks-lock` | POST | `admin_toggle_picks_lock()` | Admin + CSRF | Lock/unlock pick submissions |
| `/admin/refresh-golfers` | POST | `admin_refresh_golfers()` | Admin + CSRF | Pull latest golfer data from Golf API |
| `/admin/delete-tournament` | POST | `admin_delete_tournament()` | Admin + CSRF | Delete tournament and all related data |
| `/health` | GET | `health_check()` | Public | Returns JSON health status and cache metrics |
| `/clear_cache` | GET | `clear_cache()` | Public | Clears all in-memory cached data |

### Authentication

**Magic Link Flow:**
1. User enters email on `/auth/login`
2. Server generates a `secrets.token_urlsafe(32)` token, hashes it with Argon2id, stores in `auth_tokens` table
3. Email with verification link sent via Resend (or printed to console in dev mode)
4. User clicks link → `/auth/verify` validates token against stored Argon2 hash
5. User record created (if new) or updated; session token generated and set as `golf_session` cookie
6. Sessions stored in `sessions` table with SHA-256 hashed token, 7-day expiry

**Session Management:**
- `golf_session` cookie holds raw session token; server stores SHA-256 hash
- `load_user()` runs `@app.before_request` to populate `g.user` from session
- Session last activity updated on each authenticated request
- CLI command `flask cleanup-sessions` removes expired sessions/tokens

**Decorators:**
- `@login_required` — redirects to login page if not authenticated
- `@admin_required` — requires login + `is_admin` flag on user record
- `@csrf_required` — validates CSRF token from form field or `X-CSRF-Token` header

**Admin Users:**
- Determined by `ADMIN_EMAILS` env var (comma-separated)
- `is_admin` flag set on user creation if email matches

### CSRF Protection

- Token generated per Flask session via `get_csrf_token()`, stored in `session['csrf_token']`
- Available in templates as `{{ csrf_token() }}`
- All POST routes use `@csrf_required` decorator
- Validates via `secrets.compare_digest()` (timing-safe comparison)

### Rate Limiting

Database-backed rate limiting in `rate_limits` table:
- Magic link requests: 3 per email per hour, 10 per IP per hour
- Failed verifications: 5 per IP per 15 minutes
- Rate-limited responses return the same page as success (no information leakage)

### Security Headers

Applied via `@app.after_request`:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy` (restricts script/style sources to CDNs used)
- `Strict-Transport-Security` (production only)
- `Referrer-Policy: strict-origin-when-cross-origin`
- HTTPS redirect enforced in production via `X-Forwarded-Proto` check

### Security Logging

Events logged to `security_events` table: `magic_link_sent`, `login`, `logout`, `failed_login`, `csrf_failure`, `rate_limited`. Each event records IP address, user agent, and optional details JSON.

### Caching

- **Data cache**: In-memory dict with 5-minute TTL (`CACHE_TTL = 300`). Cache keys are per-tournament: `leaderboard_{id}`, `players_{id}`.
- Cache is cleared on pick submission, tournament activation, golfer refresh, and tournament deletion.
- No persistent/shared cache — each gunicorn worker has its own cache.

### Database

**Turso/libSQL** — connection per request via Flask `g` object (`get_db()`), closed on teardown. Local development uses a file-based SQLite database (`file:local.db`), production uses Turso's hosted libSQL.

Schema is defined in `schema.sql`. Initialize with `flask init-db`.

**Tables:**
- `users` — email, display_name, is_admin, login timestamps
- `auth_tokens` — magic link tokens (Argon2 hashed), expiry, used_at
- `sessions` — session tokens (SHA-256 hashed), expiry, IP, user agent hash
- `tournaments` — external_id (from Golf API), name, season_year, is_active, picks_locked
- `entries` — user picks (5 golfers per entry, one entry per user per tournament)
- `golfers` — cached golfer data from API (scores, position, status, OWGR rank)
- `tournament_metadata` — cut line, last API update time, API status
- `rate_limits` — rate limiting counters per identifier+action
- `security_events` — audit log for auth/security events
- `failed_logins` — failed login attempt tracking

### Golf API Integration

Golfer data is fetched from the **Slash Golf API** (via RapidAPI) at `https://live-golf-data.p.rapidapi.com`. Three endpoints are used:
- `/schedule` — tournament schedule by year/org
- `/leaderboard` — live scores for a tournament
- `/tournament` — tournament field (fallback when no leaderboard data)

Data refresh is triggered manually from the admin panel (`/admin/refresh-golfers`). The `refresh_golfers_from_api()` function upserts golfer records using `ON CONFLICT ... DO UPDATE`.

### Tournament Resolution

The app displays the tournament where `is_active = 1` in the `tournaments` table. Only one tournament can be active at a time — activating one deactivates all others. Tournament management is done entirely through the admin dashboard.

### Multi-Season Support

The `tournaments.season_year` column supports multiple seasons. The admin dashboard allows filtering the API schedule by year. The schema is ready for multi-season archive views, though the UI currently only shows the active tournament.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TURSO_DATABASE_URL` | Yes | Turso database URL (or `file:local.db` for local dev) |
| `TURSO_AUTH_TOKEN` | Prod | Turso authentication token |
| `FLASK_SECRET_KEY` | Yes | Secret key for Flask sessions (auto-generated if missing) |
| `RESEND_API_KEY` | Prod | Resend API key for sending magic link emails |
| `EMAIL_FROM` | No | From address for emails (default: `picks@80yardbombs.com`) |
| `GOLF_API_KEY` | Yes | RapidAPI key for Slash Golf API |
| `ADMIN_EMAILS` | No | Comma-separated admin email addresses |

For local development, these can be defined in a `config.py` file at the project root (gitignored). Without `RESEND_API_KEY`, magic links are printed to the console.

## Development Setup

```bash
# Use Python 3.10
pip install -r requirements.txt

# Set credentials via environment or config.py
# Initialize database
flask init-db

# Run dev server (magic links print to console)
python app.py
```

## Production Deployment

```bash
gunicorn --worker-tmp-dir /dev/shm --config gunicorn_config.py app:app
```

Deployment is configured for **DigitalOcean App Platform** (`.do/` directory) and **Heroku** (`Procfile.txt`, `runtime.txt`). Environment variables are set as secrets in the platform config.

## CLI Commands

| Command | Description |
|---------|-------------|
| `flask init-db` | Initialize database schema from `schema.sql` |
| `flask cleanup-sessions` | Remove expired sessions and auth tokens |

## Testing

No test suite exists. There are no test files, test frameworks, or CI/CD pipelines configured.

## Linting / Formatting

No linting or formatting tools are configured. There is no `pyproject.toml`, `.flake8`, or pre-commit hook setup.

## Key Conventions

- All application logic is in `app.py` — keep it as a single-file app unless there's a strong reason to split.
- Templates live in `templates/` and use Tailwind CSS via CDN (no build step).
- Database queries use parameterized SQL via `libsql_experimental` (no ORM).
- All POST routes require CSRF tokens; auth routes use `@login_required` or `@admin_required`.
- Timestamps are stored as ISO strings in UTC; converted to US/Eastern for display.
- The pick form divides golfers into three tiers by OWGR rank: top 5, next 11, and the rest.
- Error handling uses try-except with fallback values and `print()` for logging.
- Security events (logins, failures, rate limits) are logged to the `security_events` table.
- `g.user` is populated on every request via `load_user()` and passed to templates as `user`.

## TODOs / Future Work

- Remove unused `pandas`/`numpy` from `requirements.txt` (no longer needed post-Snowflake migration)
- Add proper logging (replace `print()` calls with Python `logging` module)
- Add test suite (pytest + test fixtures for Turso)
- Schedule `flask cleanup-sessions` as a cron/scheduled task (command exists but needs automation)
- Automate golfer data refresh (currently manual via admin panel)
- Multi-season archive view (schema supports it via `season_year`, but UI only shows active tournament)
- Improve email templates (currently inline HTML in `send_magic_link()`)
- `submit_success.html` lacks the auth nav bar (sign in/out) unlike other templates
- Add `display_name` support in UI (users table has the column, but it's never set or shown)
- Consider moving from in-memory cache to something persistent across gunicorn workers
- Add CI/CD pipeline
- Set up structured logging for security events
