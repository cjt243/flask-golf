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
| `app.py` | Entire application (~2600 lines) |
| `schema.sql` | Database schema (Turso/libSQL) |
| `templates/*.html` | 14 Jinja2 page templates — all extend `base.html`; `macros.html` has shared macros |
| `templates/emails/*.html` | 3 email templates (magic_link, admin_notification, approval) |
| `static/css/styles.css` | Tailwind CSS output (28KB minified) |
| `static/src/input.css` | Tailwind CSS source |
| `tailwind.config.js` | Tailwind build config with custom golf colors |
| `tests/` | 97 pytest tests (auth, picks, leaderboard, admin, utils) |
| `.github/workflows/` | CI (test.yml) + auto-refresh cron (auto-refresh.yml) |
| `gunicorn_config.py` | Production server config (port 8080, 2 workers) |
| `requirements.txt` | Pinned Python dependencies |
| `.env` | Local dev env vars (gitignored) |

### Routes

| Route | Auth | Purpose |
|-------|------|---------|
| `/` | Login | Leaderboard (hidden until picks locked; shows pre-tournament state) |
| `/players` | Login | Player standings |
| `/make_picks` | Login | Pick submission/editing form |
| `/submit_picks` | Login+CSRF | Insert or update pick submission |
| `/auth/login` | Public | Magic link login |
| `/auth/request-link` | CSRF | Send magic link email |
| `/auth/verify` | Public | Verify magic link token |
| `/auth/logout` | CSRF | Destroy session |
| `/auth/request-access` | Public | Invite-only registration form |
| `/auth/submit-access-request` | CSRF | Submit access request |
| `/submit-feedback` | Login+CSRF | Submit feedback from floating widget (JSON response) |
| `/admin` + sub-routes | Admin | Tournament management, user approval, tiers, refresh schedule |
| `/admin/feedback` | Admin | View/filter user feedback (open/resolved/all) |
| `/admin/feedback/toggle` | Admin+CSRF | Toggle feedback resolved status |
| `/admin/members` | Admin | Members list with per-season/lifetime winnings |
| `/health` | Public | Health check JSON |
| `/clear_cache` | Admin | Clear in-memory cache |
| `/api/auto-refresh` | API Key/Admin | Automated golfer score refresh (POST) |
| `/favicon.ico` | Public | SVG favicon (7-day cache) |

### Auth

Magic link email → Argon2-hashed tokens → SHA-256 session cookies (7-day expiry). Sessions in `sessions` table. Decorators: `@login_required`, `@admin_required`, `@csrf_required`. Admin status from `ADMIN_EMAILS` env var.

### Database

Turso/libSQL via `libsql_experimental`. The `LibSQLConnectionWrapper` auto-converts list params to tuples. All queries use parameterized SQL (no ORM).

**Tables**: `users`, `auth_tokens`, `sessions`, `tournaments`, `entries`, `golfers`, `tournament_metadata`, `rate_limits`, `security_events`, `access_requests`, `app_settings`, `failed_logins`, `feedback`

**User names**: `users` and `access_requests` tables have `first_name` + `last_name` columns. Leaderboard shows "First L." under entry names.

**Migrations**: `_run_migrations()` runs on every app startup. It handles ALTER TABLE additions and `CREATE INDEX IF NOT EXISTS` for performance indexes. `CREATE TABLE IF NOT EXISTS` won't add columns — use the migration list for schema changes.

### Golf API

Slash Golf API via RapidAPI (`live-golf-data.p.rapidapi.com`). Endpoints: `/schedule`, `/leaderboard` (key: `leaderboardRows`), `/tournament` (key: `players`). Some fields use MongoDB-style `{"$numberInt": "4"}` — handled by `_api_int()`. Refresh via admin panel or `POST /api/auto-refresh` (X-API-Key header auth, reuses GOLF_API_KEY).

### DraftKings Salary Fetch

Admin route `POST /admin/fetch-dk-salaries` fetches player salaries from DraftKings for tier ordering. Two-step API process: fetch contest lobby to find the PGA TOUR draft group ID, then fetch draftables for player salaries. Names matched via `_normalize_golfer_name()`. This is a **per-tournament weekly activity** — fetch new salaries each week when setting up a new tournament. Feedback shown via query params (`dk_msg`, `dk_matched`, `dk_total`, `dk_contest`) on redirect back to the tiers page.

### Tier System

Golfers are assigned to 3 tiers based on DK salary ranking (higher salary = better tier). `TIER_BOUNDARIES = [(5, 1), (16, 2)]` — top 5 are Tier 1, 6-16 are Tier 2, 17+ are Tier 3. `compute_tier(index, tier_override)` applies this with optional admin overrides. DK salary is the **sole ranking source** for tier slotting (OWGR was removed). Overrides are managed in the admin tiers page (`/admin/tiers/<id>`). **Single source of tier ordering**: All three tier-computing locations (admin tiers page, player standings, `_build_tier_lists`) use the same DB query (`ORDER BY dk_salary DESC NULLS LAST, name ASC`) — never Python re-sorts, which can diverge from DB ordering.

### Pick Editing & Leaderboard Visibility

**Pick editing**: Users can update their picks any time before `picks_locked=True`. The `/make_picks` route detects existing entries and renders the form in editing mode (pre-populated with current selections). The `/submit_picks` route uses UPDATE for existing entries, INSERT for new ones. The "Already Submitted" state was removed — users always see the editable form while picks are open.

**Leaderboard visibility**: When `picks_locked=False`, the leaderboard hides all entries to prevent users from seeing each other's picks. Instead it shows:
- **User has entry**: "Your Picks Are In!" card with entry name, golfer chips, and "Change Your Picks" link
- **No entry**: "Tournament is open for picks!" with CTA to `/make_picks`

Once `picks_locked=True`, the full leaderboard renders normally.

**Choices.js styling**: `pick_form.html` includes a full CSS theme override in `<style>` block. Dropdowns use the app's gray-800/900 palette (not the library defaults or the old dark-green theme). Selected chips are green-600, hover highlights use a subtle `rgba(22, 163, 74, 0.15)` tint. The `maxItemText` config shows "All 2 picks made" instead of the default notice.

**Helpers**: `_build_tier_lists(golfers)` extracts tier-sorting logic (shared by both new-entry and editing paths). `_render_pick_form()` accepts `editing=False` and `existing_entry=None` defaults.

### Player Standings

`player_standings.html` uses a dual layout for the `/players` page:
- **Mobile (<640px)**: Card-based layout (`sm:hidden`). Each golfer is a compact card with position badge, name, status (round/thru or CUT), and color-coded score. Tap to expand details (current round, thru, tee time, "Selected By" team chips). `togglePlayerDetail()` handles expand/collapse with chevron rotation. `event.stopPropagation()` on team chips prevents toggling the card.
- **Desktop (>=640px)**: Table layout (`hidden sm:block`).

**Filter bar** (sticky top): Player search input, team filter dropdown, "Hide CUT" checkbox. `filterPlayers()` applies all filters across both mobile cards and desktop rows. `filterCount` span updates visible count.

**View toggle**: "Tournament" (default, sorted by position) vs "By Tier" (grouped by tier with divider rows). `setView('tournament'|'tier')` toggles visibility via `data-view` attribute. Tier computed in `app.py` via `compute_tier()` on DK salary sort order, passed as `TIER` in template results.

**Tier badges**: Small colored dots next to golfer names — gold (Tier 1), green (Tier 2), muted green (Tier 3). CSS class `.tier-dot`.

**Template context**: `all_teams` (sorted unique team names) computed in `app.py` and passed to template for the filter dropdown.

Team chip highlighting (`toggleTeamHighlight()` / `updateRowHighlighting()`) works across both layouts — mobile cards use a `data-team-names` attribute for matching.

### Caching

In-memory dict, 5-minute TTL, per-worker (not shared). Use `clear_tournament_cache(tournament_id)` to clear specific caches, or `clear_tournament_cache()` to clear all. Called on pick submission, tournament activation, golfer refresh, and tier changes.

### Turbo Drive

Hotwire Turbo Drive 8.0.12 loaded via ESM import in `base.html`. Intercepts link clicks and form submissions, swapping `<body>` without full page reloads. `<meta name="turbo-cache-control" content="no-preview">` disables preview caching.

**Key patterns:**
- Use `turbo:load` instead of `DOMContentLoaded` for page-init JS — it fires on both initial load and Turbo navigations
- Forms that return 200 with HTML (not redirects) must use `data-turbo="false"` — Turbo expects 303 redirects for POST responses
- Currently disabled on: login form, request access form
- CSS `animate-fade-in` on cards/rows for smooth page transition feel

### Feedback Widget

Floating speech bubble button (bottom-right) on all authenticated pages (`{% if show_nav %}` block in `base.html`). Opens a popover with a textarea; submits via `fetch()` POST to `/submit-feedback`. Feedback stored in `feedback` table with `user_id`, `page_url`, `message`, and `resolved` flag. Admin view at `/admin/feedback` with Open/Resolved/All filter tabs and per-item toggle button. Linked from the admin dashboard.

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
- Shared helpers reduce duplication: `format_last_updated()`, `clear_tournament_cache()`, `get_tournament_external_info()`, `compute_tier()` with `TIER_BOUNDARIES` constant, `_build_tier_lists(tournament_id)`, `_render_pick_form()`, `compute_tournament_winners(tournament_id)`
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

GitHub Actions runs pytest on push/PR to `main` (`.github/workflows/test.yml`). Auto-refresh cron runs hourly during tournament windows (`.github/workflows/auto-refresh.yml`). Required GitHub Actions secrets: `GOLF_API_KEY`, `APP_URL`.

## Cut Line Modifier (Leaderboard Scoring)

The `apply_cut_modifier()` helper adjusts golfer scores on the leaderboard based on whether they made or missed the cut. The `cut_line` value is stored as an integer in `tournament_metadata` (parsed from the API via `parse_score_to_int()`).

**API convention vs app convention:** The Golf API's `cutScore` = "the worst score that makes the cut" (e.g., "+2"). The app's `cut_line` = "the score assigned to missed-cut golfers" (one stroke worse). Relationship: `app_cut_line = API_cutScore + 1`. This conversion happens during golfer refresh. **Display convention:** The player standings template shows `cut_line - 1` (the actual cut line, i.e. the worst score that makes the cut), not the internal `cut_line` value.

**Rules:**
- **Missed cut** (`status == 'cut'`): score = `cut_line`. Example: cut is +1, golfer missed at +7 → score becomes +1.
- **Made cut** (any other status): score = `min(actual_score, cut_line - 1)`. Example: cut is +1, golfer at +3 → score becomes 0 (cut_line - 1).
- If a golfer makes the cut and finishes under the cap, their actual score is used (no adjustment).

**Applied in:** `compute_leaderboard()` (team scores), `compute_tournament_winners()` (winnings), leaderboard route `player_scores` dict, player standings route `TOTAL_SCORE_INTEGER`. Raw `total_score` in the `golfers` table is never modified.

**Falsy-zero caution:** Cut line can be 0 (Even par). Always use `is not None` checks, never truthiness checks (`if cut_line` would fail for E/0). This applies in both Python and Jinja2 templates (`{% if cut_line is not none %}`).
