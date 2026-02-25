# Flask Golf — 80 Yard Bombs Cup

Web application for a fantasy golf league. Players pick golfers for each tournament, and the leaderboard tracks scores across the season.

**Live**: Deployed on DigitalOcean App Platform, auto-deploys from `main`.

## Tech Stack

- **Python 3.12** / **Flask 3.0.3** — single-file app (`app.py`)
- **Turso** (hosted libSQL) — database via `libsql_experimental`
- **Resend** — transactional email (magic links, notifications)
- **Slash Golf API** (RapidAPI) — live golf scores and tournament data
- **DraftKings** — salary data for golfer tier sorting
- **Tailwind CSS** (static build) — dark-themed responsive UI
- **Gunicorn** — production WSGI server
- **GitHub Actions** — CI (pytest) + automated score refresh cron

## User Features

### Authentication
- **Passwordless login** — enter your email, receive a magic link, click to sign in
- **Invite-only registration** — new users submit an access request (name + email); an admin must approve before they can log in
- **Session persistence** — stay logged in for 7 days

### Making Picks
- When a tournament is active and picks are unlocked, navigate to the **Picks** tab
- Golfers are organized into **tiers** (sorted by DraftKings salary when available)
- Select one golfer per tier using the searchable dropdown
- Submit your picks — duplicates and invalid selections are rejected
- You can update your picks any time before the admin locks them

### Leaderboard
- View the current tournament's fantasy leaderboard with live scores
- Each entry shows the total score and a breakdown by individual golfer
- Golfer scores update automatically during tournament hours (or manually by an admin)
- Entries are ranked by total score (lowest wins, golf-style)

### Player Standings
- See every golfer in the tournament field with their current score
- View which league members selected each golfer

## Admin Features

Admins are identified by email address (configured via `ADMIN_EMAILS` env var). The **Admin** tab is visible only to admin users.

### Tournament Management
- **Create tournaments** — enter a name and select from upcoming events fetched from the Golf API schedule
- **Activate a tournament** — sets it as the current tournament and auto-refreshes the golfer field from the API
- **Delete tournaments** — remove tournaments (with confirmation)
- **Lock/unlock picks** — toggle whether users can submit or change their picks

### Golfer & Score Management
- **Refresh golfers** — pull latest scores from the Slash Golf API on demand
- **Fetch DraftKings salaries** — import salary data used to sort golfers into tiers
- **Manage tiers** — configure how golfers are grouped into pick tiers; drag golfers between tiers or reset to defaults
- **Auto-refresh schedule** — configure the time window (hours and days of week) when the GitHub Actions cron job will automatically refresh scores

### User Management
- **Approve/reject access requests** — pending requests appear on the admin dashboard with approve/reject buttons
- **Open/close registration** — toggle whether the access request form is available to new users

### API Status
- The admin dashboard shows Golf API connection status at a glance

## Setup

```bash
# Install Python dependencies
uv pip install -r requirements.txt

# Install Node dependencies (for Tailwind CSS builds)
npm install

# Initialize the database
uv run flask init-db

# Run dev server
PYTHONUNBUFFERED=1 uv run python app.py
# App runs on http://127.0.0.1:5000
```

## Environment Variables

Configure in `.env` for local dev, or as secrets in the deployment dashboard.

| Variable | Required | Description |
|----------|----------|-------------|
| `TURSO_DATABASE_URL` | Yes | Turso libSQL connection URL |
| `TURSO_AUTH_TOKEN` | Yes (prod) | Turso auth token |
| `FLASK_SECRET_KEY` | Yes (prod) | Secret key for sessions/CSRF |
| `RESEND_API_KEY` | No | Resend API key — omit to print magic links to console |
| `EMAIL_FROM` | No | Sender address (default: `picks@updates.cullin.link`) |
| `GOLF_API_KEY` | No | RapidAPI key for Slash Golf API |
| `ADMIN_EMAILS` | No | Comma-separated admin email addresses |

## Testing

```bash
uv run pytest tests/
```

78 tests covering auth, picks, leaderboard scoring, admin routes, and utility functions. CI runs automatically on push/PR to `main`.

## Deployment

Deployed on **DigitalOcean App Platform**. Auto-deploys from `main`.

- Deploy spec: `.do/app.yaml`
- Health check: `GET /health`
- Run command: `gunicorn --worker-tmp-dir /dev/shm --config gunicorn_config.py app:app`

## License

MIT
