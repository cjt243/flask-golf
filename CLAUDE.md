# CLAUDE.md

## Project Overview

Flask Golf is a web application for a fantasy golf league. It displays leaderboards, player standings, and allows users to submit golfer picks. Data is stored in Snowflake and accessed via the Snowpark Python API. The frontend uses Tailwind CSS with a dark theme.

## Tech Stack

- **Python 3.10** (see `runtime.txt`)
- **Flask 3.0.3** with Jinja2 templates
- **Snowflake** via `snowflake-snowpark-python` and `snowflake-connector-python`
- **Pandas** for data manipulation
- **Tailwind CSS** (CDN) for frontend styling
- **Choices.js** (CDN) for dropdown components
- **Gunicorn** for production WSGI serving
- **Flask-Compress** for HTTP response compression

## Repository Structure

```
flask-golf/
├── app.py                  # Main Flask application (all routes + helpers)
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
│   ├── pick_form.html      # Golfer pick submission form
│   └── submit_success.html # Post-submission confirmation
├── .gitignore
├── LICENSE                 # MIT
└── README.md
```

This is a single-file Flask app — all routes, helpers, and configuration live in `app.py`. There is no package structure, no `__init__.py`, and no separate modules.

## Architecture

### Application Entry Point

`app.py` is both the module and the application. The Flask app instance is `app`. Run locally with `python app.py` (debug mode) or in production with gunicorn via `gunicorn --config gunicorn_config.py app:app`.

### Routes

| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/` | GET | `leaderboard()` | Main leaderboard showing fantasy league entry standings |
| `/players` | GET | `player_standings()` | Individual golfer performance table |
| `/make_picks` | GET | `make_picks()` | Pick submission form with tiered golfer dropdowns |
| `/submit_picks` | POST | `submit_picks()` | Processes pick submissions, writes to Snowflake |
| `/health` | GET | `health_check()` | Returns JSON health status and cache metrics |
| `/clear_cache` | GET | `clear_cache()` | Clears all in-memory cached data |

### Caching

- **Snowpark session cache**: Global singleton session with 1-hour timeout (`SESSION_TIMEOUT = 3600`). Sessions are reused across requests, not closed after each one.
- **Data cache**: In-memory dict with 5-minute TTL (`CACHE_TTL = 300`). Cache keys: `leaderboard_data`, `player_standings_data`, `pick_options_data`.

### Snowflake Authentication

Two authentication methods, selected automatically:
1. **Key-pair auth** (production): Uses `SNOWFLAKE_PRIVATE_KEY` env var (base64-encoded PEM private key), authenticates via `SNOWFLAKE_JWT`.
2. **Password auth** (local dev): Falls back to `SNOWFLAKE_PASSWORD` if no private key is set.

Configuration can come from environment variables or a local `config.py` file (gitignored).

### Database Schema

All queries target the `GOLF_LEAGUE` database:

- `APPLICATION.LEADERBOARD_DISPLAY_DETAILED_VW` — aggregated entry standings
- `APPLICATION.PLAYER_FOCUSED_LEADERBOARD_VW` — individual golfer scores
- `APPLICATION.LATEST_LEADERBOARD_UPDATE_VW` — last-updated timestamps
- `APPLICATION.PICK_OPTIONS_VW` — available golfers for picking
- `APPLICATION.POOL_STAGING` — pick submissions (write target)
- `FANTASY_LEAGUE_DATA.TOURNAMENT_CONFIG` — active tournament configuration
- `PRO_GOLF_DATA.LEADERBOARD` — raw leaderboard data
- `PRO_GOLF_DATA.TOURNAMENT_SCHEDULE` — tournament metadata

### Tournament Resolution

The app determines which tournament to display through a fallback chain:
1. Query `TOURNAMENT_CONFIG` for `IS_ACTIVE = TRUE`
2. Verify that tournament has leaderboard data
3. If no active config or no data, fall back to the tournament with the most recent leaderboard update

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNOWFLAKE_ACCOUNT` | Yes | Snowflake account identifier |
| `SNOWFLAKE_USER` | Yes | Snowflake username |
| `SNOWFLAKE_ROLE` | Yes | Snowflake role |
| `SNOWFLAKE_WAREHOUSE` | Yes | Snowflake compute warehouse |
| `SNOWFLAKE_DATABASE` | Yes | Database name (`GOLF_LEAGUE`) |
| `SNOWFLAKE_SCHEMA` | Yes | Schema name (`APPLICATION`) |
| `SNOWFLAKE_PRIVATE_KEY` | Prod | Base64-encoded private key for JWT auth |
| `SNOWFLAKE_PASSWORD` | Dev | Password for local testing (fallback) |
| `SNOWFLAKE_QUERY_TAG` | No | Optional query tracking tag |

For local development, these can be defined in a `config.py` file at the project root (gitignored).

## Development Setup

```bash
# Use Python 3.10
pip install -r requirements.txt

# Set Snowflake credentials via environment or config.py
python app.py  # Runs Flask dev server
```

## Production Deployment

```bash
gunicorn --worker-tmp-dir /dev/shm --config gunicorn_config.py app:app
```

Deployment is configured for **Heroku** (`Procfile.txt`, `runtime.txt`) and **DigitalOcean App Platform** (`.do/` directory).

## Testing

No test suite exists. There are no test files, test frameworks, or CI/CD pipelines configured.

## Linting / Formatting

No linting or formatting tools are configured. There is no `pyproject.toml`, `.flake8`, or pre-commit hook setup.

## Key Conventions

- All application logic is in `app.py` — keep it as a single-file app unless there's a strong reason to split.
- Templates live in `templates/` and use Tailwind CSS via CDN (no build step).
- Snowflake queries use both the Snowpark DataFrame API (`session.table().select()`) and raw SQL (`session.sql()`).
- Timestamps are converted from UTC to US/Eastern for display.
- The pick form divides golfers into three tiers by rank: top 5, next 11, and the rest.
- Error handling uses try-except with fallback values and `print()` for logging.
- No API authentication is implemented — routes are publicly accessible.
