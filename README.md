# Flask Golf

Web application for a fantasy golf league ("80 Yard Bombs Cup"). Displays leaderboards, player standings, and allows users to submit golfer picks. Data is stored in Snowflake and accessed via the Snowpark Python API.

## Features

- Entry-focused leaderboard with team scores and selected golfers
- Individual golfer standings view
- Pick submission form with tiered golfer dropdowns
- In-memory caching with 5-minute TTL
- Responsive dark-themed UI built with Tailwind CSS

## Tech Stack

- **Python 3.10** (see `runtime.txt`)
- **Flask 3.0.3** with Jinja2 templates
- **Snowflake** via `snowflake-snowpark-python`
- **Pandas** for data manipulation
- **Tailwind CSS** (CDN) for frontend styling
- **Choices.js** (CDN) for dropdown components
- **Gunicorn** for production WSGI serving
- **Flask-Compress** for HTTP response compression

## Setup

1. Use **Python 3.10** (see `runtime.txt`).
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure Snowflake credentials via environment variables or a local `config.py` (gitignored).

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

If `SNOWFLAKE_PRIVATE_KEY` is not set, the app falls back to password authentication using `SNOWFLAKE_PASSWORD`.

## Running Locally

```bash
python app.py
```

This starts Flask in debug mode on port 5000.

## Production

```bash
gunicorn --worker-tmp-dir /dev/shm --config gunicorn_config.py app:app
```

Gunicorn is configured to bind on port 8080 with 2 workers.

## Deployment

Deployment configs are provided for:
- **DigitalOcean App Platform** — `.do/app.yaml` and `.do/deploy.template.yaml`
- **Heroku** — `Procfile.txt` and `runtime.txt`

Ensure all Snowflake credentials are set as environment variables in your deployment environment.

## License

MIT
