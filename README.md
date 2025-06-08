# Flask Golf

Flask web application that displays standings and picks for a fantasy golf league using data stored in Snowflake.

## Features

- Shows a leaderboard with entry names, team scores and selected golfers.
- Retrieves data via the Snowpark Python API.
- Responsive layout built with Bulma CSS.
- Configured for Gunicorn deployment.

## Setup

1. Use **Python 3.10** (see `runtime.txt`).
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Required Environment Variables

Set the following variables to connect to Snowflake:

- `SNOWFLAKE_ACCOUNT`
- `SNOWFLAKE_USER`
- `SNOWFLAKE_ROLE`
- `SNOWFLAKE_WAREHOUSE`
- `SNOWFLAKE_DATABASE`
- `SNOWFLAKE_SCHEMA`
- `SNOWFLAKE_PRIVATE_KEY` – base64 encoded private key
- `SNOWFLAKE_PASSWORD` – optional password for local testing
- `SNOWFLAKE_QUERY_TAG` – optional query tag

These variables can also be defined in a local `config.py` for development. If `SNOWFLAKE_PRIVATE_KEY` is not provided, the application will attempt password authentication using `SNOWFLAKE_PASSWORD`.

## Running the Server Locally

After setting the environment variables, start the app with:

```bash
python app.py
```

This runs Flask in debug mode. For production use Gunicorn:

```bash
gunicorn --worker-tmp-dir /dev/shm --config gunicorn_config.py app:app
```

## Deployment Tips

`runtime.txt` and `Procfile.txt` are provided for deploying to platforms like Heroku. Ensure all Snowflake credentials are configured as environment variables in your deployment environment.
