"""Shared fixtures for Flask Golf tests."""

import hashlib
import os
import sys
import secrets
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

# Add project root to path so `import app` works from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Set env vars BEFORE importing app — module-level code runs migrations on import
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-pytest'
os.environ['FLASK_DEBUG'] = '1'
os.environ['ADMIN_EMAILS'] = 'admin@test.com'
# Unset keys that would trigger real API/email calls
os.environ.pop('RESEND_API_KEY', None)
os.environ.pop('GOLF_API_KEY', None)

# Use a temp file for the DB — libsql :memory: doesn't work across Flask request contexts
_db_fd, _db_path = tempfile.mkstemp(suffix='.db')
os.close(_db_fd)
os.environ['TURSO_DATABASE_URL'] = f'file:{_db_path}'

# Now safe to import app (triggers module-level migration code)
import app as app_module  # noqa: E402


@pytest.fixture(scope='session')
def app_instance():
    """Session-scoped Flask app instance."""
    app_module.app.config['TESTING'] = True
    return app_module.app


@pytest.fixture()
def db(app_instance, tmp_path):
    """Function-scoped fresh DB: re-init schema for each test."""
    db_file = tmp_path / 'test.db'
    os.environ['TURSO_DATABASE_URL'] = f'file:{db_file}'

    with app_instance.app_context():
        import libsql_experimental as libsql
        conn = libsql.connect(str(db_file))
        wrapped = app_module.LibSQLConnectionWrapper(conn)

        schema_path = os.path.join(os.path.dirname(__file__), '..', 'schema.sql')
        with open(schema_path) as f:
            wrapped.executescript(f.read())
        wrapped.commit()
        app_module._run_migrations(wrapped)

        # Override get_db to return this connection within the test's app context
        original_get_db = app_module.get_db

        def _test_get_db():
            from flask import g
            g.db = wrapped
            return wrapped

        app_module.get_db = _test_get_db

        yield wrapped

        app_module.get_db = original_get_db


@pytest.fixture()
def client(app_instance, db):
    """Test client with fresh DB."""
    return app_instance.test_client()


def _create_user(db, email, first_name='Test', last_name='User', is_admin=0):
    """Insert a user and return their ID."""
    user_id = secrets.token_hex(16)
    db.execute(
        "INSERT INTO users (id, email, display_name, first_name, last_name, is_admin) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [user_id, email, f'{first_name} {last_name}', first_name, last_name, is_admin],
    )
    db.commit()
    return user_id


def _create_session(db, user_id):
    """Insert a session row and return the raw token (for the cookie)."""
    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    session_id = secrets.token_hex(16)
    db.execute(
        "INSERT INTO sessions (id, user_id, session_token_hash, expires_at) "
        "VALUES (?, ?, ?, ?)",
        [session_id, user_id, token_hash, expires_at],
    )
    db.commit()
    return raw_token


@pytest.fixture()
def auth_client(app_instance, db):
    """Test client logged in as a regular user."""
    user_id = _create_user(db, 'user@test.com')
    raw_token = _create_session(db, user_id)
    c = app_instance.test_client()
    c.set_cookie('golf_session', raw_token, domain='localhost')
    return c


@pytest.fixture()
def admin_client(app_instance, db):
    """Test client logged in as an admin user."""
    user_id = _create_user(db, 'admin@test.com', first_name='Admin', last_name='Boss', is_admin=1)
    raw_token = _create_session(db, user_id)
    c = app_instance.test_client()
    c.set_cookie('golf_session', raw_token, domain='localhost')
    return c


@pytest.fixture()
def seed_tournament(db):
    """Insert an active tournament with golfers. Returns tournament dict."""
    tid = secrets.token_hex(16)
    db.execute(
        "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked) "
        "VALUES (?, ?, ?, ?, 1, 0)",
        [tid, 'ext-001', 'Test Open', 2026],
    )

    golfer_names = [
        'Tiger Woods', 'Rory McIlroy', 'Scottie Scheffler', 'Jon Rahm', 'Brooks Koepka',
        'Viktor Hovland', 'Patrick Cantlay', 'Xander Schauffele', 'Collin Morikawa', 'Justin Thomas',
        'Sam Burns', 'Max Homa', 'Wyndham Clark', 'Brian Harman', 'Matt Fitzpatrick',
        'Cameron Smith', 'Tommy Fleetwood', 'Hideki Matsuyama', 'Sahith Theegala', 'Sungjae Im',
    ]
    for i, name in enumerate(golfer_names):
        gid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO golfers (id, tournament_id, name, external_id, position, total_score, "
            "score_display, status, owgr_rank) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [gid, tid, name, str(i), str(i + 1), i - 5, format_score_for_seed(i - 5), 'active', i + 1],
        )
    db.commit()

    return {
        'id': tid,
        'external_id': 'ext-001',
        'name': 'Test Open',
        'season_year': 2026,
        'is_active': True,
        'picks_locked': False,
    }


def format_score_for_seed(score):
    if score == 0:
        return 'E'
    if score > 0:
        return f'+{score}'
    return str(score)


def get_csrf_token(client):
    """Fetch a page to populate the Flask session, then extract the CSRF token."""
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
        if not token:
            token = secrets.token_hex(32)
            sess['csrf_token'] = token
    return token
