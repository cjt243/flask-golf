"""
Flask Golf - Fantasy Golf League Application
"""

import os
import re
import json
import html
import time
import random
import logging
import secrets
import hashlib
import unicodedata
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import quote, urlparse

import libsql
import requests
import resend
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from email_validator import validate_email, EmailNotValidError
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, g, make_response
)
from flask_compress import Compress
from dotenv import load_dotenv
from pytz import timezone as pytz_timezone

# Load .env before app creation so env vars are available for config checks.
# Flask only auto-loads .env via `flask run`, not `python app.py` or gunicorn.
load_dotenv()

app = Flask(__name__)
Compress(app)

# Flask configuration
_secret_key = os.getenv('FLASK_SECRET_KEY')
if not _secret_key and not os.getenv('FLASK_DEBUG'):
    raise RuntimeError(
        'FLASK_SECRET_KEY must be set in production. '
        'Each Gunicorn worker generates a different random key without it, '
        'breaking sessions and CSRF.'
    )
app.secret_key = _secret_key or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_SECURE=not app.debug,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='golf_flask_session',
)

# Logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('flask_golf')

# Constants
CACHE_TTL = 300  # 5 minutes
SESSION_EXPIRY_DAYS = 7
MAGIC_LINK_EXPIRY_MINUTES = 10
ADMIN_EMAILS = os.getenv('ADMIN_EMAILS', '').split(',')

# Tier boundaries: (threshold, tier) — index < threshold → tier
TIER_BOUNDARIES = [(5, 1), (16, 2)]
MAJOR_KEYWORDS = ['masters', 'pga championship', 'u.s. open', 'open championship', 'the open']


def _is_major(tournament_name):
    """Check if a tournament is a major based on name keywords."""
    name_lower = tournament_name.lower()
    return any(kw in name_lower for kw in MAJOR_KEYWORDS)

# Rate limiting configuration
RATE_LIMITS = {
    'magic_link_per_email': {'max': 3, 'window_minutes': 60},
    'magic_link_per_ip': {'max': 10, 'window_minutes': 60},
    'failed_verifications_per_ip': {'max': 5, 'window_minutes': 15},
    'access_request_per_ip': {'max': 5, 'window_minutes': 60},
}

# Argon2 password hasher
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID
)

# Simple in-memory cache
_cache = {}

# =============================================================================
# Database Connection
# =============================================================================

class LibSQLConnectionWrapper:
    """Wrapper that auto-converts list params to tuples for libsql compatibility."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, parameters=None):
        if parameters is not None and isinstance(parameters, list):
            parameters = tuple(parameters)
        if parameters is not None:
            return self._conn.execute(sql, parameters)
        return self._conn.execute(sql)

    def executescript(self, sql):
        return self._conn.executescript(sql)

    def commit(self):
        return self._conn.commit()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def get_db():
    """Get database connection for current request."""
    if 'db' not in g:
        db_url = os.getenv('TURSO_DATABASE_URL', 'file:local.db')
        auth_token = os.getenv('TURSO_AUTH_TOKEN', '')

        if db_url.startswith('file:'):
            conn = libsql.connect(db_url.replace('file:', ''))
        else:
            conn = libsql.connect(db_url, auth_token=auth_token)
        g.db = LibSQLConnectionWrapper(conn)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request."""
    g.pop('db', None)


def init_db():
    """Initialize database schema."""
    db = get_db()
    with open('schema.sql', 'r') as f:
        db.executescript(f.read())
    db.commit()
    _run_migrations(db)


def _run_migrations(db):
    """Run schema migrations that ALTER TABLE can't handle via IF NOT EXISTS."""
    migrations = [
        # Phase 1.5: Split display_name into first_name + last_name
        ("ALTER TABLE users ADD COLUMN first_name TEXT", "users.first_name"),
        ("ALTER TABLE users ADD COLUMN last_name TEXT", "users.last_name"),
        ("ALTER TABLE access_requests ADD COLUMN first_name TEXT", "access_requests.first_name"),
        ("ALTER TABLE access_requests ADD COLUMN last_name TEXT", "access_requests.last_name"),
        ("ALTER TABLE golfers ADD COLUMN tier_override INTEGER", "golfers.tier_override"),
        ("ALTER TABLE golfers ADD COLUMN dk_salary INTEGER", "golfers.dk_salary"),
        ("ALTER TABLE tournaments ADD COLUMN refresh_interval_minutes INTEGER DEFAULT 60", "tournaments.refresh_interval_minutes"),
        ("ALTER TABLE tournaments ADD COLUMN buy_in INTEGER DEFAULT 5", "tournaments.buy_in"),
        ("ALTER TABLE entries ADD COLUMN paid INTEGER DEFAULT 0", "entries.paid"),
    ]
    for sql, description in migrations:
        try:
            db.execute(sql)
            logger.info(f"Migration applied: {description}")
        except Exception as e:
            if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                pass  # Column already exists, skip
            else:
                logger.warning(f"Migration skipped ({description}): {e}")
    db.commit()

    # Create new tables — idempotent via IF NOT EXISTS
    for sql in [
        """CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            page_url TEXT NOT NULL,
            message TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )""",
    ]:
        try:
            db.execute(sql)
        except Exception:
            pass
    db.commit()

    # Indexes — idempotent, but tables may not exist yet (e.g., test env before init-db)
    for sql in [
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at)",
    ]:
        try:
            db.execute(sql)
        except Exception:
            pass  # Table doesn't exist yet; init-db will create both table and index
    db.commit()


# =============================================================================
# Caching
# =============================================================================

def get_cached(key):
    """Get cached data if it exists and hasn't expired."""
    if key in _cache:
        data, timestamp = _cache[key]
        if time.time() - timestamp < CACHE_TTL:
            return data
        else:
            del _cache[key]
    return None


def set_cache(key, data):
    """Set cached data with current timestamp."""
    _cache[key] = (data, time.time())


def clear_tournament_cache(tournament_id=None):
    """Clear tournament-specific caches, or all caches if no ID given."""
    if tournament_id:
        _cache.pop(f'leaderboard_{tournament_id}', None)
        _cache.pop(f'players_{tournament_id}', None)
        # Season standings depend on all tournaments
        for key in list(_cache):
            if key.startswith('standings_'):
                _cache.pop(key, None)
    else:
        _cache.clear()


def format_last_updated(iso_string):
    """Format ISO timestamp for display in US/Eastern."""
    if not iso_string:
        return 'N/A'
    try:
        dt = datetime.fromisoformat(iso_string)
        dt = dt.replace(tzinfo=pytz_timezone('UTC')).astimezone(pytz_timezone('US/Eastern'))
        return dt.strftime('%A %B %d @ %I:%M %p %Z')
    except (ValueError, TypeError):
        return 'Recently updated'


# =============================================================================
# Security Middleware
# =============================================================================

@app.after_request
def log_request(response):
    if request.path == '/health' or request.path == '/favicon.ico':
        return response
    duration = time.time() - g.get('request_start_time', time.time())
    if response.status_code >= 500:
        logger.error("%(method)s %(path)s %(status)s %(duration).0fms",
                     {'method': request.method, 'path': request.path,
                      'status': response.status_code, 'duration': duration * 1000})
    elif duration > 2.0:
        logger.warning("Slow request: %(method)s %(path)s %(status)s %(duration).0fms",
                       {'method': request.method, 'path': request.path,
                        'status': response.status_code, 'duration': duration * 1000})
    return response


@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.before_request
def start_request_timer():
    g.request_start_time = time.time()


@app.before_request
def enforce_https():
    """Redirect HTTP to HTTPS in production."""
    if not app.debug and request.path != '/health':
        if request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            return redirect(request.url.replace('http://', 'https://'), code=301)


@app.before_request
def load_user():
    """Load current user from session cookie."""
    g.user = None
    session_token = request.cookies.get('golf_session')

    if session_token:
        db = get_db()
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()

        result = db.execute("""
            SELECT s.id, s.user_id, s.expires_at, u.email, u.display_name, u.is_admin,
                   u.first_name, u.last_name
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token_hash = ?
        """, [token_hash]).fetchone()

        if result:
            expires_at = datetime.fromisoformat(result[2]).replace(tzinfo=timezone.utc)
            if expires_at > datetime.now(timezone.utc):
                g.user = {
                    'id': result[1],
                    'email': result[3],
                    'display_name': result[4],
                    'is_admin': bool(result[5]),
                    'session_id': result[0],
                    'first_name': result[6],
                    'last_name': result[7]
                }
                # Update last activity
                db.execute(
                    "UPDATE sessions SET last_activity = datetime('now') WHERE id = ?",
                    [result[0]]
                )
                db.commit()

                # Probabilistic cleanup: ~1% of requests clean expired sessions/tokens
                if random.random() < 0.01:
                    try:
                        db.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
                        db.execute("DELETE FROM auth_tokens WHERE expires_at < datetime('now')")
                        db.commit()
                        logger.info("Probabilistic session cleanup ran")
                    except Exception:
                        pass


@app.context_processor
def inject_globals():
    """Inject global template variables."""
    picks_open = False
    tournament = get_active_tournament()
    if tournament and not tournament['picks_locked']:
        picks_open = True
    return {'season_year': datetime.now().year, 'picks_open': picks_open}


# =============================================================================
# CSRF Protection
# =============================================================================

def get_csrf_token():
    """Generate or retrieve CSRF token for current session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = get_csrf_token


def csrf_required(f):
    """Decorator to require CSRF token on POST requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or not secrets.compare_digest(token, session.get('csrf_token', '')):
            log_security_event('csrf_failure', request)
            abort(403)
        return f(*args, **kwargs)
    return decorated


# =============================================================================
# App Settings
# =============================================================================

def is_registration_open():
    """Check if registration is open (default: True)."""
    try:
        db = get_db()
        row = db.execute("SELECT value FROM app_settings WHERE key = 'registration_open'").fetchone()
        return row[0] != '0' if row else True
    except Exception:
        return True


def get_refresh_schedule():
    """Get the auto-refresh schedule from app_settings.

    Returns dict with start_hour, end_hour (US/Eastern, 0-23), and days (list of
    weekday ints, 0=Monday..6=Sunday).

    Defaults: Thu-Sun (3,4,5,6), 8:00-20:00 ET (8am-8pm Eastern).
    """
    defaults = {'start_hour': 8, 'end_hour': 20, 'days': [3, 4, 5, 6]}
    try:
        db = get_db()
        row = db.execute("SELECT value FROM app_settings WHERE key = 'refresh_schedule'").fetchone()
        if row:
            return json.loads(row[0])
    except Exception:
        pass
    return defaults


def save_refresh_schedule(start_hour, end_hour, days):
    """Save the auto-refresh schedule to app_settings."""
    schedule = {'start_hour': int(start_hour), 'end_hour': int(end_hour), 'days': sorted(days)}
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('refresh_schedule', ?)",
        [json.dumps(schedule)]
    )
    db.commit()


def get_stored_schedule(year, org_id='1'):
    """Read cached tournament schedule from app_settings."""
    key = f"tournament_schedule_{year}_{org_id}"
    try:
        db = get_db()
        row = db.execute("SELECT value FROM app_settings WHERE key = ?", [key]).fetchone()
        if row:
            return json.loads(row[0])
    except Exception:
        pass
    return None


def save_schedule(year, org_id, schedule_data):
    """Write tournament schedule to app_settings."""
    key = f"tournament_schedule_{year}_{org_id}"
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
        [key, json.dumps(schedule_data)]
    )
    db.commit()


def is_within_refresh_window():
    """Check if the current Eastern time falls within the configured refresh schedule."""
    schedule = get_refresh_schedule()
    now = datetime.now(pytz_timezone('US/Eastern'))
    current_hour = now.hour
    current_day = now.weekday()  # 0=Monday..6=Sunday

    if current_day not in schedule['days']:
        return False

    start = schedule['start_hour']
    end = schedule['end_hour']

    if start <= end:
        # Simple range, e.g. 8-20
        return start <= current_hour < end
    else:
        # Wraps midnight, e.g. 12-0 means 12:00 UTC through 23:59 UTC
        return current_hour >= start or current_hour < end


# Rate Limiting
# =============================================================================

def get_client_ip():
    """Get client IP, handling proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr


def check_rate_limit(identifier, action):
    """Check if rate limit is exceeded. Returns True if allowed, False if blocked."""
    limit_config = RATE_LIMITS.get(action)
    if not limit_config:
        return True

    db = get_db()
    window_minutes = limit_config['window_minutes']

    # Upsert: insert new row or reset expired window, then increment
    db.execute("""
        INSERT INTO rate_limits (identifier, action, attempts, window_start)
        VALUES (?, ?, 1, datetime('now'))
        ON CONFLICT(identifier, action) DO UPDATE SET
            attempts = CASE
                WHEN datetime(window_start, '+' || ? || ' minutes') < datetime('now')
                THEN 1
                ELSE attempts + 1
            END,
            window_start = CASE
                WHEN datetime(window_start, '+' || ? || ' minutes') < datetime('now')
                THEN datetime('now')
                ELSE window_start
            END
    """, [identifier, action, window_minutes, window_minutes])
    db.commit()

    result = db.execute("""
        SELECT attempts FROM rate_limits
        WHERE identifier = ? AND action = ?
    """, [identifier, action]).fetchone()

    return result[0] <= limit_config['max']


# =============================================================================
# Security Logging
# =============================================================================

def log_security_event(event_type, req, user_id=None, email=None, details=None):
    """Log security events for monitoring."""
    try:
        db = get_db()
        db.execute("""
            INSERT INTO security_events (id, event_type, user_id, email, ip_address, user_agent, details)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?)
        """, [
            event_type,
            user_id,
            email,
            get_client_ip() if req else None,
            req.headers.get('User-Agent', '')[:500] if req else None,
            json.dumps(details) if details else None
        ])
        db.commit()
    except Exception as e:
        logger.error(f"Error logging security event: {e}")


# =============================================================================
# Input Validation
# =============================================================================

def validate_user_email(email_input):
    """Validate and normalize email address."""
    try:
        valid = validate_email(email_input, check_deliverability=False)
        return valid.normalized
    except EmailNotValidError:
        return None


ENTRY_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-_\'\.]{1,50}$')


def validate_entry_name(name):
    """Validate entry name."""
    if not name:
        return None
    name = name.strip()
    if not ENTRY_NAME_PATTERN.match(name):
        return None
    return html.escape(name)


# =============================================================================
# Authentication Helpers
# =============================================================================

def login_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            return redirect(url_for('auth_login', next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            return redirect(url_for('auth_login', next=request.path))
        if not g.user.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated


def create_session(user_id):
    """Create a new session for user and return session token."""
    session_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_EXPIRY_DAYS)

    db = get_db()
    db.execute("""
        INSERT INTO sessions (id, user_id, session_token_hash, ip_address, user_agent_hash, expires_at)
        VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?)
    """, [
        user_id,
        token_hash,
        get_client_ip(),
        hashlib.sha256(request.headers.get('User-Agent', '').encode()).hexdigest()[:32],
        expires_at.isoformat()
    ])
    db.commit()

    return session_token, expires_at


def send_magic_link(email, token, next_url=''):
    """Send magic link email via Resend."""
    api_key = os.getenv('RESEND_API_KEY')
    email_from = os.getenv('EMAIL_FROM', 'picks@updates.cullin.link')

    verify_url = f"{request.host_url}auth/verify?token={token}&email={email}"
    if next_url:
        verify_url += f"&next={quote(next_url, safe='/')}"

    if not api_key:
        # Development mode - print to console
        logger.info(f"MAGIC LINK for {email}: {verify_url}")
        return True

    resend.api_key = api_key

    try:
        resend.Emails.send({
            "from": email_from,
            "to": email,
            "subject": "Sign in to 80 Yard Bombs Cup",
            "html": render_template('emails/magic_link.html', verify_url=verify_url)
        })
        return True
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        return False


def send_admin_notification(requester_name, requester_email):
    """Notify admin(s) about a new access request via Resend."""
    api_key = os.getenv('RESEND_API_KEY')
    email_from = os.getenv('EMAIL_FROM', 'picks@updates.cullin.link')
    admin_emails = [e.strip() for e in ADMIN_EMAILS if e.strip()]

    if not admin_emails:
        logger.info(f"ACCESS REQUEST from {requester_name} ({requester_email}) — no admin emails configured")
        return

    if not api_key:
        logger.info(f"ACCESS REQUEST from {requester_name} ({requester_email}) — would notify: {', '.join(admin_emails)}")
        return

    resend.api_key = api_key

    email_html = render_template('emails/admin_notification.html',
                                  requester_name=requester_name,
                                  requester_email=requester_email,
                                  admin_url=f"{request.host_url}admin")

    for admin_email in admin_emails:
        try:
            resend.Emails.send({
                "from": email_from,
                "to": admin_email,
                "subject": f"New Access Request: {requester_name}",
                "html": email_html
            })
        except Exception as e:
            logger.error(f"Error sending admin notification to {admin_email}: {e}")


def send_approval_email(email, name):
    """Send approval notification to user via Resend."""
    api_key = os.getenv('RESEND_API_KEY')
    email_from = os.getenv('EMAIL_FROM', 'picks@updates.cullin.link')

    if not api_key:
        logger.info(f"APPROVAL EMAIL for {name} ({email}) — sign in at: {request.host_url}auth/login")
        return True

    resend.api_key = api_key

    try:
        resend.Emails.send({
            "from": email_from,
            "to": email,
            "subject": "You've been approved - 80 Yard Bombs Cup",
            "html": render_template('emails/approval.html',
                                    name=name,
                                    login_url=f"{request.host_url}auth/login")
        })
        return True
    except Exception as e:
        logger.error(f"Error sending approval email: {e}")
        return False


# =============================================================================
# Tournament & Golfer Helpers
# =============================================================================

def compute_tier(index, tier_override=None):
    """Compute golfer tier from sort index, with optional manual override."""
    if tier_override:
        return tier_override
    for threshold, tier in TIER_BOUNDARIES:
        if index < threshold:
            return tier
    return 3


def get_tournament_external_info(tournament_id):
    """Fetch tournament's external_id and season_year. Returns tuple or None."""
    db = get_db()
    return db.execute(
        "SELECT external_id, season_year FROM tournaments WHERE id = ?",
        [tournament_id]
    ).fetchone()


def get_active_tournament():
    """Get the currently active tournament."""
    db = get_db()
    result = db.execute("""
        SELECT id, external_id, name, season_year, is_active, picks_locked, buy_in
        FROM tournaments WHERE is_active = 1 LIMIT 1
    """).fetchone()

    if result:
        return {
            'id': result[0],
            'external_id': result[1],
            'name': result[2],
            'season_year': result[3],
            'is_active': bool(result[4]),
            'picks_locked': bool(result[5]),
            'buy_in': result[6] or 5
        }
    return None


def get_tournament_metadata(tournament_id):
    """Get tournament metadata including cut line."""
    db = get_db()
    result = db.execute("""
        SELECT cut_line, last_api_update, api_status
        FROM tournament_metadata WHERE tournament_id = ?
    """, [tournament_id]).fetchone()

    if result:
        return {
            'cut_line': result[0],
            'last_api_update': result[1],
            'api_status': result[2]
        }
    return None


def get_golfers(tournament_id):
    """Get all golfers for a tournament."""
    db = get_db()
    results = db.execute("""
        SELECT name, position, total_score, score_display, current_round_score,
               round_number, thru, tee_time, status, last_updated,
               tier_override, dk_salary
        FROM golfers WHERE tournament_id = ? ORDER BY total_score ASC NULLS LAST
    """, [tournament_id]).fetchall()

    return [{
        'name': r[0],
        'position': r[1],
        'total_score': r[2],
        'score_display': r[3],
        'current_round_score': r[4],
        'round_number': r[5],
        'thru': r[6],
        'tee_time': r[7],
        'status': r[8],
        'last_updated': r[9],
        'tier_override': r[10],
        'dk_salary': r[11]
    } for r in results]


def get_entries(tournament_id):
    """Get all entries for a tournament."""
    db = get_db()
    results = db.execute("""
        SELECT e.id, e.entry_name, e.golfer_1, e.golfer_2, e.golfer_3, e.golfer_4, e.golfer_5,
               e.user_id, u.email, u.first_name, u.last_name
        FROM entries e
        JOIN users u ON e.user_id = u.id
        WHERE e.tournament_id = ?
    """, [tournament_id]).fetchall()

    return [{
        'id': r[0],
        'entry_name': r[1],
        'golfer_1': r[2],
        'golfer_2': r[3],
        'golfer_3': r[4],
        'golfer_4': r[5],
        'golfer_5': r[6],
        'user_id': r[7],
        'email': r[8],
        'first_name': r[9],
        'last_name': r[10]
    } for r in results]


def apply_cut_modifier(score, status, cut_line):
    """Apply cut line modifier for leaderboard scoring."""
    if cut_line is None or score is None:
        return score
    if status == 'cut':
        return cut_line + 1
    return min(score, cut_line)


def compute_leaderboard(tournament_id):
    """Compute leaderboard from entries and golfer scores."""
    entries = get_entries(tournament_id)
    golfers = {g['name']: g for g in get_golfers(tournament_id)}
    metadata = get_tournament_metadata(tournament_id)
    cut_line = metadata.get('cut_line') if metadata else None

    results = []
    for entry in entries:
        picks = [entry['golfer_1'], entry['golfer_2'], entry['golfer_3'],
                 entry['golfer_4'], entry['golfer_5']]

        total_score = 0
        pick_details = []

        for pick in picks:
            golfer = golfers.get(pick)
            if golfer is None:
                score = 999  # Golfer not found in tournament data
            elif golfer.get('total_score') is None:
                score = 0  # Golfer exists but hasn't started yet (Even par)
            else:
                score = apply_cut_modifier(golfer['total_score'], golfer.get('status'), cut_line)
            total_score += score
            pick_details.append({
                'name': pick,
                'score': score,
                'status': golfer.get('status', 'unknown') if golfer else 'unknown'
            })

        # Build abbreviated real name (e.g., "Cullin T.")
        first = entry.get('first_name') or ''
        last = entry.get('last_name') or ''
        if first and last:
            owner_name = f"{first} {last[0]}."
        elif first:
            owner_name = first
        else:
            owner_name = ''

        results.append({
            'entry_name': entry['entry_name'],
            'owner_name': owner_name,
            'user_id': entry['user_id'],
            'team_score': total_score,
            'picks': pick_details,
            'picks_str': ', '.join(picks)
        })

    # Sort by score and assign ranks
    results.sort(key=lambda x: x['team_score'])

    current_rank = 1
    for i, result in enumerate(results):
        if i > 0 and result['team_score'] == results[i-1]['team_score']:
            result['rank'] = results[i-1]['rank']
        else:
            result['rank'] = current_rank
        current_rank += 1

    return results, metadata


def compute_tournament_winners(tournament_id):
    """Compute winners and pot for a completed tournament.

    Returns {'winners': [user_ids], 'pot': int, 'per_winner': float, 'buy_in': int}
    or None if no entries.
    """
    entries = get_entries(tournament_id)
    if not entries:
        return None

    db = get_db()
    buy_in_row = db.execute(
        "SELECT buy_in FROM tournaments WHERE id = ?", [tournament_id]
    ).fetchone()
    buy_in = (buy_in_row[0] if buy_in_row and buy_in_row[0] else 5)

    golfers = {g['name']: g for g in get_golfers(tournament_id)}
    metadata = get_tournament_metadata(tournament_id)
    cut_line = metadata.get('cut_line') if metadata else None
    pot = len(entries) * buy_in

    # Score each entry
    scores = []
    for entry in entries:
        picks = [entry[f'golfer_{i}'] for i in range(1, 6)]
        total = 0
        for pick in picks:
            golfer = golfers.get(pick)
            if golfer is None:
                total += 999
            elif golfer.get('total_score') is None:
                total += 0
            else:
                total += apply_cut_modifier(golfer['total_score'], golfer.get('status'), cut_line)
        scores.append((entry['user_id'], total))

    best = min(s[1] for s in scores)
    winners = [s[0] for s in scores if s[1] == best]
    per_winner = round(pot / len(winners), 2)

    return {'winners': winners, 'pot': pot, 'per_winner': per_winner, 'buy_in': buy_in}


def compute_player_standings(tournament_id):
    """Compute player standings with selection info."""
    entries = get_entries(tournament_id)
    golfers = get_golfers(tournament_id)

    # Build selection map
    selections = {}
    for entry in entries:
        for i in range(1, 6):
            golfer_name = entry[f'golfer_{i}']
            if golfer_name not in selections:
                selections[golfer_name] = []
            selections[golfer_name].append(entry['entry_name'])

    # Add selection info to golfers
    for golfer in golfers:
        golfer['selections'] = ', '.join(selections.get(golfer['name'], []))

    return golfers


def compute_season_standings(season_year):
    """Compute season-long standings, tier breakdowns, and selection stats.

    Returns (standings_list, selection_stats) where:
    - standings_list: per-user stats sorted by profit DESC, wins DESC
    - selection_stats: {'most_picked': [...], 'tier_best': {1: [...], 2: [...], 3: [...]}}
    """
    db = get_db()
    tournaments = db.execute(
        "SELECT id, name FROM tournaments WHERE season_year = ? AND picks_locked = 1",
        [season_year]
    ).fetchall()

    if not tournaments:
        return [], {'most_picked': [], 'tier_best': {1: [], 2: [], 3: []}}, []

    tier_map = {
        'golfer_1': 1,
        'golfer_2': 2, 'golfer_3': 2,
        'golfer_4': 3, 'golfer_5': 3,
    }

    # Per-user accumulators
    users = {}  # user_id -> stats dict
    # Selection stats accumulators
    golfer_picks = {}  # golfer_name -> {count, teams (set), scores (list)}
    tier_best = {1: [], 2: [], 3: []}  # tier -> [(golfer, score, team, tournament_name)]

    # Track per-tournament entry scores for placement ranking (built during main loop)
    tournament_entry_scores = {}  # t_id -> [(user_id, total_score)]
    # Track per-tournament data for "Mr. Relevant" (best unselected golfer)
    tournament_selected = {}  # t_id -> set of selected golfer names
    tournament_golfer_data = {}  # t_id -> (golfers_dict, cut_line, t_name)

    for t_id, t_name in tournaments:
        entries = get_entries(t_id)
        if not entries:
            continue
        golfers = {g['name']: g for g in get_golfers(t_id)}
        metadata = get_tournament_metadata(t_id)
        cut_line = metadata.get('cut_line') if metadata else None
        result = compute_tournament_winners(t_id)
        winners = result['winners'] if result else []
        per_winner = result['per_winner'] if result else 0
        tournament_buy_in = result['buy_in'] if result else 5
        is_major = _is_major(t_name)

        # Track selected golfers for Mr. Relevant
        selected_names = set()
        for entry in entries:
            for col in ('golfer_1', 'golfer_2', 'golfer_3', 'golfer_4', 'golfer_5'):
                if entry[col]:
                    selected_names.add(entry[col])
        tournament_selected[t_id] = selected_names
        tournament_golfer_data[t_id] = (golfers, cut_line, t_name)

        # Score all entries first to build rank map (avoids extra compute_leaderboard call)
        entry_scores = []
        for entry in entries:
            total = 0
            for col in ('golfer_1', 'golfer_2', 'golfer_3', 'golfer_4', 'golfer_5'):
                golfer = golfers.get(entry[col])
                if golfer is None:
                    total += 999
                elif golfer.get('total_score') is None:
                    total += 0
                else:
                    total += apply_cut_modifier(golfer['total_score'], golfer.get('status'), cut_line)
            entry_scores.append((entry['user_id'], total))
        tournament_entry_scores[t_id] = entry_scores

        # Build rank map from computed scores
        entry_scores_sorted = sorted(entry_scores, key=lambda x: x[1])
        rank_map = {}
        max_rank = 0
        current_rank = 1
        for i, (uid, score) in enumerate(entry_scores_sorted):
            if i > 0 and score == entry_scores_sorted[i-1][1]:
                rank_map[uid] = rank_map[entry_scores_sorted[i-1][0]]
            else:
                rank_map[uid] = current_rank
            if current_rank > max_rank:
                max_rank = current_rank
            current_rank += 1

        for entry in entries:
            uid = entry['user_id']
            if uid not in users:
                users[uid] = {
                    'user_id': uid,
                    'first_name': entry['first_name'],
                    'last_name': entry['last_name'],
                    'wins': 0,
                    'major_wins': 0,
                    'second_place': 0,
                    'third_place': 0,
                    'last_place': 0,
                    'tournaments_played': 0,
                    'total_buy_ins': 0.0,
                    'total_winnings': 0.0,
                    'team_scores': [],
                    'tier_scores': {1: [], 2: [], 3: []},
                    'tier_positions': {1: [], 2: [], 3: []},
                    'cuts_made': 0,
                    'cuts_missed': 0,
                }

            u = users[uid]
            u['tournaments_played'] += 1
            u['total_buy_ins'] += tournament_buy_in
            if uid in winners:
                u['wins'] += 1
                u['total_winnings'] += per_winner
                if is_major:
                    u['major_wins'] += 1

            # Placement tracking
            entry_rank = rank_map.get(uid)
            if entry_rank is not None:
                if entry_rank == 2:
                    u['second_place'] += 1
                elif entry_rank == 3:
                    u['third_place'] += 1
                if entry_rank == max_rank and len(entries) > 1:
                    u['last_place'] += 1

            # Score this entry
            team_total = 0
            entry_tier_totals = {1: 0, 2: 0, 3: 0}
            entry_tier_has_scores = {1: False, 2: False, 3: False}
            entry_tier_golfers = {1: [], 2: [], 3: []}
            for col, tier in tier_map.items():
                golfer_name = entry[col]
                golfer = golfers.get(golfer_name)

                if golfer is None:
                    score = 999
                elif golfer.get('total_score') is None:
                    score = 0
                else:
                    score = apply_cut_modifier(golfer['total_score'], golfer.get('status'), cut_line)

                team_total += score
                entry_tier_totals[tier] += score
                if golfer and golfer.get('total_score') is not None:
                    entry_tier_has_scores[tier] = True
                if golfer_name:
                    entry_tier_golfers[tier].append(golfer_name)

                # Track positions (only for made-cut golfers)
                if golfer and golfer.get('status') != 'cut' and golfer.get('position'):
                    try:
                        pos = int(str(golfer['position']).lstrip('T'))
                        u['tier_positions'][tier].append(pos)
                    except (ValueError, TypeError):
                        pass

                # Track cuts
                if golfer:
                    if golfer.get('status') == 'cut':
                        u['cuts_missed'] += 1
                    else:
                        u['cuts_made'] += 1

                # Selection stats
                if golfer_name:
                    if golfer_name not in golfer_picks:
                        golfer_picks[golfer_name] = {'count': 0, 'teams': set(), 'scores': []}
                    golfer_picks[golfer_name]['count'] += 1
                    display_name = f"{entry['first_name']} {entry['last_name'][0]}."
                    golfer_picks[golfer_name]['teams'].add(display_name)
                    if golfer and golfer.get('total_score') is not None:
                        adj_score = apply_cut_modifier(golfer['total_score'], golfer.get('status'), cut_line)
                        golfer_picks[golfer_name]['scores'].append(adj_score)

            # Accumulate per-tournament tier totals and tier best
            for tier in (1, 2, 3):
                u['tier_scores'][tier].append(entry_tier_totals[tier])
                if entry_tier_has_scores[tier]:
                    # Merge entries with same golfers in same tournament
                    golfer_key = tuple(sorted(entry_tier_golfers[tier]))
                    merge_key = (golfer_key, t_name)
                    merged = False
                    display_name = f"{entry['first_name']} {entry['last_name'][0]}."
                    for existing in tier_best[tier]:
                        if existing.get('_merge_key') == merge_key:
                            existing['teams'].append(display_name)
                            merged = True
                            break
                    if not merged:
                        tier_best[tier].append({
                            'score': entry_tier_totals[tier],
                            'teams': [display_name],
                            'golfers': list(entry_tier_golfers[tier]),
                            'tournament': t_name,
                            '_merge_key': merge_key,
                        })

            u['team_scores'].append(team_total)

    # Build standings list
    standings = []
    for u in users.values():
        played = u['tournaments_played']
        total_score = sum(u['team_scores'])
        avg_score = round(total_score / played, 1) if played else 0
        profit = round(u['total_winnings'] - u['total_buy_ins'], 2)

        tier_avg_pos = {}
        tier_avg_score = {}
        for tier in (1, 2, 3):
            positions = u['tier_positions'][tier]
            tier_avg_pos[tier] = round(sum(positions) / len(positions), 1) if positions else None
            scores = u['tier_scores'][tier]
            tier_avg_score[tier] = round(sum(scores) / len(scores), 1) if scores else None

        total_picks = u['cuts_made'] + u['cuts_missed']
        cut_pct = round(u['cuts_made'] / total_picks * 100, 1) if total_picks else 0

        standings.append({
            'first_name': u['first_name'],
            'last_name': u['last_name'],
            'wins': u['wins'],
            'major_wins': u['major_wins'],
            'second_place': u['second_place'],
            'third_place': u['third_place'],
            'last_place': u['last_place'],
            'tournaments_played': played,
            'total_winnings': u['total_winnings'],
            'profit': profit,
            'avg_score': avg_score,
            'cumulative_score': total_score,
            'tier_avg_pos': tier_avg_pos,
            'tier_avg_score': tier_avg_score,
            'cuts_made': u['cuts_made'],
            'cuts_missed': u['cuts_missed'],
            'cut_pct': cut_pct,
            'user_id': u['user_id'],
        })

    # Compute owed amounts (unpaid buy-ins)
    owed_rows = db.execute("""
        SELECT e.user_id, SUM(t.buy_in)
        FROM entries e
        JOIN tournaments t ON e.tournament_id = t.id
        WHERE t.season_year = ? AND e.paid = 0
        GROUP BY e.user_id
    """, [season_year]).fetchall()
    owed_map = {r[0]: r[1] or 0 for r in owed_rows}
    for s in standings:
        s['owed'] = owed_map.get(s['user_id'], 0)

    standings.sort(key=lambda x: (-x['wins'], -x['profit'], x['avg_score'], x['cumulative_score']))

    # Build selection stats
    most_picked = []
    for name, data in golfer_picks.items():
        avg = round(sum(data['scores']) / len(data['scores']), 1) if data['scores'] else None
        most_picked.append({
            'golfer': name,
            'count': data['count'],
            'teams': sorted(data['teams']),
            'avg_score': avg,
        })
    most_picked.sort(key=lambda x: -x['count'])

    for tier in (1, 2, 3):
        tier_best[tier].sort(key=lambda x: x['score'])
        tier_best[tier] = tier_best[tier][:5]
        for entry in tier_best[tier]:
            entry.pop('_merge_key', None)

    # Build "Mr. Relevant" — best unselected golfer per tournament
    mr_relevant = []
    for t_id, t_name in tournaments:
        if t_id not in tournament_golfer_data:
            continue
        golfers_dict, cut_line, _ = tournament_golfer_data[t_id]
        selected = tournament_selected[t_id]
        best = None
        for name, g in golfers_dict.items():
            if name in selected:
                continue
            if g.get('total_score') is None:
                continue
            adj_score = apply_cut_modifier(g['total_score'], g.get('status'), cut_line)
            if best is None or adj_score < best['score']:
                best = {'golfer': name, 'score': adj_score, 'tournament': t_name,
                        'status': g.get('status', ''), 'position': g.get('position', '--')}
        if best:
            mr_relevant.append(best)

    selection_stats = {'most_picked': most_picked, 'tier_best': tier_best, 'mr_relevant': mr_relevant}

    # Build per-tournament results
    tournament_results = []
    for t_id, t_name in tournaments:
        leaderboard, lb_metadata = compute_leaderboard(t_id)
        result = compute_tournament_winners(t_id)
        winners = result['winners'] if result else []
        pot = result['pot'] if result else 0
        per_winner = result['per_winner'] if result else 0

        # Build winners_detail with MVP (best individual golfer on winning team)
        winners_detail = []
        for entry in leaderboard:
            if entry.get('rank') == 1:
                mvp = min(entry['picks'], key=lambda p: p['score'])
                winners_detail.append({
                    'owner_name': entry['owner_name'],
                    'team_score': entry['team_score'],
                    'mvp_name': mvp['name'],
                    'mvp_score': mvp['score'],
                })

        tournament_results.append({
            'id': t_id,
            'name': t_name,
            'is_major': _is_major(t_name),
            'leaderboard': leaderboard,
            'cut_line': lb_metadata.get('cut_line') if lb_metadata else None,
            'pot': pot,
            'per_winner': per_winner,
            'num_entries': len(leaderboard),
            'winner_names': [e['owner_name'] for e in leaderboard if e.get('rank') == 1],
            'winners_detail': winners_detail,
        })

    return standings, selection_stats, tournament_results


def _get_season_winner_ids(season_year):
    """Get season winner info: {user_id: {'wins': int, 'major_wins': int}}.

    Cached with 5-minute TTL.
    """
    cache_key = f'season_winners_{season_year}'
    cached = get_cached(cache_key)
    if cached:
        return cached

    db = get_db()
    tournaments = db.execute(
        "SELECT id, name FROM tournaments WHERE season_year = ? AND picks_locked = 1",
        [season_year]
    ).fetchall()

    winner_info = {}  # user_id -> {'wins': int, 'major_wins': int}
    for t_id, t_name in tournaments:
        result = compute_tournament_winners(t_id)
        if not result:
            continue
        is_major = _is_major(t_name)
        for uid in result['winners']:
            if uid not in winner_info:
                winner_info[uid] = {'wins': 0, 'major_wins': 0}
            winner_info[uid]['wins'] += 1
            if is_major:
                winner_info[uid]['major_wins'] += 1

    set_cache(cache_key, winner_info)
    return winner_info


# =============================================================================
# Golf API Integration (Slash Golf via RapidAPI)
# =============================================================================

GOLF_API_BASE_URL = "https://live-golf-data.p.rapidapi.com"


def _extract_player_name(player):
    """Extract player name from API response with multiple fallbacks."""
    first_name = player.get('firstName', '')
    last_name = player.get('lastName', '')
    name = f"{first_name} {last_name}".strip()
    if not name:
        name = player.get('name', player.get('playerName', ''))
    return name


def get_golf_api_headers():
    """Get headers for Slash Golf API requests."""
    api_key = os.getenv('GOLF_API_KEY')
    if not api_key:
        return None
    return {
        'X-RapidAPI-Key': api_key,
        'X-RapidAPI-Host': 'live-golf-data.p.rapidapi.com'
    }


def fetch_tournament_schedule(year, org_id='1'):
    """Fetch tournament schedule from Slash Golf API."""
    headers = get_golf_api_headers()
    if not headers:
        return None

    try:
        resp = requests.get(
            f"{GOLF_API_BASE_URL}/schedule",
            headers=headers,
            params={'orgId': org_id, 'year': str(year)},
            timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        # API returns dict with 'schedule' key containing list of tournaments
        return data.get('schedule', data) if isinstance(data, dict) else data
    except Exception as e:
        logger.error(f"Error fetching schedule: {e}")
        return None


def fetch_leaderboard(tournament_external_id, year=None):
    """Fetch leaderboard data from Slash Golf API."""
    headers = get_golf_api_headers()
    if not headers:
        return None

    if year is None:
        year = datetime.now().year

    try:
        resp = requests.get(
            f"{GOLF_API_BASE_URL}/leaderboard",
            headers=headers,
            params={'tournId': tournament_external_id, 'year': str(year)},
            timeout=15
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"Error fetching leaderboard: {e}")
        return None


def fetch_tournament_field(tournament_external_id, year=None):
    """Fetch tournament field/players from Slash Golf API."""
    headers = get_golf_api_headers()
    if not headers:
        return None

    if year is None:
        year = datetime.now().year

    try:
        resp = requests.get(
            f"{GOLF_API_BASE_URL}/tournament",
            headers=headers,
            params={'tournId': tournament_external_id, 'year': str(year)},
            timeout=15
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"Error fetching tournament field: {e}")
        return None


def refresh_golfers_from_api(tournament_id, tournament_external_id, year=None):
    """Refresh golfer data from Slash Golf API."""
    if year is None:
        year = datetime.now().year

    # Try leaderboard first (has live scores)
    data = fetch_leaderboard(tournament_external_id, year)

    if not data or not (data.get('leaderboardRows') or data.get('leaderboard')):
        # Fall back to tournament field if no leaderboard data
        data = fetch_tournament_field(tournament_external_id, year)
        if not data:
            return False

    db = get_db()

    # Handle leaderboard or tournament field response format
    # API uses 'leaderboardRows' for leaderboard data, 'players' for tournament field
    leaderboard = data.get('leaderboardRows', []) or data.get('leaderboard', []) or data.get('players', [])
    cut_line_raw = data.get('cutLine')
    if cut_line_raw is None and data.get('cutLines'):
        cut_line_raw = data['cutLines'][0].get('cutScore')
    # cut_line = API cutScore = worst score that still makes the cut
    cut_line = parse_score_to_int(cut_line_raw) if cut_line_raw is not None else None

    for player in leaderboard:
        name = _extract_player_name(player)
        if not name:
            continue

        # Parse score - API returns 'total' as string like "-5" or "E" or "+2"
        total_str = player.get('total', player.get('totalScore', ''))
        total_score = parse_score_to_int(total_str)

        # Current round score
        today_str = player.get('today', player.get('currentRoundScore', ''))

        # Status - check for 'status' or infer from position
        status = player.get('status', 'active')
        if status.upper() == 'CUT' or player.get('isCut'):
            status = 'cut'

        db.execute("""
            INSERT INTO golfers (id, tournament_id, name, external_id, position, total_score,
                                 score_display, current_round_score, round_number, thru,
                                 tee_time, status, last_updated)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(tournament_id, name) DO UPDATE SET
                position = excluded.position,
                total_score = excluded.total_score,
                score_display = excluded.score_display,
                current_round_score = excluded.current_round_score,
                round_number = excluded.round_number,
                thru = excluded.thru,
                tee_time = excluded.tee_time,
                status = excluded.status,
                last_updated = datetime('now')
        """, [
            tournament_id,
            name,
            str(player.get('playerId', player.get('id', ''))),
            player.get('position', player.get('pos', '')),
            total_score,
            total_str or '--',
            today_str or '--',
            _api_int(player.get('currentRound', player.get('round', 1))),
            player.get('thru', ''),
            player.get('teeTime', ''),
            status
        ])

    # Update metadata
    db.execute("""
        INSERT INTO tournament_metadata (tournament_id, cut_line, last_api_update, api_status)
        VALUES (?, ?, datetime('now'), 'success')
        ON CONFLICT(tournament_id) DO UPDATE SET
            cut_line = excluded.cut_line,
            last_api_update = datetime('now'),
            api_status = 'success'
    """, [tournament_id, cut_line])

    db.commit()
    return True


def fetch_dk_salaries():
    """Fetch current PGA TOUR DraftKings salaries.

    Returns (salaries_dict, contest_name, player_count) on success,
    or (None, None, None) on failure. salaries_dict maps normalized_name → salary.
    """
    try:
        # Step 1: Find the current-week PGA TOUR classic draft group
        resp = requests.get(
            'https://www.draftkings.com/lobby/getcontests?sport=GOLF',
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=15
        )
        resp.raise_for_status()
        data = resp.json()

        # Collect unique draft group IDs from classic PGA TOUR contests.
        # "PGA TOUR" in the name = current week's event.
        # Plain "PGA" without "TOUR" = cross-tournament specials (e.g. Masters Main Event).
        candidate_dgids = {}
        for contest in data.get('Contests', []):
            if contest.get('gameTypeId') != 6:
                continue
            name = contest.get('n', '')
            dgid = contest.get('dgid') or contest.get('dg')
            if not dgid:
                continue
            name_upper = name.upper()
            if 'PGA TOUR' in name_upper:
                candidate_dgids[dgid] = name
            elif 'PGA' in name_upper and dgid not in candidate_dgids:
                # Fallback: keep as secondary option
                candidate_dgids.setdefault(f'_fallback_{dgid}', (dgid, name))

        # Prefer "PGA TOUR" draft groups; pick the one with the most draftables
        draft_group_id = None
        contest_name = None

        # Try PGA TOUR groups first (numeric keys)
        tour_dgids = {k: v for k, v in candidate_dgids.items() if not str(k).startswith('_')}
        if tour_dgids:
            # Usually all PGA TOUR classic contests share one draft group ID
            draft_group_id = next(iter(tour_dgids))
            contest_name = tour_dgids[draft_group_id]

        if not draft_group_id:
            # Fall back to plain PGA groups
            fallbacks = {k: v for k, v in candidate_dgids.items() if str(k).startswith('_')}
            if fallbacks:
                fb = next(iter(fallbacks.values()))
                draft_group_id, contest_name = fb

        if not draft_group_id:
            logger.warning("DK: No PGA TOUR classic contest found in lobby")
            return None, None, None

        logger.info(f"DK: Found draft group {draft_group_id} — {contest_name}")

        # Step 2: Fetch draftables (player salaries)
        resp = requests.get(
            f'https://api.draftkings.com/draftgroups/v1/draftgroups/{draft_group_id}/draftables',
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=15
        )
        resp.raise_for_status()
        draftables = resp.json()

        salaries = {}
        for player in draftables.get('draftables', []):
            name = player.get('displayName', '').strip()
            salary = player.get('salary')
            if name and salary:
                normalized = _normalize_golfer_name(name)
                # Keep the highest salary if a player appears multiple times
                if normalized not in salaries or salary > salaries[normalized]:
                    salaries[normalized] = salary

        if not salaries:
            logger.warning(f"DK: Draft group {draft_group_id} returned 0 salaries (may not be populated yet)")
            return None, None, None

        logger.info(f"DK: Fetched {len(salaries)} player salaries from draft group {draft_group_id}")
        return salaries, contest_name, len(salaries)

    except requests.RequestException as e:
        logger.warning(f"DK API error: {e}")
        return None, None, None
    except (KeyError, ValueError) as e:
        logger.warning(f"DK API parse error: {e}")
        return None, None, None


def _api_int(value):
    """Extract integer from API value, handling {'$numberInt': '4'} dicts."""
    if value is None:
        return None
    if isinstance(value, dict):
        return int(value.get('$numberInt', 0))
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def parse_score_to_int(score_str):
    """Parse score string like '-5', 'E', '+2' to integer."""
    if not score_str:
        return None
    score_str = str(score_str).strip().upper()
    if score_str == 'E':
        return 0
    if score_str == '--' or score_str == 'N/A':
        return None
    try:
        return int(score_str.replace('+', ''))
    except ValueError:
        return None


def _normalize_golfer_name(name):
    """Normalize golfer name for cross-source matching.

    Handles: diacritics (é→e), Nordic letters (ø→o, æ→ae), disambiguation
    initials (Jordan L. Smith → Jordan Smith), suffixes (Jr., III, IV),
    case, extra whitespace.
    """
    # Replace Nordic standalone letters before NFD decomposition
    # (ø, ð are not decomposed by NFD — they're unique codepoints)
    name = name.replace('ø', 'o').replace('Ø', 'O')
    name = name.replace('ð', 'd').replace('Ð', 'D')
    name = name.replace('æ', 'ae').replace('Æ', 'AE')
    # Strip diacritics: NFD decompose, remove combining marks
    name = unicodedata.normalize('NFD', name)
    name = ''.join(c for c in name if unicodedata.category(c) != 'Mn')
    # Lowercase
    name = name.lower().strip()
    # Remove suffixes
    name = re.sub(r'\b(jr\.?|sr\.?|ii|iii|iv)\s*$', '', name).strip()
    # Remove single-letter middle initials: "Jordan L. Smith" → "Jordan Smith"
    # Only match a single letter+period that is BETWEEN other words (not at start)
    name = re.sub(r'(?<=\w\s)([a-z])\.\s*', '', name).strip()
    # Collapse whitespace
    name = re.sub(r'\s+', ' ', name)
    return name



# =============================================================================
# Auth Routes
# =============================================================================

@app.route('/auth/login')
def auth_login():
    """Login page."""
    if g.user:
        return redirect(url_for('make_picks'))
    return render_template('login.html', error=request.args.get('error'),
                           registration_open=is_registration_open())


@app.route('/auth/request-link', methods=['POST'])
@csrf_required
def auth_request_link():
    """Request magic link."""
    email = validate_user_email(request.form.get('email', ''))

    if not email:
        return render_template('login.html', error='Please enter a valid email address.',
                               registration_open=is_registration_open()), 422

    client_ip = get_client_ip()

    # Rate limiting
    if not check_rate_limit(email, 'magic_link_per_email'):
        log_security_event('rate_limited', request, email=email, details={'action': 'magic_link_per_email'})
        session['check_email'] = email  # Don't reveal rate limit
        return redirect(url_for('auth_check_email'))

    if not check_rate_limit(client_ip, 'magic_link_per_ip'):
        log_security_event('rate_limited', request, email=email, details={'action': 'magic_link_per_ip'})
        session['check_email'] = email
        return redirect(url_for('auth_check_email'))

    # Only send magic link if user exists (silent rejection for unregistered emails)
    db = get_db()
    existing_user = db.execute("SELECT id FROM users WHERE email = ?", [email]).fetchone()
    if not existing_user:
        log_security_event('magic_link_rejected', request, email=email, details={'reason': 'unregistered_email'})
        session['check_email'] = email
        return redirect(url_for('auth_check_email'))

    # Generate token
    raw_token = secrets.token_urlsafe(32)
    token_hash = ph.hash(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=MAGIC_LINK_EXPIRY_MINUTES)

    db.execute("""
        INSERT INTO auth_tokens (id, email, token_hash, expires_at)
        VALUES (lower(hex(randomblob(16))), ?, ?, ?)
    """, [email, token_hash, expires_at.isoformat()])
    db.commit()

    # Send email (carry `next` URL through the magic link)
    next_url = request.form.get('next', '')
    send_magic_link(email, raw_token, next_url=next_url)
    log_security_event('magic_link_sent', request, email=email)

    session['check_email'] = email
    return redirect(url_for('auth_check_email'))


@app.route('/auth/check-email')
def auth_check_email():
    """Check email confirmation page."""
    email = session.pop('check_email', '')
    return render_template('check_email.html', email=email)


def _verify_magic_token(email, raw_token):
    """Verify a magic link token against stored hashes.

    Returns (token_id, None) on success, or (None, error_message) on failure.
    """
    db = get_db()
    results = db.execute("""
        SELECT id, token_hash, expires_at, used_at
        FROM auth_tokens WHERE email = ? AND used_at IS NULL
        ORDER BY created_at DESC LIMIT 5
    """, [email]).fetchall()

    for result in results:
        token_id, stored_hash, expires_at, _used_at = result
        expires_dt = datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc)

        if expires_dt < datetime.now(timezone.utc):
            continue

        try:
            ph.verify(stored_hash, raw_token)
            return token_id, None
        except VerifyMismatchError:
            continue

    return None, 'This sign-in link is invalid or has expired.'


@app.route('/auth/verify')
def auth_verify():
    """Verify magic link token."""
    token = request.args.get('token', '')
    email = request.args.get('email', '')

    if not token or not email:
        return render_template('error.html', message='Invalid sign-in link.')

    client_ip = get_client_ip()

    # Rate limiting for failed attempts
    if not check_rate_limit(client_ip, 'failed_verifications_per_ip'):
        log_security_event('rate_limited', request, email=email, details={'action': 'verification'})
        return render_template('error.html', message='Too many attempts. Please try again later.')

    valid_token_id, error = _verify_magic_token(email, token)

    if not valid_token_id:
        log_security_event('failed_login', request, email=email, details={'reason': 'invalid_token'})
        db = get_db()
        db.execute("""
            INSERT INTO failed_logins (id, email, ip_address, reason)
            VALUES (lower(hex(randomblob(16))), ?, ?, 'invalid_token')
        """, [email, client_ip])
        db.commit()
        return render_template('error.html', message=error)

    # Mark token as used
    db = get_db()
    db.execute("UPDATE auth_tokens SET used_at = datetime('now') WHERE id = ?", [valid_token_id])

    # Get or create user
    user = db.execute("SELECT id, email, is_admin FROM users WHERE email = ?", [email]).fetchone()

    if not user:
        log_security_event('failed_login', request, email=email, details={'reason': 'account_not_approved'})
        return render_template('error.html', message='Your account is not yet approved. Please wait for admin approval.')

    user_id = user[0]
    db.execute("UPDATE users SET last_login_at = datetime('now') WHERE id = ?", [user_id])
    db.commit()

    # Create session
    session_token, expires_at = create_session(user_id)
    log_security_event('login', request, user_id=user_id, email=email)

    # Determine redirect destination (honor `next` param, prevent open redirect)
    next_url = request.args.get('next', '')
    parsed = urlparse(next_url)
    # Only allow relative paths (no scheme, no external host)
    if next_url and not parsed.scheme and not parsed.netloc and next_url.startswith('/'):
        redirect_to = next_url
    else:
        redirect_to = url_for('make_picks')

    # Set cookie and redirect
    response = make_response(redirect(redirect_to))
    response.set_cookie(
        'golf_session',
        session_token,
        expires=expires_at,
        httponly=True,
        secure=not app.debug,
        samesite='Lax'
    )
    return response


@app.route('/auth/logout', methods=['POST'])
@csrf_required
def auth_logout():
    """Log out user."""
    if g.user:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE id = ?", [g.user['session_id']])
        db.commit()
        log_security_event('logout', request, user_id=g.user['id'])

    response = make_response(redirect(url_for('auth_login')))
    response.delete_cookie('golf_session')
    return response


@app.route('/auth/request-access')
def auth_request_access():
    """Request access form."""
    if g.user:
        return redirect(url_for('leaderboard'))
    if not is_registration_open():
        return redirect(url_for('auth_login', msg='registration_closed'))
    return render_template('request_access.html')


@app.route('/auth/submit-access-request', methods=['POST'])
@csrf_required
def auth_submit_access_request():
    """Submit access request."""
    if not is_registration_open():
        return redirect(url_for('auth_login'))

    email = validate_user_email(request.form.get('email', ''))
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()

    if not email:
        return render_template('request_access.html', error='Please enter a valid email address.'), 422

    if not first_name or len(first_name) > 50:
        return render_template('request_access.html', error='Please enter a valid first name (1-50 characters).'), 422

    if not last_name or len(last_name) > 50:
        return render_template('request_access.html', error='Please enter a valid last name (1-50 characters).'), 422

    # Basic sanitization
    first_name = html.escape(first_name)
    last_name = html.escape(last_name)
    display_name = f"{first_name} {last_name}"

    client_ip = get_client_ip()

    # Rate limit
    if not check_rate_limit(client_ip, 'access_request_per_ip'):
        log_security_event('rate_limited', request, email=email, details={'action': 'access_request_per_ip'})
        return redirect(url_for('auth_access_requested'))

    db = get_db()

    # Silently succeed if email already exists in users or access_requests
    existing_user = db.execute("SELECT id FROM users WHERE email = ?", [email]).fetchone()
    existing_request = db.execute("SELECT id FROM access_requests WHERE email = ?", [email]).fetchone()

    if existing_user or existing_request:
        return redirect(url_for('auth_access_requested'))

    # Insert access request
    try:
        db.execute("""
            INSERT INTO access_requests (id, email, display_name, first_name, last_name)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?)
        """, [email, display_name, first_name, last_name])
        db.commit()

        log_security_event('access_requested', request, email=email, details={'name': display_name})
        send_admin_notification(display_name, email)
    except Exception as e:
        logger.error(f"Error creating access request: {e}")

    return redirect(url_for('auth_access_requested'))


@app.route('/auth/access-requested')
def auth_access_requested():
    """Access request confirmation page."""
    return render_template('access_requested.html')


# =============================================================================
# Main Routes
# =============================================================================

@app.route('/')
@login_required
def leaderboard():
    """Main leaderboard page."""
    tournament = get_active_tournament()

    if not tournament:
        return render_template('leaderboard.html',
                             tournament_name='No Active Tournament',
                             results=[],
                             last_updated='N/A',
                             cut_line=None,
                             player_scores={},
                             is_fallback=True,
                             user=g.user)

    # Hide leaderboard entries until picks are locked
    if not tournament['picks_locked']:
        db = get_db()
        user_entry_row = db.execute("""
            SELECT entry_name, golfer_1, golfer_2, golfer_3, golfer_4, golfer_5
            FROM entries WHERE user_id = ? AND tournament_id = ?
        """, [g.user['id'], tournament['id']]).fetchone()
        user_entry = {
            'entry_name': user_entry_row[0],
            'golfers': [user_entry_row[1], user_entry_row[2], user_entry_row[3],
                        user_entry_row[4], user_entry_row[5]]
        } if user_entry_row else None
        return render_template('leaderboard.html',
                             tournament_name=tournament['name'],
                             results=[],
                             last_updated='N/A',
                             cut_line=None,
                             player_scores={},
                             picks_locked=False,
                             user_entry=user_entry,
                             is_fallback=False,
                             buy_in=tournament.get('buy_in', 5),
                             user=g.user)

    cache_key = f'leaderboard_{tournament["id"]}'
    cached = get_cached(cache_key)

    if cached:
        results, metadata, last_updated = cached
    else:
        results, metadata = compute_leaderboard(tournament['id'])
        last_updated = format_last_updated(
            metadata.get('last_api_update') if metadata else None
        )

        set_cache(cache_key, (results, metadata, last_updated))

    # Build player scores dict for template
    golfers = get_golfers(tournament['id'])
    cut_line = metadata.get('cut_line') if metadata else None
    player_scores = {}
    for g_data in golfers:
        display_score = apply_cut_modifier(g_data['total_score'], g_data['status'], cut_line)
        player_scores[g_data['name']] = {
            'score': display_score,
            'status': g_data['status']
        }

    # Get season winner info for badges
    season_year = datetime.now().year
    season_winners = _get_season_winner_ids(season_year)

    # Format results for template
    template_results = []
    for r in results:
        user_id = r.get('user_id')
        winner_data = season_winners.get(user_id, {})
        template_results.append({
            'RANK': r['rank'],
            'ENTRY_NAME': r['entry_name'],
            'OWNER_NAME': r.get('owner_name', ''),
            'TEAM_SCORE': r['team_score'],
            'PICKS': r['picks_str'],
            'TOURNAMENT': tournament['name'],
            'HAS_WIN': winner_data.get('wins', 0) > 0,
            'HAS_MAJOR': winner_data.get('major_wins', 0) > 0,
        })

    return render_template('leaderboard.html',
                         tournament_name=tournament['name'],
                         results=template_results,
                         last_updated=last_updated,
                         cut_line=metadata.get('cut_line') if metadata else None,
                         player_scores=player_scores,
                         picks_locked=tournament.get('picks_locked', True),
                         is_fallback=False,
                         buy_in=tournament.get('buy_in', 5),
                         user=g.user)


@app.route('/players')
@login_required
def player_standings():
    """Player standings page."""
    tournament = get_active_tournament()

    if not tournament:
        return render_template('player_standings.html',
                             tournament_name='No Active Tournament',
                             results=[],
                             last_updated='N/A',
                             cut_line=None,
                             is_fallback=True,
                             picks_locked=True,
                             all_teams=[],
                             user=g.user)

    # Hide player standings until picks are locked
    if not tournament['picks_locked']:
        return render_template('player_standings.html',
                             tournament_name=tournament['name'],
                             results=[],
                             last_updated='N/A',
                             cut_line=None,
                             is_fallback=False,
                             picks_locked=False,
                             all_teams=[],
                             user=g.user)

    cache_key = f'players_{tournament["id"]}'
    cached = get_cached(cache_key)

    if cached:
        golfers, metadata, last_updated = cached
    else:
        golfers = compute_player_standings(tournament['id'])
        metadata = get_tournament_metadata(tournament['id'])
        last_updated = format_last_updated(
            metadata.get('last_api_update') if metadata else None
        )

        set_cache(cache_key, (golfers, metadata, last_updated))

    # Format for template — compute tiers by DK salary ranking
    cut_line = metadata.get('cut_line') if metadata else None

    # Assign tiers using same DB ordering as admin tiers page
    db = get_db()
    tier_rows = db.execute("""
        SELECT name, tier_override FROM golfers
        WHERE tournament_id = ?
        ORDER BY dk_salary DESC NULLS LAST, name ASC
    """, [tournament['id']]).fetchall()
    golfer_tiers = {}
    for idx, row in enumerate(tier_rows):
        golfer_tiers[row[0]] = compute_tier(idx, row[1])

    # Build unique team list for filter dropdown
    all_teams = []
    template_results = []
    for g_data in golfers:
        tier = golfer_tiers.get(g_data['name'], 3)
        selections = g_data['selections']
        if selections and selections.strip():
            for t in selections.split(','):
                t = t.strip()
                if t and t not in all_teams:
                    all_teams.append(t)
        template_results.append({
            'TOURNAMENT': tournament['name'],
            'POSITION': g_data['position'] or '--',
            'GOLFER': g_data['name'],
            'TOTAL_SCORE_INTEGER': apply_cut_modifier(g_data['total_score'], g_data['status'], cut_line),
            'CURRENT_ROUND_SCORE': g_data['current_round_score'] or '--',
            'ROUND_ID': g_data['round_number'] or 1,
            'THRU': g_data['thru'] or '--',
            'TEE_TIME': g_data['tee_time'] or '--',
            'PLAYER_STATUS': g_data['status'] or 'active',
            'SELECTIONS': selections,
            'CUT_LINE': metadata.get('cut_line') if metadata else None,
            'TIER': tier,
        })

    return render_template('player_standings.html',
                         tournament_name=tournament['name'],
                         results=template_results,
                         last_updated=last_updated,
                         cut_line=metadata.get('cut_line') if metadata else None,
                         is_fallback=False,
                         picks_locked=True,
                         all_teams=sorted(all_teams),
                         user=g.user)


@app.route('/standings')
@login_required
def season_standings():
    """Season standings and stats page."""
    season_year = datetime.now().year
    cache_key = f'standings_{season_year}'
    cached = get_cached(cache_key)
    if cached:
        standings, selection_stats, tournament_results = cached
    else:
        standings, selection_stats, tournament_results = compute_season_standings(season_year)
        set_cache(cache_key, (standings, selection_stats, tournament_results))
    return render_template('standings.html',
                         standings=standings,
                         selection_stats=selection_stats,
                         tournament_results=tournament_results,
                         season_year=season_year,
                         user=g.user)


def _build_tier_lists(tournament_id):
    """Query golfers in DB tier order and split into three tiers."""
    db = get_db()
    rows = db.execute("""
        SELECT name, tier_override FROM golfers
        WHERE tournament_id = ?
        ORDER BY dk_salary DESC NULLS LAST, name ASC
    """, [tournament_id]).fetchall()
    first, second, third = [], [], []
    for i, row in enumerate(rows):
        entry = {'name': row[0]}
        tier = compute_tier(i, row[1])
        if tier == 1:
            first.append(entry)
        elif tier == 2:
            second.append(entry)
        else:
            third.append(entry)
    return first, second, third


def _render_pick_form(**overrides):
    """Render pick_form.html with defaults for all template params."""
    ctx = dict(tournament_name='No Active Tournament', first=None, second=None,
               third=None, already_submitted=False,
               existing_entry=None, editing=False, user=g.user)
    ctx.update(overrides)
    return render_template('pick_form.html', **ctx)


@app.route('/make_picks')
@login_required
def make_picks():
    """Pick submission form."""
    tournament = get_active_tournament()

    if not tournament or tournament['picks_locked']:
        return redirect(url_for('leaderboard'))

    # Check if user already submitted
    db = get_db()
    existing = db.execute("""
        SELECT entry_name, golfer_1, golfer_2, golfer_3, golfer_4, golfer_5
        FROM entries WHERE user_id = ? AND tournament_id = ?
    """, [g.user['id'], tournament['id']]).fetchone()

    # Build tier lists
    golfers = get_golfers(tournament['id'])

    if not golfers:
        return _render_pick_form(tournament_name=tournament['name'],
                                 first=[], second=[], third=[])

    first, second, third = _build_tier_lists(tournament['id'])

    if existing:
        return _render_pick_form(tournament_name=tournament['name'], first=first,
                                 second=second, third=third, editing=True,
                                 existing_entry={
                                     'entry_name': existing[0],
                                     'golfer_1': existing[1],
                                     'golfer_2': existing[2],
                                     'golfer_3': existing[3],
                                     'golfer_4': existing[4],
                                     'golfer_5': existing[5],
                                 })

    return _render_pick_form(tournament_name=tournament['name'], first=first,
                             second=second, third=third)


@app.route('/submit_picks', methods=['POST'])
@login_required
@csrf_required
def submit_picks():
    """Submit picks."""
    tournament = get_active_tournament()

    if not tournament:
        return render_template('error.html', message='No active tournament.'), 400

    if tournament['picks_locked']:
        return render_template('error.html', message='Picks are locked for this tournament.'), 400

    db = get_db()
    existing = db.execute("""
        SELECT id FROM entries WHERE user_id = ? AND tournament_id = ?
    """, [g.user['id'], tournament['id']]).fetchone()

    # Validate input
    entry_name = validate_entry_name(request.form.get('entry_name'))
    golfer_1 = request.form.get('golfer_1')
    golfer_2_and_3 = request.form.getlist('golfer_2_and_3')
    golfer_4_and_5 = request.form.getlist('golfer_4_and_5')

    if not entry_name:
        return render_template('error.html', message='Please enter a valid team name.'), 400

    if not golfer_1 or len(golfer_2_and_3) != 2 or len(golfer_4_and_5) != 2:
        return render_template('error.html', message='Please select all 5 golfers.'), 400

    golfer_2, golfer_3 = golfer_2_and_3
    golfer_4, golfer_5 = golfer_4_and_5

    # Validate golfers exist
    valid_golfers = {g['name'] for g in get_golfers(tournament['id'])}
    selected = [golfer_1, golfer_2, golfer_3, golfer_4, golfer_5]

    for golfer in selected:
        if golfer not in valid_golfers:
            return render_template('error.html', message=f'Invalid golfer selection: {golfer}'), 400

    # Check for duplicates
    if len(set(selected)) != 5:
        return render_template('error.html', message='You cannot select the same golfer twice.'), 400

    # Insert or update entry
    is_update = existing is not None
    try:
        if is_update:
            db.execute("""
                UPDATE entries SET entry_name = ?, golfer_1 = ?, golfer_2 = ?,
                       golfer_3 = ?, golfer_4 = ?, golfer_5 = ?, updated_at = datetime('now')
                WHERE user_id = ? AND tournament_id = ?
            """, [entry_name, golfer_1, golfer_2, golfer_3, golfer_4, golfer_5,
                  g.user['id'], tournament['id']])
        else:
            db.execute("""
                INSERT INTO entries (id, user_id, tournament_id, entry_name,
                                   golfer_1, golfer_2, golfer_3, golfer_4, golfer_5)
                VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?)
            """, [g.user['id'], tournament['id'], entry_name,
                  golfer_1, golfer_2, golfer_3, golfer_4, golfer_5])
        db.commit()

        # Clear cache
        clear_tournament_cache(tournament['id'])

        return render_template('submit_success.html',
                             tournament=tournament['name'],
                             entry_name=entry_name,
                             golfers=selected,
                             is_update=is_update)
    except Exception as e:
        logger.error(f"Error submitting picks: {e}")
        return render_template('error.html', message='An error occurred. Please try again.'), 500


# =============================================================================
# Admin Routes
# =============================================================================

def _parse_api_schedule(raw_schedule):
    """Parse MongoDB-style dates from the golf API schedule into display-friendly dicts."""
    now = datetime.now(timezone.utc)
    schedule = []
    for event in raw_schedule:
        start_date = None
        end_date = None
        try:
            date_obj = event.get('date', {})
            start_ms = date_obj.get('start', {}).get('$date', {}).get('$numberLong')
            end_ms = date_obj.get('end', {}).get('$date', {}).get('$numberLong')
            if start_ms:
                start_date = datetime.fromtimestamp(int(start_ms) / 1000, tz=timezone.utc)
            if end_ms:
                end_date = datetime.fromtimestamp(int(end_ms) / 1000, tz=timezone.utc)
        except (TypeError, ValueError):
            pass

        schedule.append({
            'tournId': event.get('tournId', ''),
            'name': event.get('name', ''),
            'start_date': start_date.strftime('%b %d') if start_date else 'TBD',
            'end_date': end_date.strftime('%b %d, %Y') if end_date else '',
            'is_future': start_date > now if start_date else False,
        })
    return schedule


@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard."""
    db = get_db()

    # Get all tournaments with entry/golfer counts
    tournaments = db.execute("""
        SELECT t.id, t.external_id, t.name, t.season_year, t.is_active, t.picks_locked,
               (SELECT COUNT(*) FROM entries WHERE tournament_id = t.id) as entry_count,
               (SELECT COUNT(*) FROM golfers WHERE tournament_id = t.id) as golfer_count,
               t.refresh_interval_minutes, t.buy_in
        FROM tournaments t ORDER BY t.created_at DESC
    """).fetchall()

    tournament_list = [{
        'id': t[0],
        'external_id': t[1],
        'name': t[2],
        'season_year': t[3],
        'is_active': bool(t[4]),
        'picks_locked': bool(t[5]),
        'entry_count': t[6],
        'golfer_count': t[7],
        'refresh_interval_minutes': t[8] or 60,
        'buy_in': t[9] or 5
    } for t in tournaments]

    # Load cached schedule from DB (fetched on demand via /admin/refresh-schedule)
    year = int(request.args.get('year', datetime.now().year))
    org_id = request.args.get('org', '1')
    raw_schedule = get_stored_schedule(year, org_id) or []
    schedule = _parse_api_schedule(raw_schedule)

    api_connected = bool(os.getenv('GOLF_API_KEY'))

    # Fetch pending access requests
    pending_requests = db.execute("""
        SELECT id, email, display_name, created_at, first_name, last_name
        FROM access_requests WHERE status = 'pending'
        ORDER BY created_at ASC
    """).fetchall()

    access_requests = [{
        'id': r[0],
        'email': r[1],
        'display_name': f"{r[4]} {r[5]}" if r[4] else r[2],
        'created_at': r[3]
    } for r in pending_requests]

    registration_open = is_registration_open()
    refresh_schedule = get_refresh_schedule()

    return render_template('admin.html',
                         tournaments=tournament_list,
                         schedule=schedule,
                         year=year,
                         org_id=org_id,
                         api_connected=api_connected,
                         access_requests=access_requests,
                         registration_open=registration_open,
                         refresh_schedule=refresh_schedule,
                         user=g.user)


@app.route('/admin/refresh-schedule', methods=['POST'])
@admin_required
@csrf_required
def admin_refresh_schedule():
    """Fetch tournament schedule from API and store in DB."""
    year = request.form.get('year', str(datetime.now().year))
    org_id = request.form.get('org', '1')

    raw_schedule = fetch_tournament_schedule(int(year), org_id)
    if raw_schedule is not None:
        save_schedule(year, org_id, raw_schedule)
        flash('Schedule refreshed from API.', 'success')
    else:
        flash('Failed to fetch schedule from API.', 'error')

    return redirect(url_for('admin_dashboard', year=year, org=org_id))


@app.route('/admin/create-tournament', methods=['POST'])
@admin_required
@csrf_required
def admin_create_tournament():
    """Create a new tournament."""
    external_id = request.form.get('external_id', '').strip()
    name = request.form.get('name', '').strip()
    season_year = request.form.get('season_year', datetime.now().year)
    refresh_interval = int(request.form.get('refresh_interval_minutes', 60))
    buy_in = int(request.form.get('buy_in', 5))

    if not external_id or not name:
        return redirect(url_for('admin_dashboard'))

    db = get_db()

    try:
        db.execute("""
            INSERT INTO tournaments (id, external_id, name, season_year, refresh_interval_minutes, buy_in)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?)
        """, [external_id, name, int(season_year), refresh_interval, buy_in])
        db.commit()
    except Exception as e:
        logger.error(f"Error creating tournament: {e}")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/update-refresh-interval', methods=['POST'])
@admin_required
@csrf_required
def admin_update_refresh_interval():
    """Update the refresh interval for a tournament."""
    tournament_id = request.form.get('tournament_id')
    interval = int(request.form.get('refresh_interval_minutes', 60))

    if not tournament_id or interval not in (5, 10, 15, 30, 60):
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute(
        "UPDATE tournaments SET refresh_interval_minutes = ? WHERE id = ?",
        [interval, tournament_id]
    )
    db.commit()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/update-buy-in', methods=['POST'])
@admin_required
@csrf_required
def admin_update_buy_in():
    """Update the buy-in amount for a tournament."""
    tournament_id = request.form.get('tournament_id')
    buy_in = int(request.form.get('buy_in', 5))

    if not tournament_id or buy_in not in (5, 10):
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute(
        "UPDATE tournaments SET buy_in = ? WHERE id = ?",
        [buy_in, tournament_id]
    )
    db.commit()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/activate-tournament', methods=['POST'])
@admin_required
@csrf_required
def admin_activate_tournament():
    """Activate a tournament (deactivates others)."""
    tournament_id = request.form.get('tournament_id')

    if not tournament_id:
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute("UPDATE tournaments SET is_active = 0")
    db.execute("UPDATE tournaments SET is_active = 1 WHERE id = ?", [tournament_id])
    db.commit()

    # Auto-refresh golfers so the pick form isn't empty after activation
    tournament = get_tournament_external_info(tournament_id)
    if tournament:
        refresh_golfers_from_api(tournament_id, tournament[0], tournament[1])

    # Clear all caches
    clear_tournament_cache()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/toggle-picks-lock', methods=['POST'])
@admin_required
@csrf_required
def admin_toggle_picks_lock():
    """Toggle picks lock for a tournament."""
    tournament_id = request.form.get('tournament_id')

    if not tournament_id:
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute("""
        UPDATE tournaments SET picks_locked = NOT picks_locked WHERE id = ?
    """, [tournament_id])
    db.commit()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/refresh-golfers', methods=['POST'])
@admin_required
@csrf_required
def admin_refresh_golfers():
    """Refresh golfers from API."""
    tournament_id = request.form.get('tournament_id')

    if not tournament_id:
        return redirect(url_for('admin_dashboard'))

    tournament = get_tournament_external_info(tournament_id)

    if tournament:
        refresh_golfers_from_api(tournament_id, tournament[0], tournament[1])
        clear_tournament_cache(tournament_id)

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/fetch-dk-salaries', methods=['POST'])
@admin_required
@csrf_required
def admin_fetch_dk_salaries():
    """Fetch DraftKings salaries and match to tournament golfers."""
    tournament_id = request.form.get('tournament_id')

    if not tournament_id:
        return redirect(url_for('admin_dashboard'))

    salaries, contest_name, player_count = fetch_dk_salaries()

    if salaries is None:
        logger.warning("DK salary fetch failed — no data returned")
        return redirect(url_for('admin_manage_tiers', tournament_id=tournament_id,
                                dk_msg='fetch_failed'))

    db = get_db()
    golfers = db.execute(
        "SELECT id, name FROM golfers WHERE tournament_id = ?", [tournament_id]
    ).fetchall()

    matched = 0
    unmatched_dk = set(salaries.keys())
    unmatched_golfers = []

    for golfer_id, golfer_name in golfers:
        normalized = _normalize_golfer_name(golfer_name)
        if normalized in salaries:
            db.execute("UPDATE golfers SET dk_salary = ? WHERE id = ?",
                       [salaries[normalized], golfer_id])
            matched += 1
            unmatched_dk.discard(normalized)
        else:
            unmatched_golfers.append(golfer_name)

    db.commit()

    clear_tournament_cache()

    logger.info(f"DK salaries: {matched}/{len(golfers)} golfers matched from {contest_name}")
    if unmatched_golfers:
        logger.info(f"DK unmatched golfers (in DB, not in DK): {unmatched_golfers[:20]}")
    if unmatched_dk:
        logger.info(f"DK unmatched players (in DK, not in DB): {list(unmatched_dk)[:20]}")

    return redirect(url_for('admin_manage_tiers', tournament_id=tournament_id,
                            dk_msg='success', dk_matched=matched,
                            dk_total=len(golfers), dk_contest=contest_name))


@app.route('/admin/delete-tournament', methods=['POST'])
@admin_required
@csrf_required
def admin_delete_tournament():
    """Delete a tournament."""
    tournament_id = request.form.get('tournament_id')

    if not tournament_id:
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute("DELETE FROM entries WHERE tournament_id = ?", [tournament_id])
    db.execute("DELETE FROM golfers WHERE tournament_id = ?", [tournament_id])
    db.execute("DELETE FROM tournament_metadata WHERE tournament_id = ?", [tournament_id])
    db.execute("DELETE FROM tournaments WHERE id = ?", [tournament_id])
    db.commit()

    clear_tournament_cache()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/approve-user', methods=['POST'])
@admin_required
@csrf_required
def admin_approve_user():
    """Approve an access request and create user."""
    request_id = request.form.get('request_id')

    if not request_id:
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    access_req = db.execute("""
        SELECT id, email, display_name, status, first_name, last_name
        FROM access_requests WHERE id = ?
    """, [request_id]).fetchone()

    if not access_req or access_req[3] != 'pending':
        return redirect(url_for('admin_dashboard'))

    email = access_req[1]
    display_name = access_req[2]
    first_name = access_req[4]
    last_name = access_req[5]

    # Create user
    is_admin = 1 if email in ADMIN_EMAILS else 0
    db.execute("""
        INSERT INTO users (id, email, display_name, first_name, last_name, is_admin)
        VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?)
    """, [email, display_name, first_name, last_name, is_admin])

    # Update access request
    db.execute("""
        UPDATE access_requests SET status = 'approved', reviewed_by = ?, reviewed_at = datetime('now')
        WHERE id = ?
    """, [g.user['id'], request_id])
    db.commit()

    log_security_event('access_approved', request, user_id=g.user['id'], email=email)
    send_approval_email(email, display_name)

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reject-user', methods=['POST'])
@admin_required
@csrf_required
def admin_reject_user():
    """Reject an access request."""
    request_id = request.form.get('request_id')

    if not request_id:
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    access_req = db.execute("""
        SELECT id, email, status FROM access_requests WHERE id = ?
    """, [request_id]).fetchone()

    if not access_req or access_req[2] != 'pending':
        return redirect(url_for('admin_dashboard'))

    db.execute("""
        UPDATE access_requests SET status = 'rejected', reviewed_by = ?, reviewed_at = datetime('now')
        WHERE id = ?
    """, [g.user['id'], request_id])
    db.commit()

    log_security_event('access_rejected', request, user_id=g.user['id'], email=access_req[1])

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/toggle-registration', methods=['POST'])
@admin_required
@csrf_required
def admin_toggle_registration():
    """Toggle registration open/closed."""
    db = get_db()
    current = is_registration_open()
    new_value = '0' if current else '1'
    db.execute("""
        INSERT OR REPLACE INTO app_settings (key, value) VALUES ('registration_open', ?)
    """, [new_value])
    db.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/update-refresh-schedule', methods=['POST'])
@admin_required
@csrf_required
def admin_update_refresh_schedule():
    """Update the auto-refresh schedule for golfer scores."""
    start_hour = int(request.form.get('start_hour', 12))
    end_hour = int(request.form.get('end_hour', 0))
    days = [int(d) for d in request.form.getlist('days')]

    # Validate
    if not (0 <= start_hour <= 23) or not (0 <= end_hour <= 23):
        return redirect(url_for('admin_dashboard'))
    days = [d for d in days if 0 <= d <= 6]

    save_refresh_schedule(start_hour, end_hour, days)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/manage-tiers/<tournament_id>')
@admin_required
def admin_manage_tiers(tournament_id):
    """Manage golfer tier assignments for a tournament."""
    db = get_db()
    tournament = db.execute(
        "SELECT id, name FROM tournaments WHERE id = ?", [tournament_id]
    ).fetchone()

    if not tournament:
        return redirect(url_for('admin_dashboard'))

    # Get golfers sorted by DK salary (higher = better)
    golfers = db.execute("""
        SELECT id, name, tier_override, dk_salary
        FROM golfers WHERE tournament_id = ?
        ORDER BY dk_salary DESC NULLS LAST, name ASC
    """, [tournament_id]).fetchall()

    has_dk_data = any(row[3] for row in golfers)

    # Build golfer list with computed and effective tiers
    tier_1 = []
    tier_2 = []
    tier_3 = []
    override_count = 0

    for i, row in enumerate(golfers):
        computed_tier = compute_tier(i)
        override = row[2]
        effective_tier = override if override else computed_tier
        is_overridden = override is not None

        if is_overridden:
            override_count += 1

        entry = {
            'id': row[0],
            'name': row[1],
            'computed_tier': computed_tier,
            'effective_tier': effective_tier,
            'tier_override': override,
            'is_overridden': is_overridden,
            'dk_salary': row[3],
        }

        if effective_tier == 1:
            tier_1.append(entry)
        elif effective_tier == 2:
            tier_2.append(entry)
        else:
            tier_3.append(entry)

    return render_template('admin_tiers.html',
                         tournament_id=tournament[0],
                         tournament_name=tournament[1],
                         tier_1=tier_1,
                         tier_2=tier_2,
                         tier_3=tier_3,
                         golfer_count=len(golfers),
                         override_count=override_count,
                         has_dk_data=has_dk_data,
                         user=g.user)


@app.route('/admin/save-tiers', methods=['POST'])
@admin_required
@csrf_required
def admin_save_tiers():
    """Save tier override assignments."""
    tournament_id = request.form.get('tournament_id')
    if not tournament_id:
        return redirect(url_for('admin_dashboard'))

    db = get_db()

    # Get all golfer IDs for this tournament
    golfer_ids = db.execute(
        "SELECT id FROM golfers WHERE tournament_id = ?", [tournament_id]
    ).fetchall()

    for row in golfer_ids:
        golfer_id = row[0]
        tier_value = request.form.get(f'tier_{golfer_id}')

        if tier_value in ('1', '2', '3'):
            db.execute(
                "UPDATE golfers SET tier_override = ? WHERE id = ?",
                [int(tier_value), golfer_id]
            )
        else:
            # "auto" or missing — clear override
            db.execute(
                "UPDATE golfers SET tier_override = NULL WHERE id = ?",
                [golfer_id]
            )

    db.commit()

    clear_tournament_cache(tournament_id)

    return redirect(url_for('admin_manage_tiers', tournament_id=tournament_id))


@app.route('/admin/reset-tiers', methods=['POST'])
@admin_required
@csrf_required
def admin_reset_tiers():
    """Reset all tier overrides for a tournament."""
    tournament_id = request.form.get('tournament_id')
    if not tournament_id:
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute(
        "UPDATE golfers SET tier_override = NULL WHERE tournament_id = ?",
        [tournament_id]
    )
    db.commit()

    clear_tournament_cache(tournament_id)

    return redirect(url_for('admin_manage_tiers', tournament_id=tournament_id))


# =============================================================================
# Feedback
# =============================================================================

@app.route('/submit-feedback', methods=['POST'])
@login_required
@csrf_required
def submit_feedback():
    """Submit user feedback from the floating widget."""
    message = (request.form.get('message') or '').strip()
    page_url = (request.form.get('page_url') or '').strip()

    if not message:
        return {'ok': False, 'error': 'Message is required.'}, 400
    if len(message) > 2000:
        return {'ok': False, 'error': 'Message too long (max 2000 chars).'}, 400

    db = get_db()
    db.execute(
        "INSERT INTO feedback (user_id, page_url, message) VALUES (?, ?, ?)",
        [g.user['id'], page_url[:500], message]
    )
    db.commit()
    return {'ok': True}


@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    """View user feedback."""
    status = request.args.get('status', 'open')
    db = get_db()

    if status == 'open':
        where = "WHERE f.resolved = 0"
    elif status == 'resolved':
        where = "WHERE f.resolved = 1"
    else:
        where = ""
        status = 'all'

    rows = db.execute(f"""
        SELECT f.id, f.page_url, f.message, f.resolved, f.created_at,
               u.email, u.first_name, u.last_name
        FROM feedback f
        JOIN users u ON f.user_id = u.id
        {where}
        ORDER BY f.created_at DESC
    """).fetchall()

    feedback_list = [{
        'id': r[0],
        'page_url': r[1],
        'message': r[2],
        'resolved': bool(r[3]),
        'created_at': r[4],
        'email': r[5],
        'user_name': f"{r[6] or ''} {(r[7] or '')[:1]}.".strip() if r[6] else r[5],
    } for r in rows]

    return render_template('admin_feedback.html',
                           feedback_list=feedback_list,
                           status_filter=status)


@app.route('/admin/feedback/toggle', methods=['POST'])
@admin_required
@csrf_required
def admin_feedback_toggle():
    """Toggle resolved status of a feedback item."""
    feedback_id = request.form.get('feedback_id')
    if not feedback_id:
        return redirect(url_for('admin_feedback'))

    db = get_db()
    db.execute(
        "UPDATE feedback SET resolved = CASE WHEN resolved = 0 THEN 1 ELSE 0 END WHERE id = ?",
        [feedback_id]
    )
    db.commit()

    status = request.args.get('status', request.form.get('status', 'open'))
    return redirect(url_for('admin_feedback', status=status))


@app.route('/admin/members')
@admin_required
def admin_members():
    """Admin page showing all members and per-season/lifetime winnings."""
    db = get_db()

    # Get all users
    users = db.execute("""
        SELECT id, email, first_name, last_name, created_at
        FROM users ORDER BY created_at ASC
    """).fetchall()

    members = []
    for u in users:
        # Get last login from sessions table
        last_session = db.execute("""
            SELECT MAX(created_at) FROM sessions WHERE user_id = ?
        """, [u[0]]).fetchone()
        members.append({
            'id': u[0],
            'email': u[1],
            'first_name': u[2] or '',
            'last_name': u[3] or '',
            'name': f"{u[2] or ''} {u[3] or ''}".strip() or u[1],
            'created_at': u[4],
            'last_login': last_session[0] if last_session and last_session[0] else None,
            'is_admin': u[1] in app.config.get('ADMIN_EMAILS', [])
        })

    # Get completed tournaments grouped by season
    tournaments = db.execute("""
        SELECT id, name, season_year FROM tournaments
        WHERE picks_locked = 1
        ORDER BY season_year ASC, id ASC
    """).fetchall()

    # Compute winnings per user per season
    winnings = {}  # {user_id: {season_year: amount}}
    tournament_results = []
    seasons = sorted(set(t[2] for t in tournaments))

    for t in tournaments:
        tid, tname, season = t[0], t[1], t[2]
        result = compute_tournament_winners(tid)
        if result is None:
            continue

        winner_names = []
        for uid in result['winners']:
            m = next((m for m in members if m['id'] == uid), None)
            if m:
                winner_names.append(m['name'])
            winnings.setdefault(uid, {})
            winnings[uid][season] = winnings[uid].get(season, 0) + result['per_winner']

        tournament_results.append({
            'name': tname,
            'season': season,
            'pot': result['pot'],
            'winners': winner_names,
            'per_winner': result['per_winner']
        })

    # Compute lifetime totals
    for m in members:
        m['season_winnings'] = {}
        for s in seasons:
            m['season_winnings'][s] = winnings.get(m['id'], {}).get(s, 0)
        m['lifetime'] = sum(m['season_winnings'].values())

    return render_template('admin_members.html',
                           members=members,
                           seasons=seasons,
                           tournament_results=tournament_results)


@app.route('/admin/payments')
@admin_required
def admin_payments():
    """Admin page for tracking tournament buy-in payments."""
    db = get_db()
    tournaments = db.execute("""
        SELECT id, name, season_year, buy_in FROM tournaments
        ORDER BY created_at DESC
    """).fetchall()

    tournament_entries = []
    for t in tournaments:
        entries = db.execute("""
            SELECT e.id, e.entry_name, e.paid, u.first_name, u.last_name
            FROM entries e JOIN users u ON e.user_id = u.id
            WHERE e.tournament_id = ?
            ORDER BY u.first_name, u.last_name
        """, [t[0]]).fetchall()
        if entries:
            tournament_entries.append({
                'id': t[0],
                'name': t[1],
                'season_year': t[2],
                'buy_in': t[3] or 5,
                'entries': [{'id': e[0], 'entry_name': e[1], 'paid': bool(e[2]),
                             'name': f"{e[3]} {e[4]}"} for e in entries],
            })

    return render_template('admin_payments.html',
                           tournament_entries=tournament_entries,
                           user=g.user)


@app.route('/admin/toggle-paid', methods=['POST'])
@admin_required
@csrf_required
def admin_toggle_paid():
    """Toggle paid status for an entry."""
    entry_id = request.form.get('entry_id')
    if not entry_id:
        return redirect(url_for('admin_payments'))

    db = get_db()
    db.execute("UPDATE entries SET paid = 1 - paid WHERE id = ?", [entry_id])
    db.commit()

    # Clear standings cache so owed column updates
    for key in list(_cache):
        if key.startswith('standings_'):
            _cache.pop(key, None)

    return redirect(url_for('admin_payments'))


# =============================================================================
# Utility Routes
# =============================================================================

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return {
        'status': 'healthy',
        'cache_count': len(_cache),
        'timestamp': time.time()
    }


@app.route('/clear_cache')
@admin_required
def clear_cache():
    """Clear all cached data."""
    _cache.clear()
    return {'status': 'cache cleared', 'timestamp': time.time()}


@app.route('/api/auto-refresh', methods=['POST'])
def auto_refresh_golfers():
    """Protected endpoint for automated golfer score refresh.

    Authenticate via X-API-Key header matching GOLF_API_KEY,
    or via normal admin session. Designed to be called by
    external cron/scheduler (e.g., DO scheduled function, UptimeRobot).
    """
    # Auth: API key or admin session
    api_key = request.headers.get('X-API-Key')
    expected_key = os.getenv('GOLF_API_KEY')

    is_api_auth = api_key and expected_key and secrets.compare_digest(api_key, expected_key)
    is_admin_auth = g.user and g.user.get('is_admin')

    if not is_api_auth and not is_admin_auth:
        return {'error': 'unauthorized'}, 401

    # Check configurable refresh schedule (skip for manual admin triggers)
    force = request.args.get('force') == '1'
    if not force and is_api_auth and not is_within_refresh_window():
        return {'status': 'outside_refresh_window', 'timestamp': time.time()}, 200

    db = get_db()
    tournament = db.execute(
        "SELECT id, external_id, season_year, refresh_interval_minutes FROM tournaments WHERE is_active = 1"
    ).fetchone()

    if not tournament:
        return {'status': 'no_active_tournament'}, 200

    tournament_id, external_id, year = tournament[0], tournament[1], tournament[2]
    interval = tournament[3] or 60

    # Check if enough time has passed since last refresh
    if not force:
        metadata = get_tournament_metadata(tournament_id)
        if metadata and metadata['last_api_update']:
            try:
                last_update = datetime.fromisoformat(metadata['last_api_update'])
                now_utc = datetime.utcnow()
                elapsed_minutes = (now_utc - last_update).total_seconds() / 60
                if elapsed_minutes < interval:
                    return {
                        'status': 'too_soon',
                        'next_refresh_in_minutes': round(interval - elapsed_minutes, 1),
                        'timestamp': time.time()
                    }, 200
            except (ValueError, TypeError):
                pass  # Can't parse last_api_update, proceed with refresh

    success = refresh_golfers_from_api(tournament_id, external_id, year)

    if success:
        clear_tournament_cache(tournament_id)
        logger.info(f"Auto-refresh completed for tournament {external_id}")

    return {
        'status': 'refreshed' if success else 'api_error',
        'tournament_id': tournament_id,
        'timestamp': time.time()
    }, 200 if success else 502


@app.route('/favicon.ico')
def favicon():
    """Serve favicon to prevent 404s on every page load."""
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 50 50">
        <text y="42" font-size="42">&#x1F3C6;</text></svg>'''
    response = make_response(svg)
    response.headers['Content-Type'] = 'image/svg+xml'
    response.headers['Cache-Control'] = 'public, max-age=604800'
    return response


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', message='Access denied.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message='Page not found.'), 404


@app.errorhandler(500)
def server_error(e):
    logger.exception("Unhandled 500 error: %s", e)
    return render_template('error.html', message='An unexpected error occurred.'), 500


@app.errorhandler(Exception)
def unhandled_exception(e):
    logger.exception("Unhandled exception: %s", e)
    return render_template('error.html', message='An unexpected error occurred.'), 500


# =============================================================================
# CLI Commands
# =============================================================================

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    init_db()
    logger.info('Database initialized.')


@app.cli.command('cleanup-sessions')
def cleanup_sessions_command():
    """Clean up expired sessions and tokens."""
    db = get_db()
    db.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
    db.execute("DELETE FROM auth_tokens WHERE expires_at < datetime('now')")
    db.commit()
    logger.info('Expired sessions and tokens cleaned up.')


# =============================================================================
# Startup
# =============================================================================

# Run migrations on startup to ensure schema is up to date
with app.app_context():
    _run_migrations(get_db())


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    app.run(debug=True)
