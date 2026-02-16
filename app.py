"""
Flask Golf - Fantasy Golf League Application
Migrated from Snowflake to Turso with Magic Link Authentication
"""

import os
import re
import json
import html
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

import libsql_experimental as libsql
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
from pytz import timezone

# Try to load local config for development
try:
    from config import *
except ModuleNotFoundError:
    pass

app = Flask(__name__)
Compress(app)

# Flask configuration
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_SECURE=not app.debug,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='golf_session',
)

# Constants
CACHE_TTL = 300  # 5 minutes
SESSION_EXPIRY_DAYS = 7
MAGIC_LINK_EXPIRY_MINUTES = 10
ADMIN_EMAILS = os.getenv('ADMIN_EMAILS', '').split(',')

# Rate limiting configuration
RATE_LIMITS = {
    'magic_link_per_email': {'max': 3, 'window_minutes': 60},
    'magic_link_per_ip': {'max': 10, 'window_minutes': 60},
    'failed_verifications_per_ip': {'max': 5, 'window_minutes': 15},
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
    """Get database connection."""
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
    # libsql connections don't need explicit close


def init_db():
    """Initialize database schema."""
    db = get_db()
    with open('schema.sql', 'r') as f:
        db.executescript(f.read())
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


# =============================================================================
# Security Middleware
# =============================================================================

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
def enforce_https():
    """Redirect HTTP to HTTPS in production."""
    if not app.debug:
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
            SELECT s.id, s.user_id, s.expires_at, u.email, u.display_name, u.is_admin
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token_hash = ?
        """, [token_hash]).fetchone()

        if result:
            expires_at = datetime.fromisoformat(result[2])
            if expires_at > datetime.utcnow():
                g.user = {
                    'id': result[1],
                    'email': result[3],
                    'display_name': result[4],
                    'is_admin': bool(result[5]),
                    'session_id': result[0]
                }
                # Update last activity
                db.execute(
                    "UPDATE sessions SET last_activity = datetime('now') WHERE id = ?",
                    [result[0]]
                )
                db.commit()


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
    window_start = datetime.utcnow() - timedelta(minutes=limit_config['window_minutes'])

    result = db.execute("""
        SELECT attempts, window_start FROM rate_limits
        WHERE identifier = ? AND action = ?
    """, [identifier, action]).fetchone()

    if result:
        attempts, stored_window = result
        stored_window_dt = datetime.fromisoformat(stored_window)

        if stored_window_dt < window_start:
            # Window expired, reset
            db.execute("""
                UPDATE rate_limits SET attempts = 1, window_start = datetime('now')
                WHERE identifier = ? AND action = ?
            """, [identifier, action])
            db.commit()
            return True
        elif attempts >= limit_config['max']:
            return False
        else:
            db.execute("""
                UPDATE rate_limits SET attempts = attempts + 1
                WHERE identifier = ? AND action = ?
            """, [identifier, action])
            db.commit()
            return True
    else:
        db.execute("""
            INSERT INTO rate_limits (identifier, action, attempts, window_start)
            VALUES (?, ?, 1, datetime('now'))
        """, [identifier, action])
        db.commit()
        return True


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
        print(f"Error logging security event: {e}")


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
            return redirect(url_for('auth_login', next=request.url))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            return redirect(url_for('auth_login', next=request.url))
        if not g.user.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated


def create_session(user_id):
    """Create a new session for user and return session token."""
    session_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(days=SESSION_EXPIRY_DAYS)

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


def send_magic_link(email, token):
    """Send magic link email via Resend."""
    api_key = os.getenv('RESEND_API_KEY')
    email_from = os.getenv('EMAIL_FROM', 'picks@80yardbombs.com')

    if not api_key:
        # Development mode - print to console
        print(f"\n{'='*50}")
        print(f"MAGIC LINK for {email}:")
        print(f"{request.host_url}auth/verify?token={token}&email={email}")
        print(f"{'='*50}\n")
        return True

    resend.api_key = api_key

    try:
        resend.Emails.send({
            "from": email_from,
            "to": email,
            "subject": "Sign in to 80 Yard Bombs Cup",
            "html": f"""
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #16a34a;">Sign in to 80 Yard Bombs Cup</h2>
                <p>Click the button below to sign in. This link expires in 10 minutes.</p>
                <a href="{request.host_url}auth/verify?token={token}&email={email}"
                   style="display: inline-block; background: #16a34a; color: white; padding: 12px 24px;
                          text-decoration: none; border-radius: 8px; margin: 16px 0;">
                    Sign In
                </a>
                <p style="color: #666; font-size: 14px;">
                    If you didn't request this email, you can safely ignore it.
                </p>
            </div>
            """
        })
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# =============================================================================
# Tournament & Golfer Helpers
# =============================================================================

def get_active_tournament():
    """Get the currently active tournament."""
    db = get_db()
    result = db.execute("""
        SELECT id, external_id, name, season_year, is_active, picks_locked
        FROM tournaments WHERE is_active = 1 LIMIT 1
    """).fetchone()

    if result:
        return {
            'id': result[0],
            'external_id': result[1],
            'name': result[2],
            'season_year': result[3],
            'is_active': bool(result[4]),
            'picks_locked': bool(result[5])
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
               round_number, thru, tee_time, status, owgr_rank, last_updated
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
        'owgr_rank': r[9],
        'last_updated': r[10]
    } for r in results]


def get_entries(tournament_id):
    """Get all entries for a tournament."""
    db = get_db()
    results = db.execute("""
        SELECT e.id, e.entry_name, e.golfer_1, e.golfer_2, e.golfer_3, e.golfer_4, e.golfer_5,
               e.user_id, u.email
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
        'email': r[8]
    } for r in results]


def compute_leaderboard(tournament_id):
    """Compute leaderboard from entries and golfer scores."""
    entries = get_entries(tournament_id)
    golfers = {g['name']: g for g in get_golfers(tournament_id)}
    metadata = get_tournament_metadata(tournament_id)

    results = []
    for entry in entries:
        picks = [entry['golfer_1'], entry['golfer_2'], entry['golfer_3'],
                 entry['golfer_4'], entry['golfer_5']]

        total_score = 0
        pick_details = []

        for pick in picks:
            golfer = golfers.get(pick, {})
            score = golfer.get('total_score')
            if score is None:
                score = 999  # Missing golfer gets high score
            total_score += score
            pick_details.append({
                'name': pick,
                'score': score,
                'status': golfer.get('status', 'unknown')
            })

        results.append({
            'entry_name': entry['entry_name'],
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


# =============================================================================
# Golf API Integration (Slash Golf via RapidAPI)
# =============================================================================

GOLF_API_BASE_URL = "https://live-golf-data.p.rapidapi.com"


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
        print(f"Error fetching schedule: {e}")
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
        print(f"Error fetching leaderboard: {e}")
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
        print(f"Error fetching tournament field: {e}")
        return None


def refresh_golfers_from_api(tournament_id, tournament_external_id, year=None):
    """Refresh golfer data from Slash Golf API."""
    if year is None:
        year = datetime.now().year

    # Try leaderboard first (has live scores)
    data = fetch_leaderboard(tournament_external_id, year)

    if not data:
        # Fall back to tournament field if no leaderboard yet
        data = fetch_tournament_field(tournament_external_id, year)
        if not data:
            return False

    db = get_db()

    # Handle leaderboard response format
    leaderboard = data.get('leaderboard', [])
    cut_line = data.get('cutLine')

    for player in leaderboard:
        # Player name handling - API uses 'firstName' and 'lastName'
        first_name = player.get('firstName', '')
        last_name = player.get('lastName', '')
        name = f"{first_name} {last_name}".strip()

        if not name:
            name = player.get('name', player.get('playerName', ''))

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
                                 tee_time, status, owgr_rank, last_updated)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(tournament_id, name) DO UPDATE SET
                position = excluded.position,
                total_score = excluded.total_score,
                score_display = excluded.score_display,
                current_round_score = excluded.current_round_score,
                round_number = excluded.round_number,
                thru = excluded.thru,
                tee_time = excluded.tee_time,
                status = excluded.status,
                owgr_rank = excluded.owgr_rank,
                last_updated = datetime('now')
        """, [
            tournament_id,
            name,
            str(player.get('playerId', player.get('id', ''))),
            player.get('position', player.get('pos', '')),
            total_score,
            total_str or '--',
            today_str or '--',
            player.get('currentRound', player.get('round', 1)),
            player.get('thru', ''),
            player.get('teeTime', ''),
            status,
            player.get('owgr', player.get('ranking'))
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


def format_score(score):
    """Format score for display."""
    if score is None:
        return '--'
    if score == 0:
        return 'E'
    if score > 0:
        return f'+{score}'
    return str(score)


# =============================================================================
# Auth Routes
# =============================================================================

@app.route('/auth/login')
def auth_login():
    """Login page."""
    if g.user:
        return redirect(url_for('make_picks'))
    return render_template('login.html', error=request.args.get('error'))


@app.route('/auth/request-link', methods=['POST'])
@csrf_required
def auth_request_link():
    """Request magic link."""
    email = validate_user_email(request.form.get('email', ''))

    if not email:
        return render_template('login.html', error='Please enter a valid email address.')

    client_ip = get_client_ip()

    # Rate limiting
    if not check_rate_limit(email, 'magic_link_per_email'):
        log_security_event('rate_limited', request, email=email, details={'action': 'magic_link_per_email'})
        return render_template('check_email.html', email=email)  # Don't reveal rate limit

    if not check_rate_limit(client_ip, 'magic_link_per_ip'):
        log_security_event('rate_limited', request, email=email, details={'action': 'magic_link_per_ip'})
        return render_template('check_email.html', email=email)

    # Generate token
    raw_token = secrets.token_urlsafe(32)
    token_hash = ph.hash(raw_token)
    expires_at = datetime.utcnow() + timedelta(minutes=MAGIC_LINK_EXPIRY_MINUTES)

    db = get_db()
    db.execute("""
        INSERT INTO auth_tokens (id, email, token_hash, expires_at)
        VALUES (lower(hex(randomblob(16))), ?, ?, ?)
    """, [email, token_hash, expires_at.isoformat()])
    db.commit()

    # Send email
    send_magic_link(email, raw_token)
    log_security_event('magic_link_sent', request, email=email)

    return render_template('check_email.html', email=email)


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

    db = get_db()

    # Find valid token
    results = db.execute("""
        SELECT id, token_hash, expires_at, used_at
        FROM auth_tokens WHERE email = ? AND used_at IS NULL
        ORDER BY created_at DESC LIMIT 5
    """, [email]).fetchall()

    valid_token_id = None
    for result in results:
        token_id, stored_hash, expires_at, used_at = result
        expires_dt = datetime.fromisoformat(expires_at)

        if expires_dt < datetime.utcnow():
            continue

        try:
            ph.verify(stored_hash, token)
            valid_token_id = token_id
            break
        except VerifyMismatchError:
            continue

    if not valid_token_id:
        log_security_event('failed_login', request, email=email, details={'reason': 'invalid_token'})
        db.execute("""
            INSERT INTO failed_logins (id, email, ip_address, reason)
            VALUES (lower(hex(randomblob(16))), ?, ?, 'invalid_token')
        """, [email, client_ip])
        db.commit()
        return render_template('error.html', message='This sign-in link is invalid or has expired.')

    # Mark token as used
    db.execute("UPDATE auth_tokens SET used_at = datetime('now') WHERE id = ?", [valid_token_id])

    # Get or create user
    user = db.execute("SELECT id, email, is_admin FROM users WHERE email = ?", [email]).fetchone()

    if user:
        user_id = user[0]
        db.execute("UPDATE users SET last_login_at = datetime('now') WHERE id = ?", [user_id])
    else:
        is_admin = 1 if email in ADMIN_EMAILS else 0
        db.execute("""
            INSERT INTO users (id, email, is_admin, last_login_at)
            VALUES (lower(hex(randomblob(16))), ?, ?, datetime('now'))
        """, [email, is_admin])
        user_id = db.execute("SELECT id FROM users WHERE email = ?", [email]).fetchone()[0]

    db.commit()

    # Create session
    session_token, expires_at = create_session(user_id)
    log_security_event('login', request, user_id=user_id, email=email)

    # Set cookie and redirect
    response = make_response(redirect(url_for('make_picks')))
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

    response = make_response(redirect(url_for('leaderboard')))
    response.delete_cookie('golf_session')
    return response


# =============================================================================
# Main Routes
# =============================================================================

@app.route('/')
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

    cache_key = f'leaderboard_{tournament["id"]}'
    cached = get_cached(cache_key)

    if cached:
        results, metadata, last_updated = cached
    else:
        results, metadata = compute_leaderboard(tournament['id'])
        last_updated = metadata.get('last_api_update') if metadata else None

        if last_updated:
            try:
                dt = datetime.fromisoformat(last_updated)
                dt = dt.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern'))
                last_updated = dt.strftime('%A %B %d @ %I:%M %p %Z')
            except:
                last_updated = 'Recently updated'
        else:
            last_updated = 'N/A'

        set_cache(cache_key, (results, metadata, last_updated))

    # Build player scores dict for template
    golfers = get_golfers(tournament['id'])
    player_scores = {}
    for g_data in golfers:
        player_scores[g_data['name']] = {
            'score': g_data['total_score'],
            'status': g_data['status']
        }

    # Format results for template
    template_results = []
    for r in results:
        template_results.append({
            'RANK': r['rank'],
            'ENTRY_NAME': r['entry_name'],
            'TEAM_SCORE': r['team_score'],
            'PICKS': r['picks_str'],
            'TOURNAMENT': tournament['name']
        })

    return render_template('leaderboard.html',
                         tournament_name=tournament['name'],
                         results=template_results,
                         last_updated=last_updated,
                         cut_line=metadata.get('cut_line') if metadata else None,
                         player_scores=player_scores,
                         is_fallback=False,
                         user=g.user)


@app.route('/players')
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
                             user=g.user)

    cache_key = f'players_{tournament["id"]}'
    cached = get_cached(cache_key)

    if cached:
        golfers, metadata, last_updated = cached
    else:
        golfers = compute_player_standings(tournament['id'])
        metadata = get_tournament_metadata(tournament['id'])
        last_updated = metadata.get('last_api_update') if metadata else None

        if last_updated:
            try:
                dt = datetime.fromisoformat(last_updated)
                dt = dt.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern'))
                last_updated = dt.strftime('%A %B %d @ %I:%M %p %Z')
            except:
                last_updated = 'Recently updated'
        else:
            last_updated = 'N/A'

        set_cache(cache_key, (golfers, metadata, last_updated))

    # Format for template
    template_results = []
    for g_data in golfers:
        template_results.append({
            'TOURNAMENT': tournament['name'],
            'POSITION': g_data['position'] or '--',
            'GOLFER': g_data['name'],
            'TOTAL_SCORE_INTEGER': g_data['total_score'],
            'CURRENT_ROUND_SCORE': g_data['current_round_score'] or '--',
            'ROUND_ID': g_data['round_number'] or 1,
            'THRU': g_data['thru'] or '--',
            'TEE_TIME': g_data['tee_time'] or '--',
            'PLAYER_STATUS': g_data['status'] or 'active',
            'SELECTIONS': g_data['selections'],
            'CUT_LINE': metadata.get('cut_line') if metadata else None
        })

    return render_template('player_standings.html',
                         tournament_name=tournament['name'],
                         results=template_results,
                         last_updated=last_updated,
                         cut_line=metadata.get('cut_line') if metadata else None,
                         is_fallback=False,
                         user=g.user)


@app.route('/make_picks')
@login_required
def make_picks():
    """Pick submission form."""
    tournament = get_active_tournament()

    if not tournament:
        return render_template('pick_form.html',
                             tournament_name='No Active Tournament',
                             first=None,
                             second=None,
                             third=None,
                             picks_locked=True,
                             already_submitted=False,
                             existing_entry=None,
                             is_fallback=True,
                             user=g.user)

    # Check if picks are locked
    if tournament['picks_locked']:
        return render_template('pick_form.html',
                             tournament_name=tournament['name'],
                             first=None,
                             second=None,
                             third=None,
                             picks_locked=True,
                             already_submitted=False,
                             existing_entry=None,
                             is_fallback=False,
                             user=g.user)

    # Check if user already submitted
    db = get_db()
    existing = db.execute("""
        SELECT entry_name FROM entries
        WHERE user_id = ? AND tournament_id = ?
    """, [g.user['id'], tournament['id']]).fetchone()

    if existing:
        return render_template('pick_form.html',
                             tournament_name=tournament['name'],
                             first=None,
                             second=None,
                             third=None,
                             picks_locked=False,
                             already_submitted=True,
                             existing_entry=existing[0],
                             is_fallback=False,
                             user=g.user)

    # Get golfers for pick options
    golfers = get_golfers(tournament['id'])

    if not golfers:
        return render_template('pick_form.html',
                             tournament_name=tournament['name'],
                             first=[],
                             second=[],
                             third=[],
                             picks_locked=False,
                             already_submitted=False,
                             existing_entry=None,
                             is_fallback=False,
                             user=g.user)

    # Sort by OWGR rank (lower is better)
    golfers.sort(key=lambda x: x['owgr_rank'] or 999)

    golfer_names = [g['name'] for g in golfers]

    # Split into tiers
    first = golfer_names[:5]
    second = golfer_names[5:16]
    third = golfer_names[16:]

    return render_template('pick_form.html',
                         tournament_name=tournament['name'],
                         first=first,
                         second=second,
                         third=third,
                         picks_locked=False,
                         already_submitted=False,
                         existing_entry=None,
                         is_fallback=False,
                         user=g.user)


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

    # Check if already submitted
    db = get_db()
    existing = db.execute("""
        SELECT id FROM entries WHERE user_id = ? AND tournament_id = ?
    """, [g.user['id'], tournament['id']]).fetchone()

    if existing:
        return render_template('error.html', message='You have already submitted picks for this tournament.'), 400

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

    # Insert entry
    try:
        db.execute("""
            INSERT INTO entries (id, user_id, tournament_id, entry_name,
                               golfer_1, golfer_2, golfer_3, golfer_4, golfer_5)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?)
        """, [g.user['id'], tournament['id'], entry_name,
              golfer_1, golfer_2, golfer_3, golfer_4, golfer_5])
        db.commit()

        # Clear cache
        _cache.pop(f'leaderboard_{tournament["id"]}', None)
        _cache.pop(f'players_{tournament["id"]}', None)

        return render_template('submit_success.html',
                             tournament=tournament['name'],
                             entry_name=entry_name,
                             golfers=selected)
    except Exception as e:
        print(f"Error submitting picks: {e}")
        return render_template('error.html', message='An error occurred. Please try again.'), 500


# =============================================================================
# Admin Routes
# =============================================================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard."""
    db = get_db()

    # Get all tournaments with entry/golfer counts
    tournaments = db.execute("""
        SELECT t.id, t.external_id, t.name, t.season_year, t.is_active, t.picks_locked,
               (SELECT COUNT(*) FROM entries WHERE tournament_id = t.id) as entry_count,
               (SELECT COUNT(*) FROM golfers WHERE tournament_id = t.id) as golfer_count
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
        'golfer_count': t[7]
    } for t in tournaments]

    # Fetch schedule from API
    year = int(request.args.get('year', datetime.now().year))
    org_id = request.args.get('org', '1')
    schedule = fetch_tournament_schedule(year, org_id) or []

    api_connected = bool(os.getenv('GOLF_API_KEY'))

    return render_template('admin.html',
                         tournaments=tournament_list,
                         schedule=schedule,
                         year=year,
                         org_id=org_id,
                         api_connected=api_connected,
                         user=g.user)


@app.route('/admin/create-tournament', methods=['POST'])
@admin_required
@csrf_required
def admin_create_tournament():
    """Create a new tournament."""
    external_id = request.form.get('external_id', '').strip()
    name = request.form.get('name', '').strip()
    season_year = request.form.get('season_year', datetime.now().year)

    if not external_id or not name:
        return redirect(url_for('admin_dashboard'))

    db = get_db()

    try:
        db.execute("""
            INSERT INTO tournaments (id, external_id, name, season_year)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?)
        """, [external_id, name, int(season_year)])
        db.commit()
    except Exception as e:
        print(f"Error creating tournament: {e}")

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

    # Clear all caches
    _cache.clear()

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

    db = get_db()
    tournament = db.execute(
        "SELECT external_id, season_year FROM tournaments WHERE id = ?",
        [tournament_id]
    ).fetchone()

    if tournament:
        refresh_golfers_from_api(tournament_id, tournament[0], tournament[1])
        # Clear caches
        _cache.pop(f'leaderboard_{tournament_id}', None)
        _cache.pop(f'players_{tournament_id}', None)

    return redirect(url_for('admin_dashboard'))


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

    # Clear caches
    _cache.clear()

    return redirect(url_for('admin_dashboard'))


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
def clear_cache():
    """Clear all cached data."""
    _cache.clear()
    return {'status': 'cache cleared', 'timestamp': time.time()}


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
    return render_template('error.html', message='An unexpected error occurred.'), 500


# =============================================================================
# CLI Commands
# =============================================================================

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    init_db()
    print('Database initialized.')


@app.cli.command('cleanup-sessions')
def cleanup_sessions_command():
    """Clean up expired sessions and tokens."""
    db = get_db()
    db.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
    db.execute("DELETE FROM auth_tokens WHERE expires_at < datetime('now')")
    db.commit()
    print('Expired sessions and tokens cleaned up.')


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    app.run(debug=True)
