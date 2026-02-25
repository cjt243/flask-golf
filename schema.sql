-- Flask Golf Database Schema for Turso/libSQL
-- Run this to initialize the database

-- Users (verified by magic link)
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT UNIQUE NOT NULL,
    display_name TEXT,
    first_name TEXT,
    last_name TEXT,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    last_login_at TEXT
);

-- Magic link tokens
CREATE TABLE IF NOT EXISTS auth_tokens (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_email ON auth_tokens(email);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash TEXT NOT NULL,
    ip_address TEXT,
    user_agent_hash TEXT,
    expires_at TEXT NOT NULL,
    last_activity TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Tournaments
CREATE TABLE IF NOT EXISTS tournaments (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    external_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    season_year INTEGER NOT NULL,
    is_active INTEGER DEFAULT 0,
    picks_locked INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Entries (one per user per tournament)
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tournament_id TEXT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
    entry_name TEXT NOT NULL,
    golfer_1 TEXT NOT NULL,
    golfer_2 TEXT NOT NULL,
    golfer_3 TEXT NOT NULL,
    golfer_4 TEXT NOT NULL,
    golfer_5 TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, tournament_id)
);
CREATE INDEX IF NOT EXISTS idx_entries_tournament ON entries(tournament_id);
CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(user_id);

-- Cached golfer data from API
CREATE TABLE IF NOT EXISTS golfers (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    tournament_id TEXT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    external_id TEXT,
    position TEXT,
    total_score INTEGER,
    score_display TEXT,
    current_round_score TEXT,
    round_number INTEGER,
    thru TEXT,
    tee_time TEXT,
    status TEXT,
    owgr_rank INTEGER,
    tier_override INTEGER,
    dk_salary INTEGER,
    last_updated TEXT DEFAULT (datetime('now')),
    UNIQUE(tournament_id, name)
);
CREATE INDEX IF NOT EXISTS idx_golfers_tournament ON golfers(tournament_id);

-- Tournament metadata (cut line, last API update)
CREATE TABLE IF NOT EXISTS tournament_metadata (
    tournament_id TEXT PRIMARY KEY REFERENCES tournaments(id) ON DELETE CASCADE,
    cut_line INTEGER,
    last_api_update TEXT,
    api_status TEXT
);

-- Rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
    identifier TEXT NOT NULL,
    action TEXT NOT NULL,
    attempts INTEGER DEFAULT 1,
    window_start TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (identifier, action)
);

-- Security audit log
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    event_type TEXT NOT NULL,
    user_id TEXT,
    email TEXT,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(created_at);

-- Access requests (invite-only workflow)
CREATE TABLE IF NOT EXISTS access_requests (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT UNIQUE NOT NULL,
    display_name TEXT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    status TEXT DEFAULT 'pending',  -- 'pending', 'approved', 'rejected'
    reviewed_by TEXT REFERENCES users(id),
    reviewed_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_access_requests_email ON access_requests(email);

-- App settings (key-value store)
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Failed login tracking
CREATE TABLE IF NOT EXISTS failed_logins (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    reason TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_failed_logins_email ON failed_logins(email);
CREATE INDEX IF NOT EXISTS idx_failed_logins_ip ON failed_logins(ip_address);
