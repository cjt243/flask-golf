"""Tests for authentication, session handling, and access control."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from conftest import _create_session, _create_user, get_csrf_token

import app as app_module


# ── @login_required ─────────────────────────────────────────────────────────

class TestLoginRequired:
    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get('/')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

    def test_unauthenticated_players_redirects(self, client):
        resp = client.get('/players')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

    def test_unauthenticated_make_picks_redirects(self, client):
        resp = client.get('/make_picks')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']


# ── @admin_required ─────────────────────────────────────────────────────────

class TestAdminRequired:
    def test_unauthenticated_redirects(self, client):
        resp = client.get('/admin')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

    def test_non_admin_gets_403(self, auth_client):
        resp = auth_client.get('/admin')
        assert resp.status_code == 403


# ── @csrf_required ──────────────────────────────────────────────────────────

class TestCsrfRequired:
    def test_post_without_csrf_returns_403(self, auth_client):
        resp = auth_client.post('/auth/logout')
        assert resp.status_code == 403

    def test_post_with_wrong_csrf_returns_403(self, auth_client):
        resp = auth_client.post('/auth/logout', data={'csrf_token': 'wrong-token'})
        assert resp.status_code == 403

    def test_post_with_correct_csrf_succeeds(self, auth_client):
        token = get_csrf_token(auth_client)
        resp = auth_client.post('/auth/logout', data={'csrf_token': token})
        # Logout redirects to login page
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']


# ── Authenticated access ────────────────────────────────────────────────────

class TestAuthenticatedAccess:
    def test_authenticated_can_access_leaderboard(self, auth_client):
        resp = auth_client.get('/')
        assert resp.status_code == 200

    def test_authenticated_can_access_players(self, auth_client):
        resp = auth_client.get('/players')
        assert resp.status_code == 200

    def test_authenticated_can_access_make_picks(self, auth_client):
        resp = auth_client.get('/make_picks')
        assert resp.status_code == 200


# ── Session expiry ──────────────────────────────────────────────────────────

class TestSessionExpiry:
    def test_expired_session_rejected(self, app_instance, db, client):
        user_id = _create_user(db, 'expired@test.com')
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        # Expired 1 day ago
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        db.execute(
            "INSERT INTO sessions (id, user_id, session_token_hash, expires_at) "
            "VALUES (?, ?, ?, ?)",
            [secrets.token_hex(16), user_id, token_hash, expired],
        )
        db.commit()

        client.set_cookie('golf_session', raw_token, domain='localhost')
        resp = client.get('/')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']


# ── Logout ──────────────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_destroys_session(self, app_instance, db, auth_client):
        token = get_csrf_token(auth_client)
        resp = auth_client.post('/auth/logout', data={'csrf_token': token})
        assert resp.status_code == 302

        # After logout, subsequent requests should redirect to login
        resp = auth_client.get('/')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']


# ── Public routes ───────────────────────────────────────────────────────────

class TestPublicRoutes:
    def test_health_accessible_without_auth(self, client):
        resp = client.get('/health')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'healthy'

    def test_login_page_accessible(self, client):
        resp = client.get('/auth/login')
        assert resp.status_code == 200

    def test_favicon_accessible(self, client):
        resp = client.get('/favicon.ico')
        assert resp.status_code == 200
        assert resp.content_type == 'image/svg+xml'
