"""Tests for admin routes: tournament CRUD, user approval, registration toggle."""

import secrets

from conftest import _create_session, _create_user, get_csrf_token

import app as app_module


# ── Access control ──────────────────────────────────────────────────────────

class TestAdminAccess:
    def test_non_admin_cannot_access_admin(self, auth_client):
        resp = auth_client.get('/admin')
        assert resp.status_code == 403

    def test_admin_can_access_admin(self, admin_client):
        resp = admin_client.get('/admin')
        assert resp.status_code == 200


# ── Tournament CRUD ─────────────────────────────────────────────────────────

class TestTournamentCRUD:
    def test_create_tournament(self, app_instance, db, admin_client):
        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/create-tournament', data={
            'csrf_token': token,
            'external_id': 'ext-999',
            'name': 'New Tournament',
            'season_year': '2026',
        })
        assert resp.status_code == 302

        row = db.execute("SELECT name FROM tournaments WHERE external_id = 'ext-999'").fetchone()
        assert row is not None
        assert row[0] == 'New Tournament'

    def test_activate_tournament(self, app_instance, db, admin_client):
        # Create two tournaments
        tid1 = secrets.token_hex(16)
        tid2 = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active) VALUES (?, ?, ?, ?, ?)",
            [tid1, 'e1', 'T1', 2026, 1],
        )
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active) VALUES (?, ?, ?, ?, ?)",
            [tid2, 'e2', 'T2', 2026, 0],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/activate-tournament', data={
            'csrf_token': token,
            'tournament_id': tid2,
        })
        assert resp.status_code == 302

        r1 = db.execute("SELECT is_active FROM tournaments WHERE id = ?", [tid1]).fetchone()
        r2 = db.execute("SELECT is_active FROM tournaments WHERE id = ?", [tid2]).fetchone()
        assert r1[0] == 0
        assert r2[0] == 1

    def test_toggle_picks_lock(self, app_instance, db, admin_client):
        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, picks_locked) VALUES (?, ?, ?, ?, ?)",
            [tid, 'e3', 'T3', 2026, 0],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/toggle-picks-lock', data={
            'csrf_token': token,
            'tournament_id': tid,
        })
        assert resp.status_code == 302

        row = db.execute("SELECT picks_locked FROM tournaments WHERE id = ?", [tid]).fetchone()
        assert row[0] == 1

    def test_delete_tournament_cascades(self, app_instance, db, admin_client):
        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year) VALUES (?, ?, ?, ?)",
            [tid, 'e4', 'T4', 2026],
        )
        # Add golfer and entry
        uid = db.execute("SELECT id FROM users WHERE email = 'admin@test.com'").fetchone()[0]
        db.execute(
            "INSERT INTO golfers (id, tournament_id, name, external_id) VALUES (?, ?, ?, ?)",
            [secrets.token_hex(16), tid, 'Golfer X', '0'],
        )
        db.execute(
            "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
            "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [secrets.token_hex(16), uid, tid, 'Team', 'A', 'B', 'C', 'D', 'E'],
        )
        db.execute(
            "INSERT INTO tournament_metadata (tournament_id, cut_line) VALUES (?, ?)",
            [tid, -3],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/delete-tournament', data={
            'csrf_token': token,
            'tournament_id': tid,
        })
        assert resp.status_code == 302

        assert db.execute("SELECT id FROM tournaments WHERE id = ?", [tid]).fetchone() is None
        assert db.execute("SELECT id FROM golfers WHERE tournament_id = ?", [tid]).fetchone() is None
        assert db.execute("SELECT id FROM entries WHERE tournament_id = ?", [tid]).fetchone() is None
        assert db.execute("SELECT tournament_id FROM tournament_metadata WHERE tournament_id = ?", [tid]).fetchone() is None


# ── User approval / rejection ──────────────────────────────────────────────

class TestUserApproval:
    def test_approve_user_creates_account(self, app_instance, db, admin_client):
        req_id = secrets.token_hex(16)
        db.execute(
            "INSERT INTO access_requests (id, email, display_name, first_name, last_name, status) "
            "VALUES (?, ?, ?, ?, ?, 'pending')",
            [req_id, 'new@test.com', 'New User', 'New', 'User'],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/approve-user', data={
            'csrf_token': token,
            'request_id': req_id,
        })
        assert resp.status_code == 302

        user = db.execute("SELECT email, first_name FROM users WHERE email = 'new@test.com'").fetchone()
        assert user is not None
        assert user[1] == 'New'

        ar = db.execute("SELECT status FROM access_requests WHERE id = ?", [req_id]).fetchone()
        assert ar[0] == 'approved'

    def test_reject_user_updates_status(self, app_instance, db, admin_client):
        req_id = secrets.token_hex(16)
        db.execute(
            "INSERT INTO access_requests (id, email, display_name, first_name, last_name, status) "
            "VALUES (?, ?, ?, ?, ?, 'pending')",
            [req_id, 'bad@test.com', 'Bad Actor', 'Bad', 'Actor'],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/reject-user', data={
            'csrf_token': token,
            'request_id': req_id,
        })
        assert resp.status_code == 302

        ar = db.execute("SELECT status FROM access_requests WHERE id = ?", [req_id]).fetchone()
        assert ar[0] == 'rejected'


# ── Registration toggle ────────────────────────────────────────────────────

class TestRegistrationToggle:
    def test_toggle_registration(self, app_instance, db, admin_client):
        # Default is open
        with app_instance.app_context():
            assert app_module.is_registration_open() is True

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/toggle-registration', data={
            'csrf_token': token,
        })
        assert resp.status_code == 302

        row = db.execute("SELECT value FROM app_settings WHERE key = 'registration_open'").fetchone()
        assert row[0] == '0'

        # Toggle back
        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/toggle-registration', data={
            'csrf_token': token,
        })
        assert resp.status_code == 302

        row = db.execute("SELECT value FROM app_settings WHERE key = 'registration_open'").fetchone()
        assert row[0] == '1'


# ── Tournament announcement ───────────────────────────────────────────────

class TestTournamentAnnouncement:
    def test_announce_tournament_sends_to_all_users(self, app_instance, db, admin_client):
        """Announcement creates auth tokens for all users and stores status."""
        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked, buy_in) "
            "VALUES (?, ?, ?, ?, 1, 0, 10)",
            [tid, 'ann-1', 'Announcement Open', 2026],
        )
        # Create a second regular user (admin user already exists from admin_client fixture)
        _create_user(db, 'member@test.com', first_name='Member', last_name='One')
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/announce-tournament', data={
            'csrf_token': token,
            'tournament_id': tid,
        })
        assert resp.status_code == 302

        # Auth tokens should be created for both users
        tokens = db.execute("SELECT email FROM auth_tokens").fetchall()
        emails = {t[0] for t in tokens}
        assert 'admin@test.com' in emails
        assert 'member@test.com' in emails

        # Announcement status should be stored
        import json
        row = db.execute(
            "SELECT value FROM app_settings WHERE key = ?",
            [f'announcement_sent_{tid}']
        ).fetchone()
        assert row is not None
        status = json.loads(row[0])
        assert status['total'] == 2
        assert status['success'] == 2

    def test_announce_blocked_when_picks_locked(self, app_instance, db, admin_client):
        """Cannot announce a tournament with picks locked."""
        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked) "
            "VALUES (?, ?, ?, ?, 1, 1)",
            [tid, 'ann-2', 'Locked Tournament', 2026],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/announce-tournament', data={
            'csrf_token': token,
            'tournament_id': tid,
        })
        assert resp.status_code == 302

        # No auth tokens should be created
        tokens = db.execute("SELECT email FROM auth_tokens").fetchall()
        assert len(tokens) == 0

    def test_announce_blocked_when_inactive(self, app_instance, db, admin_client):
        """Cannot announce an inactive tournament."""
        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked) "
            "VALUES (?, ?, ?, ?, 0, 0)",
            [tid, 'ann-3', 'Inactive Tournament', 2026],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/announce-tournament', data={
            'csrf_token': token,
            'tournament_id': tid,
        })
        assert resp.status_code == 302

        tokens = db.execute("SELECT email FROM auth_tokens").fetchall()
        assert len(tokens) == 0

    def test_announce_requires_admin(self, app_instance, db, auth_client):
        """Non-admin users cannot announce tournaments."""
        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked) "
            "VALUES (?, ?, ?, ?, 1, 0)",
            [tid, 'ann-4', 'Test', 2026],
        )
        db.commit()

        token = get_csrf_token(auth_client)
        resp = auth_client.post('/admin/announce-tournament', data={
            'csrf_token': token,
            'tournament_id': tid,
        })
        assert resp.status_code == 403

    def test_announce_tokens_have_48h_expiry(self, app_instance, db, admin_client):
        """Announcement magic tokens should expire in 48 hours, not 10 minutes."""
        from datetime import datetime, timezone

        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked) "
            "VALUES (?, ?, ?, ?, 1, 0)",
            [tid, 'ann-5', 'Expiry Test', 2026],
        )
        db.commit()

        token = get_csrf_token(admin_client)
        admin_client.post('/admin/announce-tournament', data={
            'csrf_token': token,
            'tournament_id': tid,
        })

        row = db.execute(
            "SELECT expires_at FROM auth_tokens ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        assert row is not None

        expires = datetime.fromisoformat(row[0]).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        hours_until_expiry = (expires - now).total_seconds() / 3600
        # Should be close to 48 hours, definitely more than 1 hour
        assert hours_until_expiry > 47
        assert hours_until_expiry < 49

    def test_admin_dashboard_shows_announcement_status(self, app_instance, db, admin_client):
        """Admin dashboard should show announcement indicator after sending."""
        tid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked) "
            "VALUES (?, ?, ?, ?, 1, 0)",
            [tid, 'ann-6', 'Dashboard Test', 2026],
        )
        db.commit()

        # Send announcement
        token = get_csrf_token(admin_client)
        admin_client.post('/admin/announce-tournament', data={
            'csrf_token': token,
            'tournament_id': tid,
        })

        # Check dashboard shows status
        resp = admin_client.get('/admin')
        assert resp.status_code == 200
        assert b'Announced' in resp.data
