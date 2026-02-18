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
