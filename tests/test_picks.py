"""Tests for pick submission validation and storage."""

import secrets

from conftest import _create_session, _create_user, get_csrf_token

import app as app_module


class TestPickSubmission:
    def _make_pick_data(self, csrf_token, entry_name='My Team',
                        golfer_1='Tiger Woods',
                        golfer_2_and_3=('Rory McIlroy', 'Scottie Scheffler'),
                        golfer_4_and_5=('Jon Rahm', 'Brooks Koepka')):
        """Build form data for a pick submission."""
        data = {
            'csrf_token': csrf_token,
            'entry_name': entry_name,
            'golfer_1': golfer_1,
            'golfer_2_and_3': list(golfer_2_and_3),
            'golfer_4_and_5': list(golfer_4_and_5),
        }
        return data

    def test_no_active_tournament_returns_400(self, auth_client):
        token = get_csrf_token(auth_client)
        data = self._make_pick_data(token)
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_picks_locked_returns_400(self, app_instance, db, auth_client, seed_tournament):
        db.execute("UPDATE tournaments SET picks_locked = 1 WHERE id = ?", [seed_tournament['id']])
        db.commit()

        token = get_csrf_token(auth_client)
        data = self._make_pick_data(token)
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_duplicate_entry_returns_400(self, app_instance, db, auth_client, seed_tournament):
        # Get the user_id from the session
        user_id = db.execute("SELECT id FROM users WHERE email = 'user@test.com'").fetchone()[0]

        # Insert an existing entry
        db.execute(
            "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
            "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [secrets.token_hex(16), user_id, seed_tournament['id'], 'Existing',
             'Tiger Woods', 'Rory McIlroy', 'Scottie Scheffler', 'Jon Rahm', 'Brooks Koepka'],
        )
        db.commit()

        token = get_csrf_token(auth_client)
        data = self._make_pick_data(token)
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_empty_entry_name_returns_400(self, auth_client, seed_tournament):
        token = get_csrf_token(auth_client)
        data = self._make_pick_data(token, entry_name='')
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_invalid_entry_name_returns_400(self, auth_client, seed_tournament):
        token = get_csrf_token(auth_client)
        data = self._make_pick_data(token, entry_name='<script>alert(1)</script>')
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_missing_golfer_tier_returns_400(self, auth_client, seed_tournament):
        token = get_csrf_token(auth_client)
        # Only 1 golfer in tier 2 instead of 2
        data = {
            'csrf_token': token,
            'entry_name': 'My Team',
            'golfer_1': 'Tiger Woods',
            'golfer_2_and_3': ['Rory McIlroy'],
            'golfer_4_and_5': ['Jon Rahm', 'Brooks Koepka'],
        }
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_duplicate_golfer_returns_400(self, auth_client, seed_tournament):
        token = get_csrf_token(auth_client)
        data = self._make_pick_data(
            token,
            golfer_1='Tiger Woods',
            golfer_2_and_3=('Tiger Woods', 'Scottie Scheffler'),
            golfer_4_and_5=('Jon Rahm', 'Brooks Koepka'),
        )
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_invalid_golfer_name_returns_400(self, auth_client, seed_tournament):
        token = get_csrf_token(auth_client)
        data = self._make_pick_data(
            token,
            golfer_1='Nonexistent Player',
        )
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400

    def test_successful_submission(self, app_instance, db, auth_client, seed_tournament):
        token = get_csrf_token(auth_client)
        data = self._make_pick_data(token)
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 200

        # Verify entry was created
        entry = db.execute(
            "SELECT entry_name, golfer_1, golfer_2, golfer_3, golfer_4, golfer_5 FROM entries"
        ).fetchone()
        assert entry is not None
        assert entry[0] == 'My Team'
        assert entry[1] == 'Tiger Woods'

    def test_unauthenticated_submit_redirects(self, client, seed_tournament):
        resp = client.post('/submit_picks', data={'entry_name': 'Test'})
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']
