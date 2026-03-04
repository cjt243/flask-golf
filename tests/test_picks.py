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

    def test_existing_entry_updates_instead_of_error(self, app_instance, db, auth_client, seed_tournament):
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
        # Submit with different picks — should update
        data = self._make_pick_data(token, entry_name='Updated Team',
                                    golfer_1='Tiger Woods',
                                    golfer_2_and_3=('Viktor Hovland', 'Patrick Cantlay'),
                                    golfer_4_and_5=('Cameron Smith', 'Tommy Fleetwood'))
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 200

        # Verify the entry was updated (not duplicated)
        entries = db.execute(
            "SELECT entry_name, golfer_2, golfer_3 FROM entries WHERE user_id = ? AND tournament_id = ?",
            [user_id, seed_tournament['id']],
        ).fetchall()
        assert len(entries) == 1
        assert entries[0][0] == 'Updated Team'
        assert entries[0][1] == 'Viktor Hovland'
        assert entries[0][2] == 'Patrick Cantlay'

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

    def test_update_with_locked_picks_returns_400(self, app_instance, db, auth_client, seed_tournament):
        """Even with existing entry, locked picks should reject updates."""
        user_id = db.execute("SELECT id FROM users WHERE email = 'user@test.com'").fetchone()[0]
        db.execute(
            "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
            "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [secrets.token_hex(16), user_id, seed_tournament['id'], 'Existing',
             'Tiger Woods', 'Rory McIlroy', 'Scottie Scheffler', 'Jon Rahm', 'Brooks Koepka'],
        )
        db.execute("UPDATE tournaments SET picks_locked = 1 WHERE id = ?", [seed_tournament['id']])
        db.commit()

        token = get_csrf_token(auth_client)
        data = self._make_pick_data(token, entry_name='Updated')
        resp = auth_client.post('/submit_picks', data=data)
        assert resp.status_code == 400


class TestMakePicksEditing:
    """Tests for the make_picks page editing behavior."""

    def test_make_picks_shows_form_when_no_entry(self, auth_client, seed_tournament):
        resp = auth_client.get('/make_picks')
        assert resp.status_code == 200
        assert b'Make Your Picks' in resp.data
        assert b'Edit Your Picks' not in resp.data

    def test_make_picks_shows_editing_form_when_entry_exists(self, app_instance, db, auth_client, seed_tournament):
        user_id = db.execute("SELECT id FROM users WHERE email = 'user@test.com'").fetchone()[0]
        db.execute(
            "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
            "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [secrets.token_hex(16), user_id, seed_tournament['id'], 'My Team',
             'Tiger Woods', 'Viktor Hovland', 'Patrick Cantlay', 'Cameron Smith', 'Tommy Fleetwood'],
        )
        db.commit()

        resp = auth_client.get('/make_picks')
        assert resp.status_code == 200
        assert b'Edit Your Picks' in resp.data
        assert b'Update Picks' in resp.data
        # Pre-populated entry name
        assert b'My Team' in resp.data

    def test_make_picks_locked_shows_locked_state(self, app_instance, db, auth_client, seed_tournament):
        db.execute("UPDATE tournaments SET picks_locked = 1 WHERE id = ?", [seed_tournament['id']])
        db.commit()

        resp = auth_client.get('/make_picks')
        assert resp.status_code == 200
        assert b'Picks Are Locked' in resp.data


class TestLeaderboardPreTournament:
    """Tests for the leaderboard hiding entries when picks are unlocked."""

    def test_leaderboard_hides_entries_when_unlocked(self, app_instance, db, auth_client, seed_tournament):
        """Leaderboard should not show any entries when picks are not locked."""
        user_id = db.execute("SELECT id FROM users WHERE email = 'user@test.com'").fetchone()[0]
        db.execute(
            "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
            "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [secrets.token_hex(16), user_id, seed_tournament['id'], 'Hidden Team',
             'Tiger Woods', 'Viktor Hovland', 'Patrick Cantlay', 'Cameron Smith', 'Tommy Fleetwood'],
        )
        db.commit()

        resp = auth_client.get('/')
        assert resp.status_code == 200
        # Should show user's entry info but not the full leaderboard
        assert b'Your Picks Are In' in resp.data
        assert b'Hidden Team' in resp.data
        assert b'Change Your Picks' in resp.data

    def test_leaderboard_shows_make_picks_cta_when_no_entry(self, auth_client, seed_tournament):
        """Leaderboard should show CTA to make picks when user has no entry."""
        resp = auth_client.get('/')
        assert resp.status_code == 200
        assert b'Tournament is open for picks' in resp.data
        assert b'Make Your Picks' in resp.data

    def test_leaderboard_shows_entries_when_locked(self, app_instance, db, auth_client, seed_tournament):
        """Leaderboard should show full results when picks are locked."""
        user_id = db.execute("SELECT id FROM users WHERE email = 'user@test.com'").fetchone()[0]
        # Add golfers needed for the entry
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            gid = secrets.token_hex(16)
            db.execute(
                "INSERT INTO golfers (id, tournament_id, name, external_id, total_score, score_display, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [gid, seed_tournament['id'], name, '0', -2, '-2', 'active'],
            )
        db.execute(
            "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
            "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [secrets.token_hex(16), user_id, seed_tournament['id'], 'Visible Team',
             'G1', 'G2', 'G3', 'G4', 'G5'],
        )
        db.execute("UPDATE tournaments SET picks_locked = 1 WHERE id = ?", [seed_tournament['id']])
        db.commit()

        resp = auth_client.get('/')
        assert resp.status_code == 200
        assert b'Visible Team' in resp.data
        assert b'Your Picks Are In' not in resp.data
