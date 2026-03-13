"""Tests for leaderboard computation, ranking, and player standings."""

import secrets

import app as app_module


def _insert_tournament(db, tid=None, active=True):
    tid = tid or secrets.token_hex(16)
    db.execute(
        "INSERT INTO tournaments (id, external_id, name, season_year, is_active) VALUES (?, ?, ?, ?, ?)",
        [tid, f'ext-{tid[:6]}', 'Test Open', 2026, 1 if active else 0],
    )
    db.commit()
    return tid


def _format_score(score):
    if score is None:
        return '--'
    if score == 0:
        return 'E'
    return f'+{score}' if score > 0 else str(score)


def _insert_golfer(db, tid, name, total_score, status='active'):
    gid = secrets.token_hex(16)
    display = _format_score(total_score)
    db.execute(
        "INSERT INTO golfers (id, tournament_id, name, external_id, total_score, score_display, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [gid, tid, name, '0', total_score, display, status],
    )
    db.commit()


def _insert_metadata(db, tid, cut_line):
    db.execute(
        "INSERT INTO tournament_metadata (tournament_id, cut_line) VALUES (?, ?)",
        [tid, cut_line],
    )
    db.commit()


def _insert_entry(db, tid, user_id, entry_name, golfers):
    eid = secrets.token_hex(16)
    db.execute(
        "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
        "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [eid, user_id, tid, entry_name] + golfers,
    )
    db.commit()


def _insert_user(db, email, first_name='Test', last_name='User'):
    uid = secrets.token_hex(16)
    db.execute(
        "INSERT INTO users (id, email, display_name, first_name, last_name) VALUES (?, ?, ?, ?, ?)",
        [uid, email, f'{first_name} {last_name}', first_name, last_name],
    )
    db.commit()
    return uid


class TestComputeLeaderboard:
    def test_empty_entries(self, app_instance, db):
        tid = _insert_tournament(db)
        with app_instance.app_context():
            results, metadata = app_module.compute_leaderboard(tid)
        assert results == []

    def test_single_entry_score(self, app_instance, db):
        tid = _insert_tournament(db)
        uid = _insert_user(db, 'a@test.com', 'Alice', 'Smith')
        names = ['G1', 'G2', 'G3', 'G4', 'G5']
        scores = [-5, -3, 0, 2, 4]
        for name, score in zip(names, scores):
            _insert_golfer(db, tid, name, score)
        _insert_entry(db, tid, uid, 'Team A', names)

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        assert len(results) == 1
        assert results[0]['team_score'] == sum(scores)  # -2
        assert results[0]['rank'] == 1

    def test_missing_golfer_gets_999(self, app_instance, db):
        tid = _insert_tournament(db)
        uid = _insert_user(db, 'b@test.com')
        _insert_golfer(db, tid, 'G1', -5)
        _insert_golfer(db, tid, 'G2', -3)
        _insert_golfer(db, tid, 'G3', 0)
        _insert_golfer(db, tid, 'G4', 2)
        # G5 does NOT exist — should get 999 penalty
        _insert_entry(db, tid, uid, 'Team B', ['G1', 'G2', 'G3', 'G4', 'Missing'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        assert results[0]['team_score'] == -5 + -3 + 0 + 2 + 999

    def test_sorted_by_score_ascending(self, app_instance, db):
        tid = _insert_tournament(db)
        for name in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']:
            _insert_golfer(db, tid, name, 0)

        uid1 = _insert_user(db, 'c@test.com')
        uid2 = _insert_user(db, 'd@test.com')
        _insert_golfer(db, tid, 'High1', 10)
        _insert_golfer(db, tid, 'Low1', -10)

        _insert_entry(db, tid, uid1, 'Worse', ['High1', 'A', 'B', 'C', 'D'])
        _insert_entry(db, tid, uid2, 'Better', ['Low1', 'A', 'B', 'C', 'D'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        assert results[0]['entry_name'] == 'Better'
        assert results[1]['entry_name'] == 'Worse'

    def test_tied_scores_same_rank(self, app_instance, db):
        tid = _insert_tournament(db)
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 0)

        uid1 = _insert_user(db, 'e@test.com')
        uid2 = _insert_user(db, 'f@test.com')
        _insert_entry(db, tid, uid1, 'T1', ['G1', 'G2', 'G3', 'G4', 'G5'])
        _insert_entry(db, tid, uid2, 'T2', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        assert results[0]['rank'] == 1
        assert results[1]['rank'] == 1


class TestOwnerNameFormatting:
    def test_first_and_last(self, app_instance, db):
        tid = _insert_tournament(db)
        uid = _insert_user(db, 'g@test.com', 'Cullin', 'Tripp')
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 0)
        _insert_entry(db, tid, uid, 'Team C', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        assert results[0]['owner_name'] == 'Cullin T.'

    def test_first_only(self, app_instance, db):
        tid = _insert_tournament(db)
        uid = _insert_user(db, 'h@test.com', 'Madonna', '')
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 0)
        _insert_entry(db, tid, uid, 'Team D', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        assert results[0]['owner_name'] == 'Madonna'

    def test_no_name(self, app_instance, db):
        tid = _insert_tournament(db)
        uid = secrets.token_hex(16)
        db.execute(
            "INSERT INTO users (id, email, display_name) VALUES (?, ?, ?)",
            [uid, 'i@test.com', 'legacy'],
        )
        db.commit()
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 0)
        _insert_entry(db, tid, uid, 'Team E', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        assert results[0]['owner_name'] == ''


class TestComputePlayerStandings:
    def test_selections_mapped(self, app_instance, db):
        tid = _insert_tournament(db)
        uid = _insert_user(db, 'j@test.com')
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 0)
        _insert_entry(db, tid, uid, 'Selectors', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            golfers = app_module.compute_player_standings(tid)

        g1 = next(g for g in golfers if g['name'] == 'G1')
        assert 'Selectors' in g1['selections']


class TestApplyCutModifier:
    """Unit tests for apply_cut_modifier()."""

    def test_missed_cut_returns_cut_line_plus_one(self):
        # cut_line=1 means +1 makes the cut; missed → +2
        assert app_module.apply_cut_modifier(7, 'cut', 1) == 2

    def test_made_cut_over_cap(self):
        # Cut line +1, golfer at +3 → capped at cut_line = 1
        assert app_module.apply_cut_modifier(3, 'active', 1) == 1

    def test_made_cut_under_par(self):
        # Under par is better than cap — use actual score
        assert app_module.apply_cut_modifier(-2, 'active', 1) == -2

    def test_made_cut_at_cap_exactly(self):
        # Score equals cut_line - 1 → no change
        assert app_module.apply_cut_modifier(0, 'active', 1) == 0

    def test_none_cut_line_passthrough(self):
        assert app_module.apply_cut_modifier(5, 'active', None) == 5

    def test_none_score_passthrough(self):
        assert app_module.apply_cut_modifier(None, 'active', 1) is None

    def test_negative_cut_line(self):
        # Cut at -1: missed → 0 (cut_line+1), made at +2 → -1 (cut_line)
        assert app_module.apply_cut_modifier(2, 'cut', -1) == 0
        assert app_module.apply_cut_modifier(2, 'active', -1) == -1

    def test_complete_status_treated_as_made_cut(self):
        assert app_module.apply_cut_modifier(3, 'complete', 1) == 1


class TestCutLineModifier:
    """Integration tests: cut modifier through compute_leaderboard()."""

    def test_missed_cut_team_score(self, app_instance, db):
        tid = _insert_tournament(db)
        _insert_metadata(db, tid, 1)
        uid = _insert_user(db, 'cut1@test.com')
        # All 5 golfers missed cut — each gets cut_line + 1 = 2
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 5, status='cut')
        _insert_entry(db, tid, uid, 'Cut Team', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        # Each golfer: cut_line + 1 = 2, so 5 * 2 = 10
        assert results[0]['team_score'] == 10

    def test_made_cut_capped_score(self, app_instance, db):
        tid = _insert_tournament(db)
        _insert_metadata(db, tid, 1)
        uid = _insert_user(db, 'cut2@test.com')
        # 5 golfers who made cut but finished over par
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 3, status='active')
        _insert_entry(db, tid, uid, 'Cap Team', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        # Each capped at cut_line = 1, so 5 * 1 = 5
        assert results[0]['team_score'] == 5

    def test_under_par_actual_score_used(self, app_instance, db):
        tid = _insert_tournament(db)
        _insert_metadata(db, tid, 1)
        uid = _insert_user(db, 'cut3@test.com')
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, -4, status='complete')
        _insert_entry(db, tid, uid, 'Under Par', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        # -4 < 1 (cut_line), so actual score used: 5 * -4 = -20
        assert results[0]['team_score'] == -20

    def test_no_metadata_no_modifier(self, app_instance, db):
        tid = _insert_tournament(db)
        # No metadata inserted
        uid = _insert_user(db, 'cut4@test.com')
        for name in ['G1', 'G2', 'G3', 'G4', 'G5']:
            _insert_golfer(db, tid, name, 5, status='cut')
        _insert_entry(db, tid, uid, 'No Meta', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        # No cut_line → raw scores used: 5 * 5 = 25
        assert results[0]['team_score'] == 25

    def test_missing_golfer_still_gets_999(self, app_instance, db):
        tid = _insert_tournament(db)
        _insert_metadata(db, tid, 1)
        uid = _insert_user(db, 'cut5@test.com')
        for name in ['G1', 'G2', 'G3', 'G4']:
            _insert_golfer(db, tid, name, -2, status='active')
        _insert_entry(db, tid, uid, 'Missing', ['G1', 'G2', 'G3', 'G4', 'Gone'])

        with app_instance.app_context():
            results, _ = app_module.compute_leaderboard(tid)

        # 4 golfers at -2 (under cap, actual used) + 999 for missing
        assert results[0]['team_score'] == 4 * -2 + 999
