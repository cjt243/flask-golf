"""Tests for season standings page and computation."""

import secrets

import pytest

import app as app_module
from tests.conftest import _create_user, _create_session


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear app cache before each test."""
    app_module._cache.clear()
    yield
    app_module._cache.clear()


def _insert_tournament(db, tid=None, name='Test Open', season_year=2026, active=False, picks_locked=True):
    tid = tid or secrets.token_hex(16)
    db.execute(
        "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [tid, f'ext-{tid[:6]}', name, season_year, 1 if active else 0, 1 if picks_locked else 0],
    )
    db.commit()
    return tid


def _format_score(score):
    if score is None:
        return '--'
    if score == 0:
        return 'E'
    return f'+{score}' if score > 0 else str(score)


def _insert_golfer(db, tid, name, total_score, status='active', position='1', dk_salary=5000):
    gid = secrets.token_hex(16)
    db.execute(
        "INSERT INTO golfers (id, tournament_id, name, external_id, total_score, "
        "score_display, status, position, dk_salary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [gid, tid, name, '0', total_score, _format_score(total_score), status, position, dk_salary],
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


def _insert_metadata(db, tid, cut_line):
    db.execute(
        "INSERT INTO tournament_metadata (tournament_id, cut_line) VALUES (?, ?)",
        [tid, cut_line],
    )
    db.commit()


class TestStandingsRoute:
    def test_requires_login(self, client):
        resp = client.get('/standings')
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

    def test_empty_season(self, auth_client):
        resp = auth_client.get('/standings')
        assert resp.status_code == 200
        assert b'No Completed Tournaments' in resp.data

    def test_standings_with_data(self, app_instance, db):
        user_id = _create_user(db, 'player@test.com', 'Alice', 'Smith')
        raw_token = _create_session(db, user_id)

        tid = _insert_tournament(db, picks_locked=True)
        golfer_names = ['G1', 'G2', 'G3', 'G4', 'G5']
        scores = [-5, -3, 0, 2, 4]
        for i, (name, score) in enumerate(zip(golfer_names, scores)):
            _insert_golfer(db, tid, name, score, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, user_id, 'Team Alice', golfer_names)

        c = app_instance.test_client()
        c.set_cookie('golf_session', raw_token, domain='localhost')
        resp = c.get('/standings')
        assert resp.status_code == 200
        assert b'Alice S.' in resp.data
        assert b'Standings' in resp.data

    def test_standings_tab_content(self, app_instance, db):
        user_id = _create_user(db, 'player2@test.com', 'Bob', 'Jones')
        raw_token = _create_session(db, user_id)

        tid = _insert_tournament(db, picks_locked=True)
        golfer_names = ['G1', 'G2', 'G3', 'G4', 'G5']
        for i, name in enumerate(golfer_names):
            _insert_golfer(db, tid, name, i - 2, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, user_id, 'Team Bob', golfer_names)

        c = app_instance.test_client()
        c.set_cookie('golf_session', raw_token, domain='localhost')
        resp = c.get('/standings')
        assert resp.status_code == 200
        # Has standings and selection stats tabs
        assert b'Selection Stats' in resp.data
        assert b'Cut Stats' in resp.data
        assert b'Most Picked Golfers' in resp.data


class TestComputeSeasonStandings:
    def test_empty_season(self, app_instance, db):
        with app_instance.app_context():
            standings, stats, _ = app_module.compute_season_standings(2026)
        assert standings == []
        assert stats['most_picked'] == []

    def test_unlocked_tournaments_excluded(self, app_instance, db):
        _insert_tournament(db, picks_locked=False)
        with app_instance.app_context():
            standings, stats, _ = app_module.compute_season_standings(2026)
        assert standings == []

    def test_single_tournament_standings(self, app_instance, db):
        uid = _create_user(db, 'a@test.com', 'Alice', 'Smith')
        tid = _insert_tournament(db, picks_locked=True)

        golfer_names = ['G1', 'G2', 'G3', 'G4', 'G5']
        scores = [-5, -3, 0, 2, 4]
        for i, (name, score) in enumerate(zip(golfer_names, scores)):
            _insert_golfer(db, tid, name, score, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, uid, 'Team Alice', golfer_names)

        with app_instance.app_context():
            standings, stats, _ = app_module.compute_season_standings(2026)

        assert len(standings) == 1
        s = standings[0]
        assert s['first_name'] == 'Alice'
        assert s['tournaments_played'] == 1
        assert s['cumulative_score'] == -2  # -5 + -3 + 0 + 2 + 4
        assert s['avg_score'] == -2.0
        assert s['cuts_made'] == 5
        assert s['cuts_missed'] == 0
        assert s['cut_pct'] == 100.0

    def test_profit_calculation(self, app_instance, db):
        uid = _create_user(db, 'b@test.com', 'Bob', 'Jones')
        tid = _insert_tournament(db, picks_locked=True)

        golfer_names = ['G1', 'G2', 'G3', 'G4', 'G5']
        for i, name in enumerate(golfer_names):
            _insert_golfer(db, tid, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, uid, 'Team Bob', golfer_names)

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        # Only entry so Bob wins. Pot = 1 * $5 = $5, per_winner = $5.
        # Profit = $5 - $5 = $0
        assert standings[0]['profit'] == 0

    def test_cut_tracking(self, app_instance, db):
        uid = _create_user(db, 'c@test.com', 'Carol', 'White')
        tid = _insert_tournament(db, picks_locked=True)

        _insert_golfer(db, tid, 'G1', -5, status='active', position='1', dk_salary=10000)
        _insert_golfer(db, tid, 'G2', -3, status='active', position='2', dk_salary=9000)
        _insert_golfer(db, tid, 'G3', 0, status='active', position='10', dk_salary=8000)
        _insert_golfer(db, tid, 'G4', 3, status='cut', position='', dk_salary=7000)
        _insert_golfer(db, tid, 'G5', 5, status='cut', position='', dk_salary=6000)
        _insert_metadata(db, tid, 2)
        _insert_entry(db, tid, uid, 'Team Carol', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        assert standings[0]['cuts_made'] == 3
        assert standings[0]['cuts_missed'] == 2
        assert standings[0]['cut_pct'] == 60.0

    def test_selection_stats_most_picked(self, app_instance, db):
        uid1 = _create_user(db, 'd@test.com', 'Dan', 'Lee')
        uid2 = _create_user(db, 'e@test.com', 'Eve', 'Park')
        tid = _insert_tournament(db, picks_locked=True)

        for i, name in enumerate(['G1', 'G2', 'G3', 'G4', 'G5', 'G6']):
            _insert_golfer(db, tid, name, i - 3, position=str(i + 1), dk_salary=10000 - i * 1000)

        _insert_entry(db, tid, uid1, 'Team Dan', ['G1', 'G2', 'G3', 'G4', 'G5'])
        _insert_entry(db, tid, uid2, 'Team Eve', ['G1', 'G3', 'G4', 'G5', 'G6'])

        with app_instance.app_context():
            _, stats, _ = app_module.compute_season_standings(2026)

        # G1, G3, G4, G5 picked twice; G2, G6 picked once
        most_picked = stats['most_picked']
        top = [g for g in most_picked if g['count'] == 2]
        assert len(top) == 4

    def test_tier_best_performances(self, app_instance, db):
        uid = _create_user(db, 'f@test.com', 'Fay', 'Kim')
        tid = _insert_tournament(db, picks_locked=True)

        _insert_golfer(db, tid, 'G1', -8, position='1', dk_salary=10000)
        _insert_golfer(db, tid, 'G2', -4, position='5', dk_salary=9000)
        _insert_golfer(db, tid, 'G3', -2, position='10', dk_salary=8000)
        _insert_golfer(db, tid, 'G4', 1, position='20', dk_salary=7000)
        _insert_golfer(db, tid, 'G5', 3, position='30', dk_salary=6000)
        _insert_entry(db, tid, uid, 'Team Fay', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            _, stats, _ = app_module.compute_season_standings(2026)

        # G1 is tier 1 (golfer_1), G2/G3 tier 2, G4/G5 tier 3
        # Tier best stores combined tier totals with golfers list and teams list
        assert len(stats['tier_best'][1]) >= 1
        assert stats['tier_best'][1][0]['score'] == -8  # T1: just G1
        assert stats['tier_best'][1][0]['golfers'] == ['G1']
        assert stats['tier_best'][1][0]['teams'] == ['Fay K.']
        assert stats['tier_best'][2][0]['score'] == -6  # T2: G2(-4) + G3(-2)
        assert stats['tier_best'][2][0]['golfers'] == ['G2', 'G3']
        assert stats['tier_best'][3][0]['score'] == 4   # T3: G4(1) + G5(3)

    def test_sort_order_wins_first(self, app_instance, db):
        uid1 = _create_user(db, 'g@test.com', 'Gina', 'Adams')
        uid2 = _create_user(db, 'h@test.com', 'Hank', 'Brown')

        # Tournament 1: both enter, Gina wins (lower score)
        tid1 = _insert_tournament(db, tid='t1', name='T1', picks_locked=True)
        _insert_golfer(db, tid1, 'A1', -10, position='1', dk_salary=10000)
        _insert_golfer(db, tid1, 'A2', -5, position='2', dk_salary=9000)
        _insert_golfer(db, tid1, 'A3', -3, position='3', dk_salary=8000)
        _insert_golfer(db, tid1, 'A4', -1, position='4', dk_salary=7000)
        _insert_golfer(db, tid1, 'A5', 0, position='5', dk_salary=6000)
        _insert_golfer(db, tid1, 'B1', 1, position='6', dk_salary=5000)
        _insert_golfer(db, tid1, 'B2', 2, position='7', dk_salary=4000)
        _insert_golfer(db, tid1, 'B3', 3, position='8', dk_salary=3000)
        _insert_golfer(db, tid1, 'B4', 4, position='9', dk_salary=2000)
        _insert_golfer(db, tid1, 'B5', 5, position='10', dk_salary=1000)
        _insert_entry(db, tid1, uid1, 'Team Gina', ['A1', 'A2', 'A3', 'A4', 'A5'])
        _insert_entry(db, tid1, uid2, 'Team Hank', ['B1', 'B2', 'B3', 'B4', 'B5'])

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        # Gina has 1 win, Hank has 0 — Gina should be first even though
        # profit could be equal. Wins is the primary sort key.
        assert standings[0]['first_name'] == 'Gina'
        assert standings[0]['wins'] == 1
        assert standings[1]['first_name'] == 'Hank'
        assert standings[1]['wins'] == 0
