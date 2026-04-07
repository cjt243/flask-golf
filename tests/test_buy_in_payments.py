"""Tests for configurable buy-in, payment tracking, and refresh interval."""

import secrets

import app as app_module
from tests.conftest import _create_user, _create_session, get_csrf_token


def _insert_tournament(db, tid=None, name='Test Open', season_year=2026,
                       picks_locked=True, buy_in=5):
    tid = tid or secrets.token_hex(16)
    db.execute(
        "INSERT INTO tournaments (id, external_id, name, season_year, is_active, picks_locked, buy_in) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        [tid, f'ext-{tid[:6]}', name, season_year, 1 if picks_locked else 0, buy_in],
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


def _insert_entry(db, tid, user_id, entry_name, golfers, paid=0):
    eid = secrets.token_hex(16)
    db.execute(
        "INSERT INTO entries (id, user_id, tournament_id, entry_name, "
        "golfer_1, golfer_2, golfer_3, golfer_4, golfer_5, paid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [eid, user_id, tid, entry_name] + golfers + [paid],
    )
    db.commit()
    return eid


class TestComputeTournamentWinnersBuyIn:
    def test_default_buy_in_pot(self, app_instance, db):
        """Default $5 buy-in: 2 entries → $10 pot."""
        uid1 = _create_user(db, 'a@test.com', 'Alice', 'A')
        uid2 = _create_user(db, 'b@test.com', 'Bob', 'B')
        tid = _insert_tournament(db, buy_in=5, picks_locked=True)

        for i, name in enumerate(['G1', 'G2', 'G3', 'G4', 'G5']):
            _insert_golfer(db, tid, name, i - 2, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, uid1, 'Team A', ['G1', 'G2', 'G3', 'G4', 'G5'])
        _insert_entry(db, tid, uid2, 'Team B', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            result = app_module.compute_tournament_winners(tid)

        assert result['pot'] == 10
        assert result['buy_in'] == 5

    def test_custom_buy_in_pot(self, app_instance, db):
        """$10 buy-in: 3 entries → $30 pot."""
        uids = [_create_user(db, f'{c}@test.com', c, 'X') for c in ['C', 'D', 'E']]
        tid = _insert_tournament(db, buy_in=10, picks_locked=True)

        for i, name in enumerate(['G1', 'G2', 'G3', 'G4', 'G5']):
            _insert_golfer(db, tid, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        for uid in uids:
            _insert_entry(db, tid, uid, f'Team {uid[:4]}', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            result = app_module.compute_tournament_winners(tid)

        assert result['pot'] == 30
        assert result['per_winner'] == 10.0  # 3-way tie, $30 / 3
        assert result['buy_in'] == 10


class TestSeasonStandingsBuyIn:
    def test_profit_with_custom_buy_in(self, app_instance, db):
        """Profit uses tournament buy_in, not hardcoded $5."""
        uid = _create_user(db, 'f@test.com', 'Fay', 'Z')
        tid = _insert_tournament(db, buy_in=10, picks_locked=True)

        for i, name in enumerate(['G1', 'G2', 'G3', 'G4', 'G5']):
            _insert_golfer(db, tid, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, uid, 'Team Fay', ['G1', 'G2', 'G3', 'G4', 'G5'])

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        # Solo entry wins: pot = $10, winnings = $10, cost = $10 → profit = $0
        assert standings[0]['profit'] == 0

    def test_profit_mixed_buy_ins(self, app_instance, db):
        """Mixed buy-ins across tournaments computed correctly."""
        uid = _create_user(db, 'g@test.com', 'Gina', 'Y')

        # Tournament 1: $5 buy-in
        tid1 = _insert_tournament(db, tid='t1mix', name='T1', buy_in=5, picks_locked=True)
        for i, name in enumerate(['A1', 'A2', 'A3', 'A4', 'A5']):
            _insert_golfer(db, tid1, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid1, uid, 'Team G1', ['A1', 'A2', 'A3', 'A4', 'A5'])

        # Tournament 2: $10 buy-in
        tid2 = _insert_tournament(db, tid='t2mix', name='T2', buy_in=10, picks_locked=True)
        for i, name in enumerate(['B1', 'B2', 'B3', 'B4', 'B5']):
            _insert_golfer(db, tid2, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid2, uid, 'Team G2', ['B1', 'B2', 'B3', 'B4', 'B5'])

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        # Wins both (sole entry). Winnings = $5 + $10 = $15. Cost = $5 + $10 = $15. Profit = $0
        assert standings[0]['profit'] == 0


class TestOwedCalculation:
    def test_all_unpaid(self, app_instance, db):
        """Unpaid entries show full owed amount."""
        uid = _create_user(db, 'h@test.com', 'Hank', 'W')
        tid = _insert_tournament(db, buy_in=10, picks_locked=True)

        for i, name in enumerate(['G1', 'G2', 'G3', 'G4', 'G5']):
            _insert_golfer(db, tid, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, uid, 'Team H', ['G1', 'G2', 'G3', 'G4', 'G5'], paid=0)

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        assert standings[0]['owed'] == 10

    def test_paid_entry_no_owed(self, app_instance, db):
        """Paid entries show $0 owed."""
        uid = _create_user(db, 'i@test.com', 'Ivy', 'V')
        tid = _insert_tournament(db, buy_in=5, picks_locked=True)

        for i, name in enumerate(['G1', 'G2', 'G3', 'G4', 'G5']):
            _insert_golfer(db, tid, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid, uid, 'Team I', ['G1', 'G2', 'G3', 'G4', 'G5'], paid=1)

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        assert standings[0]['owed'] == 0

    def test_mixed_paid_unpaid(self, app_instance, db):
        """Owed sums only unpaid tournaments."""
        uid = _create_user(db, 'j@test.com', 'Jack', 'U')

        tid1 = _insert_tournament(db, tid='t1owed', name='T1', buy_in=5, picks_locked=True)
        for i, name in enumerate(['C1', 'C2', 'C3', 'C4', 'C5']):
            _insert_golfer(db, tid1, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid1, uid, 'Team J1', ['C1', 'C2', 'C3', 'C4', 'C5'], paid=1)

        tid2 = _insert_tournament(db, tid='t2owed', name='T2', buy_in=10, picks_locked=True)
        for i, name in enumerate(['D1', 'D2', 'D3', 'D4', 'D5']):
            _insert_golfer(db, tid2, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        _insert_entry(db, tid2, uid, 'Team J2', ['D1', 'D2', 'D3', 'D4', 'D5'], paid=0)

        with app_instance.app_context():
            standings, _, _ = app_module.compute_season_standings(2026)

        # T1 paid, T2 unpaid → owed = $10
        assert standings[0]['owed'] == 10


class TestAdminPaymentRoutes:
    def test_toggle_paid(self, app_instance, db, admin_client):
        """Toggle paid status for an entry."""
        uid = db.execute("SELECT id FROM users WHERE email = 'admin@test.com'").fetchone()[0]
        tid = _insert_tournament(db, buy_in=5)
        for i, name in enumerate(['G1', 'G2', 'G3', 'G4', 'G5']):
            _insert_golfer(db, tid, name, i, position=str(i + 1), dk_salary=10000 - i * 1000)
        eid = _insert_entry(db, tid, uid, 'Team Admin', ['G1', 'G2', 'G3', 'G4', 'G5'], paid=0)

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/toggle-paid', data={
            'csrf_token': token,
            'entry_id': eid,
        })
        assert resp.status_code == 302

        row = db.execute("SELECT paid FROM entries WHERE id = ?", [eid]).fetchone()
        assert row[0] == 1

        # Toggle back
        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/toggle-paid', data={
            'csrf_token': token,
            'entry_id': eid,
        })
        assert resp.status_code == 302

        row = db.execute("SELECT paid FROM entries WHERE id = ?", [eid]).fetchone()
        assert row[0] == 0

    def test_payments_page_loads(self, admin_client):
        resp = admin_client.get('/admin/payments')
        assert resp.status_code == 200
        assert b'Payments' in resp.data

    def test_payments_requires_admin(self, auth_client):
        resp = auth_client.get('/admin/payments')
        assert resp.status_code == 403


class TestAdminBuyInRoute:
    def test_update_buy_in(self, app_instance, db, admin_client):
        tid = _insert_tournament(db, buy_in=5)

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/update-buy-in', data={
            'csrf_token': token,
            'tournament_id': tid,
            'buy_in': '10',
        })
        assert resp.status_code == 302

        row = db.execute("SELECT buy_in FROM tournaments WHERE id = ?", [tid]).fetchone()
        assert row[0] == 10

    def test_invalid_buy_in_rejected(self, app_instance, db, admin_client):
        tid = _insert_tournament(db, buy_in=5)

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/update-buy-in', data={
            'csrf_token': token,
            'tournament_id': tid,
            'buy_in': '20',
        })
        assert resp.status_code == 302

        row = db.execute("SELECT buy_in FROM tournaments WHERE id = ?", [tid]).fetchone()
        assert row[0] == 5  # Unchanged


class TestAdminRefreshIntervalRoute:
    def test_update_refresh_interval(self, app_instance, db, admin_client):
        tid = _insert_tournament(db)

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/update-refresh-interval', data={
            'csrf_token': token,
            'tournament_id': tid,
            'refresh_interval_minutes': '5',
        })
        assert resp.status_code == 302

        row = db.execute("SELECT refresh_interval_minutes FROM tournaments WHERE id = ?", [tid]).fetchone()
        assert row[0] == 5

    def test_invalid_interval_rejected(self, app_instance, db, admin_client):
        tid = _insert_tournament(db)

        token = get_csrf_token(admin_client)
        resp = admin_client.post('/admin/update-refresh-interval', data={
            'csrf_token': token,
            'tournament_id': tid,
            'refresh_interval_minutes': '7',
        })
        assert resp.status_code == 302

        row = db.execute("SELECT refresh_interval_minutes FROM tournaments WHERE id = ?", [tid]).fetchone()
        assert row[0] == 60  # Unchanged (default)
