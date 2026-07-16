# Data Golf Hot-Fix for The Open Championship 2026

**Date:** 2026-07-16
**Status:** Approved design → implementation
**Author:** Cullin + Claude

## Problem

The Slash Golf API (`live-golf-data.p.rapidapi.com`), the app's sole golfer-score
data source, was disabled by the provider mid-tournament. Every endpoint returns:

```
HTTP 405 {"message":"The API provider has disabled request access to the API..."}
```

As a result, `refresh_golfers_from_api()` fails on every call, `last_api_update`
is frozen at `2026-07-15 11:37 UTC`, and The Open Championship leaderboard shows
no live scores. The Open's 156 golfer rows currently have `total_score = NULL`
(status "not started") — they were never refreshed before the API died.

## Goal

Restore live scoring for The Open Championship using the Data Golf API, as a
**minimally invasive, single-season stopgap**. The wiring must be trivial to
remove next season, when a permanent (cheaper) data source will be chosen.

## Constraints & Key Facts

- **Picks are matched to golfers by exact name string** (`compute_leaderboard`
  does `golfers.get(pick)`). Both `entries.golfer_1..5` and `golfers.name` are
  stored as `"First Last"` (e.g. `Scottie Scheffler`).
- **Data Golf returns `"Last, First"`** (e.g. `Scheffler, Scottie`). Names must be
  flipped and normalized before matching.
- The refresh must **UPDATE existing golfer rows in place**, never INSERT — an
  INSERT with a differently-formatted name would create duplicate rows and make
  every pick score 999 ("not found").
- Verified against live data (2026-07-16): **152 of 156 names auto-match**, and
  **all 29 distinct picked golfers match**. The 4 unmatched are non-picked
  nickname/spelling variants, handled by a small alias map.
- Data Golf has **no numeric cut-line field** in any endpoint (verified against
  docs + full field enumeration of `/preds/in-play` and
  `/preds/live-tournament-stats`). Only `make_cut` (a probability) exists.

## Decisions

| Decision | Choice |
|---|---|
| Automation | Auto via existing 5-min cron (route The Open through Data Golf) |
| Gating | Hardcode The Open only (`external_id == '100'`); all other paths untouched |
| Cut line | Derive from field: `max(current_score)` among players who made the cut |

## Design

### Data source

`GET https://feeds.datagolf.com/preds/in-play?tour=pga&file_format=json&key=<DG_API_KEY>`

Returns `{info: {...}, data: [ ...156 players... ]}`. Relevant per-player fields:
`player_name` (`"Last, First"`), `current_pos` (`"T13"`, `"1"`, `"CUT"`),
`current_score` (int total), `today` (int, current round), `thru`, `round`.
`info.event_name` = `"The Open Championship"`, `info.current_round`.

### New function: `refresh_golfers_from_datagolf(tournament_id, external_id, year)`

Sits beside `refresh_golfers_from_api()`, writes to the same `golfers` table and
`tournament_metadata`. Steps:

1. Fetch the in-play feed. On network/HTTP/parse error → log, return `False`.
2. **Wrong-event guard:** if `"open championship"` not in `info.event_name`
   (lowercased) → log a warning and return `False`. Prevents clobbering The Open's
   board if the PGA feed has rolled to a different event.
3. Build `{normalized_name → actual_db_name}` from the tournament's existing rows.
   Overlay `DG_NAME_ALIASES` (4 hardcoded variants) onto the lookup.
4. For each Data Golf player:
   - Flip `"Last, First"` → `"First Last"` (`_datagolf_flip_name`).
   - Normalize via existing `_normalize_golfer_name`.
   - Resolve to an existing DB row name. If unmatched → skip + log (never INSERT).
   - **UPDATE** the row: `position`, `total_score`, `score_display`,
     `current_round_score`, `round_number`, `thru`, `status`, `last_updated`.
5. **Cut line:** if any player has `current_pos == "CUT"`, set
   `cut_line = max(current_score)` over players whose `current_pos != "CUT"` and
   `current_score is not None`. Otherwise `cut_line = None`.
6. Upsert `tournament_metadata` with the cut line, `last_api_update = now`,
   `api_status = 'success'`. Commit. Return `True`.

### Field mapping

| Data Golf | golfers column | Transform |
|---|---|---|
| `current_score` | `total_score` | int; `None` → `None` (not started) |
| `current_score` | `score_display` | `E` (0) / `-2` / `+3` / `--` (None) |
| `today` | `current_round_score` | same display format |
| `current_pos` | `position` | as-is string |
| `round` | `round_number` | int |
| `thru` | `thru` | str(value) |
| `current_pos == "CUT"` | `status` | `'cut'`, else `'active'`, else `'not started'` |

`tee_time` is not provided by this endpoint and is left unchanged.

### Status inference

- `current_pos == "CUT"` → `status = 'cut'`
- else if `current_score is None` and not yet started → `status = 'not started'`
- else → `status = 'active'`

Only `'cut'` is load-bearing (drives `apply_cut_modifier`); the rest is display.

### The gate

Single branch at the top of `refresh_golfers_from_api()`, covering all three
callers (cron endpoint, admin manual refresh, tournament activation):

```python
# The Open Championship 2026: Slash Golf API disabled by provider mid-tournament.
# Temporary Data Golf source — remove this whole branch next season.
if tournament_external_id == '100':
    return refresh_golfers_from_datagolf(tournament_id, tournament_external_id, year)
```

### Config

- `DATAGOLF_BASE_URL = "https://feeds.datagolf.com"` constant.
- Read `DG_API_KEY` from env (already in local `.env`).

### Helpers added

- `_datagolf_flip_name(name)` — `"Last, First"` → `"First Last"`.
- `DG_NAME_ALIASES` — dict mapping the 4 known Data-Golf-normalized names to the
  existing DB golfer names.
- Small inline score-display formatter (`E`/`+N`/`-N`/`--`).

## Error Handling

- Any failure (network, HTTP, parse, wrong event) → log + return `False` →
  endpoint returns 502, board holds last-good data. `last_api_update` only
  advances on success, so a Data Golf outage looks like the current frozen state
  rather than wiping scores.
- Unmatched players are skipped, never inserted.

## Testing

- **Unit test** (no network): `_datagolf_flip_name` and name-resolution + alias
  logic against a fixture of Data Golf names → expected DB names.
- **Dry-run script** against live Data Golf: reads the feed, prints the mapped
  scores per golfer and any unmatched names, writes nothing. Eyeball before the
  first real refresh.
- **One real refresh** via the admin refresh path, then spot-check the leaderboard
  and `/players` page against Data Golf's live board.

## Deployment

- **Set `DG_API_KEY` in DigitalOcean App Platform env vars** — the production cron
  calls the deployed app, which needs the key to authenticate to Data Golf.
  Without it the refresh returns `False` and the board stays frozen.

## Removal (next season)

Delete `refresh_golfers_from_datagolf`, the gate branch, `_datagolf_flip_name`,
`DG_NAME_ALIASES`, `DATAGOLF_BASE_URL`, and the `DG_API_KEY` env var. The original
`refresh_golfers_from_api` Slash Golf path is untouched underneath.
