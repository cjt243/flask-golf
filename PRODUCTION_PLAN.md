# Production Readiness Assessment: Flask Golf

## Context

Flask Golf is a single-file Flask app for a fantasy golf league ("80 Yard Bombs Cup"). It's deployed on DigitalOcean App Platform, uses Turso for data, Resend for email, and the Slash Golf API for scores. The app is functional — auth, picks, leaderboard, admin panel all work. This assessment identifies what's production-ready, what's missing, and what's ambiguous, organized into actionable work.

---

## What's Already Production-Ready

These features are implemented and solid:

- **Authentication**: Magic link flow with Argon2 token hashing, SHA-256 session tokens, 7-day expiry, proper cookie settings (HttpOnly, Secure, SameSite)
- **Authorization**: `@login_required`, `@admin_required` decorators, invite-only registration with admin approval
- **CSRF protection**: Per-session tokens, timing-safe comparison, applied to all POST routes
- **Rate limiting**: Database-backed, per-email and per-IP limits on magic links and access requests
- **Security headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **HTTPS enforcement**: Redirect via `X-Forwarded-Proto` in production
- **Security audit log**: All auth events logged to `security_events` table
- **Input validation**: Email validation via `email-validator`, entry name regex, HTML escaping
- **Core features**: Leaderboard, player standings, pick form with tier-based golfer selection, admin tournament management
- **Deployment config**: DigitalOcean App Platform spec, Gunicorn config, env var management
- **Registration toggle**: Admin can open/close registration (just implemented)
- **Email notifications**: Admin notified on new access requests, users notified on approval
- **Response compression**: Flask-Compress with Brotli

---

## What Needs Work Before Production

### P0 — Bugs & Security Fixes (do now)

1. **`/clear_cache` is unauthenticated** (`app.py:1716`)
   - Anyone can hit `GET /clear_cache` to flush the in-memory cache
   - Fix: Add `@admin_required` or remove the route entirely

2. **Procfile.txt has wrong module reference** (`Procfile.txt:1`)
   - Says `app.wsgi` but should be `app:app` (matches gunicorn_config and DO config)
   - Fix: `web: gunicorn --worker-tmp-dir /dev/shm --config gunicorn_config.py app:app`

3. **`FLASK_SECRET_KEY` auto-generates on startup if missing** (`app.py:39`)
   - Each Gunicorn worker gets a different key, breaking Flask sessions/CSRF
   - With 2 workers, users randomly get CSRF failures
   - Fix: Make it a hard requirement — fail fast if not set in production

4. **Bare `except:` clauses** (`app.py:1155`, `app.py:1223`)
   - Leaderboard/player date formatting uses bare `except:` which swallows all errors silently
   - Fix: Change to `except (ValueError, TypeError):`

5. **Remove unused `pandas`/`numpy` from `requirements.txt`**
   - Adds ~100MB to deploy image for no reason
   - Listed in CLAUDE.md TODOs as known issue

### P1 — Operational Readiness (do before real users)

6. **No proper logging** — all error handling uses `print()` statements
   - In Gunicorn these go to stdout/stderr, but without structure
   - Fix: Replace `print()` with Python `logging` module, add request ID, structured format
   - ~30 `print()` calls across app.py

7. **No database migration strategy**
   - `flask init-db` uses `CREATE TABLE IF NOT EXISTS` which won't add columns to existing tables
   - Just hit this with `app_settings` table (had to create it manually)
   - Fix: Either add a lightweight migration system (numbered SQL files) or use `flask-migrate`/Alembic

8. **Session cleanup not automated**
   - `flask cleanup-sessions` CLI command exists but isn't scheduled
   - Expired sessions/tokens accumulate in the DB forever
   - Fix: Add a cron job, or add cleanup logic to the `load_user` before_request (probabilistic cleanup, e.g. 1% of requests)

9. **No error alerting/monitoring**
   - If the app crashes or the API goes down, nobody knows
   - Fix: Add error tracking (Sentry free tier) or at minimum a health check monitor (UptimeRobot/similar)

10. **Golfer refresh is fully manual** (**elevated priority — automation needed**)
    - Admin must click "Refresh Golfers" to pull live scores
    - During a tournament, this needs to happen frequently and is not sustainable manually
    - Fix: Add a scheduled job. Options: DO scheduled function calling a refresh endpoint, a background thread with `APScheduler`, or an external cron hitting a protected `/admin/auto-refresh` endpoint
    - Needs a protected endpoint (API key or admin auth) that triggers `refresh_golfers_from_api()` for the active tournament

### P2 — Quality & Polish (do soon after launch)

11. **No test suite**
    - Zero tests, no test framework configured
    - Fix: Add pytest + basic test fixtures. Priority tests:
      - Auth flow (magic link, session, logout)
      - Pick submission (validation, duplicate prevention)
      - Leaderboard computation
      - Admin routes (auth gates, tournament management)
      - Rate limiting

12. **`submit_success.html` missing nav bar**
    - No sign-out button, no way to navigate back except the "View Leaderboard" link
    - Listed in CLAUDE.md TODOs

13. **No admin link in nav bar**
    - Admin users must navigate to `/admin` directly
    - Fix: Add conditional "Admin" link in the nav bar when `user.is_admin`

14. **OWGR rank data not populated**
    - Pick form tiers depend on OWGR rank but the API doesn't reliably provide it
    - Current behavior: all golfers may end up in one tier
    - Fix: Find alternative OWGR data source, or redesign tier logic

15. **No favicon** — 404 on every page load (logged in CLAUDE.md)
    - Templates use inline SVG data URIs which works, but the browser still requests `/favicon.ico`
    - Fix: Add a static favicon or a route that returns the SVG

16. **In-memory cache not shared across workers**
    - With 2 Gunicorn workers, each has its own cache
    - Users may see stale data if their requests alternate between workers
    - Impact is low (5-minute TTL, read-only cache), but worth noting

### P3 — Nice to Have (future)

17. **Display name support** — column exists but never set or shown
18. **Multi-season archive view** — schema supports it, UI doesn't
19. **Email templates** — currently inline HTML strings in Python functions
20. **CI/CD pipeline** — no automated testing or deployment
21. **`next` parameter not used after login** — `login_required` passes `next=request.url` but `auth_verify` always redirects to `make_picks`

---

## UI/UX Review & Refresh

### Systemic Issues (affect all templates)

**S1. Generic typography — Inter everywhere**
- Every template loads `Inter` from Google Fonts. It's the most common "AI-generated UI" font choice and makes the app feel generic.
- Fix: Choose a distinctive display font for headings (e.g., a slab serif or condensed sans for the sports/league feel) paired with a clean body font. Golf/sports apps benefit from bold, confident type — think ESPN or The Athletic, not a SaaS dashboard.
- Affected files: all 10 templates

**S2. No shared layout / base template**
- Every template is a standalone HTML document with duplicated `<head>`, Tailwind config, color definitions, header, and nav bar.
- This means: every UI change requires editing 6+ files, styles drift between pages, and the nav bar is inconsistent across templates.
- Fix: Create a `base.html` Jinja2 template with `{% block content %}`. All pages extend it. Single source for nav, fonts, colors, footer.
- This is the single highest-leverage UI fix — it unblocks everything else.

**S3. Nav bar inconsistencies**
- `leaderboard.html`, `player_standings.html`, `pick_form.html`: Full nav with tabs + auth
- `check_email.html`, `error.html`: Partial nav (Leaderboard + Players links, no auth)
- `submit_success.html`: No nav bar at all
- `login.html`, `request_access.html`, `access_requested.html`: Brand header only, no nav
- `admin.html`: Separate admin header
- Fix: Unified nav via base template. Logged-in pages get full nav + auth. Public pages get brand + minimal nav. Admin gets admin badge in same nav.

**S4. No footer anywhere**
- No page has a footer. There's no copyright, no version indicator, no link back to admin for admins, no "powered by" or league context.
- Fix: Add a minimal footer to base template (season year, maybe a subtle brand mark).

**S5. Tailwind CDN in production**
- Every page loads `https://cdn.tailwindcss.com` which is the dev-only JIT compiler. Tailwind's docs explicitly say not to use this in production — it's slower, larger (~300KB), and adds a visible FOUC (flash of unstyled content) on each page load.
- Fix: Build a static CSS file with Tailwind CLI (`npx tailwindcss -o styles.css --minify`). Serve from a `/static` directory. This also means the inline `tailwind.config` can move to a build config.

**S6. Color palette is safe but flat**
- Green (#16a34a) + Gold (#fbbf24) + Gray-900 dark theme. It's functional but reads as a generic dark-mode dashboard. There's no texture, depth, or atmosphere.
- Fix: Add subtle visual depth — a noise texture overlay on the background, a gradient mesh on hero sections, or even a subtle golf-course green gradient. The gold is good for accents but currently underused.

### Per-Page Issues

**P1. Leaderboard (`leaderboard.html`) — the main event, needs the most polish**
- The card-based layout is good, but team scores lack context (no "+/- vs par" formatting, no "E" for even).
- The expand/collapse cards hide player details by default — on a leaderboard people want to see picks at a glance without clicking.
- Mobile: The nav tabs + auth + expand toggle crowd the header. On small screens the tab labels get squished.
- Player chips inside expanded cards are small and hard to tap on mobile.
- No visual distinction between "in contention" vs "way behind" entries. Could use subtle background tinting.
- The stagger animation on load (`data-delay`) adds up to noticeable delay with many entries.
- Fix: Consider a default-expanded view on desktop (collapse on mobile), score formatting with +/- and color coding per player, and a more compact mobile header.

**P2. Player Standings (`player_standings.html`) — data-heavy table**
- The sticky column approach is good for horizontal scroll, but the table is very wide with 9 columns. On mobile it's hard to use.
- Stats summary cards at the top are useful but "Total Teams Entered" requires complex Jinja logic in the template (iterating all results to count unique teams) — this should be computed server-side.
- The "Selected By" column with team chips is the most useful feature but it's the last column and gets scrolled off-screen.
- The legend section at the bottom is helpful for first-time users but takes up a lot of space.
- Fix: Move "Selected By" closer to the player name. Consider a card-based mobile layout instead of table. Compute stats server-side.

**P3. Pick Form (`pick_form.html`) — critical conversion flow**
- The Choices.js multi-select works well but the dark theme override is hacky (~50 lines of `!important` CSS overrides).
- The "you can only submit once!" warning is easy to miss — it's a small gray line in the header. This is a high-stakes action with no undo.
- No confirmation step before final submission. Users might misclick.
- The tier labels ("Top 5 Pick", "Two 6-16 Picks", "Two 17+ Picks") are confusing without OWGR context. If OWGR data isn't populated, the tiers are meaningless.
- The submit button spinner re-enables after 3 seconds via setTimeout — if the server is slow, the user can double-submit.
- Fix: Add a confirmation modal or review step before submit. Make the "one submission only" warning more prominent (banner, not inline text). Fix the double-submit protection. Consider showing the golfer's current ranking/score next to their name in the dropdown.

**P4. Login (`login.html`) — clean but generic**
- The centered card layout with icon is standard. Works fine.
- The green gradient on the user icon and CTA button is a nice touch.
- Fix: Minor — could benefit from the typography refresh and some atmosphere (subtle background pattern).

**P5. Submit Success (`submit_success.html`) — over-animated**
- The floating dots animation (`animate-pulse-slow`) with 6 absolute-positioned elements feels gratuitous.
- The "bounce-in" checkmark + "fade-in-up" staggered content is a lot of motion for a confirmation page.
- No nav bar — user is stranded on a dead-end page with only "View Leaderboard" as escape.
- The "What's Next?" info card is good content but the styling is heavy for a confirmation page.
- Fix: Tone down animations (one entrance animation is enough). Add nav bar. Simplify the layout.

**P6. Admin Dashboard (`admin.html`) — functional but dense**
- Good use of status indicators (API connected dot, active tournament badge, picks locked badge).
- The button cluster per tournament (Refresh, Lock/Unlock, Activate, Delete) gets crowded. "Delete" being right next to "Activate" is risky.
- The tournament schedule table at the bottom is useful but the "Create" button only shows for future tournaments — could be confusing.
- The registration toggle we just added fits well stylistically.
- Fix: Separate destructive actions (Delete) visually — maybe move to an "overflow" menu or add more spacing. Consider grouping tournament actions into a toolbar pattern.

**P7. Check Email (`check_email.html`) — solid**
- Clean confirmation page. The email icon + gold accent works well.
- Has partial nav (Leaderboard + Players) which is fine for this context.
- Fix: Minor — "Try again with a different email" link text is slightly misleading (it links to login, not a retry flow).

**P8. Request Access (`request_access.html`) / Access Requested (`access_requested.html`) — clean**
- Both pages are well-structured with appropriate iconography and messaging.
- The gold accent on the request access icon differentiates it from the green login icon — good.
- Fix: Minor polish only. These work well.

**P9. Error (`error.html`) — adequate**
- Red warning icon + message + two CTAs (Leaderboard, Go Back). Functional.
- Fix: The "Oops!" heading is informal. Consider "Something went wrong" for a more professional tone, or make it dynamic based on the error type.

### Recommended UI Refresh Approach

**Tier 1 — Architecture (do first, unblocks everything)**
1. Create `base.html` with shared layout, nav, footer, and Tailwind config
2. Refactor all 10 templates to extend `base.html`
3. Build static Tailwind CSS (replace CDN)

**Tier 2 — Design system refresh**
4. Choose distinctive typography (display + body font pair)
5. Refine color palette — add depth, texture, atmosphere to the dark theme
6. Standardize component patterns (buttons, cards, badges, form inputs)

**Tier 3 — Page-specific improvements**
7. Leaderboard: default-expanded on desktop, better score formatting, mobile header
8. Pick form: add confirmation step, fix double-submit, improve tier labels
9. Player standings: mobile-friendly layout, move "Selected By" column
10. Submit success: add nav bar, reduce animation, simplify
11. Admin: separate destructive actions, toolbar pattern for tournament actions

### UI Files to Modify

| File | Changes |
|------|---------|
| `templates/base.html` | **New** — shared layout with nav, footer, Tailwind config, typography |
| `templates/leaderboard.html` | Extend base, default-expanded, score formatting, mobile fixes |
| `templates/player_standings.html` | Extend base, mobile layout, reorder columns |
| `templates/pick_form.html` | Extend base, confirmation step, fix double-submit |
| `templates/submit_success.html` | Extend base (gets nav), reduce animations |
| `templates/login.html` | Extend base, typography refresh |
| `templates/check_email.html` | Extend base |
| `templates/request_access.html` | Extend base |
| `templates/access_requested.html` | Extend base |
| `templates/error.html` | Extend base, improve heading |
| `templates/admin.html` | Extend base, destructive action separation |
| `static/styles.css` | **New** — built Tailwind CSS output |

---

## Decisions Made

- **Deploy strategy**: Merge `feature/turso-migration-magic-auth` to `main`, then DO deploys from `main` automatically
- **Golfer refresh**: Automated refresh is needed — manual admin clicking is not sustainable during live tournaments. This bumps item #10 to P1 priority.
- **This plan is assessment-only** — reference document for future implementation work

---

## Recommended Implementation Order

**Phase 1 — Fix bugs & security (P0)**
1. Secure `/clear_cache` route
2. Fix Procfile.txt (`app.wsgi` → `app:app`)
3. Fail fast on missing `FLASK_SECRET_KEY` in production
4. Fix bare `except:` clauses
5. Remove `pandas`/`numpy` from requirements.txt

**Phase 1.5 — User names & entry name data model (P1)**
6. Split `display_name` into `first_name` + `last_name` on `users` and `access_requests` tables
   - `ALTER TABLE users ADD COLUMN first_name TEXT; ALTER TABLE users ADD COLUMN last_name TEXT;`
   - `ALTER TABLE access_requests ADD COLUMN first_name TEXT; ALTER TABLE access_requests ADD COLUMN last_name TEXT;`
   - Migrate existing `display_name` data: parse "First Last" → `first_name`, `last_name`
   - Update `schema.sql` for fresh installs
   - Keep `display_name` column temporarily for backwards compat (drop later)
7. Update request access form — two fields (First Name, Last Name) instead of one
8. Update `submit-access-request` route — accept, validate, store both name fields
9. Update `approve-user` route — copy `first_name` + `last_name` to `users` table
10. Update admin panel — show "First Last" from new columns
11. Update leaderboard query — join `users` table to pull `first_name`/`last_name` alongside `entry_name`
12. Update leaderboard template — show user's real name (e.g., "Cullin T.") under the entry name
13. Update pick form — relabel "Team Name" to encourage funny names (e.g., "Entry Nickname")

**Phase 2 — Operational basics (P1)**
14. Replace `print()` with `logging`
15. Add lightweight DB migration system
16. Automate session cleanup
17. Automate golfer refresh (protected endpoint + scheduled job)
18. Add favicon route

**Phase 3 — UI/UX Refresh (P1)**
19. Create `base.html` shared layout — nav, footer, Tailwind config (this fixes nav inconsistencies, missing admin link, submit_success nav bar all at once)
20. Refactor all templates to extend `base.html`
21. Build static Tailwind CSS to replace CDN
22. Typography and color palette refresh
23. Leaderboard: default-expanded desktop, score formatting, mobile header
24. Pick form: confirmation step, double-submit fix, tier label improvements
25. Player standings: mobile-friendly, column reorder
26. Submit success: reduce animation
27. Admin: destructive action separation

**Phase 4 — Testing (P2)**
28. Set up pytest with local SQLite test fixtures
29. Write core tests (auth, picks, leaderboard, admin)

**Phase 5 — Monitoring (P2)**
30. Add Sentry or similar error tracking
31. Set up uptime monitoring

**Phase 6 — Merge & Deploy**
32. Merge `feature/turso-migration-magic-auth` to `main`
33. Verify DO deployment picks up the merge
34. Smoke test all routes in production

---

## Files to Modify

| File | Changes |
|------|---------|
| `app.py` | Secure `/clear_cache`, fail-fast on secret key, fix bare excepts, add logging, add favicon route, automate session cleanup, auto-refresh endpoint |
| `requirements.txt` | Remove pandas/numpy, add pytest (dev) |
| `Procfile.txt` | Fix `app.wsgi` → `app:app` |
| `templates/base.html` | **New** — shared layout, nav, footer, typography, Tailwind config |
| `templates/leaderboard.html` | Extend base, default-expanded desktop, score formatting, mobile fixes |
| `templates/player_standings.html` | Extend base, mobile layout, column reorder |
| `templates/pick_form.html` | Extend base, confirmation step, double-submit fix |
| `templates/submit_success.html` | Extend base (gets nav), reduce animations |
| `templates/login.html` | Extend base |
| `templates/check_email.html` | Extend base |
| `templates/request_access.html` | Extend base |
| `templates/access_requested.html` | Extend base |
| `templates/error.html` | Extend base, improve heading |
| `templates/admin.html` | Extend base, destructive action separation |
| `static/styles.css` | **New** — built Tailwind CSS output |
| `tests/` | New directory with pytest tests |

---

## Verification

After each phase:
1. Run dev server, test all routes manually
2. Run test suite (once created)
3. Check health endpoint
4. Verify admin dashboard functions
5. Test auth flow end-to-end
6. For production deploy: smoke test all routes on live URL

---

## Progress Tracker

_Update this section after completing each phase._

| Phase | Status | Date | Notes |
|-------|--------|------|-------|
| Phase 1 — P0 Bugs & Security | **Complete** | 2026-02-16 | Secured /clear_cache, fixed Procfile, fail-fast secret key, fixed bare excepts, removed pandas/numpy |
| Phase 1.5 — User Names & Entry Name | **Complete** | 2026-02-16 | Split display_name into first/last, updated access form, approval flow, leaderboard shows "First L.", pick form relabeled |
| Phase 2 — Operational Basics | **Complete** | 2026-02-16 | Replaced all print() with logging, migration system (done in 1.5), probabilistic session cleanup, /api/auto-refresh endpoint, favicon route |
| Phase 3 — UI/UX Refresh | **Complete** | 2026-02-16 | base.html + refactor (-719 lines), DM Serif Display + DM Sans typography, turf-green gradient + card-glow theme, leaderboard score formatting + auto-expand desktop + player scores in chips, pick form confirmation dialog + double-submit fix + prominent warning, admin Delete button separated |
| Phase 4 — Testing | Not started | | |
| Phase 5 — Monitoring | Not started | | |
| Phase 6 — Merge & Deploy | Not started | | |
