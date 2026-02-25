# Production Plan: Flask Golf

## Remaining Work Items

### 1. Replace Tailwind CDN with static CSS build

**Priority**: P1
**Status**: Done

`cdn.tailwindcss.com` is the dev-only JIT compiler (~300KB, causes FOUC on every page load). Tailwind docs explicitly say not to use it in production.

**Fix**: Build a static CSS file with Tailwind CLI (`npx tailwindcss -o styles.css --minify`). Serve from `/static`. Move the inline `tailwind.config` to a build config file. Update `base.html` to reference the static file instead of the CDN.

**Files**: `base.html`, new `tailwind.config.js`, new `static/styles.css`, `package.json` (for build script)

---

### 2. Configure auto-refresh cron for golfer scores

**Priority**: P1
**Status**: Done

The `/api/auto-refresh` endpoint exists and works (API key auth via `X-API-Key` header, reuses `GOLF_API_KEY`). But nothing is calling it on a schedule. During live tournaments, an admin must manually click "Refresh Golfers" — not sustainable.

**Fix**: Set up an external cron job (e.g., cron-job.org, GitHub Actions scheduled workflow, or DO Functions) that hits `POST /api/auto-refresh` with the API key header every 5-10 minutes during tournament hours.

**Also**: Tournament activation (`/admin/activate-tournament`) should automatically trigger a golfer refresh so the pick form isn't empty after activating a new tournament.

**Files**: `app.py` (activate route), external cron config

---

### 3. Honor the `next` parameter after login

**Priority**: P2
**Status**: Done

`@login_required` passes `next=request.url` to the login page, but `auth_verify` always redirects to `/make_picks`. Users who click a deep link while logged out don't return to the page they wanted.

**Fix**: Carry the `next` URL through the magic link flow (login form → magic link email → verify endpoint → redirect). Validate the URL is a relative path (no open redirect).

**Files**: `app.py` (login route, request-link route, verify route), `templates/login.html`

---

### 4. Set up CI/CD pipeline

**Priority**: P2
**Status**: Done

78 pytest tests exist but only run manually. No automated testing on push/PR.

**Fix**: Add a GitHub Actions workflow that runs `uv run pytest` on push to `main` and on PRs. Optionally add a linting step.

**Files**: New `.github/workflows/test.yml`

---

### 5. Python version mismatch (dev 3.12, prod 3.10)

**Priority**: P3
**Status**: Done

Local dev uses Python 3.12, but `runtime.txt` specifies `python-3.10.14` for DigitalOcean. This works today but could cause subtle differences (e.g., `tomllib` built-in in 3.11+, exception groups in 3.11+, `match` statement in 3.10+).

**Fix**: Update `runtime.txt` to `python-3.12.x` (or whatever version DO App Platform supports closest to 3.12). Test the deploy.

**Files**: `runtime.txt`

---

### 6. Move email templates out of inline Python strings

**Priority**: P3
**Status**: Done

Magic link and notification emails are built as HTML string concatenation inside Python functions in `app.py`. Hard to read, maintain, and style.

**Fix**: Move email HTML to Jinja2 templates (e.g., `templates/emails/magic_link.html`, `templates/emails/approval.html`). Render with `render_template()` like the page templates.

**Files**: `app.py`, new `templates/emails/*.html`

---

### 7. Admin template XSS pattern cleanup

**Priority**: P2
**Status**: Done

`admin.html` has `onsubmit="return confirm('Delete {{ t.name }}?')"` and similar patterns that inject Jinja2 template variables directly into inline JavaScript. Data is HTML-escaped at storage time so this is safe today, but it's a fragile pattern — a future developer could introduce stored XSS without realizing it.

**Fix**: Move confirmation logic to a JavaScript function that reads the name from a `data-*` attribute instead of inline template interpolation.

**Files**: `templates/admin.html`

---

## Progress Tracker

| # | Item | Status | Date | Notes |
|---|------|--------|------|-------|
| 1 | Replace Tailwind CDN with static CSS | Done | 2026-02-24 | Built via Tailwind CLI, 28KB minified. `npm run build:css` to rebuild. |
| 2 | Configure auto-refresh cron | Done | 2026-02-24 | GH Actions hourly cron + admin-configurable schedule (hours/days). Tournament activation auto-refreshes. |
| 3 | Honor `next` parameter after login | Done | 2026-02-24 | `next` carried through login → email → verify. Validates relative paths only. |
| 4 | Set up CI/CD pipeline | Done | 2026-02-24 | `.github/workflows/test.yml` runs pytest on push/PR to main. |
| 5 | Python version mismatch | Done | 2026-02-24 | `runtime.txt` updated to `python-3.12.7`. |
| 6 | Email templates out of inline strings | Done | 2026-02-24 | Moved to `templates/emails/{magic_link,admin_notification,approval}.html`. |
| 7 | Admin template XSS cleanup | Done | 2026-02-24 | Replaced inline `onsubmit` confirm with `data-confirm` attributes + event listener. |
