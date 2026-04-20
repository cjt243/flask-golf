# UX/UI Review: Mobile Polish & Visual Consistency

## Context

The Flask Golf app's primary audience uses mobile for the leaderboard (`/`), players (`/players`), and standings (`/standings`) pages. A code-level review of all 17 templates identified several mobile UX gaps and visual inconsistencies. The leaderboard and pick form are already well-optimized for mobile, but the standings page forces horizontal scrolling with no affordance, tier colors are inconsistent across pages, and several small polish items would improve the overall experience.

This spec covers: fixing standings table mobile usability, unifying tier colors, and polishing the leaderboard and minor pages. The visual identity (dark theme, golf-green/gold palette) is not changing.

## Pre-Implementation: Playwright Screenshot Baseline

Before writing any code, capture baseline screenshots of every affected page at mobile (375x812) and desktop (1440x900) viewports using Playwright. These screenshots serve two purposes:

1. **Validate findings** — Confirm each issue identified from code review actually manifests visually. If a finding doesn't reproduce (e.g., tables fit fine at 375px, nav doesn't overflow), drop it from scope.
2. **Before/after comparison** — After implementing each change, re-capture the same screenshots and compare against the baseline to verify the fix works and hasn't caused regressions.

### Pages to capture

| Page | URL | State required |
|------|-----|----------------|
| Leaderboard | `/` | Active tournament with picks locked and golfer scores |
| Player standings | `/players` | Same active tournament |
| Season standings (League tab) | `/standings` | At least 1 completed tournament |
| Season standings (Tournament Stats tab) | `/standings` | Same |
| Season standings (Selection Stats tab) | `/standings` | Same |
| Season standings (Winner's Circle tab) | `/standings` | Same |
| Pick form | `/make_picks` | Active tournament with picks unlocked |
| Login | `/auth/login` | Logged out |
| Request access | `/auth/request-access` | Logged out, registration open |
| Admin dashboard | `/admin` | Admin session |
| Admin tiers | `/admin/manage-tiers/<id>` | Admin session, tournament with golfers |

### Screenshot procedure

1. Start dev server (`PYTHONUNBUFFERED=1 uv run python app.py`)
2. Activate a completed tournament with data (set `is_active=1` temporarily via DB) to populate leaderboard/players
3. Create an authenticated session in the DB for Playwright (see CLAUDE.md testing section)
4. Capture each page at both viewports, saved to `/tmp/screenshots/baseline/`
5. Review each screenshot against the findings below — drop any that don't reproduce
6. Restore tournament state after capture

### Go/no-go gate

If a finding doesn't reproduce in screenshots, it is removed from scope. Do not implement changes that aren't confirmed visually. Present the validated finding list to the user before proceeding to implementation.

---

## Change 1: Sticky First Column on Standings Tables

**Priority:** High
**Effort:** Medium
**Files:** `templates/standings.html`, `static/src/input.css`

### Problem

The standings page has 4 tabs. Three of them (League, Tournament Stats, Selection Stats) use HTML tables with `overflow-x-auto`. On a 375px mobile screen, tables with 6-8 columns overflow horizontally. There is no visual indicator that content extends off-screen, and scrolling loses the context of which row you're reading.

### Solution

Apply a sticky first-column pattern to all standings tables on mobile:

- Pin the **# (rank)** and **Name** columns using `position: sticky; left: 0; z-index: 10` with a matching background color so content doesn't show through
- Add a subtle right box-shadow on the pinned column to indicate scroll affordance (e.g., `box-shadow: 4px 0 8px -2px rgba(0,0,0,0.3)`)
- The shadow provides the visual cue that there is more content to the right
- All data columns remain in the table and are accessible via horizontal scroll
- Desktop is unaffected (tables fit without scrolling)

### Scope

Apply to these tables within `standings.html`:
- League tab: main standings table, podium finishes table
- Tournament Stats tab: per-tournament leaderboard table
- Selection Stats tab: most picked golfers table, tier best tables

The Winner's Circle tab already has a mobile card layout and does not need this treatment.

---

## Change 2: Reorder League Tab Columns

**Priority:** High
**Effort:** Small
**Files:** `templates/standings.html`

### Problem

The League standings table column order is: #, Name, W, P, $, Avg, Tot, Owed. With sticky # and Name columns, the first visible scrollable columns are W and P. Since **wins** and **average score** are the two most important stats (and the sort keys), Avg should appear immediately after W so users see both without scrolling.

### Solution

Reorder columns to: **#, Name, W, Avg, P, $, Tot, Owed**

This is a template-only change — reorder the `<th>` and `<td>` elements in the League standings table.

---

## Change 3: Tier Color Consistency

**Priority:** High
**Effort:** Small
**Files:** `templates/player_standings.html`, `templates/standings.html`, any other templates with tier dots/badges

### Problem

Tier colors differ between pages:
- **Player standings:** gold (T1), green (T2), muted green (T3)
- **Season standings:** gold (`bg-golf-gold-400`, T1), blue (`bg-blue-400`, T2), purple (`bg-purple-400`, T3)

### Solution

Standardize on **gold / blue / purple** everywhere:
- Tier 1: `bg-golf-gold-400` / `text-golf-gold-400`
- Tier 2: `bg-blue-400` / `text-blue-400`
- Tier 3: `bg-purple-400` / `text-purple-400`

Update `player_standings.html` tier dots and any associated text colors to match. Verify pick form tier accent colors already align (they use gold/blue/purple for the left border accents — confirm consistency).

### Where to check

Grep for tier-related color classes across all templates:
- `bg-golf-green` in tier contexts
- `text-green` in tier contexts
- `tier-dot` class usage
- Tier header/divider row styling

---

## Change 4: Leaderboard Expand/Collapse Button

**Priority:** Medium
**Effort:** Small
**Files:** `templates/leaderboard.html`

### Problem

The expand/collapse all button is positioned top-right above the leaderboard cards. It's small and not immediately obvious, especially for first-time users.

### Solution

Increase the button's visual weight:
- Add a text label next to the icon (e.g., "Expand All" / "Collapse All") visible on mobile
- Or increase the button size and add a subtle background/border to make it look more like an interactive control rather than a floating icon
- Keep it positioned top-right but make it more clearly tappable

Exact styling to be determined after reviewing baseline screenshots — the current button may be more visible than the code suggests.

---

## Change 5: Leaderboard Card Tappable Affordance

**Priority:** Medium
**Effort:** Small
**Files:** `templates/leaderboard.html`

### Problem

The "Tap to see players" helper text below entry names on mobile is explicit but adds visual clutter. Removing it requires a different signal that cards are interactive.

### Solution

1. Remove the `sm:hidden` "Tap to see players" text span
2. Add a small chevron icon (right-pointing arrow, rotates down on expand) to the right side of the card header, next to the score — this is the same pattern used in player standings cards and is universally understood as "tappable/expandable"
3. The chevron already exists in the card (there's an arrow that rotates on expand) — verify in screenshots whether it's visible enough. May just need the "Tap to see players" text removed with no other changes needed.

---

## Change 6: Request Access Form Responsive Grid

**Priority:** Low
**Effort:** Small
**Files:** `templates/request_access.html`

### Problem

The first name / last name fields use `grid grid-cols-2 gap-4` with no responsive breakpoint. On phones narrower than 375px (e.g., iPhone SE at 320px), each input is ~148px wide, which is tight for text entry.

### Solution

Change to `grid grid-cols-1 sm:grid-cols-2 gap-4` so the name fields stack vertically on small screens and sit side-by-side on larger screens.

---

## Change 7: Feedback Widget Popover Position

**Priority:** Low
**Effort:** Small
**Files:** `templates/base.html`

### Problem

The feedback popover is `w-72` (288px) anchored `absolute bottom-12 right-0` from a button at `fixed bottom-4 right-4`. On a 375px screen this leaves ~71px of left margin — not broken but tight.

### Solution

Verify in screenshots whether this is actually a problem. If the popover feels cramped or clips, add `right-0 sm:right-0` with a mobile override like `right-[-12px]` or switch to a centered bottom sheet on mobile. If it looks fine in screenshots, drop this item.

---

## Not In Scope

- **Nav bar** — fits fine on mobile per user confirmation
- **Hide CUT filter** — cut golfers are important, filter not needed
- **Tier dot sizing** on player standings — good as-is
- **Pick form** — already well-optimized for mobile
- **Dark theme / color palette** — working well, no changes
- **Submit success page** — works fine with Turbo Drive

---

## Verification

After implementing each change:

1. Re-capture Playwright screenshots at both viewports for affected pages
2. Compare against baseline screenshots — confirm improvement, no regressions
3. Test on desktop to verify no layout breakage
4. Run `uv run pytest tests/` to ensure no broken template rendering
5. Rebuild Tailwind CSS (`npm run build:css`) after any template or `input.css` changes
6. Manual spot-check: scroll the sticky-column tables on mobile viewport to verify the pin and shadow work correctly
