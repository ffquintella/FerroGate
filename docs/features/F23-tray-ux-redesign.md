# F23 — Tray UX redesign (mia-tray / mia-tray-admin)

Status: implemented in phases (see §7). Scope: `crates/mia-tray` only; the
daemon, CMIS, the admin API and the authentication contract (F20) are
unchanged. Builds on [F18](F18-mia-tray.md) (tray) and
[F22](F22-tray-admin-client.md) (administrator client).

## 1. Problems found

Read from the code before the redesign (0.30.14):

| # | Problem | Where |
|---|---------|-------|
| P1 | The menu repeats everything: one submenu per environment with 6–10 disabled detail lines, the worst environment's recoveries again at the top, four window entries, "Admin client…", "Last action", Quit. Inapplicable entries stay. | `model.rs` `menu_model` |
| P2 | Every menu entry starts its own process: "Open status", "Setup…", "Logs…" and "Run self-test" could open four copies of the same four-tab window ("windows inside windows"). A second click on "Admin client…" did nothing visible. | `gui/tray.rs` `open_window`, `windows: HashMap<WindowKind, Child>` |
| P3 | State is colour first: a coloured disc, a glyph only for *not configured*, and a 500 ms blink while attesting. The window headline is coloured text. | `icon.rs`, `status_view.rs` |
| P4 | Layouts do not reflow: the setup form's scroll area is `available_height - 140` (negative on small windows), fixed 160 px text boxes, a 9-column request grid with no horizontal scroll, minimum sizes of 560×380 / 440×380. | `setup_view.rs`, `logs_view.rs`, `gui/admin/views.rs` |
| P5 | The admin page stacks the session summary, the factor panel, the request views and the decision dialog as nested group boxes on one long page. A non-wide approval needs Continue → Review → Confirm. | `gui/admin/mod.rs`, `gui/admin/views.rs` |
| P6 | Notifications are two ad-hoc `notify::show` calls with different titles, no urgency, no click action, no replacement, and no in-app mirror; the action result lives only in a "Last action" menu line. | `gui/notify.rs`, `gui/tray.rs` |
| P7 | English and Portuguese only, no user override; plurals written as "record(s)". | `i18n.rs` |
| P8 | Setup needs "Check with mia" and then "Apply" as two separate clicks. | `gui/setup_view.rs` |

## 2. Principles applied

- The tray shows status and offers quick access. Every action also exists
  in a window, because users can hide the tray icon.
- The icon encodes state with one glyph overlay. It never relies on colour
  alone and does not blink.
- The default action comes first and inapplicable items are removed, not
  disabled. Labels are specific.
- Show the state, when it was last updated, and the next step; plain
  language first, details on demand.
- Confirm inline in the same view. Keep the existing security gates
  (wide-scope confirmation, step-up, review) and remove only the clicks
  around them. Enter never sends a decision.
- One window per task, no floating sub-windows, every window resizable.

Sources: Microsoft *Notifications* guidelines
(learn.microsoft.com/en-us/windows/win32/uxguide/winenv-notification);
Nielsen's usability heuristics (nngroup.com/articles/ten-usability-heuristics);
WCAG 2.2 1.4.1 *Use of Color* and 1.4.3 *Contrast*.

## 3. Information architecture

**Tray icon.** A disc in the state colour plus a glyph: ✓ healthy, … attesting
(static), ! degraded or not configured, × broken, – absent or stopped. The
tooltip reads `FerroGate MIA — <summary>`.

**Tray menu** (rebuilt whenever the language changes):

```
FerroGate MIA — CRL stale (prod)       ← summary (disabled)
Restart: succeeded                      ← latest notice line, if any
────────
Run self-test (prod)                    ← recoveries for the worst environment
Read: CRL-stale runbook (prod)
────────
Open FerroGate…                         ← default action (left click on macOS/Windows)
Environments ▸ prod: CRL stale ▸ …      ← only with 2+ environments
Review approvals…                       ← only when mia-tray-admin is installed and trusted
────────
Setup…
Quit
```

"Logs…" and "Run self-test" move into the window (the Logs tab and the
Recovery tab). The self-test stays in the menu when it is a recovery for the current
state.

**Main window.** One process, opened by `mia-tray --window <kind>` and reused
afterwards: the tray keeps the child's stdin as a control pipe and sends
`show <kind>` lines from a closed set (`control.rs`). Layout:

- a header with the state badge (glyph and text), the explanation, "updated
  hh:mm:ss", the primary recovery buttons, and a language selector;
- tabs Status · Recovery · Setup · Logs;
- a status bar at the bottom that mirrors notifications.

The Setup tab's primary button is "Check and apply", which runs
`mia setup --check` and, when the draft is accepted, applies exactly that
draft. "Check only" stays available.

**Admin client.** Still a separate process and binary (F22 isolation). The
signed-in page is one navigable view: a top bar with a breadcrumb, the
session chip and Sign out, and a single content area showing the step-up,
second factors, or the request views. After sign-in the client opens on
pending requests, and the tab shows a pending-count badge. Approve and Deny
show a live "what will be sent" preview, and "Approve and send" sends at once
when the scope is narrow. A wide scope still goes through Accept → Review →
Confirm, and a `step_up_required` reply still asks for the step-up.
Persisting the user name was rejected because F22 §3 forbids persistence
(and LGPD favours minimisation); re-clicking the tray item brings the open
window to the front instead.

**Notifications** (`notice.rs`, `gui/notify.rs`). There is one type,
`Notice`, with kind `info | success | warning | error | approval_pending`.

- *Content:* the title is always `FerroGate`, the subtitle is the
  environment or app, the body is short localised plain language, plus a
  click target.
- *Deduplication:* `NoticeCenter` keeps a bounded history and
  de-duplicates and rate-limits OS delivery with the `alerts::RateLimiter`
  already used for state alerts.
- *Delivery:* the OS notification is the primary channel. The menu line and
  the window status bar render the same `Notice`, and the tray forwards
  notices to the open window over the control pipe.
- *Per platform:*
  - Linux: freedesktop over D-Bus, with app name, icon, urgency (critical
    only for approval-pending and errors), Open, Review and Dismiss buttons,
    and the previous notification id reused per tag so repeats replace each
    other.
  - Windows: a toast with buttons. The toast uses the FerroGate
    AppUserModelID when the installer registered one, and otherwise the
    default.
  - macOS: Notification Center with click-to-open, under the bundle
    identifier `com.ferrogate.mia-tray`.
- *Safety:* a notification never carries codes, secrets, tokens, paths or
  user names, and never approves anything; "Review" only opens the view.
  When no notification daemon is running, the failure is logged and the
  in-app message remains.

## 4. Journeys — steps before → after

| Journey | Before | After |
|---------|--------|-------|
| Check status | 4 (icon, menu, Open status, read the tab) | 1: the tooltip, or a left click that opens the window (macOS, Windows); 2 on Linux (icon, "Open FerroGate…") |
| Fix a stopped service | 5 (icon, find the environment submenu or top item, Start, OS consent, confirm in "Last action") | 3 (icon, first item "Start the agent service", OS consent); the result arrives as a notification |
| Approve a request (narrow scope) | 11–13 + step-up (icon, Admin client…, user, Continue, password + code, Sign in, Requests, Open, Approve…, Continue, Confirm and send) | 9 + step-up (icon, Review approvals…, user, Tab, password + code, Sign in, Open, Approve…, Approve and send), on one sign-in screen instead of two. Tab replaces the Continue click, so the key presses are the same; fixing a mistyped name drops from 3 steps (Change user, retype, Continue) to 2 (edit, Tab). 5 when the admin window is already open and signed in. |
| First-run setup | icon, Setup…, load consent, edit, Check, Apply, consent = 7 | icon, Setup…, load consent, edit, Check and apply, consent = 6 |
| Change the UI language | not possible (environment variables only) | 2 (window, language selector); the tray menu follows within 2 s |

## 5. i18n decision

The in-house table stays and gains `Lang::Es` in `i18n/es.rs`, which is an
exhaustive `match` with no wildcard: a missing Spanish string is a compile
error, and a unit test checks that every key is non-empty with matching
placeholders in all three languages. Adding Spanish this way needs no new
dependency and keeps compile-time completeness. Fluent would bring three
crates, runtime fallbacks and a 529-key migration with no concrete blocker
to remove. Plurals use a small CLDR-based `plural(lang, n)` helper, and
placeholders stay named (`fill`).

Language is resolved in this order:

1. `MIA_TRAY_LANG`
2. the per-user preference file (`mia-tray.toml`, 0600, holding the
   language only)
3. `LC_ALL`, `LC_MESSAGES`, `LANG`, `LANGUAGE`
4. the OS locale
5. English

Region tags fall back as `pt-BR`/`pt-*` → `pt` and `es-*` → `es`, then to
English.

## 6. Security invariants kept

- `actions.rs` keeps its closed command set and its elevation wrappers.
- Window kinds and control-pipe commands are closed sets parsed from bounded
  lines.
- Daemon and server text is still escaped (`text.rs`).
- Admin secrets stay out of egui widgets.
- Wide-scope confirmation, step-up and the review are preserved, and Enter
  never confirms.
- No new network calls. The approval-pending notification is raised only
  from data the admin client already loads.
- The preference file is per user, holds the language only, has a bounded
  size, and an unreadable file is ignored.
- Notifications carry no secrets.

## 7. Phases

1. **i18n foundation:** `Es`, override and fallback, preference file,
   plural helper, completeness test. ✔
2. **Tray:**
   - simplified menu, glyph icon without animation, pure dispatch planning
     (`model::plan`) with tests;
   - one main-window process with a control pipe and left-click to open;
   - the notification layer (`notice.rs`, `gui/notify.rs`). ✔
3. **Main window:**
   - status header and badge, tabs, status bar mirroring notices, language
     selector;
   - resizable viewports with reflowing layouts;
   - "Check and apply". ✔
4. **Admin client:**
   - resizable, one navigable page with breadcrumb and no nested group
     boxes;
   - opens on pending requests with a count badge;
   - merged form and preview with "Approve and send" for narrow scopes
     (`Decision::send_from_form`, `ViewAction::DecisionSend`);
   - bring-to-front on re-open;
   - in-app notices. ✔ (see §8 for the rest)
5. **Single sign-in screen** (follow-up). ✔ It is a UI and flow change
   only: the F20 protocol is unchanged (`BeginLogin`, then `Login`; the same
   calls in the same order).
   - The name stays on screen. Leaving it (Tab or Enter) sends
     `BeginLogin` once, and its answer reveals the password and code or key
     fields below the name; no Continue screen.
   - Editing the name drops the answer and the secrets typed for it.
   - A stale answer is ignored; one call is in flight at a time.
   - An answer older than 2 min is asked again before the submit (the
     worker's sign-in still takes a fresh nonce right before `Login`).
   - Decoy answers for unknown names are handled exactly like real ones.
   - egui's keyboard focus is dropped whenever the page changes, so an
     Enter meant for one page never presses a button on the next.
   - Tests in `admin/login.rs` and `admin/flow.rs`, plus a 380×300 egui
     frame test in all three languages.

There were no `egui::Window`s, modals or nested viewports. The "windows
inside windows" came from two places: one process per menu entry (fixed by
the single main window), and the admin page's stacked group boxes (fixed by
flattening it into one page with a breadcrumb and a stepper). The server
screen's two side-by-side cards (current server, new server) stay as a
comparison, not a window.

## 8. Not done / follow-ups

- **Background approval-pending alerts:** there is no source without new
  network calls (the tray has no CMIS link). This needs a count in the
  status endpoint or a server push.
- **Windows AppUserModelID:** the MSI (`crates/mia/wix/mia.wxs`, outside
  this change) should register `HKCU\Software\Classes\AppUserModelId\FerroGate.MIA`
  (DisplayName, IconUri). Until then, toasts use the default app id.
- **Visual review:** the GUI was verified with egui frame tests only
  (texts painted, tab switching, no horizontal overflow at 380×300 and
  1600×1000 in all three languages) plus a WCAG contrast test of the badge
  colours. A human must review the appearance on each OS.
- **Platform behaviour not exercised:**
  - Linux: notification buttons, replacement by id and the D-Bus wait (the
    Linux cfg path was not compiled here; it needs GTK);
  - Windows: toasts, buttons and the AppUserModelID check (compiled with
    `cargo check --target x86_64-pc-windows-msvc`, never run);
  - macOS: Notification Center click-to-open and the bundle id;
  - left-click on the tray icon.
