# Iris UI — the observability console language

This is the design the app is built to, transcribed from the template it came from
("App redesign with observability template": a log-explorer console in the New Relic Logs / Loggly
family). It is the reference for any new surface. **Take values from here rather than inventing
ones that look similar** — a shade that is merely close is what turns a copied design into an
imitation of one.

Everything below is already expressed as CSS variables in `src/styles/themes.css` (palette) and
`src/styles/base.css` (type, metrics). No stylesheet in `src/styles/` outside `themes.css` contains a
literal colour, and it must stay that way: a hard-coded hex is a value that will be wrong in eight of
the nine themes.

---

## 1. The palette (default theme `iris-dark`)

| role | value | token |
|---|---|---|
| page ground | `#0d0f11` | `--bg` |
| chrome (sidebar, header, rails, status bars) | `#101315` | `--panel`, `--bg-sidebar` |
| table / rail heads | `#131719` | `--panel-inset` |
| row hover | `#15191c` | `--row-hover` |
| controls (inputs, chips, pills, buttons with a fill) | `#161a1d` | `--panel-2` |
| nav hover | `#171b1e` | `--hover` |
| row line | `#171b1e` | `--row-line` |
| selected row | `#181f22` | `--selected` |
| active nav item | `#1b2427` | `--nav-active` |
| soft rule (inside a panel) | `#1c2124` | `--border-2` |
| chart gridline | `#1e2327` | `--grid-line` |
| strong rule (between regions) | `#23282c` | `--border` |
| control rule | `#262b2f` | `--border-strong` |
| input rule | `#2c3236` | `--border-input` |
| control rule, hovered | `#3a434a` | `--border-hover` |

Text ramp, brightest first: `#ffffff` `--text-brightest` (screen title, active nav) ·
`#e4e9ea` `--text` (body) · `#d3dadd` `--text-2` (log message) · `#b9c2c6` `--text-3` ·
`#9aa4a9` `--text-4` (secondary control label) · `#8a949a` `--muted` · `#6d777c` `--muted-2`
(column heads, ticks) · `#5d666b` `--muted-3` (group labels, status bar) · `#4d565b` `--muted-4`.

Accent (teal): `#35c2c8` `--accent` · `#4ad3d8` `--accent-hover` · `#9fd9db` `--accent-soft`
(accent-coloured TEXT, e.g. the service column) · `#2f7f86` `--accent-deep` (borders, chart fills) ·
`#122528` `--accent-bg` · `#08181a` `--on-accent` (the label on a filled accent button).

Level colours, each with a deep tint of itself as its ground:

| level | colour | tint |
|---|---|---|
| critical | `#e2695f` | `#2a1a19` |
| high | `#e0a33c` | `#2a2116` |
| medium | `#c9b45f` | `#24210f` |
| low | `#7f8a90` | `#191d20` |
| info | `#35c2c8` | `#12262a` |

`--ok` is the accent teal, `--warn` is `--sev-high`, `--bad` is `--sev-critical`. There is no green
in this palette; do not introduce one.

## 2. Type

**IBM Plex Sans** is the interface face (`--font-ui`), **JetBrains Mono** is for every number,
timestamp, identifier, field name, query and log line (`--font-mono`). Both are bundled; the app
makes no runtime network request for a font. Body is 13px/1.45.

Sizes are `--fs-xxs` 10 · `--fs-xs` 10.5 · `--fs-sm` 11 · `--fs-md` 11.5 · `--fs-base` 12 ·
`--fs-lg` 12.5 · `--fs-xl` 13 · `--fs-3xl` 14 · `--fs-4xl` 15 · `--fs-stat` 20.

**One label treatment, everywhere.** A column head, a rail head, a nav group label and a section
eyebrow are the same object: the UI face, 10-10.5px, weight 600, uppercase, letter-spaced
(`--ls-head` 0.09em for a column head, `--ls-eyebrow` 0.13em for a group label), in `--muted-2` /
`--muted-3` on the surface's own ground. `.lbl` / `.lbl--group` in `base.css` is the shared class.

A **figure** is `--fs-stat` in the mono face at weight 500 with `-0.02em` tracking, and the word
that names it sits beside it in the UI face at `--fs-base` in `--muted`. Never label a figure with a
second figure.

## 3. Shape

The template is a **rectangular system**. Radii: `--radius-sm` 3px on a tag, `--radius-md` 5px on
every control (button, input, chip, pill, menu), `--radius-lg` 6px on a panel or card. The only
capsule in the whole design is a numeric badge in the nav. **Do not use `--radius-pill` on a filter
chip, a status pill or a badge** — that is the single loudest thing that would say "different app".

Nothing lifts, nothing glows, nothing animates a colour. There is exactly one animation in the
design (`livePulse`, the live-tail dot fading) and it is used in exactly one place. No shadows on a
panel — separation is a 1px rule, not a blur.

## 4. Metrics

| thing | value | token |
|---|---|---|
| sidebar | 216px | `--sidebar-w` |
| header, and the sidebar's brand row | 52px | `--header-h` |
| table head, rail head, sub-header strip | 34px | `--toolbar-h` |
| the query box and anything that lines up with it | 36px | `--field-h` |
| status bar under a result list | 30px | `--status-h` |
| the fields rail | 264px | `--rail-w` |
| page padding | 18px | `--page-pad` |
| row padding | 9px / 18px | `--row-pad-y` / `--row-pad-x` |

Buttons: secondary is 30px tall, a 1px `--border-strong` rule, no fill, a `--text-4` label; primary
is the accent fill with an `--on-accent` label at weight 600 and 16px of side padding. `.btn--lg` is
36px so it lines up with the query box.

## 5. Composition

The template's screen is: **sidebar · header · toolbar · body · status bar**, each separated by a
1px rule and each on its own ground, with nothing floating and no page-level scroll — the RESULT
LIST scrolls, inside a frame that does not.

- **Sidebar** — brand row (the WORDMARK ALONE at 14/600/0.14em plus the health dot; the template's
  accent lozenge was transcribed and removed, like the eye glyph before it — no mark, unasked), then
  nav in labelled groups 22px apart, items 7px/8px on a 5px radius, the active one carrying the
  accent as an `inset 2px 0 0` rail; the workspace identity block sits at the bottom.
- **Header** — `Parent / Screen` on one baseline (parent dim, screen at 15/600 in white), then a
  mono context chip, then the controls, right-aligned, in one row of bordered pills.
- **Toolbar** — the row you act in: scope selector, the thing you type in (flex: 1), the primary
  action, then secondary actions.
- **Body** — the answer. Where there is a facet rail it is on the RIGHT, at `--rail-w`, in the
  chrome colour with its own 34px head.
- **Status bar** — the smallest and quietest text on the screen, in the mono face, stating what the
  query cost. Never a place to put something the analyst has to act on.

## 6. Rules this design does not change

The design is the surface; the following are product rules and outrank it.

- A control is **dimmed, never hover-hidden** — a control that only exists on hover is unreachable
  by touch.
- **State what is missing.** An empty result that is really a build in flight, a source that did not
  load, a query that cannot reach a raw source: every one of those says so on the screen it affects.
  An absence the analyst cannot see is the failure this app exists to avoid.
- **A figure is exact or visibly not** — `10,000+`, never a rounded number that reads exact.
- No demo data, no marketing copy, no emoji, no sparkles.

---

## 7. The nav rail is TEXT

The template draws its nav icons as geometry — a 14px box with a 1.5px rule, reshaped per screen (a
square for search, a drum for a data source, a bell for alerts, a 2x2 lattice for a pattern). They
were transcribed and then **removed**: in place they read as clutter rather than as instrumentation,
which is the same call that removed the previous set. This is a 216px TEXT rail — the label is the
item, the group heading places it, and the active one carries the accent as an `inset 2px 0 0` rail.
Do not reintroduce them without being asked.

The rail is grouped the way the template groups it — by what you are DOING, not by which part of the
app owns the screen: **Explore** (Search, Entity graph) · **Data** (Sources, Cases) · **Monitor**
(Anomalies) · **System** (Settings).

**The one capsule in the whole design is the numeric badge on a nav item**, and it is the only correct
use of `--radius-pill` outside the assistant panel. A count of **zero draws nothing** — the template
badges the one item that has something waiting and leaves the rest bare; a column of "0"s is four
numbers saying there is nothing to see.

## 8. Button variants

| variant | shape |
|---|---|
| `.btn` | 30px, 1px `--border-strong`, no fill, `--text-4` label — beside prose |
| `.btn--lg` | `--field-h` (36px), so it lines up with a query box |
| `.btn--primary` | `--accent` fill, `--on-accent` label, weight 600, 16px side padding |
| `.btn--field` | the control ground (`--panel-2`) + the input rule — for a control that sits in a BAR rather than beside prose, so a toolbar reads as a row of fields rather than a row of links |
| `.btn--live` | tinted accent, with `.btn__live-dot` — the template's "live tail". Its dot is the ONE element in this design that animates a colour, and it is used in one place: the compute badge, when a GPU is actually carrying the work |

## 9. The assistant is a different template

The AI panel follows a second design — a reading-first chat interface — and its rules are its own:

- The **assistant's prose is set in a serif** (Newsreader, 15px/1.6 — brought down from 19px and then 16px on request, "seems large" both times; headings 18/16px, a long bold run is demoted to weight-inherit + `--text-bright` by `.md-strong--long`, because a model that bolds a whole paragraph has bolded nothing). The answer reads like a
  document; everything around it is mono or sans. This is the single most recognisable thing about it.
- The thread is a **centred 792px column**, messages 34px apart, and the composer is `sticky` at its
  bottom behind a gradient scrim.
- A **user message is a bubble** (`border-radius: 20px 20px 7px 20px`, right-aligned, max 80%); an
  **assistant message is not** — it is a collapsible steps card, then prose, then optional code /
  artifact cards, then a quiet actions row.
- Micro-labels are **mono, uppercase, ~10.5px at 0.07-0.08em**, and the small round-cornered controls
  there are the one place capsule buttons are correct.
- It takes its COLOURS from the tokens above, so it belongs to the same app.

Everything in §6 still applies to it: a warning is never folded into the collapsible card, a write is
never drawn as a read, and Stop stays reachable for the whole run.
