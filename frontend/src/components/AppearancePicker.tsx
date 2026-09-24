/* The theme and typeface pickers (Settings -> Appearance).
 *
 * They used to be a flat 9-card grid and two rows of name-only chips. At eighteen themes and twenty-two
 * faces that stops working for a reason worth writing down: a picker is not a list of options, it is a
 * way of DECIDING, and deciding needs three things a flat grid does not give you —
 *
 *   • GROUPING by what the choice is for. Dark / Light / High contrast, because "I am on a bright
 *     screen" and "I need maximum separation" are different questions with different right answers,
 *     and the two high-contrast themes were unfindable among sixteen others.
 *   • a FILTER, over the name, the description AND hidden tags, so "purple", "grey", "a11y" and
 *     "reading" each land on something although no theme is called any of them.
 *   • a PREVIEW THAT LOOKS LIKE THE APP. The old card drew three grey bars; this one draws the
 *     sidebar, a table head, three rows with a severity dot and an accent chip, in the theme's own
 *     colours. Those colours are set INLINE and that is the one place in this codebase where a
 *     literal is correct: the whole point is to show a palette the surrounding document is not
 *     rendered in.
 *
 * The faces get the same treatment and one more idea: every option is rendered IN ITSELF, next to a
 * SAMPLE of the job it actually does — a row of interface chrome for the UI face, a log line with
 * the characters that are confusable (0O 1lI) for the mono face, a sentence for the reading face. A
 * list that describes typefaces in the current typeface tells you nothing about the one you are
 * choosing. That requires the face to be loaded before it is picked, which is what `preloadFaces`
 * is for — see theme/fontLoader.ts, where only the three defaults are in the entry bundle.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import type { FontName, MonoName, SerifName, ThemeName } from '../api/types';
import {
  MONO_FONTS, SERIF_FONTS, THEMES, TONE_LABEL, TONE_ORDER, UI_FONTS,
  themeMatches, type FaceMeta, type ThemeMeta, type Tone,
} from '../theme/themes';
import { preloadFaces } from '../theme/fontLoader';
import { cx } from '../utils/format';
import { Icon } from './icons';

/** Above this many options the filter box appears. Same rule the Sources and Cases screens use: a
 *  toolbar over a handful of rows is furniture. */
const FILTER_ABOVE = 8;

/* ───────────────────────── the theme preview ─────────────────────────
   A miniature of the app, not an abstract swatch: it is the only way to tell at a glance whether a
   theme's rules are visible against its panels, which is the thing that actually goes wrong. */
function ThemePreview({ s }: { s: ThemeMeta['swatch'] }) {
  return (
    <div className="tprev" style={{ background: s.bg, borderColor: s.border }} aria-hidden="true">
      <div className="tprev__side" style={{ background: s.sidebar, borderColor: s.border }}>
        <i className="tprev__brand" style={{ background: s.text }} />
        <i className="tprev__nav" style={{ background: s.muted }} />
        <i className="tprev__nav tprev__nav--on" style={{ background: s.accent }} />
        <i className="tprev__nav" style={{ background: s.muted }} />
        <i className="tprev__nav" style={{ background: s.muted }} />
      </div>
      <div className="tprev__main">
        <div className="tprev__head" style={{ background: s.panel, borderColor: s.border }}>
          <i style={{ background: s.muted }} />
          <i style={{ background: s.accent }} />
        </div>
        <div className="tprev__row" style={{ borderColor: s.border }}>
          <i className="tprev__dot" style={{ background: s.sev }} />
          <i className="tprev__bar" style={{ background: s.text, width: '52%' }} />
        </div>
        <div className="tprev__row" style={{ borderColor: s.border }}>
          <i className="tprev__dot" style={{ background: s.muted }} />
          <i className="tprev__bar" style={{ background: s.muted, width: '70%' }} />
        </div>
        <div className="tprev__row" style={{ borderColor: s.border }}>
          <i className="tprev__dot" style={{ background: s.accent }} />
          <i className="tprev__bar" style={{ background: s.muted, width: '38%' }} />
        </div>
      </div>
    </div>
  );
}

/* Roving focus over a radio group: Tab reaches the group once and the arrow keys move within it,
   which is what a `role="radiogroup"` promises a screen reader. Eighteen cards each taking a tab
   stop is how a keyboard user ends up pressing Tab eighteen times to reach Density. */
function useRoving<T extends string>(ids: T[], value: T, onPick: (v: T) => void) {
  const ref = useRef<HTMLDivElement | null>(null);
  const onKeyDown = (e: React.KeyboardEvent) => {
    const keys = ['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp', 'Home', 'End'];
    if (!keys.includes(e.key)) return;
    e.preventDefault();
    const i = Math.max(0, ids.indexOf(value));
    const next = e.key === 'Home' ? 0
      : e.key === 'End' ? ids.length - 1
        : e.key === 'ArrowRight' || e.key === 'ArrowDown' ? (i + 1) % ids.length
          : (i - 1 + ids.length) % ids.length;
    const id = ids[next];
    if (id === undefined) return;
    onPick(id);
    // focus follows selection in a radio group, so the next arrow key continues from the new one
    window.requestAnimationFrame(() => {
      ref.current?.querySelector<HTMLElement>(`[data-opt="${CSS.escape(id)}"]`)?.focus();
    });
  };
  return { ref, onKeyDown };
}

export function ThemePicker({ value, onPick }: { value: ThemeName; onPick: (t: ThemeName) => void }) {
  const [q, setQ] = useState('');
  const shown = useMemo(() => THEMES.filter((t) => themeMatches(t, q)), [q]);
  const groups = useMemo(() => TONE_ORDER
    .map((tone) => [tone, shown.filter((t) => t.tone === tone)] as [Tone, ThemeMeta[]])
    .filter(([, list]) => list.length > 0), [shown]);
  const ids = useMemo(() => shown.map((t) => t.id), [shown]);
  const { ref, onKeyDown } = useRoving(ids, value, onPick);
  const current = THEMES.find((t) => t.id === value);

  return (
    <div className="field">
      <div className="pickhead">
        <span className="field__label">Theme</span>
        <span className="pickhead__now">
          {current ? current.name : value}
          <span className="dim"> · {THEMES.length} available</span>
        </span>
        {THEMES.length > FILTER_ABOVE && (
          <label className="pickhead__filter">
            <Icon.Search />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter themes"
              aria-label="Filter themes" spellCheck={false} />
            {q && (
              <button type="button" className="pickhead__clear" onClick={() => setQ('')}>Clear</button>
            )}
          </label>
        )}
      </div>
      <div ref={ref} onKeyDown={onKeyDown} role="radiogroup" aria-label="Theme">
        {groups.map(([tone, list]) => (
          <div className="thmgroup" key={tone}>
            <div className="lbl lbl--group thmgroup__head">{TONE_LABEL[tone]} <span className="num">{list.length}</span></div>
            <div className="themes">
              {list.map((t) => (
                <button key={t.id} type="button" role="radio" data-opt={t.id}
                  aria-checked={value === t.id} tabIndex={value === t.id ? 0 : -1}
                  className={cx('theme-card', value === t.id && 'on')} onClick={() => onPick(t.id)}>
                  <ThemePreview s={t.swatch} />
                  <div className="theme-card__name">
                    {t.name}
                    {value === t.id && <Icon.Check />}
                  </div>
                  <div className="theme-card__desc">{t.desc}</div>
                </button>
              ))}
            </div>
          </div>
        ))}
        {!groups.length && (
          <div className="pickempty">No theme matches “{q}”. Try a colour (purple, grey), a mood
            (warm, calm) or what it is for (reading, projector, a11y).</div>
        )}
      </div>
    </div>
  );
}

/* ───────────────────────── the face pickers ───────────────────────── */

/** What each axis is sampled WITH. The sample is the argument for the face, so it has to be the job
 *  the face actually does in Iris — chrome, a log line, a paragraph — and not a pangram. */
const SAMPLES = {
  ui: 'Sources · 12,480 events · 3 detections',
  mono: '10.0.0.104 → 203.0.113.9  4624  0Ol1I  sha256:9f3b…',
  serif: 'The account authenticated from two networks within four minutes.',
} as const;

type Axis = 'ui' | 'mono' | 'serif';

function FaceList<Id extends string>({ axis, label, hint, faces, value, onPick }: {
  axis: Axis; label: string; hint?: React.ReactNode;
  faces: FaceMeta<Id>[]; value: Id; onPick: (v: Id) => void;
}) {
  const [q, setQ] = useState('');
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return s ? faces.filter((f) => (f.name + ' ' + f.desc).toLowerCase().includes(s)) : faces;
  }, [faces, q]);
  const ids = useMemo(() => shown.map((f) => f.id), [shown]);
  const { ref, onKeyDown } = useRoving(ids, value, onPick);
  const current = faces.find((f) => f.id === value);

  return (
    <div className="field">
      <div className="pickhead">
        <span className="field__label">{label}</span>
        <span className="pickhead__now" style={{ fontFamily: current?.stack }}>{current?.name || value}</span>
        {faces.length > FILTER_ABOVE && (
          <label className="pickhead__filter">
            <Icon.Search />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter faces"
              aria-label={'Filter ' + label.toLowerCase()} spellCheck={false} />
          </label>
        )}
      </div>
      <div ref={ref} onKeyDown={onKeyDown} className="facepick" role="radiogroup" aria-label={label}>
        {shown.map((f) => (
          <button key={f.id} type="button" role="radio" data-opt={f.id}
            aria-checked={value === f.id} tabIndex={value === f.id ? 0 : -1}
            className={cx('face', value === f.id && 'on')} onClick={() => onPick(f.id)}>
            <div className="face__top">
              <span className="face__name" style={{ fontFamily: f.stack }}>{f.name}</span>
              {value === f.id && <Icon.Check />}
            </div>
            <div className={cx('face__sample', axis === 'mono' && 'face__sample--mono')}
              style={{ fontFamily: f.stack }}>{SAMPLES[axis]}</div>
            <div className="face__desc">{f.desc}</div>
          </button>
        ))}
      </div>
      {hint && <div className="field__hint">{hint}</div>}
    </div>
  );
}

export function FacePickers({ font, mono, serif, setFont, setMono, setSerif }: {
  font: FontName; mono: MonoName; serif: SerifName;
  setFont: (v: FontName) => void; setMono: (v: MonoName) => void; setSerif: (v: SerifName) => void;
}) {
  // Every sample has to be drawn in the face it is naming, and all but three of them are code-split.
  // Fetching them when this section mounts (rather than on hover, which only helps the pointer) is
  // what makes the list readable at all; the loader de-duplicates, so choosing one costs nothing more.
  useEffect(() => {
    preloadFaces(UI_FONTS.map((f) => f.id), MONO_FONTS.map((f) => f.id), SERIF_FONTS.map((f) => f.id));
  }, []);

  return (
    <>
      <FaceList axis="ui" label="Interface font" faces={UI_FONTS} value={font} onPick={setFont}
        hint="Every label, button, table head and paragraph of chrome." />
      <FaceList axis="mono" label="Monospace font" faces={MONO_FONTS} value={mono} onPick={setMono}
        hint={'Every log line, event id, address, hash and figure you compare down a column. '
          + 'Fira Code’s ligatures are switched off here: a face may not redraw → as one glyph in evidence.'} />
      <FaceList axis="serif" label="Assistant reading font" faces={SERIF_FONTS} value={serif} onPick={setSerif}
        hint={'The AI assistant sets its ANSWER in this face, in its own reading column — '
          + 'the working and the tool calls stay in the interface font. “Match interface” opts out of the serif.'} />
      <div className="field">
        <span className="field__label">Together</span>
        <div className="typeprev">
          <div className="typeprev__row">
            <span className="typeprev__label">Anomalies</span>
            <span className="typeprev__val num">1,284</span>
            <span className="typeprev__mono">svc-backup@10.0.0.104</span>
          </div>
          <p className="typeprev__prose">
            Two accounts authenticated from the same address inside four minutes, and only one of
            them has ever appeared on that host before.
          </p>
        </div>
        <div className="field__hint">
          All faces are bundled with Iris. Nothing is fetched from the internet at runtime — only the
          three defaults are in the first load, and a face you choose is fetched from Iris itself.
        </div>
      </div>
    </>
  );
}
