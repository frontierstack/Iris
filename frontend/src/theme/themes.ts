import type { FontName, MonoName, SerifName, ThemeName } from '../api/types';

/** What a theme is FOR, which is how the picker groups them.
 *
 *  `contrast` is not "a dark theme that happens to be high contrast" — it is a different answer to a
 *  different question (a projector, a screen read over someone's shoulder, low vision), and burying
 *  the two high-contrast themes among fourteen others is how nobody finds them. */
export type Tone = 'dark' | 'light' | 'contrast';

export interface ThemeMeta {
  id: ThemeName;
  name: string;
  desc: string;
  tone: Tone;
  /** searchable words that are NOT in the name or the description */
  tags?: string[];
  /** swatches for the preview card */
  swatch: { bg: string; sidebar: string; panel: string; border: string; text: string; muted: string; accent: string; sev: string };
}

export const THEMES: ThemeMeta[] = [
  { id: 'iris-dark', name: 'Iris dark', desc: 'Default · observability console — teal on graphite', tone: 'dark', tags: ['teal', 'default'], swatch: { bg: '#0d0f11', sidebar: '#101315', panel: '#161a1d', border: '#23282c', text: '#e4e9ea', muted: '#8a949a', accent: '#35c2c8', sev: '#e2695f' } },
  { id: 'abyss', name: 'Abyss', desc: 'Deep ocean black · ice accent, the lowest-emission dark here', tone: 'dark', tags: ['night', 'blue', 'oled'], swatch: { bg: '#06090d', sidebar: '#080c11', panel: '#0d131a', border: '#1a2430', text: '#cfdae4', muted: '#77848f', accent: '#5ac8e8', sev: '#e0685f' } },
  { id: 'slate', name: 'Slate', desc: 'Blue-grey chrome · indigo accent, the most neutral dark', tone: 'dark', tags: ['grey', 'gray', 'blue', 'neutral'], swatch: { bg: '#0f1216', sidebar: '#12161b', panel: '#181d23', border: '#262d36', text: '#dde3ea', muted: '#87919d', accent: '#7c9cf5', sev: '#e4695f' } },
  { id: 'carbon', name: 'Carbon', desc: 'IBM Carbon greys · blue accent and its own status ramp', tone: 'dark', tags: ['ibm', 'grey', 'gray', 'blue', 'enterprise'], swatch: { bg: '#161616', sidebar: '#131313', panel: '#262626', border: '#393939', text: '#f4f4f4', muted: '#8d8d8d', accent: '#4589ff', sev: '#fa4d56' } },
  { id: 'graphite', name: 'Graphite', desc: 'Neutral grey · cyan accent', tone: 'dark', tags: ['grey', 'gray', 'cyan'], swatch: { bg: '#0d0e10', sidebar: '#0f1013', panel: '#131418', border: '#22242a', text: '#d5d8de', muted: '#61666f', accent: '#5fd7e8', sev: '#ff6b6b' } },
  { id: 'midnight-blue', name: 'Midnight blue', desc: 'Deep navy · blue accent', tone: 'dark', tags: ['navy', 'blue'], swatch: { bg: '#070b14', sidebar: '#090e19', panel: '#0c1220', border: '#172035', text: '#d3dae8', muted: '#5a657f', accent: '#6aa8ff', sev: '#ff6b6b' } },
  { id: 'nord', name: 'Nord', desc: 'Cool blue-grey · ice accent', tone: 'dark', tags: ['blue', 'grey', 'gray'], swatch: { bg: '#2e3440', sidebar: '#2b303b', panel: '#333a47', border: '#3f4757', text: '#e5e9f0', muted: '#8b97ab', accent: '#88c0d0', sev: '#bf616a' } },
  { id: 'moss', name: 'Moss', desc: 'Warm green-grey · sage accent, the least saturated dark', tone: 'dark', tags: ['green', 'sage', 'calm', 'long session'], swatch: { bg: '#0e120f', sidebar: '#111613', panel: '#161c18', border: '#232d26', text: '#dee5df', muted: '#86948a', accent: '#85c48c', sev: '#e0695f' } },
  { id: 'phosphor', name: 'Phosphor', desc: 'Near-black · muted terminal green, nothing glows', tone: 'dark', tags: ['green', 'terminal', 'crt'], swatch: { bg: '#0a0c0a', sidebar: '#0c0f0c', panel: '#111511', border: '#1f271f', text: '#d6e0d6', muted: '#7f8d7f', accent: '#62cf83', sev: '#e0655c' } },
  { id: 'plum', name: 'Plum', desc: 'Aubergine chrome · orchid accent', tone: 'dark', tags: ['purple', 'violet', 'mauve'], swatch: { bg: '#100d14', sidebar: '#131019', panel: '#191521', border: '#2a2438', text: '#e0dae8', muted: '#8b8099', accent: '#bb8ce0', sev: '#e26a70' } },
  { id: 'ember', name: 'Ember', desc: 'Warm charcoal · terracotta', tone: 'dark', tags: ['orange', 'red', 'warm'], swatch: { bg: '#141210', sidebar: '#171412', panel: '#1b1815', border: '#2c2622', text: '#e8ded6', muted: '#8a7c72', accent: '#e2725b', sev: '#e05252' } },
  { id: 'solar', name: 'Solar', desc: 'Warm dark · amber accent', tone: 'dark', tags: ['amber', 'yellow', 'warm'], swatch: { bg: '#100d0a', sidebar: '#130f0b', panel: '#17130e', border: '#2a2218', text: '#e2d9cb', muted: '#6d6252', accent: '#f5b342', sev: '#ff6f5c' } },

  { id: 'frost', name: 'Frost', desc: 'Light · cool near-white, slate blue — for a screen by a window', tone: 'light', tags: ['white', 'blue', 'bright room', 'print'], swatch: { bg: '#f2f5f9', sidebar: '#e9eef5', panel: '#ffffff', border: '#d5dde8', text: '#1f2a38', muted: '#6d7b8b', accent: '#2c6bb0', sev: '#b3352c' } },
  { id: 'daylight', name: 'Daylight', desc: 'Light · cool grey, blue accent', tone: 'light', tags: ['white', 'grey', 'gray', 'blue'], swatch: { bg: '#f7f8fa', sidebar: '#eef1f5', panel: '#ffffff', border: '#d8dee7', text: '#1f2733', muted: '#78859a', accent: '#2f6fd0', sev: '#c2312b' } },
  { id: 'paper', name: 'Paper', desc: 'Light · off-white, deep green', tone: 'light', tags: ['cream', 'green'], swatch: { bg: '#f4f2ec', sidebar: '#edeae2', panel: '#faf9f5', border: '#d9d5c9', text: '#2a2e28', muted: '#7d847a', accent: '#1f7a3d', sev: '#c9302c' } },
  { id: 'sepia', name: 'Sepia', desc: 'Light · warm paper, umber — for long reading rather than bright rooms', tone: 'light', tags: ['warm', 'brown', 'reading', 'notes'], swatch: { bg: '#f6f0e4', sidebar: '#efe7d8', panel: '#fdfaf3', border: '#ddd2ba', text: '#3a3226', muted: '#7e7460', accent: '#9a5b2d', sev: '#a63a2e' } },

  { id: 'contrast', name: 'High contrast', desc: 'Black · maximum separation', tone: 'contrast', tags: ['accessible', 'a11y', 'low vision', 'projector'], swatch: { bg: '#000000', sidebar: '#040404', panel: '#0a0a0a', border: '#3a3a3a', text: '#f2f2f2', muted: '#a0a0a0', accent: '#ffd400', sev: '#ff5c5c' } },
  { id: 'contrast-light', name: 'High contrast light', desc: 'White · black rules, one dark blue accent', tone: 'contrast', tags: ['accessible', 'a11y', 'low vision', 'projector', 'print'], swatch: { bg: '#ffffff', sidebar: '#f5f5f5', panel: '#fafafa', border: '#707070', text: '#0a0a0a', muted: '#454545', accent: '#0a49c4', sev: '#a30000' } },
];

export const TONE_LABEL: Record<Tone, string> = { dark: 'Dark', light: 'Light', contrast: 'High contrast' };
export const TONE_ORDER: Tone[] = ['dark', 'light', 'contrast'];

/** Does this theme match what was typed in the picker's filter? Name, description and the hidden
 *  tags, so "purple", "a11y" and "grey" find something even though no theme is called any of them. */
export function themeMatches(t: ThemeMeta, q: string): boolean {
  const s = q.trim().toLowerCase();
  if (!s) return true;
  return (t.name + ' ' + t.desc + ' ' + t.id + ' ' + (t.tags || []).join(' ')).toLowerCase().includes(s);
}

/** A face the analyst can choose.
 *
 *  `desc` names what the face is FOR rather than describing its letterforms — the point of the
 *  setting is legibility on the screen they actually have, and the sample beside it already shows
 *  the shapes better than a sentence can. `bundled` is false only for the system stack, which is
 *  whatever the OS has: everything else ships with Iris and is fetched from Iris, so choosing a
 *  font can never be a way for this page to phone home. */
export interface FaceMeta<Id extends string> { id: Id; name: string; desc: string; stack: string; bundled?: boolean }

export type FontMeta = FaceMeta<FontName>;
export const UI_FONTS: FontMeta[] = [
  { id: 'ibm-plex-sans', name: 'IBM Plex Sans', desc: 'Default · the console face, pairs with JetBrains Mono', stack: "'IBM Plex Sans', sans-serif", bundled: true },
  { id: 'inter', name: 'Inter', desc: 'Designed for screen UI at small sizes', stack: "'Inter', sans-serif", bundled: true },
  { id: 'geist', name: 'Geist', desc: 'Tight and modern · narrow, so more of a label fits', stack: "'Geist', sans-serif", bundled: true },
  { id: 'public-sans', name: 'Public Sans', desc: 'Plain and unstyled · built for dense official interfaces', stack: "'Public Sans', sans-serif", bundled: true },
  { id: 'source-sans', name: 'Source Sans 3', desc: 'Humanist · easy over long reading', stack: "'Source Sans 3', sans-serif", bundled: true },
  { id: 'atkinson', name: 'Atkinson Hyperlegible', desc: 'Drawn for low vision — every letter deliberately unlike its neighbours', stack: "'Atkinson Hyperlegible', sans-serif", bundled: true },
  { id: 'noto-sans', name: 'Noto Sans', desc: 'The widest script coverage · for logs that are not only Latin', stack: "'Noto Sans', sans-serif", bundled: true },
  { id: 'space-grotesk', name: 'Space Grotesk', desc: 'Geometric, slightly technical', stack: "'Space Grotesk', sans-serif", bundled: true },
  { id: 'system', name: 'System', desc: 'Whatever this OS uses · no webfont at all', stack: 'system-ui, sans-serif' },
];

export type MonoMeta = FaceMeta<MonoName>;
export const MONO_FONTS: MonoMeta[] = [
  { id: 'jetbrains-mono', name: 'JetBrains Mono', desc: 'Default · tall x-height, clear 0/O and 1/l', stack: "'JetBrains Mono', monospace", bundled: true },
  { id: 'ibm-plex-mono', name: 'IBM Plex Mono', desc: 'Narrower · fits more of a log line', stack: "'IBM Plex Mono', monospace", bundled: true },
  { id: 'geist-mono', name: 'Geist Mono', desc: 'Even and quiet · slashed zero', stack: "'Geist Mono', monospace", bundled: true },
  { id: 'roboto-mono', name: 'Roboto Mono', desc: 'Narrow · the most log lines per screen width', stack: "'Roboto Mono', monospace", bundled: true },
  { id: 'fira-code', name: 'Fira Code', desc: 'Dotted zero, very distinct l/1/I · ligatures are switched OFF here', stack: "'Fira Code', monospace", bundled: true },
  { id: 'red-hat-mono', name: 'Red Hat Mono', desc: 'Open apertures · holds up at small sizes', stack: "'Red Hat Mono', monospace", bundled: true },
  { id: 'source-code-pro', name: 'Source Code Pro', desc: 'Even width · calm in long dumps', stack: "'Source Code Pro', monospace", bundled: true },
  { id: 'system', name: 'System', desc: 'Whatever this OS uses · no webfont at all', stack: 'ui-monospace, monospace' },
];

/** The assistant's ANSWER column (ai-panel.css `--aic-serif`). It is a separate axis because it is a
 *  separate job: the interface face has to survive a 10px table head, this one only ever sets a
 *  paragraph someone is reading. `ui` opts out of the serif entirely. */
export type SerifMeta = FaceMeta<SerifName>;
export const SERIF_FONTS: SerifMeta[] = [
  { id: 'newsreader', name: 'Newsreader', desc: 'Default · the reading face the assistant panel was drawn for', stack: "'Newsreader', Georgia, serif", bundled: true },
  { id: 'source-serif', name: 'Source Serif 4', desc: 'Sturdier on screen · pairs with Source Sans', stack: "'Source Serif 4', Georgia, serif", bundled: true },
  { id: 'literata', name: 'Literata', desc: 'Drawn for e-readers · the easiest here over many paragraphs', stack: "'Literata', Georgia, serif", bundled: true },
  { id: 'lora', name: 'Lora', desc: 'Contrasted and slightly calligraphic', stack: "'Lora', Georgia, serif", bundled: true },
  { id: 'ui', name: 'Match interface', desc: 'No serif at all · sets the answer in the interface font', stack: 'var(--font-ui)' },
];

export const DEFAULT_FONT: FontName = 'ibm-plex-sans';
export const DEFAULT_MONO: MonoName = 'jetbrains-mono';
export const DEFAULT_SERIF: SerifName = 'newsreader';
export const isFontName = (v: unknown): v is FontName => UI_FONTS.some((f) => f.id === v);
export const isMonoName = (v: unknown): v is MonoName => MONO_FONTS.some((f) => f.id === v);
export const isSerifName = (v: unknown): v is SerifName => SERIF_FONTS.some((f) => f.id === v);

export const THEME_IDS: ThemeName[] = THEMES.map((t) => t.id);
export const DEFAULT_THEME: ThemeName = 'iris-dark';
export type Density = 'comfortable' | 'compact';

export function isThemeName(v: unknown): v is ThemeName {
  return typeof v === 'string' && (THEME_IDS as string[]).includes(v);
}

export function themeMeta(id: ThemeName): ThemeMeta {
  const hit = THEMES.find((t) => t.id === id);
  // THEMES is a non-empty literal, but `noUncheckedIndexedAccess` cannot know that and a
  // non-null assertion here would be the one place this file lied about its own invariant.
  return hit ?? (THEMES[0] as ThemeMeta);
}
