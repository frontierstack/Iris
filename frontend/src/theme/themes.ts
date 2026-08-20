import type { FontName, MonoName, ThemeName } from '../api/types';

export interface ThemeMeta {
  id: ThemeName;
  name: string;
  desc: string;
  /** swatches for the preview card */
  swatch: { bg: string; sidebar: string; panel: string; border: string; text: string; muted: string; accent: string };
}

export const THEMES: ThemeMeta[] = [
  { id: 'iris-dark', name: 'Iris dark', desc: 'Default · green on near-black', swatch: { bg: '#0a0b0a', sidebar: '#0c0e0c', panel: '#0e110e', border: '#1c211c', text: '#d6dcd4', muted: '#5c665b', accent: '#6ee787' } },
  { id: 'graphite', name: 'Graphite', desc: 'Neutral grey · cyan accent', swatch: { bg: '#0d0e10', sidebar: '#0f1013', panel: '#131418', border: '#22242a', text: '#d5d8de', muted: '#61666f', accent: '#5fd7e8' } },
  { id: 'midnight-blue', name: 'Midnight blue', desc: 'Deep navy · blue accent', swatch: { bg: '#070b14', sidebar: '#090e19', panel: '#0c1220', border: '#172035', text: '#d3dae8', muted: '#5a657f', accent: '#6aa8ff' } },
  { id: 'solar', name: 'Solar', desc: 'Warm dark · amber accent', swatch: { bg: '#100d0a', sidebar: '#130f0b', panel: '#17130e', border: '#2a2218', text: '#e2d9cb', muted: '#6d6252', accent: '#f5b342' } },
  { id: 'paper', name: 'Paper', desc: 'Light · off-white, deep green', swatch: { bg: '#f4f2ec', sidebar: '#edeae2', panel: '#faf9f5', border: '#d9d5c9', text: '#2a2e28', muted: '#7d847a', accent: '#1f7a3d' } },
  { id: 'nord', name: 'Nord', desc: 'Cool blue-grey · ice accent', swatch: { bg: '#2e3440', sidebar: '#2b303b', panel: '#333a47', border: '#3f4757', text: '#e5e9f0', muted: '#8b97ab', accent: '#88c0d0' } },
  { id: 'ember', name: 'Ember', desc: 'Warm charcoal · terracotta', swatch: { bg: '#141210', sidebar: '#171412', panel: '#1b1815', border: '#2c2622', text: '#e8ded6', muted: '#8a7c72', accent: '#e2725b' } },
  { id: 'daylight', name: 'Daylight', desc: 'Light · cool grey, blue accent', swatch: { bg: '#f7f8fa', sidebar: '#eef1f5', panel: '#ffffff', border: '#d8dee7', text: '#1f2733', muted: '#78859a', accent: '#2f6fd0' } },
  { id: 'contrast', name: 'High contrast', desc: 'Black · maximum separation', swatch: { bg: '#000000', sidebar: '#040404', panel: '#0a0a0a', border: '#3a3a3a', text: '#f2f2f2', muted: '#a0a0a0', accent: '#ffd400' } },
];

/** The interface face. Every one is bundled (no runtime network request), and each entry names what
 *  it is FOR rather than describing the letterforms — the point of the setting is legibility on the
 *  screen the analyst actually has. */
export interface FontMeta { id: FontName; name: string; desc: string; stack: string }
export const UI_FONTS: FontMeta[] = [
  { id: 'space-grotesk', name: 'Space Grotesk', desc: 'Default · geometric, slightly technical', stack: "'Space Grotesk', sans-serif" },
  { id: 'inter', name: 'Inter', desc: 'Neutral · designed for screen UI at small sizes', stack: "'Inter', sans-serif" },
  { id: 'ibm-plex-sans', name: 'IBM Plex Sans', desc: 'Corporate-neutral · pairs with Plex Mono', stack: "'IBM Plex Sans', sans-serif" },
  { id: 'source-sans', name: 'Source Sans 3', desc: 'Humanist · easy over long reading', stack: "'Source Sans 3', sans-serif" },
  { id: 'system', name: 'System', desc: 'Whatever this OS uses · no webfont at all', stack: 'system-ui, sans-serif' },
];

export interface MonoMeta { id: MonoName; name: string; desc: string; stack: string }
export const MONO_FONTS: MonoMeta[] = [
  { id: 'jetbrains-mono', name: 'JetBrains Mono', desc: 'Default · tall x-height, clear 0/O and 1/l', stack: "'JetBrains Mono', monospace" },
  { id: 'ibm-plex-mono', name: 'IBM Plex Mono', desc: 'Narrower · fits more of a log line', stack: "'IBM Plex Mono', monospace" },
  { id: 'source-code-pro', name: 'Source Code Pro', desc: 'Even width · calm in long dumps', stack: "'Source Code Pro', monospace" },
  { id: 'system', name: 'System', desc: 'Whatever this OS uses · no webfont at all', stack: 'ui-monospace, monospace' },
];

export const DEFAULT_FONT: FontName = 'space-grotesk';
export const DEFAULT_MONO: MonoName = 'jetbrains-mono';
export const isFontName = (v: unknown): v is FontName => UI_FONTS.some((f) => f.id === v);
export const isMonoName = (v: unknown): v is MonoName => MONO_FONTS.some((f) => f.id === v);

export const THEME_IDS: ThemeName[] = THEMES.map((t) => t.id);
export const DEFAULT_THEME: ThemeName = 'iris-dark';
export type Density = 'comfortable' | 'compact';

export function isThemeName(v: unknown): v is ThemeName {
  return typeof v === 'string' && (THEME_IDS as string[]).includes(v);
}
