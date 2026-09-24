import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { FontName, MonoName, SerifName, ThemeName } from '../api/types';
import { loadMonoFont, loadSerifFont, loadUiFont } from './fontLoader';
import {
  DEFAULT_FONT, DEFAULT_MONO, DEFAULT_SERIF, DEFAULT_THEME,
  isFontName, isMonoName, isSerifName, isThemeName, type Density,
} from './themes';

const THEME_KEY = 'iris.theme';
const DENSITY_KEY = 'iris.density';
const FONT_KEY = 'iris.font';
const MONO_KEY = 'iris.mono';
const SERIF_KEY = 'iris.serif';

interface ThemeCtx {
  theme: ThemeName;
  density: Density;
  font: FontName;
  mono: MonoName;
  serif: SerifName;
  setTheme: (t: ThemeName) => void;
  setDensity: (d: Density) => void;
  setFont: (f: FontName) => void;
  setMono: (m: MonoName) => void;
  setSerif: (s: SerifName) => void;
}

const Ctx = createContext<ThemeCtx | null>(null);

/** One read of localStorage, validated. Every one of these is inside a try: a private window, blocked
 *  site data or a cleared profile makes the accessor THROW rather than return null, and a theme that
 *  cannot be remembered must still render. */
function read<T>(key: string, ok: (v: unknown) => v is T, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    if (ok(v)) return v;
  } catch {
    /* ignore */
  }
  return fallback;
}

const isDensity = (v: unknown): v is Density => v === 'compact' || v === 'comfortable';

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeName>(() => read(THEME_KEY, isThemeName, DEFAULT_THEME));
  const [density, setDensityState] = useState<Density>(() => read(DENSITY_KEY, isDensity, 'comfortable'));
  const [font, setFontState] = useState<FontName>(() => read(FONT_KEY, isFontName, DEFAULT_FONT));
  const [mono, setMonoState] = useState<MonoName>(() => read(MONO_KEY, isMonoName, DEFAULT_MONO));
  const [serif, setSerifState] = useState<SerifName>(() => read(SERIF_KEY, isSerifName, DEFAULT_SERIF));

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  useEffect(() => {
    document.documentElement.setAttribute('data-density', density);
    try {
      localStorage.setItem(DENSITY_KEY, density);
    } catch {
      /* ignore */
    }
  }, [density]);

  // The faces are attributes on :root, exactly like the theme — one attribute write, no re-render of
  // anything. See styles/base.css for the stacks each one selects.
  //
  // The ATTRIBUTE IS SET FIRST AND THE FACE IS FETCHED AFTER, on purpose. Only the three defaults are
  // in the entry bundle (theme/fontLoader.ts), so a remembered choice of any other face has to be
  // loaded — and until it lands the CSS variable's own fallback stack is what draws, which is the
  // right outcome and needs no loading state. Setting the attribute after the await instead would
  // leave the previously chosen face on screen while the new one downloaded, which reads as a click
  // that did nothing.
  useEffect(() => {
    document.documentElement.setAttribute('data-font', font);
    void loadUiFont(font);
    try {
      localStorage.setItem(FONT_KEY, font);
    } catch {
      /* ignore */
    }
  }, [font]);
  useEffect(() => {
    document.documentElement.setAttribute('data-mono', mono);
    void loadMonoFont(mono);
    try {
      localStorage.setItem(MONO_KEY, mono);
    } catch {
      /* ignore */
    }
  }, [mono]);
  useEffect(() => {
    document.documentElement.setAttribute('data-serif', serif);
    void loadSerifFont(serif);
    try {
      localStorage.setItem(SERIF_KEY, serif);
    } catch {
      /* ignore */
    }
  }, [serif]);

  const setTheme = useCallback((t: ThemeName) => setThemeState(t), []);
  const setDensity = useCallback((d: Density) => setDensityState(d), []);
  const setFont = useCallback((f: FontName) => setFontState(f), []);
  const setMono = useCallback((m: MonoName) => setMonoState(m), []);
  const setSerif = useCallback((s: SerifName) => setSerifState(s), []);
  const value = useMemo(
    () => ({ theme, density, font, mono, serif, setTheme, setDensity, setFont, setMono, setSerif }),
    [theme, density, font, mono, serif, setTheme, setDensity, setFont, setMono, setSerif]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useTheme must be used inside ThemeProvider');
  return c;
}
