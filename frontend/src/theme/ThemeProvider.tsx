import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { FontName, MonoName, ThemeName } from '../api/types';
import { DEFAULT_FONT, DEFAULT_MONO, DEFAULT_THEME, isFontName, isMonoName, isThemeName, type Density } from './themes';

const THEME_KEY = 'iris.theme';
const DENSITY_KEY = 'iris.density';
const FONT_KEY = 'iris.font';
const MONO_KEY = 'iris.mono';

interface ThemeCtx {
  theme: ThemeName;
  density: Density;
  font: FontName;
  mono: MonoName;
  setTheme: (t: ThemeName) => void;
  setDensity: (d: Density) => void;
  setFont: (f: FontName) => void;
  setMono: (m: MonoName) => void;
}

const Ctx = createContext<ThemeCtx | null>(null);

function readTheme(): ThemeName {
  try {
    const v = localStorage.getItem(THEME_KEY);
    if (isThemeName(v)) return v;
  } catch {
    /* ignore */
  }
  return DEFAULT_THEME;
}
function readDensity(): Density {
  try {
    const v = localStorage.getItem(DENSITY_KEY);
    if (v === 'compact' || v === 'comfortable') return v;
  } catch {
    /* ignore */
  }
  return 'comfortable';
}

function readFont(): FontName {
  try {
    const v = localStorage.getItem(FONT_KEY);
    if (isFontName(v)) return v;
  } catch {
    /* ignore */
  }
  return DEFAULT_FONT;
}
function readMono(): MonoName {
  try {
    const v = localStorage.getItem(MONO_KEY);
    if (isMonoName(v)) return v;
  } catch {
    /* ignore */
  }
  return DEFAULT_MONO;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeName>(readTheme);
  const [density, setDensityState] = useState<Density>(readDensity);
  const [font, setFontState] = useState<FontName>(readFont);
  const [mono, setMonoState] = useState<MonoName>(readMono);

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
  useEffect(() => {
    document.documentElement.setAttribute('data-font', font);
    try {
      localStorage.setItem(FONT_KEY, font);
    } catch {
      /* ignore */
    }
  }, [font]);
  useEffect(() => {
    document.documentElement.setAttribute('data-mono', mono);
    try {
      localStorage.setItem(MONO_KEY, mono);
    } catch {
      /* ignore */
    }
  }, [mono]);

  const setTheme = useCallback((t: ThemeName) => setThemeState(t), []);
  const setDensity = useCallback((d: Density) => setDensityState(d), []);
  const setFont = useCallback((f: FontName) => setFontState(f), []);
  const setMono = useCallback((m: MonoName) => setMonoState(m), []);
  const value = useMemo(() => ({ theme, density, font, mono, setTheme, setDensity, setFont, setMono }),
    [theme, density, font, mono, setTheme, setDensity, setFont, setMono]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useTheme must be used inside ThemeProvider');
  return c;
}
