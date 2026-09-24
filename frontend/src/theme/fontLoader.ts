/* Faces are fetched WHEN THEY ARE CHOSEN, not on every page load.
 *
 * Every family here is bundled with Iris (@fontsource, vendored into the build) — no runtime network
 * request ever leaves this origin, which is the property that must not change. What changed is WHEN
 * the bundle is read: main.tsx used to import all eight families eagerly, 28 stylesheets of
 * @font-face blocks across a dozen unicode-range subsets each, in the ENTRY chunk that first paint
 * waits on. Three of those families are the defaults and are still imported there, because a face
 * that arrives late is a visible reflow on the very first screen. The other seventeen are here.
 *
 * The map has to be written out literally: Vite resolves a dynamic import at BUILD time, and
 * `import('@fontsource/' + name + '/400.css')` gives it a variable it cannot follow — it would emit
 * a warning and ship nothing. One arrow function per family is the price of a code-split face.
 *
 * Resolution is remembered per family (`_loaded`), so switching back and forth costs one fetch, and a
 * failure is remembered as a failure rather than retried on every render: a face that will not load
 * degrades to the fallback stack in the CSS variable, which is the correct outcome and needs no
 * error path of its own.
 */
import type { FontName, MonoName, SerifName } from '../api/types';

type Loader = () => Promise<unknown>;

/** Families already in the entry bundle (main.tsx). Never lazy — first paint uses them. */
export const EAGER: ReadonlySet<string> = new Set(['ibm-plex-sans', 'jetbrains-mono', 'newsreader']);

const UI: Partial<Record<FontName, Loader>> = {
  inter: () => Promise.all([
    import('@fontsource/inter/400.css'), import('@fontsource/inter/500.css'),
    import('@fontsource/inter/600.css'), import('@fontsource/inter/700.css')]),
  'space-grotesk': () => Promise.all([
    import('@fontsource/space-grotesk/400.css'), import('@fontsource/space-grotesk/500.css'),
    import('@fontsource/space-grotesk/600.css'), import('@fontsource/space-grotesk/700.css')]),
  'source-sans': () => Promise.all([
    import('@fontsource/source-sans-3/400.css'), import('@fontsource/source-sans-3/600.css'),
    import('@fontsource/source-sans-3/700.css')]),
  geist: () => Promise.all([
    import('@fontsource/geist-sans/400.css'), import('@fontsource/geist-sans/500.css'),
    import('@fontsource/geist-sans/600.css'), import('@fontsource/geist-sans/700.css')]),
  'public-sans': () => Promise.all([
    import('@fontsource/public-sans/400.css'), import('@fontsource/public-sans/500.css'),
    import('@fontsource/public-sans/600.css'), import('@fontsource/public-sans/700.css')]),
  atkinson: () => Promise.all([
    import('@fontsource/atkinson-hyperlegible/400.css'),
    import('@fontsource/atkinson-hyperlegible/700.css')]),
  'noto-sans': () => Promise.all([
    import('@fontsource/noto-sans/400.css'), import('@fontsource/noto-sans/500.css'),
    import('@fontsource/noto-sans/600.css'), import('@fontsource/noto-sans/700.css')]),
};

const MONO: Partial<Record<MonoName, Loader>> = {
  'ibm-plex-mono': () => Promise.all([
    import('@fontsource/ibm-plex-mono/400.css'), import('@fontsource/ibm-plex-mono/500.css'),
    import('@fontsource/ibm-plex-mono/700.css')]),
  'source-code-pro': () => Promise.all([
    import('@fontsource/source-code-pro/400.css'), import('@fontsource/source-code-pro/500.css'),
    import('@fontsource/source-code-pro/700.css')]),
  'geist-mono': () => Promise.all([
    import('@fontsource/geist-mono/400.css'), import('@fontsource/geist-mono/500.css'),
    import('@fontsource/geist-mono/700.css')]),
  'roboto-mono': () => Promise.all([
    import('@fontsource/roboto-mono/400.css'), import('@fontsource/roboto-mono/500.css'),
    import('@fontsource/roboto-mono/700.css')]),
  'fira-code': () => Promise.all([
    import('@fontsource/fira-code/400.css'), import('@fontsource/fira-code/500.css'),
    import('@fontsource/fira-code/700.css')]),
  'red-hat-mono': () => Promise.all([
    import('@fontsource/red-hat-mono/400.css'), import('@fontsource/red-hat-mono/500.css'),
    import('@fontsource/red-hat-mono/700.css')]),
};

const SERIF: Partial<Record<SerifName, Loader>> = {
  'source-serif': () => Promise.all([
    import('@fontsource/source-serif-4/300.css'), import('@fontsource/source-serif-4/400.css'),
    import('@fontsource/source-serif-4/500.css')]),
  literata: () => Promise.all([
    import('@fontsource/literata/300.css'), import('@fontsource/literata/400.css'),
    import('@fontsource/literata/500.css')]),
  lora: () => Promise.all([
    import('@fontsource/lora/400.css'), import('@fontsource/lora/500.css')]),
};

const _loaded = new Map<string, Promise<unknown>>();

function run(kind: string, id: string, loader?: Loader): Promise<unknown> {
  if (!loader) return Promise.resolve();
  const key = kind + ':' + id;
  let p = _loaded.get(key);
  if (!p) {
    // A face that cannot be fetched must not become an unhandled rejection or a retry loop: the CSS
    // variable carries a real fallback stack, so the screen stays readable either way.
    p = loader().catch(() => undefined);
    _loaded.set(key, p);
  }
  return p;
}

export const loadUiFont = (id: FontName): Promise<unknown> => run('ui', id, UI[id]);
export const loadMonoFont = (id: MonoName): Promise<unknown> => run('mono', id, MONO[id]);
export const loadSerifFont = (id: SerifName): Promise<unknown> => run('serif', id, SERIF[id]);

/** Fetch a face so it is ready before it is chosen — the settings picker calls this on hover and on
 *  first render, so the sample beside each name is set in the face it is naming rather than in the
 *  fallback. It is the same promise `loadUiFont` would return, so nothing is fetched twice. */
export function preloadFaces(ui: FontName[], mono: MonoName[], serif: SerifName[] = []): void {
  ui.forEach((id) => { void loadUiFont(id); });
  mono.forEach((id) => { void loadMonoFont(id); });
  serif.forEach((id) => { void loadSerifFont(id); });
}
