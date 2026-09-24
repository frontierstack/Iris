import React from 'react';
import ReactDOM from 'react-dom/client';
// ONLY THE THREE DEFAULT FACES ARE IMPORTED HERE, and the reason is first paint: this is the entry
// chunk, so anything in it is parsed before the first screen draws. Every other selectable face is
// code-split and fetched when it is chosen (theme/fontLoader.ts) — the list of faces can then grow
// without the default install paying for any of it. All of them are BUNDLED either way: Iris makes
// no network request at runtime, so a font cannot be a way for a page to phone home.
//
// The interface face...
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
// ...the monospace one, which is every log line, event id, address and hash...
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/700.css';
// ...and the SERIF, which belongs to the AI assistant's answer (styles/ai-panel.css `--aic-serif`):
// the template sets it in Newsreader at 19px/1.66 so the report reads like a document while
// everything around it stays mono or sans.
import '@fontsource/newsreader/300.css';
import '@fontsource/newsreader/400.css';
import '@fontsource/newsreader/500.css';
import './styles/themes.css';
import './styles/base.css';
import './styles/components.css';
import './styles/ai-panel.css';
import './styles/cases.css';
// One stylesheet per screen. `screens.css` had grown to 4,256 lines covering every screen in the
// app, so any change to any screen touched the same file; the sections were already marked and
// this is that split. `responsive.css` stays LAST of the screen files because its narrow-window
// rules have to win over the layouts they fall back from.
import './styles/screens/ingest.css';
import './styles/screens/search.css';
import './styles/screens/graph.css';
import './styles/screens/detail.css';
import './styles/screens/report.css';
import './styles/screens/settings.css';
import './styles/screens/cases.css';
import './styles/screens/anomalies.css';
import './styles/screens/responsive.css';
import './styles/notes.css';
import './styles/findings.css';
import './styles/graph-v2.css';
import './styles/rawlog.css';
import './styles/search-fields.css';
import './styles/chart.css';
import { App, preloadRouteChunk } from './App';

// Ask for THIS route's chunk now, not after React has rendered the shell and reached its Suspense
// boundary — see the note on `preloadRouteChunk`. It is one statement here because it has to run
// before anything else does any work; putting it inside a component would put it back behind the
// render it exists to overlap with.
preloadRouteChunk(window.location.pathname);

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
