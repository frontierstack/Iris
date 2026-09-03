import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource/space-grotesk/400.css';
import '@fontsource/space-grotesk/500.css';
import '@fontsource/space-grotesk/600.css';
import '@fontsource/space-grotesk/700.css';
// The other faces an analyst can choose in Settings -> Appearance. All BUNDLED: Iris makes no
// network request at runtime, so a font cannot be a way for a page to phone home.
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/source-sans-3/400.css';
import '@fontsource/source-sans-3/600.css';
import '@fontsource/source-sans-3/700.css';
// The SERIF, and the one face that is not selectable in Settings: it belongs to the AI assistant's
// answer (styles/ai-panel.css `--aic-serif`), which the template sets in Newsreader at 19px/1.66 so
// the report reads like a document while everything around it stays mono or sans. Bundled like the
// rest — the app never fetches a font at runtime, so there is no <link> to Google Fonts anywhere.
import '@fontsource/newsreader/300.css';
import '@fontsource/newsreader/400.css';
import '@fontsource/newsreader/500.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import '@fontsource/ibm-plex-mono/700.css';
import '@fontsource/source-code-pro/400.css';
import '@fontsource/source-code-pro/500.css';
import '@fontsource/source-code-pro/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/700.css';
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
