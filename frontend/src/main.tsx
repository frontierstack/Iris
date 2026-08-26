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
import './styles/cases.css';
import './styles/screens.css';
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
