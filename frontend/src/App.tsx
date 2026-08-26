import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { lazy, useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AiPanelProvider } from './components/AiPanelContext';
import { AppShell } from './components/Layout';
import { LoginGate } from './components/LoginGate';
import { useCase, useSettings } from './hooks/queries';
import { ToastProvider } from './hooks/useToast';
import { ThemeProvider, useTheme } from './theme/ThemeProvider';
import { isThemeName } from './theme/themes';

/**
 * EVERY SCREEN IS ITS OWN CHUNK.
 *
 * The app used to ship as ONE 634 KB script, so an analyst opening /search downloaded, parsed and
 * evaluated the entity graph (d3-force, the quadtree, the canvas painter), the whole rules manager and
 * the Settings screen before their first result rendered. None of that is reachable from the screen
 * they asked for. `lazy()` moves each route into a chunk that is fetched when the route is entered.
 *
 * The `.then(m => ({ default: … }))` is because these are NAMED exports and `lazy` wants a default —
 * adding a default export to each screen would leave two names for one component, which is how the two
 * eventually drift. The loader is written out per screen rather than hidden behind a helper so the
 * import specifier stays a literal: Vite resolves and pre-bundles dynamic imports statically, and a
 * computed path silently degrades to no split at all.
 *
 * The Suspense boundary is INSIDE the shell (`Layout.AppShell`, around the Outlet), so the sidebar and
 * the header are painted while a route chunk arrives — see the note there about its fallback.
 */
const load = {
  anomalies: () => import('./screens/AnomaliesScreen').then((m) => ({ default: m.AnomaliesScreen })),
  caseDetail: () => import('./screens/CaseDetailScreen').then((m) => ({ default: m.CaseDetailScreen })),
  cases: () => import('./screens/CasesScreen').then((m) => ({ default: m.CasesScreen })),
  eventDetail: () => import('./screens/EventDetailScreen').then((m) => ({ default: m.EventDetailScreen })),
  graph: () => import('./screens/GraphScreen').then((m) => ({ default: m.GraphScreen })),
  ingest: () => import('./screens/IngestScreen').then((m) => ({ default: m.IngestScreen })),
  search: () => import('./screens/SearchScreen').then((m) => ({ default: m.SearchScreen })),
  settings: () => import('./screens/SettingsScreen').then((m) => ({ default: m.SettingsScreen })),
};

const AnomaliesScreen = lazy(load.anomalies);
const CaseDetailScreen = lazy(load.caseDetail);
const CasesScreen = lazy(load.cases);
const EventDetailScreen = lazy(load.eventDetail);
const GraphScreen = lazy(load.graph);
const IngestScreen = lazy(load.ingest);
const SearchScreen = lazy(load.search);
const SettingsScreen = lazy(load.settings);

/**
 * START THE ROUTE'S CHUNK BEFORE REACT DOES — the split is a REGRESSION without this, and it was
 * measured as one.
 *
 * `lazy()` on its own serialises the load: the browser fetches the entry, evaluates it, React renders
 * the shell, reaches the Suspense boundary, and only THEN discovers which chunk it needs and asks for
 * it. Two round trips where there was one. Measured cold on /search against the live instance (median
 * of 7, cache disabled): the shell painted sooner (FCP 124 → 96 ms) but the SEARCH SCREEN ITSELF
 * appeared LATER — 101 → 190 ms, and 353 → 506 ms with the CPU throttled 4x. Faster to a sidebar and
 * slower to the evidence is not a win; it is the same page dressed as a quicker one.
 *
 * `main.tsx` calls this the moment the entry evaluates, so the chunk is in flight while React is still
 * bootstrapping and the two costs overlap. It is the same loader object `lazy()` holds, so it is the
 * same specifier, the same chunk and the same module promise — the browser's module registry dedupes
 * it, and `lazy` gets a promise that is already resolving rather than starting a second fetch.
 *
 * Getting the path wrong costs a chunk that is never used, never an error: unknown paths preload
 * nothing, and `lazy` still loads whatever the router actually renders.
 */
export function preloadRouteChunk(pathname: string): void {
  const p = pathname.toLowerCase();
  const pick =
    p === '/' || p.startsWith('/ingest') ? load.ingest
    : p.startsWith('/search') ? load.search
    : p.startsWith('/anomalies') ? load.anomalies
    : p.startsWith('/graph') ? load.graph
    : p.startsWith('/events/') ? load.eventDetail
    : p.startsWith('/cases/') ? load.caseDetail
    : p.startsWith('/cases') ? load.cases
    : p.startsWith('/settings') ? load.settings
    : null;
  // A rejected preload must not become an unhandled rejection: `lazy` retries and reports properly.
  if (pick) void pick().catch(() => {});
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 5_000 },
  },
});

/** On first load, adopt the server-side theme if the browser has none persisted yet. */
function ThemeSync() {
  const settings = useSettings();
  const { setTheme } = useTheme();
  useEffect(() => {
    if (!settings.data) return;
    let stored: string | null = null;
    try { stored = localStorage.getItem('iris.theme'); } catch { /* ignore */ }
    if (!stored && isThemeName(settings.data.theme)) setTheme(settings.data.theme);
  }, [settings.data, setTheme]);
  return null;
}

/**
 * `/report` used to be the standalone Findings page and `/timeline` the global cluster view. Both now
 * live on the case detail screen, so send old links to the active case (or the case list when there is
 * no case yet).
 */
function ReportRedirect() {
  const c = useCase();
  if (c.isLoading) return null;
  const id = c.data && !c.data.pending ? c.data.id : null;
  return <Navigate to={id ? `/cases/${encodeURIComponent(id)}` : '/cases'} replace />;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <ToastProvider>
          <BrowserRouter>
            {/* The gate wraps the router, not a route: every screen is behind it, and a deep link to
                /search must land on the login page rather than on a 401-shaped empty screen. */}
            <LoginGate>
            <AiPanelProvider>
              <ThemeSync />
              <Routes>
                <Route element={<AppShell />}>
                  <Route index element={<Navigate to="/ingest" replace />} />
                  <Route path="/cases" element={<CasesScreen />} />
                  <Route path="/cases/:id" element={<CaseDetailScreen />} />
                  <Route path="/ingest" element={<IngestScreen />} />
                  <Route path="/search" element={<SearchScreen />} />
                  <Route path="/anomalies" element={<AnomaliesScreen />} />
                  {/* Timeline is a property of a case now (the curated events, in order), not a global
                      screen — old links land on the case that owns one. */}
                  <Route path="/timeline" element={<ReportRedirect />} />
                  <Route path="/graph" element={<GraphScreen />} />
                  <Route path="/events/:id" element={<EventDetailScreen />} />
                  {/* the Findings page was folded into the case detail screen — keep old links working */}
                  <Route path="/report" element={<ReportRedirect />} />
                  <Route path="/settings" element={<SettingsScreen />} />
                  <Route path="*" element={<Navigate to="/ingest" replace />} />
                </Route>
              </Routes>
            </AiPanelProvider>
            </LoginGate>
          </BrowserRouter>
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
