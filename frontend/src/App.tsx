import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AiPanelProvider } from './components/AiPanel';
import { AppShell } from './components/Layout';
import { LoginGate } from './components/LoginGate';
import { useCase, useSettings } from './hooks/queries';
import { ToastProvider } from './hooks/useToast';
import { AnomaliesScreen } from './screens/AnomaliesScreen';
import { CaseDetailScreen } from './screens/CaseDetailScreen';
import { CasesScreen } from './screens/CasesScreen';
import { EventDetailScreen } from './screens/EventDetailScreen';
import { GraphScreen } from './screens/GraphScreen';
import { IngestScreen } from './screens/IngestScreen';
import { SearchScreen } from './screens/SearchScreen';
import { SettingsScreen } from './screens/SettingsScreen';
import { ThemeProvider, useTheme } from './theme/ThemeProvider';
import { isThemeName } from './theme/themes';

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
