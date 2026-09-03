import { useQuery } from '@tanstack/react-query';
import { Suspense, useEffect, useMemo, useState, type ReactNode, useRef } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { qk, useAnomalyCount, useCase, useCases, useHealth, useInvalidateCaseData } from '../hooks/queries';
import { useHotkey } from '../hooks/useHotkey';
import type { PoolProgress } from '../api/types';
import { cx, fmtBytes, fmtCompact, fmtEta } from '../utils/format';
import { useAiPanel } from './AiPanelContext';
import { EnrichBanner } from './Enrichment';
import { Icon } from './icons';
import { Toasts } from './ui';

/** `alert` gives the count the template's tinted badge rather than a quiet figure. There is no icon
 *  field: this rail is TEXT (see the note in components.css). */
interface NavDef { to: string; label: string; tag: string; alert?: boolean }
interface NavGroup { id: string; label: string; items: NavDef[] }

function useScreenMeta(): { crumb: string; title: string; sub: string } {
  const { pathname } = useLocation();
  const c = useCase().data;
  // the POOL, not the case: analysis spans every ingested source, with or without a case
  const nSrc = (c?.sources.length ?? 0) + (c?.librarySources.length ?? 0);
  const nEv = c?.poolEventCount ?? 0;
  if (pathname.startsWith('/cases')) return { crumb: 'Workbench', title: 'Cases', sub: 'every investigation on disk — one is active at a time' };
  if (pathname.startsWith('/search')) return { crumb: 'Workbench', title: 'Search', sub: 'normalized fields across every parser' };
  if (pathname.startsWith('/anomalies')) return { crumb: 'Workbench', title: 'Anomalies', sub: 'rules with hits across every ingested source · built-in and custom detections' };
  if (pathname.startsWith('/graph'))
    return { crumb: 'Workbench', title: 'Entity graph', sub: 'IPs, accounts, hosts, processes, files — linked by what happened between them' };
  if (pathname.startsWith('/events/')) return { crumb: 'Search', title: 'Event detail', sub: 'with the reasoning behind every correlation' };
  if (pathname.startsWith('/settings')) return { crumb: 'System', title: 'Settings', sub: 'appearance · compute · AI assistant · case · data' };
  return { crumb: 'Workbench', title: 'Sources', sub: `${nSrc} file${nSrc === 1 ? '' : 's'} · ${fmtCompact(nEv)} events normalized` };
}

const GROUP_KEY = 'iris.nav.collapsed';
function readCollapsed(): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(GROUP_KEY) ?? '{}') as Record<string, boolean>; } catch { return {}; }
}

/** Per-group nav order the analyst set by dragging: { groupId: [to, to, …] }. Unknown/new items fall to the end. */
const ORDER_KEY = 'iris.nav.order';
type NavOrder = Record<string, string[]>;
function readOrder(): NavOrder {
  try {
    const raw = JSON.parse(localStorage.getItem(ORDER_KEY) ?? '{}') as unknown;
    if (!raw || typeof raw !== 'object') return {};
    const out: NavOrder = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      if (Array.isArray(v) && v.every((x) => typeof x === 'string')) out[k] = v as string[];
    }
    return out;
  } catch { return {}; }
}
function applyOrder(items: NavDef[], saved: string[] | undefined): NavDef[] {
  if (!saved?.length) return items;
  const rank = new Map(saved.map((to, i) => [to, i]));
  // Array.prototype.sort is stable, so items missing from `saved` keep their declared order at the end.
  return [...items].sort((a, b) => (rank.get(a.to) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.to) ?? Number.MAX_SAFE_INTEGER));
}

export function Sidebar() {
  const c = useCase();
  const cases = useCases();
  const anomalies = useAnomalyCount();
  const health = useHealth();
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(readCollapsed);
  const toggleGroup = (id: string) =>
    setCollapsed((s) => {
      const n = { ...s, [id]: !s[id] };
      try { localStorage.setItem(GROUP_KEY, JSON.stringify(n)); } catch { /* ignore */ }
      return n;
    });

  const baseGroups: NavGroup[] = useMemo(() => {
    const d = c.data;
    // The template's rail is grouped by WHAT YOU ARE DOING, not by which part of the app owns the
    // screen — EXPLORE / DATA / MONITOR, each a short group with its own label. Iris's screens map
    // onto that directly: two you ask questions with, two that are the evidence itself, one that
    // watches it, and the machine.
    return [
      {
        id: 'explore',
        label: 'Explore',
        items: [
          { to: '/search', label: 'Search', tag: d ? fmtCompact(d.poolEventCount) : '' },
          // No graph request from the sidebar. `useGraph` here made EVERY page start a full entity
          // extraction after every store bump — during a 300 MB library load that was a six-worker
          // build every few seconds, each thrown away on the next bump, and on a memory-tight WSL2 VM
          // it helped push the process into a segfault. A nav badge is not worth a 100-second build.
          { to: '/graph', label: 'Entity graph', tag: '' },
        ],
      },
      {
        id: 'data',
        label: 'Data',
        items: [
          { to: '/ingest', label: 'Sources', tag: d ? String(d.sources.length + d.librarySources.length) : '' },
          // No Timeline entry: the timeline is a property of a CASE (the curated events, in order),
          // not a global screen — it lives on the case detail page.
          { to: '/cases', label: 'Cases', tag: cases.data ? String(cases.data.length) : '' },
        ],
      },
      {
        id: 'monitor',
        label: 'Monitor',
        items: [
          { to: '/anomalies', label: 'Anomalies', tag: anomalies.data === undefined ? '' : String(anomalies.data),
            glyph: 'anomalies', alert: !!anomalies.data },
        ],
      },
      { id: 'system', label: 'System', items: [{ to: '/settings', label: 'Settings', tag: '' }] },
    ];
  }, [c.data, cases.data, anomalies.data]);

  /* ── drag to reorder nav items (within a group) ── */
  const [order, setOrder] = useState<NavOrder>(readOrder);
  const [dragging, setDragging] = useState<string | null>(null);
  const dragGroup = useRef<string | null>(null);

  const groups = useMemo(() => baseGroups.map((grp) => ({ ...grp, items: applyOrder(grp.items, order[grp.id]) })), [baseGroups, order]);

  const persist = (next: NavOrder) => {
    setOrder(next);
    try { localStorage.setItem(ORDER_KEY, JSON.stringify(next)); } catch { /* ignore */ }
  };
  const onItemDragStart = (grpId: string, to: string) => (e: React.DragEvent) => {
    dragGroup.current = grpId;
    setDragging(to);
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', to); // Firefox needs payload for the drag to start
  };
  const onItemDragOver = (grpId: string, overTo: string) => (e: React.DragEvent) => {
    const from = dragging;
    if (!from || dragGroup.current !== grpId) return;
    e.preventDefault(); // marks this a valid drop target
    e.dataTransfer.dropEffect = 'move';
    if (from === overTo) return;
    const cur = groups.find((x) => x.id === grpId)?.items.map((i) => i.to) ?? [];
    const fromIdx = cur.indexOf(from);
    const overIdx = cur.indexOf(overTo);
    if (fromIdx < 0 || overIdx < 0) return;
    const next = [...cur];
    next.splice(overIdx, 0, ...next.splice(fromIdx, 1));
    persist({ ...order, [grpId]: next });
  };
  const endDrag = () => { setDragging(null); dragGroup.current = null; };
  const resetOrder = (grpId: string) => {
    const { [grpId]: _drop, ...rest } = order;
    persist(rest);
  };

  const online = !health.isError;
  return (
    <div className="sidebar-slot">
    <aside className="sidebar">
      {/* THE BRAND IS THE WORDMARK ALONE. The template puts a rotated accent lozenge beside its
          wordmark and that was transcribed; it went the same way the eye glyph did, on sight
          ("Remove this Iris icon, sidebar__mark"). What is left is the row's height — exactly the
          header's, so the sidebar rule and the header rule are one continuous line across the
          window — the wordmark, and the health light as a DOT rather than the line of prose that
          used to sit under it. */}
      <div className="sidebar__brand">
        <div className="sidebar__brand-row">
          <div className="sidebar__brand-text">
            <div className="sidebar__logo">IRIS</div>
            <div className="sidebar__tag">
              <span
                className={online ? 'sidebar__dot' : 'sidebar__dot sidebar__dot--offline'}
                title={online ? `API online${health.data ? ` · v${health.data.version}` : ''}` : 'API unreachable'}
              />
            </div>
          </div>
        </div>
      </div>

      {/* The "Active case" panel that used to sit here is gone on request: a five-line block repeating
          what the header already shows, in the one place that has to stay narrow. The active case is
          named in the header and on the Cases page. */}

      <nav className="sidebar__nav" aria-label="Screens">
        {groups.map((grp) => {
          const isCollapsed = !!collapsed[grp.id];
          const reorderable = grp.items.length > 1;
          return (
            <div key={grp.id} className={cx('nav-group', isCollapsed && 'collapsed')}>
              <div className="nav-group__row">
                <button className="nav-group__head" onClick={() => toggleGroup(grp.id)} aria-expanded={!isCollapsed}>
                  {grp.label}
                  <Icon.Chevron className="nav-group__caret" />
                </button>
                {reorderable && order[grp.id] && (
                  <button className="nav-group__reset" onClick={() => resetOrder(grp.id)} title="Restore the default order of these items">reset</button>
                )}
              </div>
              {!isCollapsed &&
                grp.items.map((n) => (
                  <NavLink
                    key={n.to}
                    to={n.to}
                    className={({ isActive }) => cx('nav-item', isActive && 'active', dragging === n.to && 'dragging')}
                    draggable={reorderable}
                    onDragStart={reorderable ? onItemDragStart(grp.id, n.to) : undefined}
                    onDragOver={reorderable ? onItemDragOver(grp.id, n.to) : undefined}
                    onDrop={reorderable ? (e) => { e.preventDefault(); endDrag(); } : undefined}
                    onDragEnd={reorderable ? endDrag : undefined}
                  >
                    {reorderable && <Icon.Grip className="nav-item__grip" aria-hidden />}
                    <span className="nav-item__label">{n.label}</span>
                    {/* A ZERO is not a count worth drawing. The template puts a badge on the one nav
                        item that has something waiting and nothing on the rest; a column of "0"s is
                        four numbers saying there is nothing to see. */}
                    <span className={cx('nav-item__tag', n.alert && 'nav-item__tag--alert')}>{n.tag === '0' ? '' : n.tag}</span>
                  </NavLink>
                ))}
            </div>
          );
        })}
      </nav>

      <div className="sidebar__foot">
        <div className="sidebar__hints">
          <div className="sidebar__hint"><span>Focus search</span><span className="kbd">/</span></div>
          <div className="sidebar__hint"><span>Ask AI about case</span><span><span className="kbd">⇧</span> <span className="kbd">A</span></span></div>
        </div>
        {/* The template's identity block. Iris has no user model and is not getting one — one
            analyst, one machine, one evidence pool — so what it states is the WORKSPACE: the build
            that is running and whether the API is answering. */}
        <div className="sidebar__ver">
          <div className="sidebar__ver-mark" aria-hidden>IR</div>
          <div className="sidebar__ver-text">
            <div className="sidebar__ver-name">Iris {health.data ? `v${health.data.version}` : ''}</div>
            <div className={cx('sidebar__ver-role', !online && 'sidebar__ver-role--off')}>{online ? 'API online' : 'API unreachable'}</div>
          </div>
        </div>
      </div>
    </aside>
    </div>
  );
}

/* A big library loads in the background so the API is up immediately — say so, or a half-filled pool
   reads as missing data on every analysis screen. "N more sources" was NOT progress: on the real library
   one of those files is 263 MB and the rest are 2 MB each, so the count sat still for ten minutes. This
   shows the bytes, the file being worked on, and an ETA. */
function PoolLoadingSub({ p, pending }: { p: PoolProgress | null; pending: number }) {
  if (!p || !p.bytesTotal) return <>{`loading ${pending} more source${pending === 1 ? '' : 's'} — results are still filling in`}</>;
  const bits = [
    `loading ${Math.round(p.pct)}%`,
    `${fmtBytes(p.bytesDone)} of ${fmtBytes(p.bytesTotal)}`,
    `${p.filesDone}/${p.filesTotal} files`,
    p.currentFile ? `${p.currentFile}${p.currentBytesTotal ? ` ${Math.round(p.currentPct)}%` : ''}` : '',
    fmtEta(p.etaSec),
  ].filter(Boolean);
  return (
    <>
      <span className="header__bar" aria-hidden><i style={{ width: `${Math.min(100, p.pct)}%` }} /></span>
      {bits.join(' · ')} — results are still filling in
    </>
  );
}

function useUtcClock(): string {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(t);
  }, []);
  return now.toISOString().slice(11, 19);
}

function ComputeBadge() {
  const q = useQuery({ queryKey: qk.compute, queryFn: api.compute, refetchInterval: 60_000, retry: false });
  const nav = useNavigate();
  const s = q.data;
  const active = s?.active ?? 'cpu';
  const title = s
    ? `${active.toUpperCase()} · backend ${s.backend}${s.gpus[0] ? ` · ${s.gpus[0].name}` : ''}${s.error ? ` · ${s.error}` : ''}`
    : 'Compute status';
  // The template's "live tail" control: it TINTS when the thing it reports is actually happening,
  // and its dot is the one element in this design that animates a colour. Here that is the GPU
  // carrying the work — the only state on this bar that is live rather than static.
  const live = active === 'cuda';
  return (
    <button className={cx('btn btn--sm', live ? 'btn--live' : 'btn--field')} title={title} onClick={() => nav('/settings#compute')}>
      {live ? <span className="btn__live-dot" aria-hidden /> : <Icon.Cpu width={11} height={11} />}
      {s ? active : '…'}
    </button>
  );
}

export function Header() {
  const meta = useScreenMeta();
  const c = useCase();
  const nav = useNavigate();
  const ai = useAiPanel();
  const clock = useUtcClock();
  const inCase = c.data?.caseSet.length ?? 0;
  const loc = useLocation();
  // Findings now live on the case detail screen; with no case yet, fall back to the case list
  const caseHref = c.data && !c.data.pending ? `/cases/${encodeURIComponent(c.data.id)}` : '/cases';
  // history.state.idx is set by react-router's history — >0 means there is an in-app page to go back to
  const canGoBack = typeof window !== 'undefined' && (window.history.state?.idx ?? 0) > 0;
  return (
    <header className="header">
      <div className="header__crumbs">
        <button
          className="btn btn--sm btn--icon header__back"
          onClick={() => (canGoBack ? nav(-1) : nav('/ingest'))}
          title={canGoBack ? 'Back (Alt+←)' : 'Sources'}
          aria-label="Back"
          disabled={!canGoBack && loc.pathname === '/ingest'}
        >
          <Icon.ArrowLeft />
        </button>
        <span className="header__crumb">{meta.crumb}</span>
        <span className="header__crumb-sep">/</span>
        <div className="header__title">{meta.title}</div>
        {/* The template parks the environment after the title, because every figure on the screen is
            read against it. Here that context is the ACTIVE CASE — and when there is none, it says
            so as a normal state (a case is optional; every analysis screen works without one). */}
        <button
          className="header__ctx"
          onClick={() => nav(caseHref)}
          title={c.data && !c.data.pending ? `Active case: ${c.data.name} (${c.data.id})` : 'No active case — analysis spans the whole workspace'}
        >
          {c.data && !c.data.pending ? c.data.name : 'no case'}
        </button>
      </div>
      {/* A big library loads in the background so the API is up immediately — say so, or a half-filled
          pool reads as missing data on every analysis screen. */}
      <div className="header__sub">
        {c.data?.poolLoading ? <PoolLoadingSub p={c.data.poolProgress} pending={c.data.poolPending} /> : meta.sub}
      </div>
      <div className="header__right">
        <span className="header__utc" title="Coordinated Universal Time"><b>{clock}</b> UTC</span>
        <button className="btn btn--sm btn--field" title="Events curated into this case" onClick={() => nav(caseHref)}>
          <Icon.Check width={11} height={11} />
          {inCase} in case
        </button>
        <ComputeBadge />
        <span className="header__sep" />
        <button className="btn btn--sm btn--field" onClick={() => ai.open({ scope: 'case', label: c.data?.name ?? 'Active case' })} title="Ask the AI assistant about this case (Shift+A)">
          <Icon.Sparkle />
          Assistant
        </button>
      </div>
    </header>
  );
}

export function AppShell({ children }: { children?: ReactNode }) {
  const { pathname } = useLocation();
  const nav = useNavigate();
  const ai = useAiPanel();
  const c = useCase();
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [pathname]);
  // "/" anywhere jumps to search (the Search screen itself focuses the input)
  useHotkey('/', (e) => {
    if (pathname.startsWith('/search')) return;
    e.preventDefault();
    nav('/search');
    window.setTimeout(() => (document.querySelector<HTMLInputElement>('.search__input input') ?? undefined)?.focus(), 50);
  });
  // The background pool load finishes without any request from the UI, so every derived query (search,
  // timeline, graph, anomalies, IOCs) is stale the moment it does. Refresh them once, on the transition.
  const poolLoading = !!c.data?.poolLoading;
  const wasLoading = useRef(poolLoading);
  const invalidateCaseData = useInvalidateCaseData();
  useEffect(() => {
    if (wasLoading.current && !poolLoading) invalidateCaseData();
    wasLoading.current = poolLoading;
  }, [poolLoading, invalidateCaseData]);
  useHotkey('A', (e) => {
    if (!e.shiftKey) return;
    e.preventDefault();
    ai.open({ scope: 'case', label: c.data?.name ?? 'Active case' });
  });
  return (
    <div className="app">
      <Sidebar />
      <main className="main">
        <Header />
        {/* Two-phase ingest: while sources are still raw, every derived screen is answering over part
            of the corpus. The strip removes itself the moment nothing is outstanding — a `skipped`
            source is a decision, not an omission, and never keeps it alive. */}
        <EnrichBanner />
        {/* Each screen is its own chunk (see App.tsx). The boundary sits HERE, inside the shell, so the
            sidebar, the header and the banner stay painted while a route's code arrives — a boundary
            around the router would blank the whole window instead.

            The fallback is NOTHING, on purpose, and the trade is stated rather than hidden: for the few
            milliseconds a chunk takes, the content area is EMPTY while the shell stays put. These chunks
            are same-origin, content-hashed and served `immutable` (see "Deploying: FOUR caches"), so
            after the first visit the load is a cache read, and the first visit after a deploy is one
            local request — measured cold, cache disabled, on this host at ~30 ms for the largest of
            them (the graph). A spinner that appears and disappears inside one
            frame is worse than a blank region: it is motion the analyst cannot act on and cannot even
            read, on a screen whose rule is that nothing animates for decoration. If a chunk ever grew
            large enough to be seen waiting, the honest fallback would be the screen's own skeleton, not
            a spinner. */}
        <div className="content">
          <Suspense fallback={null}>{children ?? <Outlet />}</Suspense>
        </div>
      </main>
      <Toasts />
    </div>
  );
}
