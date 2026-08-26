import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { DeepPartial, GraphQuery, Scope, Settings, Severity } from '../api/types';
import type { FieldFacetsQuery } from '../api/types';

export const qk = {
  case: ['case'] as const,
  settings: ['settings'] as const,
  aiSystemPrompts: ['ai', 'systemPrompts'] as const,
  compute: ['compute'] as const,
  timeline: ['timeline'] as const,
  timelineIocs: ['timeline-iocs'] as const,
  graph: ['graph'] as const,
  entity: (name: string) => ['entity', name] as const,
  event: (id: string) => ['event', id] as const,
  events: (params: unknown) => ['events', params] as const,
  caseSet: ['case-set'] as const,
  caseDetail: (id: string) => ['case-detail', id] as const,
  notes: (id: string) => ['notes', id] as const,
  iocs: (scope: string) => ['iocs', scope] as const,
  pendingMappings: ['pending-mappings'] as const,
  library: ['library'] as const,
  report: ['report'] as const,
  health: ['health'] as const,
  cases: ['cases'] as const,
  rules: ['rules'] as const,
  anomalies: (params: unknown) => ['anomalies', params] as const,
};

export function useCase() {
  return useQuery({
    queryKey: qk.case,
    queryFn: api.getCase,
    refetchInterval: (q) => {
      const c = q.state.data;
      if (!c) return 15000;
      // poll fast while anything is still being parsed — including the background load of the case-less
      // pool, which is what fills Search/Timeline/Graph after a restart with a large library
      const parsing = c.poolLoading || [...c.sources, ...c.librarySources].some((s) => s.state === 'PARSING');
      // Phase 2 of ingest moves without any request from the UI, so poll fast while a source is
      // actually queued or being enriched — and ONLY then. A source left `raw` with auto-enrich off
      // can only change when the analyst asks for it, and that mutation invalidates this query, so
      // there is nothing to watch for: `outstanding` must never drive a permanent 2 s poll.
      const enriching = (c.enrichment?.pending ?? 0) > 0;
      return parsing || enriching ? 2000 : 15000;
    },
  });
}

export function useSettings() {
  return useQuery({ queryKey: qk.settings, queryFn: api.settings, staleTime: 60_000 });
}

export function useHealth() {
  return useQuery({ queryKey: qk.health, queryFn: api.health, refetchInterval: 20_000, retry: false });
}

/** Both of these are DERIVED structures the server builds in the background (see DerivedState). While
 *  `status.state === 'building'` the payload is empty on purpose, so poll until it lands — otherwise the
 *  screen sits on an empty result that looks like "there is nothing here" and never corrects itself. */
const BUILD_POLL_MS = 1_500;

/** Poll while the server is building — and also while it reports `idle` with nothing to show, which is a
 *  state that should not exist (the endpoint starts a build on every miss) but is indistinguishable from
 *  a real outage at the screen. Backing off to a slower poll there means a graph that never arrives is a
 *  few seconds of "building", not a permanently blank page. */
/* Poll cadence for a derived structure. While a build is running the interval SCALES with the build:
   a 1.5 s poll is right for a 50 k-event graph and wrong for a 13.8 M-event one, where every poll lands
   on a process that is packing the pool and swapping — the polls themselves were part of "the page
   becomes unresponsive". Bounded at 8 s so progress still visibly moves. */
function buildPoll(state: string | undefined, empty: boolean, target?: number): number | false {
  if (state === 'building') {
    const n = target ?? 0;
    if (n > 5_000_000) return BUILD_POLL_MS * 5;
    if (n > 1_000_000) return BUILD_POLL_MS * 3;
    if (n > 200_000) return BUILD_POLL_MS * 2;
    return BUILD_POLL_MS;
  }
  if (state !== 'ready' && empty) return BUILD_POLL_MS * 4;
  return false;
}

export function useTimeline(scope: Scope = 'all') {
  return useQuery({
    queryKey: [...qk.timeline, scope],
    queryFn: () => api.timeline(scope),
    refetchInterval: (q) => buildPoll(q.state.data?.status?.state, !q.state.data?.clusters?.length),
  });
}

/** Indicators as timeline markers. Separate from useTimeline so a slow IOC pass never delays clusters. */
export function useTimelineIocs(scope: Scope = 'all') {
  return useQuery({ queryKey: [...qk.timelineIocs, scope], queryFn: () => api.timelineIocs(scope) });
}

export function useGraph(gq: GraphQuery = {}, enabled = true) {
  return useQuery({
    queryKey: [...qk.graph, gq],
    queryFn: () => api.graph(gq),
    enabled,
    placeholderData: (p) => p,
    refetchInterval: (q) => buildPoll(q.state.data?.stats?.status?.state, !q.state.data?.nodes?.length,
                                      q.state.data?.stats?.status?.target),
  });
}

export function useCases() {
  return useQuery({ queryKey: qk.cases, queryFn: api.cases });
}

export function useRules(includeRemoved = false) {
  // key stays prefixed with qk.rules so invalidating qk.rules refreshes both variants
  return useQuery({ queryKey: [...qk.rules, includeRemoved], queryFn: () => api.rules(includeRemoved) });
}

/** Just the "how many rules fired" total — for the sidebar tag. Keeps the payload to one sample anomaly.
 *  Polls while the server is aggregating, or the tag would sit on 0 (i.e. "no detections") until the next
 *  navigation. */
export function useAnomalyCount() {
  const params = { limit: 1 };
  return useQuery({
    queryKey: qk.anomalies(params),
    queryFn: () => api.anomalies(params),
    refetchInterval: (q) => buildPoll(q.state.data?.status?.state, !q.state.data?.anomalies?.length),
    select: (d) => d.total,
  });
}

/** The anomaly list itself. Same background-build contract as the graph and the timeline. */
export function useAnomalies(params: { sev?: Severity[]; limit?: number }) {
  return useQuery({
    queryKey: qk.anomalies(params),
    queryFn: () => api.anomalies(params),
    placeholderData: (p) => p,
    refetchInterval: (q) => buildPoll(q.state.data?.status?.state, !q.state.data?.anomalies?.length),
  });
}

export function useCaseSet() {
  return useQuery({ queryKey: qk.caseSet, queryFn: api.caseSet });
}

export function useNotes(caseId: string | undefined) {
  return useQuery({ queryKey: qk.notes(caseId ?? ''), queryFn: () => api.notes(caseId!), enabled: !!caseId });
}

export function useIocs(scope: Scope = 'all') {
  return useQuery({ queryKey: qk.iocs(scope), queryFn: () => api.iocs(scope) });
}

export function useLibrary() {
  return useQuery({ queryKey: qk.library, queryFn: api.library });
}

export function usePendingMappings() {
  return useQuery({ queryKey: qk.pendingMappings, queryFn: api.pendingMappings });
}

export function useCaseDetail(id: string | undefined) {
  return useQuery({ queryKey: qk.caseDetail(id ?? ''), queryFn: () => api.caseDetail(id!), enabled: !!id });
}

/** Invalidate everything derived from case data (after ingest / reset / demo / mapping). */
export function useInvalidateCaseData() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: qk.case });
    void qc.invalidateQueries({ queryKey: qk.timeline });
    void qc.invalidateQueries({ queryKey: qk.graph });
    void qc.invalidateQueries({ queryKey: ['events'] });
    void qc.invalidateQueries({ queryKey: ['event'] });
    void qc.invalidateQueries({ queryKey: ['entity'] });
    void qc.invalidateQueries({ queryKey: qk.caseSet });
    void qc.invalidateQueries({ queryKey: ['case-detail'] });
    void qc.invalidateQueries({ queryKey: qk.report });
    void qc.invalidateQueries({ queryKey: qk.cases });
    void qc.invalidateQueries({ queryKey: qk.rules });
    void qc.invalidateQueries({ queryKey: ['anomalies'] });
    void qc.invalidateQueries({ queryKey: ['iocs'] });
    void qc.invalidateQueries({ queryKey: qk.pendingMappings });
    void qc.invalidateQueries({ queryKey: qk.library });
  };
}

export function useSaveSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (patch: DeepPartial<Settings>) => api.putSettings(patch),
    onSuccess: (data) => {
      qc.setQueryData(qk.settings, data);
      void qc.invalidateQueries({ queryKey: qk.case });
      void qc.invalidateQueries({ queryKey: qk.compute });
    },
  });
}

/** Everything that changes when case-set membership changes (it now drives scoped analysis too). */
function useInvalidateCaseSet() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: qk.caseSet });
    void qc.invalidateQueries({ queryKey: qk.case });
    void qc.invalidateQueries({ queryKey: ['case-detail'] });
    void qc.invalidateQueries({ queryKey: qk.report });
    void qc.invalidateQueries({ queryKey: ['events'] });
    void qc.invalidateQueries({ queryKey: ['event'] });
    void qc.invalidateQueries({ queryKey: qk.cases });
    // scope='case' results are now stale
    void qc.invalidateQueries({ queryKey: qk.timeline });
    void qc.invalidateQueries({ queryKey: qk.graph });
    void qc.invalidateQueries({ queryKey: ['iocs'] });
  };
}

export function useAddToCase() {
  const invalidate = useInvalidateCaseSet();
  return useMutation({
    mutationFn: (v: { id: string; labels?: string[]; note?: string }) => api.addToCase(v.id, { labels: v.labels, note: v.note }),
    onSuccess: invalidate,
  });
}

export function useUpdateCaseEntry() {
  const invalidate = useInvalidateCaseSet();
  return useMutation({
    mutationFn: (v: { id: string; labels?: string[]; note?: string }) => api.updateCaseEntry(v.id, { labels: v.labels, note: v.note }),
    onSuccess: invalidate,
  });
}

export function useAddSourceToCase() {
  const invalidate = useInvalidateCaseSet();
  return useMutation({
    mutationFn: (v: { id: string; labels?: string[] }) => api.addSourceToCase(v.id, v.labels),
    onSuccess: invalidate,
  });
}

export function useRemoveSourceFromCase() {
  const invalidate = useInvalidateCaseSet();
  return useMutation({ mutationFn: (id: string) => api.removeSourceFromCase(id), onSuccess: invalidate });
}

export function useRemoveFromCase() {
  const invalidate = useInvalidateCaseSet();
  return useMutation({
    mutationFn: (id: string) => api.removeFromCase(id),
    onSuccess: invalidate,
  });
}

/** Field facets for the Search sidebar. Keyed under ['events', …] so ingest invalidation refreshes it too. */
export function useEventFields(params: FieldFacetsQuery, enabled = true) {
  return useQuery({
    queryKey: ['events', 'fields', params] as const,
    queryFn: () => api.eventFields(params),
    enabled,
    placeholderData: (prev) => prev,
    staleTime: 15_000,
  });
}
