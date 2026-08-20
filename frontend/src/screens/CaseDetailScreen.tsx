import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Severity } from '../api/types';
import { SEVERITIES } from '../api/types';
import { CaseNotesFeed } from '../components/CaseNotes';
import { CaseTimeline } from '../components/CaseTimeline';
import { IocPanel } from '../components/IocPanel';
import { Icon } from '../components/icons';
import { EmptyState, ErrorState, Loading, SectionHead } from '../components/ui';
import { useCase, useCaseDetail, useGraph } from '../hooks/queries';
import { useToast } from '../hooks/useToast';
import { fmtInt, fmtRelative, fmtTs, sevVar } from '../utils/format';

function SevBar({ sev, total }: { sev: Partial<Record<Severity, number>>; total: number }) {
  const parts = SEVERITIES.map((s) => ({ s, n: sev[s] ?? 0 })).filter((p) => p.n > 0);
  if (!total || !parts.length) return null;
  return (
    <div className="sevbar" role="img" aria-label={parts.map((p) => `${p.n} ${p.s}`).join(', ')}>
      {parts.map((p) => (
        <span key={p.s} className="sevbar__seg" style={{ width: `${(p.n / total) * 100}%`, background: sevVar(p.s) }} title={`${fmtInt(p.n)} ${p.s}`} />
      ))}
    </div>
  );
}


/**
 * The case's own view of the entity graph: how many connections have been AUTHORED on it — by the
 * assistant during an investigation, or by hand — and the way through to the graph itself.
 *
 * The analyst asked for the graph to be linked to cases. It always was, in the data (`graph_links` and
 * `graph_nodes` live in case.json and move with the case), but nothing on the case screen said so, so
 * a picture the assistant had drawn was only findable by going to another screen and knowing to switch
 * the scope. The counts come from the case-scoped graph itself, so they cannot drift from what the
 * Graph screen renders.
 */
function CaseGraphSummary() {
  const g = useGraph({ scope: 'case', limit: 400 }, true);
  const nodes = g.data?.nodes ?? [];
  const edges = g.data?.edges ?? [];
  const authoredNodes = nodes.filter((n) => n.manual).length;
  const authoredEdges = edges.filter((e) => e.ai || e.manual).length;
  const building = g.data?.stats?.status?.state === 'building';

  if (g.isLoading || building) {
    return (
      <div className="state state--inline">
        <div className="spinner" />
        <div className="state__body">
          {building ? 'The entity graph is still building for this workspace.' : 'Loading the graph…'}
        </div>
      </div>
    );
  }
  if (!nodes.length) {
    return (
      <EmptyState inline title="Nothing on the graph yet"
        body={'Put events on the case timeline and the entities in them appear here. The assistant can also '
              + 'draw the connections it concludes — ask it to build the graph for this investigation.'} />
    );
  }
  return (
    <div className="case-graph">
      <div className="case-graph__chips">
        <span className="case-chip"><b>{fmtInt(nodes.length)}</b> entit{nodes.length === 1 ? 'y' : 'ies'}</span>
        <span className="case-chip"><b>{fmtInt(edges.length)}</b> connection{edges.length === 1 ? '' : 's'}</span>
        {authoredEdges > 0 && (
          <span className="case-chip case-chip--accent" title="drawn by the assistant or by hand, not extracted">
            <b>{fmtInt(authoredEdges)}</b> drawn by hand or AI
          </span>
        )}
        {authoredNodes > 0 && (
          <span className="case-chip case-chip--quiet" title="entities nobody extracted — they were concluded">
            <b>{fmtInt(authoredNodes)}</b> authored entit{authoredNodes === 1 ? 'y' : 'ies'}
          </span>
        )}
      </div>
      <p className="field__hint">
        Authored links are dashed on the graph and each one carries the reason and the events it came
        from. Anything the assistant drew can be reverted from its conversation.
      </p>
    </div>
  );
}

export function CaseDetailScreen() {
  const { id } = useParams<{ id: string }>();
  const nav = useNavigate();
  const toast = useToast();
  const qc = useQueryClient();
  const detail = useCaseDetail(id);
  const active = useCase();
  const isActive = detail.data?.active ?? false;
  // live data (case set, timeline, indicators) only exists for the active case — the store holds
  // exactly one at a time
  // the Indicators "Add indicator" control lives in that section's header, so the panel is told when to open
  const [addingIoc, setAddingIoc] = useState(false);

  const activate = useMutation({
    mutationFn: () => api.activateCase(id!),
    onSuccess: (c) => { toast.success('Case activated', c.name); void qc.invalidateQueries(); },
    onError: (e) => toast.error('Could not activate case', e),
  });

  if (detail.isLoading) return <div className="page"><Loading label="Loading case…" /></div>;
  if (detail.isError || !detail.data) {
    return <div className="page"><ErrorState title="Could not load case" error={detail.error} onRetry={() => void detail.refetch()} /></div>;
  }
  const d = detail.data;
  const snap = d.snapshot;

  return (
    <div className="page case-detail">
      <div className="detail__backrow">
        <button className="btn btn--sm btn--ghost" onClick={() => nav('/cases')}><Icon.ArrowLeft /> All cases</button>
      </div>

      <SectionHead
        eyebrow={d.id}
        title={d.name}
        hint={<>{d.analyst || 'no analyst'} · created {fmtTs(d.createdAt)} UTC · updated {fmtTs(d.updatedAt)} UTC
          <span title={fmtRelative(d.updatedAt)}> ({fmtRelative(d.updatedAt)})</span></>}
        actions={isActive
          ? <span className="badge badge--ok">Active case</span>
          : <button className="btn btn--accent btn--sm" onClick={() => activate.mutate()} disabled={activate.isPending}>
              {activate.isPending && <span className="btn__spinner" />}Activate
            </button>}
      />

      {/* The five stat tiles (Sources / Events / In case set / Detections / Entities) were removed on
          request: a row of large numbers above the working area, each of which the section below it
          states again in context. */}

      {snap && snap.events > 0 && (
        <div className="case-detail__sev">
          <SevBar sev={snap.sev} total={snap.events} />
          <div className="case-detail__sev-legend">
            {SEVERITIES.filter((s) => (snap.sev[s] ?? 0) > 0).map((s) => (
              <span key={s} className="case-detail__sev-item">
                <span className="sev__bar" style={{ background: sevVar(s), width: 3, height: 10, display: 'inline-block' }} />
                {s} <b>{fmtInt(snap.sev[s] ?? 0)}</b>
              </span>
            ))}
          </div>
        </div>
      )}

      {!isActive && (
        <div className="case-detail__inactive">
          <Icon.Lock />
          <div>
            <b>This case is not loaded.</b> Iris keeps one case in memory at a time, so its events, timeline and case-set
            details need it activated first. The totals above come from the snapshot saved with the case.
            {active.data && <> Currently active: <b>{active.data.name}</b>.</>}
          </div>
          <button className="btn btn--accent btn--sm" onClick={() => activate.mutate()} disabled={activate.isPending}>
            {activate.isPending && <span className="btn__spinner" />}Activate this case
          </button>
        </div>
      )}

      <section className="case-notes">
        <SectionHead eyebrow="Notes" title="Investigation log"
          hint={`${d.notes.length} entr${d.notes.length === 1 ? 'y' : 'ies'} · timestamped, editable, included in the export`} />
        <CaseNotesFeed caseId={d.id} />
      </section>

      <section>
        <SectionHead
          eyebrow="Timeline"
          title="What happened, in order"
          hint={isActive
            ? `${fmtInt(d.caseSet)} event${d.caseSet === 1 ? '' : 's'} · add from a source or from Search, label each step, remove what does not belong`
            : 'activate the case to build it'}
        />
        {isActive
          ? <CaseTimeline sources={active.data?.sources ?? []} />
          : <EmptyState inline title="Not loaded" body="Activate this case to see and edit its timeline." />}
      </section>

      {isActive && (
        <section>
          <SectionHead eyebrow="Indicators" title="IOCs found in this case"
            hint="extracted from detection-bearing events · expand one to jump to the log it came from"
            actions={
              <button className="btn btn--sm btn--accent" onClick={() => setAddingIoc((v) => !v)} aria-expanded={addingIoc}>
                <Icon.Plus /> Add indicator
              </button>
            } />
          <IocPanel adding={addingIoc} onAddingDone={() => setAddingIoc(false)} />
        </section>
      )}

      {isActive && (
        <section>
          <SectionHead eyebrow="Entity graph" title="How this case connects"
            hint="the graph for this case's evidence, plus every link the assistant or you drew on it"
            actions={
              <Link className="btn btn--sm" to="/graph?scope=case">Open the graph</Link>
            } />
          <CaseGraphSummary />
        </section>
      )}

      {/* The correlated-cluster list and the Findings draft both used to sit here. Findings was removed
          on request — a report draft belongs in the export, not on the working screen — and clusters are
          a property of the whole pool, not of a curated case timeline. */}

      {/* The "Files in scope for this case" section was removed on request. Filing a log into a case
          (and taking it back out) now lives where the files are — the Sources page names the case per
          row and offers the picker; "Add existing sources" there does it in bulk. Repeating the same
          table inside the case was a second place to maintain and a second place to disagree. */}

    </div>
  );
}
