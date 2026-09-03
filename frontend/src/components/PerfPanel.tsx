import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { MetricSample } from '../api/types';
import { cx } from '../utils/format';

/* ───────── tiny SVG line chart (no deps) ─────────
   EVERY colour here is a theme variable, never a literal: `color` on a Series is a `var(--…)` string
   the browser resolves against the live theme, so the same chart is correct in all nine. The
   gridline and the tick take theirs from CSS (`.perf__gridline`, `.perf__tick` in
   styles/screens/settings.css) — a hard-coded stroke would be wrong in eight of them. */
interface Series { key: string; label: string; color: string; values: (number | null)[]; unit?: string; max?: number }

function LineChart({ series, height = 84, ymax, unit, fill = true }: { series: Series[]; height?: number; ymax?: number; unit?: string; fill?: boolean }) {
  const W = 600;
  const H = height;
  const pad = { l: 34, r: 8, t: 6, b: 4 };
  const n = Math.max(2, ...series.map((s) => s.values.length));
  const maxV = ymax ?? Math.max(1, ...series.flatMap((s) => s.values.filter((v): v is number => v != null)));
  const top = ymax ?? niceCeil(maxV);
  const x = (i: number) => pad.l + ((W - pad.l - pad.r) * i) / Math.max(1, n - 1);
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - Math.min(1, Math.max(0, v / top)));
  const gridVals = [0, top / 2, top];
  return (
    <svg className="perf__chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
      {gridVals.map((g) => (
        <g key={g}>
          {/* `perf__gridline`, NOT `perf__grid` — that name is already the class on the container
              div holding the four charts, and one class doing two jobs is how the stroke ended up
              being selected for by `.perf__grid line.perf__grid`. */}
          <line x1={pad.l} x2={W - pad.r} y1={y(g)} y2={y(g)} className="perf__gridline" />
          <text x={pad.l - 6} y={y(g) + 3} textAnchor="end" className="perf__tick">{fmtTick(g, unit)}</text>
        </g>
      ))}
      {series.map((s) => {
        const pts: string[] = [];
        let d = '';
        let open = false;
        s.values.forEach((v, i) => {
          if (v == null) { open = false; return; }
          const px = x(i + (n - s.values.length));
          const py = y(v);
          d += (open ? ' L' : ' M') + px.toFixed(1) + ' ' + py.toFixed(1);
          pts.push(`${px.toFixed(1)},${py.toFixed(1)}`);
          open = true;
        });
        const first = pts[0]?.split(',')[0];
        const last = pts[pts.length - 1]?.split(',')[0];
        const area = fill && first && last ? `${d} L${last} ${y(0)} L${first} ${y(0)} Z` : '';
        return (
          <g key={s.key}>
            {area && <path d={area} fill={s.color} opacity={0.12} />}
            <path d={d} fill="none" stroke={s.color} strokeWidth={1.6} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
          </g>
        );
      })}
    </svg>
  );
}

function niceCeil(v: number): number {
  if (v <= 1) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const m = v / p;
  const nice = m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10;
  return nice * p;
}
function fmtTick(v: number, unit?: string): string {
  const s = v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 0 : 1)}k` : v % 1 === 0 ? String(v) : v.toFixed(1);
  return unit ? `${s}${unit}` : s;
}
function fmtNum(v: number | null | undefined, unit = '', digits = 0): string {
  if (v == null) return '—';
  return `${v.toFixed(digits)}${unit}`;
}

/* ───────── panel ───────── */
const WINDOWS = [
  { id: 60, label: '2 min' },
  { id: 150, label: '5 min' },
  { id: 450, label: '15 min' },
  { id: 900, label: '30 min' },
];

export function PerfPanel({ compact = false }: { compact?: boolean }) {
  const [win, setWin] = useState(150);
  const [live, setLive] = useState(true);
  const q = useQuery({
    queryKey: ['compute', 'metrics', win],
    queryFn: () => api.metrics(win),
    refetchInterval: live ? 2000 : false,
    refetchIntervalInBackground: false,
  });
  const samples: MetricSample[] = q.data?.samples ?? [];
  const cur = q.data?.current ?? null;
  const gpuCount = Math.max(0, ...samples.map((s) => s.gpus.length));
  const gpuIdx = 0; // charts follow GPU #0; the table below lists all
  const gpu = (s: MetricSample) => s.gpus[gpuIdx];

  const util = useMemo<Series[]>(() => [
    { key: 'gpu', label: 'GPU util', color: 'var(--accent)', values: samples.map((s) => gpu(s)?.util ?? null), unit: '%' },
    { key: 'mem', label: 'GPU mem bus', color: 'var(--sev-medium)', values: samples.map((s) => gpu(s)?.memUtil ?? null), unit: '%' },
    { key: 'cpu', label: 'process CPU', color: 'var(--sev-high)', values: samples.map((s) => (s.cpuPct == null ? null : Math.min(100, s.cpuPct))), unit: '%' },
  ], [samples]);
  const memMB = useMemo<Series[]>(() => [
    { key: 'vram', label: 'VRAM used', color: 'var(--accent)', values: samples.map((s) => gpu(s)?.memUsedMB ?? null) },
    { key: 'rss', label: 'process RSS', color: 'var(--sev-high)', values: samples.map((s) => s.rssMB ?? null) },
  ], [samples]);
  const thermal = useMemo<Series[]>(() => [
    { key: 'temp', label: 'GPU temp', color: 'var(--sev-critical)', values: samples.map((s) => gpu(s)?.tempC ?? null), unit: '°' },
    { key: 'power', label: 'power', color: 'var(--sev-medium)', values: samples.map((s) => gpu(s)?.powerW ?? null), unit: 'W' },
  ], [samples]);
  const thr = useMemo<Series[]>(() => [
    { key: 'eps', label: 'events / s parsed', color: 'var(--accent)', values: samples.map((s) => s.eventsPerSec) },
  ], [samples]);
  const vramTotal = cur?.gpus[gpuIdx]?.memTotalMB ?? 0;
  const g0 = cur?.gpus[gpuIdx];

  return (
    <div className={cx('perf', compact && 'perf--compact')}>
      <div className="perf__head">
        <div className="perf__title">
          <span className={cx('badge', live ? 'badge--ok' : '')}><span className={cx('badge__dot', live && 'perf__live-dot')} />{live ? 'live · 2 s' : 'paused'}</span>
          {cur && <span className="badge">{cur.active === 'cuda' ? 'processing on CUDA' : 'processing on CPU'}</span>}
          {gpuCount === 0 && !q.isLoading && <span className="badge badge--warn">no GPU telemetry</span>}
        </div>
        <div className="perf__ctl">
          {/* `perf__seg`, not the shared `.seg`: AnomaliesScreen's segmented filter claims that name
              too (defined at the bottom of styles/screens/settings.css), and it loads after
              components.css — so this control was silently taking a filter chip's box. */}
          <div className="perf__seg" role="radiogroup" aria-label="Window">
            {WINDOWS.map((w) => (
              <button key={w.id} role="radio" aria-checked={win === w.id}
                className={cx('perf__seg-btn', win === w.id && 'on')} onClick={() => setWin(w.id)}>{w.label}</button>
            ))}
          </div>
          <button className="btn btn--sm" onClick={() => setLive((v) => !v)}>{live ? 'Pause' : 'Resume'}</button>
        </div>
      </div>

      <div className="perf__tiles">
        <Tile label="GPU utilization" value={fmtNum(g0?.util, '%')} color="var(--accent)" />
        <Tile label="VRAM" value={g0 ? `${fmtNum(g0.memUsedMB / 1024, ' GB', 1)} / ${fmtNum(g0.memTotalMB / 1024, ' GB', 1)}` : '—'} color="var(--sev-medium)" />
        <Tile label="GPU temp · power" value={g0 ? `${fmtNum(g0.tempC, '°C')} · ${fmtNum(g0.powerW, ' W', 0)}` : '—'} color="var(--sev-critical)" />
        <Tile label="SM clock" value={fmtNum(g0?.smClockMHz, ' MHz')} color="var(--text-bright)" />
        <Tile label="Process CPU · RSS" value={cur ? `${fmtNum(cur.cpuPct, '%', 0)} · ${fmtNum(cur.rssMB, ' MB')}` : '—'} color="var(--sev-high)" />
        <Tile label="Parse throughput" value={cur ? `${fmtNum(cur.eventsPerSec, ' ev/s', 0)}` : '—'} sub={cur ? `${fmtNum(cur.totalParsedEvents)} total` : ''} color="var(--accent)" />
      </div>

      <div className="perf__grid">
        <Chart title="Utilization" legend={util}><LineChart series={util} ymax={100} unit="%" /></Chart>
        <Chart title="Memory (MB)" legend={memMB}><LineChart series={memMB} ymax={vramTotal > 0 ? vramTotal : undefined} /></Chart>
        <Chart title="Thermal / power" legend={thermal}><LineChart series={thermal} fill={false} /></Chart>
        <Chart title="Parse throughput (events/s)" legend={thr}><LineChart series={thr} /></Chart>
      </div>

      {cur && cur.gpus.length > 1 && (
        <div className="perf__gpus">
          {cur.gpus.map((g) => (
            <div key={g.index} className="perf__gpu-row">
              <span className="mono">#{g.index} {g.name}</span>
              <span className="mono">{g.util}% · {(g.memUsedMB / 1024).toFixed(1)}/{(g.memTotalMB / 1024).toFixed(1)} GB · {g.tempC ?? '—'}°C · {g.powerW ?? '—'} W</span>
            </div>
          ))}
        </div>
      )}
      {q.isError && <div className="compute-error">Metrics unavailable: {(q.error as Error)?.message ?? 'error'}</div>}
    </div>
  );
}

function Tile({ label, value, sub, color }: { label: string; value: string; sub?: string; color: string }) {
  return (
    <div className="perf__tile">
      <div className="perf__tile-v" style={{ color }}>{value}</div>
      <div className="perf__tile-l">{label}{sub ? <span className="muted"> · {sub}</span> : null}</div>
    </div>
  );
}
function Chart({ title, legend, children }: { title: string; legend: Series[]; children: React.ReactNode }) {
  return (
    <div className="perf__card">
      <div className="perf__card-head">
        <span className="perf__card-title">{title}</span>
        <span className="perf__legend">{legend.map((s) => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}</span>
      </div>
      {children}
    </div>
  );
}
