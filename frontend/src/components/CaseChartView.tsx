import { useMemo, useState } from 'react';
import type { CaseChart } from '../api/types';
import { cx } from '../utils/format';

/**
 * A chart on the case — line, area or bars — drawn as inline SVG with no dependency.
 *
 * WHY NO CHART LIBRARY. The same reason `utils/graphPaint.ts` is hand-written and `PerfPanel` draws
 * its own: every colour in this app is a theme variable resolved against the live theme, and a chart
 * library brings its own palette, its own type scale and ~100 kB to the entry chunk. There are three
 * marks here (a polyline, a filled band, a rect) and one axis.
 *
 * WHAT IT REFUSES TO DO, which is the part worth keeping:
 *
 *  * It never smooths. A monotone spline through hourly counts draws values that were never counted —
 *    at 02:30 a curve says "about 26" when the evidence says nothing about 02:30. Straight segments
 *    between measured points, and a dot on each point once there is room for one.
 *  * It never omits the zero. A y axis that starts at the minimum turns a 3 % variation into a cliff,
 *    and on an evidence surface that is a claim about the data.
 *  * It says when the read was BOUNDED. `exact: false` means the shape came from the first `counted`
 *    matches rather than from all of them — the caption says so, because a partial read presented as
 *    the whole picture is the silent-omission bug this project fights everywhere else.
 *  * It says how many events carried NO TIMESTAMP. They are not in any bucket (they cannot honestly
 *    be), so without that line the chart and the count disagree and the analyst cannot see why.
 *
 * The hover readout is a value per series at one bucket. It is keyboard reachable through the
 * `<select>`-free route: arrow keys move the cursor when the figure has focus.
 */

/** Theme variables, in the order series are drawn. Never literals — see themes.css. */
const SERIES_COLORS = [
  'var(--accent)', 'var(--sev-high, #d98c3a)', 'var(--sev-medium, #c9b03c)',
  'var(--ok, #4f9e6a)', 'var(--sev-critical, #c0554f)', 'var(--muted)',
];

const W = 760;
const H = 210;
const PAD = { l: 46, r: 12, t: 12, b: 30 };

function niceCeil(v: number): number {
  if (v <= 1) return 1;
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const step of [1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10]) {
    if (mag * step >= v) return mag * step;
  }
  return mag * 10;
}

function fmtCount(v: number): string {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(v >= 10_000_000 ? 0 : 1)}M`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(v >= 10_000 ? 0 : 1)}k`;
  return String(Math.round(v));
}

/** An x label the analyst can read a time off. Bucket size decides how much of the stamp matters. */
function fmtX(raw: string, mode: string, bucketSec: number): string {
  if (mode !== 'time') return raw;
  const t = Date.parse(raw);
  if (Number.isNaN(t)) return raw;
  const d = new Date(t);
  const iso = d.toISOString();
  if (bucketSec >= 86400) return iso.slice(5, 10);                       // MM-DD
  if (bucketSec >= 3600) return `${iso.slice(5, 10)} ${iso.slice(11, 13)}h`;
  return iso.slice(11, 16);                                              // HH:MM
}

function fullX(raw: string, mode: string): string {
  if (mode !== 'time') return raw;
  const t = Date.parse(raw);
  return Number.isNaN(t) ? raw : `${new Date(t).toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

export function CaseChartView({ chart, onDelete }: { chart: CaseChart; onDelete?: () => void }) {
  const [at, setAt] = useState<number | null>(null);
  const n = chart.x.length;
  const series = chart.series.length ? chart.series : [];
  const top = useMemo(
    () => niceCeil(Math.max(1, ...series.flatMap((s) => s.points))), [series]);

  const x = (i: number) => PAD.l + ((W - PAD.l - PAD.r) * (n <= 1 ? 0.5 : i / (n - 1)));
  const y = (v: number) => PAD.t + (H - PAD.t - PAD.b) * (1 - Math.min(1, Math.max(0, v / top)));
  const bars = chart.kind === 'bar';
  const bw = bars ? Math.max(2, ((W - PAD.l - PAD.r) / Math.max(1, n)) * 0.7) : 0;
  const bx = (i: number) => PAD.l + ((W - PAD.l - PAD.r) * (i + 0.5)) / Math.max(1, n) - bw / 2;

  const ticks = [0, top / 2, top];
  // Enough x labels to read the axis, never so many that they collide: one every ceil(n/6).
  const every = Math.max(1, Math.ceil(n / 6));

  const cursor = at != null && at >= 0 && at < n ? at : null;

  return (
    <figure className="chart" tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'ArrowRight') { setAt((v) => Math.min(n - 1, (v ?? -1) + 1)); e.preventDefault(); }
              if (e.key === 'ArrowLeft') { setAt((v) => Math.max(0, (v ?? n) - 1)); e.preventDefault(); }
              if (e.key === 'Escape') setAt(null);
            }}
            onMouseLeave={() => setAt(null)}>
      <figcaption className="chart__head">
        <span className="chart__title">{chart.title}</span>
        <span className="chart__meta">
          {chart.mode === 'time' ? chart.xLabel : `by ${chart.groupBy || 'value'}`}
          {' · '}{chart.total.toLocaleString()} event{chart.total === 1 ? '' : 's'}
          {chart.scope === 'case' && ' · case set only'}
        </span>
        {onDelete && (
          <button type="button" className="btn btn--sm btn--ghost chart__del" onClick={onDelete}>Remove</button>
        )}
      </figcaption>

      {series.length > 1 && (
        <div className="chart__legend">
          {series.map((s, i) => (
            <span key={s.label + i} className="chart__key" title={s.query ? `query: ${s.query}` : undefined}>
              <i style={{ background: SERIES_COLORS[i % SERIES_COLORS.length] }} />
              {s.label}
              <b>{s.total.toLocaleString()}</b>
            </span>
          ))}
        </div>
      )}

      <div className="chart__plot">
        <svg viewBox={`0 0 ${W} ${H}`} className="chart__svg" role="img"
             aria-label={`${chart.title}: ${series.map((s) => `${s.label} ${s.total}`).join(', ')}`}>
          {ticks.map((g) => (
            <g key={g}>
              <line x1={PAD.l} x2={W - PAD.r} y1={y(g)} y2={y(g)} className="chart__grid" />
              <text x={PAD.l - 7} y={y(g) + 3.5} textAnchor="end" className="chart__tick">{fmtCount(g)}</text>
            </g>
          ))}
          {/* the x axis itself, so a chart of zeros still reads as an axis rather than as nothing */}
          <line x1={PAD.l} x2={W - PAD.r} y1={y(0)} y2={y(0)} className="chart__axis" />

          {series.map((s, si) => {
            const color = SERIES_COLORS[si % SERIES_COLORS.length];
            if (bars) {
              return (
                <g key={s.label + si}>
                  {s.points.map((v, i) => (
                    <rect key={i} x={bx(i)} y={y(v)} width={bw} height={Math.max(0, y(0) - y(v))}
                          fill={color} opacity={cursor === null || cursor === i ? 0.85 : 0.4}
                          className="chart__bar" />
                  ))}
                </g>
              );
            }
            const d = s.points.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ');
            const area = `${d} L${x(n - 1).toFixed(1)} ${y(0).toFixed(1)} L${x(0).toFixed(1)} ${y(0).toFixed(1)} Z`;
            return (
              <g key={s.label + si}>
                {chart.kind === 'area' && <path d={area} fill={color} opacity={0.14} />}
                <path d={d} fill="none" stroke={color} strokeWidth={1.8} strokeLinejoin="round"
                      strokeLinecap="round" vectorEffect="non-scaling-stroke" />
                {n <= 60 && s.points.map((v, i) => (
                  <circle key={i} cx={x(i)} cy={y(v)} r={cursor === i ? 3.2 : 1.9} fill={color} />
                ))}
              </g>
            );
          })}

          {cursor !== null && (
            <line x1={bars ? bx(cursor) + bw / 2 : x(cursor)} x2={bars ? bx(cursor) + bw / 2 : x(cursor)}
                  y1={PAD.t} y2={y(0)} className="chart__cursor" />
          )}

          {chart.x.map((raw, i) => (i % every === 0 || i === n - 1 ? (
            <text key={i} x={bars ? bx(i) + bw / 2 : x(i)} y={H - 10} textAnchor="middle" className="chart__xtick">
              {fmtX(raw, chart.mode, chart.bucketSec)}
            </text>
          ) : null))}

          {/* One hit target per bucket: a transparent column, so the readout follows the pointer
              anywhere in the plot rather than only exactly on a 2px line. */}
          {chart.x.map((_, i) => (
            <rect key={`h${i}`} x={PAD.l + ((W - PAD.l - PAD.r) * i) / Math.max(1, n) } y={PAD.t}
                  width={(W - PAD.l - PAD.r) / Math.max(1, n)} height={H - PAD.t - PAD.b}
                  fill="transparent" onMouseEnter={() => setAt(i)} />
          ))}
        </svg>

        {cursor !== null && (
          <div className="chart__read">
            <span className="chart__read-x">{fullX(chart.x[cursor]!, chart.mode)}</span>
            {series.map((s, i) => (
              <span key={s.label + i} className="chart__read-v">
                <i style={{ background: SERIES_COLORS[i % SERIES_COLORS.length] }} />
                {s.label}: <b>{(s.points[cursor] ?? 0).toLocaleString()}</b>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* THE CAPTION IS PART OF THE EVIDENCE, not decoration: what it was drawn from, and every way
          the picture is less than the whole truth. */}
      <div className="chart__foot">
        {chart.note && <span className="chart__note">{chart.note}</span>}
        <span className="chart__prov">
          {series.map((s) => s.query || '(every event)').join('  ·  ')}
        </span>
        {(!chart.exact || chart.withoutTimestamp > 0 || chart.truncated) && (
          <span className="chart__caveat">
            {!chart.exact && `shape read from the first ${chart.counted.toLocaleString()} matches of ${chart.total.toLocaleString()}. `}
            {chart.withoutTimestamp > 0 && `${chart.withoutTimestamp.toLocaleString()} matching event${chart.withoutTimestamp === 1 ? '' : 's'} carr${chart.withoutTimestamp === 1 ? 'ies' : 'y'} no parsed timestamp and ${chart.withoutTimestamp === 1 ? 'is' : 'are'} in no bucket. `}
            {chart.truncated && `${chart.distinctGroups.toLocaleString()} distinct values; the top ${n} are drawn.`}
          </span>
        )}
        <span className={cx('chart__by', chart.createdBy.startsWith('AI') && 'chart__by--ai')}>
          {chart.createdBy || 'analyst'}
        </span>
      </div>
    </figure>
  );
}
