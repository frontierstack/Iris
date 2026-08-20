import type { Severity } from '../api/types';

export const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function sevVar(sev: Severity | string): string {
  return `var(--sev-${sev})`;
}

export function maxSev(list: Severity[]): Severity {
  let best: Severity = 'info';
  for (const s of list) if (SEV_ORDER[s] < SEV_ORDER[best]) best = s;
  return best;
}

export function fmtInt(n: number | undefined | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—';
  return n.toLocaleString('en-US');
}

/** compact number: 1.42M, 58.4k */
export function fmtCompact(n: number | undefined | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(n >= 10_000_000 ? 0 : 2).replace(/\.?0+$/, '')}M`;
  if (n >= 10_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k`;
  return n.toLocaleString('en-US');
}

export function fmtBytes(n: number | undefined | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** Byte size for a file listing. An unknown size must read as unknown — never as "0 B",
 *  which looks like a real, empty file. */
export function fmtSize(n: number | undefined | null): string {
  if (n === undefined || n === null || Number.isNaN(n) || n <= 0) return '—';
  return fmtBytes(n);
}

/** Total bytes over a list of files, and how many of them had no size to count.
 *  The caller must surface `unknown` — a total that silently drops files is a lie about coverage. */
export function totalSize(items: Array<{ size?: number | null }>): { bytes: number; unknown: number } {
  let bytes = 0;
  let unknown = 0;
  for (const it of items) {
    const s = it.size;
    if (s === undefined || s === null || Number.isNaN(s) || s <= 0) unknown++;
    else bytes += s;
  }
  return { bytes, unknown };
}

export function fmtMB(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

export function parseTs(ts: string | undefined | null): Date | null {
  if (!ts) return null;
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** 2026-08-11 03:09:41 (UTC) */
export function fmtTs(ts: string | undefined | null): string {
  const d = parseTs(ts);
  if (!d) return ts ?? '—';
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
/** 03:09:41 */
export function fmtClock(ts: string | undefined | null): string {
  const d = parseTs(ts);
  if (!d) return ts ?? '—';
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
/** 03:09 */
export function fmtHM(ts: string | undefined | null): string {
  const d = parseTs(ts);
  if (!d) return ts ?? '—';
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
/** 11 Aug 2026 */
export function fmtDate(ts: string | undefined | null): string {
  const d = parseTs(ts);
  if (!d) return ts ?? '—';
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return `${d.getUTCDate()} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}
export function fmtRange(range: [string, string] | null | undefined): string {
  if (!range) return '—';
  const [a, b] = range;
  const da = parseTs(a);
  const db = parseTs(b);
  if (!da || !db) return `${a} – ${b}`;
  const sameDay = da.toISOString().slice(0, 10) === db.toISOString().slice(0, 10);
  return sameDay ? `${fmtHM(a)} – ${fmtHM(b)}` : `${fmtTs(a).slice(5, 16)} – ${fmtTs(b).slice(5, 16)}`;
}
export function fmtRelative(ts: string | undefined | null): string {
  const d = parseTs(ts);
  if (!d) return '—';
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/** "4m 20s left" / "18s left" — a coarse ETA for a long-running parse or index build. */
export function fmtEta(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return '';
  const s = Math.round(seconds);
  if (s < 60) return `${s}s left`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s left`;
  return `${Math.floor(m / 60)}h ${m % 60}m left`;
}

/** "12.4 MB/s" */
export function fmtRate(bytesPerSec: number | null | undefined): string {
  if (!bytesPerSec || bytesPerSec <= 0) return '';
  return `${fmtBytes(bytesPerSec)}/s`;
}

export function pct(n: number): string {
  return `${Math.round(Math.max(0, Math.min(1, n)) * 100)}%`;
}

export function initials(name: string | undefined | null): string {
  if (!name) return '??';
  return (
    name
      .split(/[\s.]+/)
      .filter(Boolean)
      .map((s) => s[0] ?? '')
      .join('')
      .slice(0, 2)
      .toUpperCase() || '??'
  );
}

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === 'string') return e;
  return 'Unknown error';
}

/** ISO → value for <input type="datetime-local"> interpreted as UTC */
export function toLocalInputValue(iso: string): string {
  const d = parseTs(iso);
  if (!d) return '';
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
export function fromLocalInputValue(v: string): string {
  if (!v) return '';
  const d = new Date(`${v}:00Z`);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}


/** "Mon 17 Aug 2026" — the heading a chronology is grouped under. Always UTC, always with the year:
 *  a case is read weeks later and correlated against raw logs by absolute date. */
export function fmtDay(isoDate: string): string {
  const d = new Date(`${isoDate}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return isoDate;
  return d.toLocaleDateString('en-GB', {
    weekday: 'short', day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC',
  });
}
