import type { SVGProps } from 'react';

type P = SVGProps<SVGSVGElement>;
const base = { width: 14, height: 14, viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;

/* ─────────────────────────────────────────────────────────────────────────────
   Nav glyphs share one geometry: 16×16 box, 1.5 stroke, round caps/joins, and all
   artwork inside a 12px live area (2 → 14) so every icon reads at the same optical
   weight in the 60px rail. One unambiguous metaphor each — no decorative filler.
   ───────────────────────────────────────────────────────────────────────────── */
export const Icon = {
  /* Sources: a stack of ingested files — front sheet with content, one sheet behind */
  Sources: (p: P) => (
    <svg {...base} {...p}>
      <path d="M6.4 2.6h4.8c.66 0 1.2.54 1.2 1.2v6.4c0 .66-.54 1.2-1.2 1.2H6.4c-.66 0-1.2-.54-1.2-1.2V3.8c0-.66.54-1.2 1.2-1.2Z" />
      <path d="M7.4 5.4h2.8M7.4 7.8h2.8" />
      <path d="M3.4 5.8v6c0 .88.72 1.6 1.6 1.6h4.4" />
    </svg>
  ),
  Search: (p: P) => (
    <svg {...base} {...p}><circle cx="7.1" cy="7.1" r="4.35" /><path d="m10.25 10.25 3.15 3.15" /></svg>
  ),
  /* Timeline: an axis with end caps and two events marked on it */
  Timeline: (p: P) => (
    <svg {...base} {...p}>
      <path d="M2.6 8h10.8M2.6 6.3v3.4M13.4 6.3v3.4" />
      <circle cx="6.2" cy="8" r="1.45" fill="currentColor" stroke="none" />
      <circle cx="10.1" cy="8" r="1.45" fill="currentColor" stroke="none" />
    </svg>
  ),
  /* Entity graph: three linked nodes */
  Graph: (p: P) => (
    <svg {...base} {...p}>
      <circle cx="3.9" cy="4.6" r="1.75" /><circle cx="12.1" cy="5.6" r="1.75" /><circle cx="7.9" cy="11.9" r="1.75" />
      <path d="m5.62 4.81 4.76.58M4.5 6.24l2.8 4.03M11.4 7.22 8.6 10.3" />
    </svg>
  ),
  /* Findings: a clipboard with a check — a reviewed, written-up result */
  Findings: (p: P) => (
    <svg {...base} {...p}>
      <path d="M6.1 3.5H4.7c-.72 0-1.3.58-1.3 1.3v7.6c0 .72.58 1.3 1.3 1.3h6.6c.72 0 1.3-.58 1.3-1.3V4.8c0-.72-.58-1.3-1.3-1.3H9.9" />
      <path d="M6.5 2.3h3c.33 0 .6.27.6.6v1.5c0 .33-.27.6-.6.6h-3c-.33 0-.6-.27-.6-.6V2.9c0-.33.27-.6.6-.6Z" />
      <path d="m6 9.5 1.5 1.5 3-3.2" />
    </svg>
  ),
  /* Settings: one closed 6-tooth gear body plus a hub. The old glyph drew the teeth as
     detached radial ticks around a ring, which read as a sunburst rather than a gear. */
  Settings: (p: P) => (
    <svg {...base} {...p}>
      <path d="M13.80 6.45 L13.80 9.55 L11.96 9.68 L11.43 10.59 L12.24 12.24 L9.55 13.80 L8.52 12.27 L7.48 12.27 L6.45 13.80 L3.76 12.24 L4.57 10.59 L4.04 9.68 L2.20 9.55 L2.20 6.45 L4.04 6.32 L4.57 5.41 L3.76 3.76 L6.45 2.20 L7.48 3.73 L8.52 3.73 L9.55 2.20 L12.24 3.76 L11.43 5.41 L11.96 6.32 Z" />
      <circle cx="8" cy="8" r="2.1" />
    </svg>
  ),
  ArrowLeft: (p: P) => (
    <svg {...base} {...p}><path d="M13 8H3.5M7.5 4 3.5 8l4 4" /></svg>
  ),
  Chevron: (p: P) => (
    <svg {...base} {...p}><path d="m4 6 4 4 4-4" /></svg>
  ),
  /* AI assistant: a plain message glyph (no sparkles) */
  Sparkle: (p: P) => (
    <svg {...base} {...p}><path d="M2.5 3.5h11v7H6.5L3.5 13v-2.5h-1z" /><path d="M5.5 6.5h5M5.5 8.5h3" /></svg>
  ),
  Sliders: (p: P) => (
    <svg {...base} {...p}><path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" /><circle cx="6" cy="4.5" r="1.4" fill="var(--bg-sidebar)" /><circle cx="10.5" cy="8" r="1.4" fill="var(--bg-sidebar)" /><circle cx="5" cy="11.5" r="1.4" fill="var(--bg-sidebar)" /></svg>
  ),
  Fit: (p: P) => (
    <svg {...base} {...p}><path d="M2.5 6V2.5H6M10 2.5h3.5V6M13.5 10v3.5H10M6 13.5H2.5V10" /></svg>
  ),
  PanelLeft: (p: P) => (
    <svg {...base} {...p}><rect x="2" y="3" width="12" height="10" rx="1.5" /><path d="M6 3v10" /></svg>
  ),
  Export: (p: P) => (
    <svg {...base} {...p}><path d="M8 10.5V2.5M5 5.5l3-3 3 3M3 10.5v3h10v-3" /></svg>
  ),
  Cpu: (p: P) => (
    <svg {...base} {...p}><rect x="4" y="4" width="8" height="8" rx="1" /><path d="M6.5 1.5v2.5M9.5 1.5v2.5M6.5 12v2.5M9.5 12v2.5M1.5 6.5H4M1.5 9.5H4M12 6.5h2.5M12 9.5h2.5" /></svg>
  ),
  Upload: (p: P) => (
    <svg {...base} {...p}><path d="M8 11V4M4.8 7.2 8 4l3.2 3.2M2.5 12.5v1h11v-1" /></svg>
  ),
  Plus: (p: P) => (
    <svg {...base} {...p}><path d="M8 3v10M3 8h10" /></svg>
  ),
  Minus: (p: P) => (
    <svg {...base} {...p}><path d="M3 8h10" /></svg>
  ),
  Home: (p: P) => (
    <svg {...base} {...p}><path d="M2.5 8 8 3l5.5 5M4 7v6.5h8V7" /></svg>
  ),
  Refresh: (p: P) => (
    <svg {...base} {...p}><path d="M13 8a5 5 0 1 1-1.5-3.6" /><path d="M13 2.5v3h-3" /></svg>
  ),
  Pin: (p: P) => (
    <svg {...base} {...p}><path d="M9.5 2.5 13.5 6.5 10.5 8l-1 3.5L5 7l3.5-1z" /><path d="m5.5 10.5-3 3" /></svg>
  ),
  Warn: (p: P) => (
    <svg {...base} {...p}><path d="M8 2.5 14 13H2z" /><path d="M8 6.5v3M8 11.5v.2" /></svg>
  ),
  Trash: (p: P) => (
    <svg {...base} {...p}><path d="M3 4.5h10M6 4.5V3h4v1.5M4.5 4.5l.7 9h5.6l.7-9" /></svg>
  ),
  Inbox: (p: P) => (
    <svg {...base} {...p}><path d="M2.5 9.5 4 3.5h8l1.5 6v3h-11z" /><path d="M2.5 9.5H6l.8 1.5h2.4l.8-1.5h3.5" /></svg>
  ),
  /* Plug: an external client connecting into Iris — used for the MCP server section */
  Plug: (p: P) => (
    <svg {...base} {...p}><path d="M6 2.5v3M10 2.5v3" /><path d="M4 5.5h8v2.2A3.8 3.8 0 0 1 8.2 11.5h-.4A3.8 3.8 0 0 1 4 7.7Z" /><path d="M8 11.5v2" /></svg>
  ),
  Lock: (p: P) => (
    <svg {...base} {...p}><rect x="3.5" y="7" width="9" height="7" rx="1" /><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" /></svg>
  ),
  /* Cases: a case folder — the canonical container for an investigation */
  Cases: (p: P) => (
    <svg {...base} {...p}>
      <path d="M2.75 12.1V4.9c0-.66.54-1.2 1.2-1.2h2.3c.4 0 .78.2 1 .53l.62.94c.22.33.6.53 1 .53h3.18c.66 0 1.2.54 1.2 1.2v5.2c0 .66-.54 1.2-1.2 1.2H3.95c-.66 0-1.2-.54-1.2-1.2Z" />
    </svg>
  ),
  /* Anomalies: a flat signal broken by one spike */
  Anomalies: (p: P) => (
    <svg {...base} {...p}><path d="M2.2 9.2h2.5l1.5-4.8 2.3 7.6 1.35-2.8h4.05" /></svg>
  ),
  Sort: (p: P) => (
    <svg {...base} {...p}><path d="M4.5 3v10M2.5 10.5 4.5 13l2-2.5M9 4.5h5M9 8h4M9 11.5h2.5" /></svg>
  ),
  Note: (p: P) => (
    <svg {...base} {...p}><path d="M3 3.9h10v6.6H7.4L4.4 13v-2.5H3z" /><path d="M5.4 6.2h5.2M5.4 8.2h3.2" /></svg>
  ),
  Check: (p: P) => (
    <svg {...base} {...p}><path d="m3.5 8.4 3 3 6-6.8" /></svg>
  ),
  /* Drag handle for reorderable nav items */
  Grip: (p: P) => (
    <svg {...base} {...p} fill="currentColor" stroke="none">
      <circle cx="6.2" cy="4.2" r=".95" /><circle cx="9.8" cy="4.2" r=".95" />
      <circle cx="6.2" cy="8" r=".95" /><circle cx="9.8" cy="8" r=".95" />
      <circle cx="6.2" cy="11.8" r=".95" /><circle cx="9.8" cy="11.8" r=".95" />
    </svg>
  ),
  /* Download: the mirror of Export — arrow into a tray */
  Download: (p: P) => (
    <svg {...base} {...p}><path d="M8 2.5v8M5 7.5l3 3 3-3M3 10.5v3h10v-3" /></svg>
  ),
  /* Raw log: a sheet with text lines */
  /* Edit (pen) — the prompt picker's per-row edit control */
  Edit: (p: P) => (
    <svg {...base} {...p}><path d="M3 13h10" /><path d="m4.2 10.3 6.3-6.3 1.5 1.5-6.3 6.3H4.2z" /></svg>
  ),
  Doc: (p: P) => (
    <svg {...base} {...p}><path d="M4.4 2.6h5.2l2.6 2.6v8.2H4.4z" /><path d="M9.6 2.6v2.6h2.6M6.2 8h3.6M6.2 10.4h3.6" /></svg>
  ),
};
