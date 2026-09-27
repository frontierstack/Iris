/**
 * The replay map's LAYOUT: where every event sits, and the route every link takes.
 *
 * "Better structure the process graph, have the nodes placed better and be placed in a more advanced
 * layout that is easy to read and follow." The map used to put each event in a box per PHASE and
 * wrap the boxes across the width, so a process and the child it spawned could land two rows apart
 * and every causal link crossed the map in whatever direction the wrap left it. The chain of
 * causation — this process spawned that one, which wrote this file and connected out — is what the
 * map exists to show, so it is now what the layout is BUILT FROM:
 *
 *   - A link says what each event came FROM. Every event has at most one ACTOR link (the process that
 *     did it) and at most one SHARED link (the earlier event it has the same thing as), so choosing
 *     one PRIMARY parent per event — the actor if there is one, else the shared one — turns the links
 *     into a FOREST, and a forest can be drawn with no crossings at all.
 *   - COLUMNS are causal depth. An actor link moves one column RIGHT (the next generation of the
 *     process tree); a shared link stays in the SAME column (the same thing again, later), stacked
 *     directly under the event it continues. So a column reads as "what this generation did" and a
 *     process's own activity reads as a vertical run beneath it.
 *   - Rows are handed out by a tidy-tree walk with a per-column contour: a node's first child takes
 *     its parent's row, so a chain of spawns is a STRAIGHT line; later children go below. Children are
 *     walked in time order, actor children before continuations, which keeps every primary link free
 *     of crossings by construction.
 *   - Each HOST is a lane (the host the chain STARTED on), and each tree inside it starts on a band
 *     of its own below the one before, so two chains never interleave their rows. Events linked to
 *     nothing share a band, left to right in time order. Lanes sit side by side while they fit.
 *   - A chain deeper than the width WRAPS: the child that would fall off the right edge starts a band
 *     under the tree, reached by a line down the lane's right margin, like a carriage return. Wraps
 *     are taken last-source-first, so their lines nest instead of crossing.
 *   - Too narrow for two columns (a phone), the same forest is drawn as an OUTLINE — one event per
 *     row in walk order, a generation per indent step, elbows down a rail at the parent's left: a
 *     tree view, which has no crossings at any width.

 * Links run LEFT TO RIGHT as orthogonal routes with rounded corners: out of the parent's right edge,
 * along a TRUNK in the gap between two columns, and into the child's left edge. The children of one
 * process share their trunk, so a process tree reads as a bracket, and trunks of different parents
 * whose spans overlap are given separate lanes in the gap so two never run on top of each other. A
 * continuation directly under its source is a short vertical connector; a longer one is a bracket
 * down the column's left margin, also on its own lane. The one link a forest cannot hold (an event
 * with both an actor and a shared link keeps the shared one as a secondary) runs forward like any
 * other, and when it has to run BACK, or into another lane, it follows the channels — the gaps
 * between columns, rows and lanes — so no route passes through an event.
 *
 * The layout is computed ONCE over EVERY event, never over the ones reached so far: a node never moves
 * when a later one arrives, and neither does any route. The component draws only what has been
 * reached and crops its frame to that, so the map still grows as it plays and never reserves empty
 * boxes. Deterministic: the same events and width always give the same picture.
 *
 * Pure and dependency-free, so it can be exercised under Node (types are stripped).
 */

export interface LayoutNode {
  key: string;
  /** position in time order: the tie-break for everything */
  first: number;
  host?: string;
}
/** `step`: the target is a NEW THING the source produced (a spawned process, a file it wrote, a DLL it
 *  loaded, a connection it made) and belongs one column to the right. Without it — an actor link to the
 *  process's own activity ("then"), or a shared link — the target stays in the source's column, under
 *  it. Defaults to `kind === 'actor'`. */
export interface LayoutEdge { a: string; b: string; kind: 'actor' | 'shared'; step?: boolean }
export interface LayoutOpts {
  nodeW: number;
  nodeH: number;
  /** horizontal gap between two columns: the trunks and the arrowheads live in it */
  colGap: number;
  rowGap: number;
  /** padding inside a block */
  pad: number;
  /** a block's header band */
  head: number;
  /** space between two blocks */
  blockGap: number;
  /** the width available; blocks wrap onto a new shelf past it */
  avail: number;
}
export interface Block {
  id: number;
  x: number; y: number; w: number; h: number;
  keys: string[];
  hosts: string[];
  first: number;
}
export interface Route {
  d: string;
  /** the arrowhead, a stroked chevron */
  head: string;
  /** where the reason plate goes; `side:'r'` = start the plate here rather than centring it */
  mid: { x: number; y: number };
  side: 'c' | 'r';
  /** the route as a polyline, for measuring */
  pts: { x: number; y: number }[];
}
export interface Layout {
  pos: Map<string, { x: number; y: number }>;
  col: Map<string, number>;
  row: Map<string, number>;
  blocks: Block[];
  blockOf: Map<string, number>;
  routes: Map<string, Route>;
  /** The edges the layout was BUILT from (each event's one primary parent). Every other link is a
   *  SECONDARY one: still routed and drawn, but through the channels rather than as the tree. */
  primary: Set<string>;
  width: number;
  height: number;
}

export const edgeKey = (a: string, b: string) => `${a}|${b}`;

/** The left margin of a block: continuation brackets run down it. */
const MARGIN = 16;
/** The right margin a lane keeps when a chain in it wraps: the wrap's trunk runs down it. */
const WRAP_MARGIN = 26;
/** One generation's indent in the outline (narrow) form. */
const INDENT = 24;
const LANE_STEP = 7;
const BRACKET_STEP = 6;
const RADIUS = 7;
const CHEVRON = 5;

export function layoutReplay(nodes: LayoutNode[], edges: LayoutEdge[], o: LayoutOpts): Layout {
  const byKey = new Map(nodes.map((n) => [n.key, n]));
  const ordered = [...nodes].sort((p, q) => p.first - q.first);
  const firstOf = (k: string) => byKey.get(k)!.first;
  const valid = edges.filter((e) => byKey.has(e.a) && byKey.has(e.b) && e.a !== e.b);

  /* ── the forest: one primary parent per event ── */
  const actorIn = new Map<string, LayoutEdge>();
  const sharedIn = new Map<string, LayoutEdge>();
  for (const e of valid) {
    if (firstOf(e.a) >= firstOf(e.b)) continue;            // a parent is always earlier
    const m = e.kind === 'actor' ? actorIn : sharedIn;
    if (!m.has(e.b)) m.set(e.b, e);
  }
  // `kind` here is where the child goes: 'actor' = the next column, 'shared' = the same column, below.
  const parent = new Map<string, { p: string; kind: 'actor' | 'shared' }>();
  const primary = new Set<string>();
  for (const n of ordered) {
    const e = actorIn.get(n.key) ?? sharedIn.get(n.key);
    if (e) {
      parent.set(n.key, { p: e.a, kind: (e.step ?? e.kind === 'actor') ? 'actor' : 'shared' });
      primary.add(edgeKey(e.a, e.b));
    }
  }
  const kids = new Map<string, { k: string; kind: 'actor' | 'shared' }[]>();
  for (const n of ordered) {
    const pr = parent.get(n.key);
    if (!pr) continue;
    const l = kids.get(pr.p);
    if (l) l.push({ k: n.key, kind: pr.kind }); else kids.set(pr.p, [{ k: n.key, kind: pr.kind }]);
  }

  /* ── trees, and the HOST lane each one belongs to ── */
  const rootOf = new Map<string, string>();
  for (const n of ordered) {
    const pr = parent.get(n.key);
    rootOf.set(n.key, pr ? rootOf.get(pr.p)! : n.key);
  }
  const trees = new Map<string, string[]>();
  for (const n of ordered) {
    const r = rootOf.get(n.key)!;
    const t = trees.get(r);
    if (t) t.push(n.key); else trees.set(r, [n.key]);
  }
  // A tree lives in its ROOT's host lane (where the chain started); a root with no host takes the first
  // host any of its events names. Lanes keep the order their first tree began in.
  const lanes = new Map<string, string[]>();       // host -> tree roots, in time order
  for (const [r, keys] of trees) {
    const host = byKey.get(r)!.host || keys.map((k) => byKey.get(k)!.host).find((h) => !!h) || '';
    const l = lanes.get(host);
    if (l) l.push(r); else lanes.set(host, [r]);
  }

  /* ── inside a lane: columns by causal depth, rows by a tidy-tree walk ── */
  const pitchX = o.nodeW + o.colGap;
  const pitchY = o.nodeH + o.rowGap;
  const chrome = 2 * o.pad + MARGIN + WRAP_MARGIN;
  // As many columns as the width holds. A chain deeper than that WRAPS onto a new band below, the way
  // a line of text does, rather than running off the side of the map where nobody scrolls to it.
  const maxCols = Math.max(1, Math.floor((o.avail - chrome + o.colGap) / pitchX));
  // Too narrow for even two columns (a phone): the tree is drawn as an OUTLINE instead — one event per
  // row in walk order, each generation indented a step, the links an elbow down a rail at the parent's
  // left — which is a tree view, and a tree view has no crossings at any width.
  const outline = maxCols < 2;
  const maxDepth = Math.max(0, Math.floor((o.avail - 2 * o.pad - MARGIN - WRAP_MARGIN - o.nodeW) / INDENT));
  const col = new Map<string, number>();
  const row = new Map<string, number>();
  const wrapped = new Set<string>();                // edge keys that wrap to a new band
  const blocks: Block[] = [];
  const blockOf = new Map<string, number>();
  const inner: { cols: number; rows: number; keys: string[]; wraps: boolean; host: string }[] = [];
  for (const [host, roots] of lanes) {
    const free: number[] = [];
    const top = () => free.reduce((m, v) => Math.max(m, v ?? 0), 0);
    let wraps = false;
    const deferred: string[][] = [];                   // one group per source, taken LAST-first
    const place = (k: string, c: number, want: number) => {
      const r = Math.max(want, free[c] ?? 0);
      col.set(k, c); row.set(k, r);
      free[c] = r + 1;
      const ch = kids.get(k) ?? [];
      // Actor children first (the next generation, the first one on this row so a chain is straight),
      // then the continuations under it — this order is what keeps the primary links from crossing.
      const wrapGroup: string[] = [];
      for (const x of ch) {
        if (x.kind !== 'actor') continue;
        if (c + 1 < maxCols) place(x.k, c + 1, r);
        else {
          // Out of width: the child is DEFERRED to a band of its own under the whole tree, so the rest
          // of this tree lays out exactly as it would have, and the line into the band runs down the
          // lane's right margin, where nothing else is drawn.
          wraps = true; wrapped.add(edgeKey(k, x.k)); wrapGroup.push(x.k);
        }
      }
      if (wrapGroup.length) deferred.push(wrapGroup);
      for (const x of ch) if (x.kind === 'shared') place(x.k, c, r + 1);
    };
    // Each tree starts on a band of its own, below everything before it, so two chains never
    // interleave their rows. Consecutive one-event trees share a band, left to right, so events linked
    // to nothing read as a compact row in time order rather than a tall column.
    let run: { row: number; col: number } | null = null;
    const keysOf: string[] = [];
    for (const r of roots) {
      const t = trees.get(r)!;
      keysOf.push(...t);
      if (t.length === 1) {
        if (!run || run.col >= maxCols) run = { row: top(), col: 0 };
        col.set(r, run.col); row.set(r, run.row);
        free[run.col] = run.row + 1;
        for (let c = 0; c < maxCols; c++) free[c] = Math.max(free[c] ?? 0, run.row + 1);
        run.col++;
      } else if (outline) {
        run = null;
        let next = top();
        const walk = (k: string, depth: number) => {
          col.set(k, Math.min(depth, maxDepth)); row.set(k, next++);
          const ch = kids.get(k) ?? [];
          for (const x of ch) if (x.kind === 'actor') walk(x.k, depth + 1);
          for (const x of ch) if (x.kind === 'shared') walk(x.k, depth);
        };
        walk(r, 0);
        free[0] = next;
      } else {
        run = null;
        place(r, 0, top());
        // Last source first: its lines then NEST inside the earlier source's (which runs further down
        // the margin, further out), so the carriage returns do not cross each other.
        while (deferred.length) for (const k of deferred.pop()!) place(k, 0, top());
      }
    }
    for (const k of keysOf) if (!col.has(k)) place(k, 0, top());   // cannot happen in a forest; never lose one
    let cols = 0, rows = 0;
    for (const k of keysOf) { cols = Math.max(cols, col.get(k)! + 1); rows = Math.max(rows, row.get(k)! + 1); }
    keysOf.sort((p, q) => firstOf(p) - firstOf(q));
    inner.push({ cols, rows, keys: keysOf, wraps, host });
  }
  inner.sort((p, q) => firstOf(p.keys[0]!) - firstOf(q.keys[0]!));

  /* ── shelves: lanes side by side while they fit, else stacked ── */
  let x = 0, y = 0, shelfH = 0;
  inner.forEach((g, id) => {
    const w = outline ? 2 * o.pad + MARGIN + WRAP_MARGIN + (g.cols - 1) * INDENT + o.nodeW
      : 2 * o.pad + MARGIN + (g.wraps ? WRAP_MARGIN : 0) + g.cols * o.nodeW + (g.cols - 1) * o.colGap;
    const h = o.head + o.pad + g.rows * pitchY - o.rowGap;
    if (x > 0 && x + w > o.avail) { x = 0; y += shelfH + o.blockGap; shelfH = 0; }
    const hosts = g.host ? [g.host] : [];
    blocks.push({ id, x, y, w, h, keys: g.keys, hosts, first: firstOf(g.keys[0]!) });
    for (const k of g.keys) blockOf.set(k, id);
    x += w + o.blockGap;
    shelfH = Math.max(shelfH, h);
  });
  const pos = new Map<string, { x: number; y: number }>();
  for (const b of blocks) {
    const ox = b.x + o.pad + MARGIN;
    const oy = b.y + o.head;
    for (const k of b.keys) pos.set(k, { x: ox + col.get(k)! * (outline ? INDENT : pitchX), y: oy + row.get(k)! * pitchY });
  }

  /* ── routes ── */
  const routes = new Map<string, Route>();
  const W = o.nodeW, H = o.nodeH;
  const cy = (k: string) => pos.get(k)!.y + H / 2;
  // Trunk lanes: the forward links leaving one column of one block, grouped by the node they leave,
  // each group spanning its rows. Groups whose spans overlap get different lanes (interval colouring).
  const isWrap = (e: LayoutEdge) => wrapped.has(edgeKey(e.a, e.b));
  const wrapY = (k: string) => pos.get(k)!.y - o.rowGap / 2;
  const fwd = valid.filter((e) => col.get(e.b)! > col.get(e.a)! && !isWrap(e) && blockOf.get(e.a) === blockOf.get(e.b));
  // Wrap trunks run down the right margin. The one that ENDS first takes the lane nearest the column,
  // so a wrap's leftward run into its band never crosses a trunk that is still on its way down.
  const wrapLane = new Map<string, number>();
  {
    const bySlot = new Map<number, { k: string; lo: number; hi: number }[]>();
    for (const e of valid) {
      if (!isWrap(e)) continue;
      const b = blockOf.get(e.a)!;
      const l = bySlot.get(b) ?? [];
      const cur = l.find((x) => x.k === e.a);
      if (cur) { cur.lo = Math.min(cur.lo, cy(e.a)); cur.hi = Math.max(cur.hi, wrapY(e.b)); }
      else l.push({ k: e.a, lo: cy(e.a), hi: wrapY(e.b) });
      bySlot.set(b, l);
    }
    for (const list of bySlot.values()) {
      list.sort((p, q) => p.hi - q.hi || p.lo - q.lo);
      const used: { lo: number; hi: number; lane: number }[] = [];
      for (const it of list) {
        let lane = 0;
        while (used.some((u) => u.lane === lane && !(u.hi < it.lo - 1 || it.hi < u.lo - 1))) lane++;
        used.push({ lo: it.lo, hi: it.hi, lane });
        wrapLane.set(it.k, lane);
      }
    }
  }
  const trunkLane = new Map<string, number>();       // by source node key
  {
    const bySlot = new Map<string, { k: string; lo: number; hi: number }[]>();
    const span = new Map<string, { lo: number; hi: number; slot: string }>();
    for (const e of fwd) {
      const slot = `${blockOf.get(e.a)}|${col.get(e.a)}`;
      const yb = cy(e.b);
      const lo = Math.min(cy(e.a), yb), hi = Math.max(cy(e.a), yb);
      const s = span.get(e.a);
      if (s) { s.lo = Math.min(s.lo, lo); s.hi = Math.max(s.hi, hi); } else span.set(e.a, { lo, hi, slot });
    }
    for (const [k, s] of span) {
      const l = bySlot.get(s.slot);
      if (l) l.push({ k, lo: s.lo, hi: s.hi }); else bySlot.set(s.slot, [{ k, lo: s.lo, hi: s.hi }]);
    }
    for (const list of bySlot.values()) {
      // Bottom-most first, so a trunk that starts LOWER takes the lane nearer the column: the one above
      // it then leaves its source above that trunk and arrives at children above it, crossing nothing.
      list.sort((p, q) => q.lo - p.lo || q.hi - p.hi || firstOf(p.k) - firstOf(q.k));
      const used: { lo: number; hi: number; lane: number }[] = [];
      for (const it of list) {
        let lane = 0;
        while (used.some((u) => u.lane === lane && !(u.hi < it.lo - 1 || it.hi < u.lo - 1))) lane++;
        used.push({ lo: it.lo, hi: it.hi, lane });
        trunkLane.set(it.k, lane);
      }
    }
  }
  // Bracket lanes: same-column links that are not a straight drop to the very next row.
  const bracketLane = new Map<string, number>();
  {
    const bySlot = new Map<string, { e: LayoutEdge; lo: number; hi: number }[]>();
    for (const e of valid) {
      if (col.get(e.a) !== col.get(e.b) || blockOf.get(e.a) !== blockOf.get(e.b)) continue;
      if (row.get(e.b)! - row.get(e.a)! === 1) continue;
      const slot = `${blockOf.get(e.a)}|${col.get(e.a)}`;
      const lo = Math.min(row.get(e.a)!, row.get(e.b)!), hi = Math.max(row.get(e.a)!, row.get(e.b)!);
      const l = bySlot.get(slot);
      if (l) l.push({ e, lo, hi }); else bySlot.set(slot, [{ e, lo, hi }]);
    }
    for (const list of bySlot.values()) {
      list.sort((p, q) => (p.hi - p.lo) - (q.hi - q.lo) || p.lo - q.lo);   // short brackets hug the node
      const used: { lo: number; hi: number; lane: number }[] = [];
      for (const it of list) {
        let lane = 0;
        while (used.some((u) => u.lane === lane && !(u.hi <= it.lo || it.hi <= u.lo))) lane++;
        used.push({ lo: it.lo, hi: it.hi, lane });
        bracketLane.set(edgeKey(it.e.a, it.e.b), lane);
      }
    }
  }
  const maxLanes = Math.max(1, Math.floor((o.colGap - 30) / LANE_STEP) + 1);
  // Two lanes are side by side when their vertical extents overlap; otherwise one is under the other.
  const sideBySide = (e: LayoutEdge) => {
    const p = blocks[blockOf.get(e.a)!]!, q = blocks[blockOf.get(e.b)!]!;
    return p.y < q.y + q.h && q.y < p.y + p.h;
  };
  const rightBracket = (e: LayoutEdge, lane: number): Route => {
    const a = pos.get(e.a)!, b = pos.get(e.b)!;
    const ya = cy(e.a), yb = cy(e.b);
    const lo = Math.min(ya, yb), hi = Math.max(ya, yb);
    let right = Math.max(a.x, b.x) + W;
    for (const [k, p] of pos) {
      if (k === e.a || k === e.b) continue;
      if (p.y + H > lo && p.y < hi) right = Math.max(right, p.x + W);
    }
    const bx = right + 10 + lane * BRACKET_STEP;
    const x1 = a.x + W, x2 = b.x + W + 1;
    const q = Math.min(5, Math.abs(yb - ya) / 2), sg = yb > ya ? 1 : -1;
    return { d: `M${x1},${ya} H${bx - q} Q${bx},${ya} ${bx},${ya + sg * q} V${yb - sg * q} Q${bx},${yb} ${bx - q},${yb} H${x2 + 1}`,
      head: chevron(x2, yb, 'l'), mid: { x: bx + 6, y: (ya + yb) / 2 }, side: 'r',
      pts: [{ x: x1, y: ya }, { x: bx, y: ya }, { x: bx, y: yb }, { x: x2, y: yb }] };
  };
  for (const e of valid) {
    const a = pos.get(e.a)!, b = pos.get(e.b)!;
    const ca = col.get(e.a)!, cb = col.get(e.b)!;
    const same = blockOf.get(e.a) === blockOf.get(e.b);
    let r: Route;
    if (outline && same && parent.get(e.b)?.p === e.a) {
      // The outline's elbow: down the rail at the parent's left, then in to a child one step in. A
      // child at the same indent (the same thing again, or the indent has run out) is entered from above.
      const rx = a.x + 10;
      const y1 = a.y + H, yb = cy(e.b);
      if (b.x - a.x > 12) {
        const x2 = b.x - 1;
        const q = Math.min(6, (yb - y1) / 2);
        r = { d: `M${rx},${y1} V${yb - q} Q${rx},${yb} ${rx + q},${yb} H${x2 - 1}`, head: chevron(x2, yb, 'r'),
          mid: { x: rx + 8, y: (y1 + yb) / 2 }, side: 'r', pts: [{ x: rx, y: y1 }, { x: rx, y: yb }, { x: x2, y: yb }] };
      } else {
        const y2 = b.y - 1;
        r = { d: `M${rx},${y1} V${y2 - 1}`, head: chevron(rx, y2, 'd'), mid: { x: rx + 8, y: (y1 + y2) / 2 }, side: 'r',
          pts: [{ x: rx, y: y1 }, { x: rx, y: y2 }] };
      }
    } else if (outline) {
      // A second link in the outline, or one between two STACKED lanes: a bracket down the right of
      // everything it passes, so it never runs through an event.
      r = rightBracket(e, bracketLane.get(edgeKey(e.a, e.b)) ?? 0);
    } else if (same && isWrap(e)) {
      // A chain that ran out of width: down the lane's right margin, back along the gap above the row
      // it continues on, and into the child from the left — the line reads like a carriage return.
      const x1 = a.x + W, ya = cy(e.a);
      const lane = Math.min(wrapLane.get(e.a) ?? 0, 2);
      const tx = x1 + 9 + lane * BRACKET_STEP;
      const yw = wrapY(e.b), yb = cy(e.b);
      const xl = b.x - 9, x2 = b.x - 1;
      const q = 6;
      r = {
        d: `M${x1},${ya} H${tx - q} Q${tx},${ya} ${tx},${ya + q} V${yw - q} Q${tx},${yw} ${tx - q},${yw} H${xl + q} Q${xl},${yw} ${xl},${yw + q} V${yb - q} Q${xl},${yb} ${xl + q},${yb} H${x2 - 1}`,
        head: chevron(x2, yb, 'r'),
        mid: { x: (x1 + tx) / 2 + 60, y: yw }, side: 'c',
        pts: [{ x: x1, y: ya }, { x: tx, y: ya }, { x: tx, y: yw }, { x: xl, y: yw }, { x: xl, y: yb }, { x: x2, y: yb }],
      };
    } else if (same && cb > ca) {
      const x1 = a.x + W, x2 = b.x - 1;
      const ya = cy(e.a), yb = cy(e.b);
      const lane = Math.min(trunkLane.get(e.a) ?? 0, maxLanes - 1);
      const tx = x1 + 14 + lane * LANE_STEP;
      if (Math.abs(ya - yb) < 0.5) {
        r = { d: `M${x1},${ya} H${x2 - 1}`, head: chevron(x2, yb, 'r'), mid: { x: (x1 + x2) / 2, y: ya }, side: 'c',
          pts: [{ x: x1, y: ya }, { x: x2, y: yb }] };
      } else {
        const rad = Math.min(RADIUS, Math.abs(yb - ya) / 2);
        const s = yb > ya ? 1 : -1;
        r = {
          d: `M${x1},${ya} H${tx - rad} Q${tx},${ya} ${tx},${ya + s * rad} V${yb - s * rad} Q${tx},${yb} ${tx + rad},${yb} H${x2 - 1}`,
          head: chevron(x2, yb, 'r'),
          mid: { x: (tx + x2) / 2 + 2, y: yb }, side: 'c',
          pts: [{ x: x1, y: ya }, { x: tx, y: ya }, { x: tx, y: yb }, { x: x2, y: yb }],
        };
      }
    } else if (same && cb === ca && row.get(e.b)! - row.get(e.a)! === 1) {
      // straight down to the next row: a short spine under the badge
      const vx = a.x + 21;
      const y1 = a.y + H, y2 = b.y - 1;
      r = { d: `M${vx},${y1} V${y2 - 1}`, head: chevron(vx, y2, 'd'), mid: { x: vx + 8, y: (y1 + y2) / 2 }, side: 'r',
        pts: [{ x: vx, y: y1 }, { x: vx, y: y2 }] };
    } else if (same && cb === ca) {
      // a longer continuation: a bracket down the left margin, on its own lane
      const lane = bracketLane.get(edgeKey(e.a, e.b)) ?? 0;
      const bx = a.x - 7 - lane * BRACKET_STEP;
      const ya = a.y + H * 0.7, yb = b.y + H * 0.3;
      const xe = b.x - 1;
      const rad = Math.min(5, Math.abs(yb - ya) / 2);
      const s = yb > ya ? 1 : -1;
      r = {
        d: `M${a.x},${ya} H${bx + rad} Q${bx},${ya} ${bx},${ya + s * rad} V${yb - s * rad} Q${bx},${yb} ${bx + rad},${yb} H${xe - 1}`,
        head: chevron(xe, yb, 'r'),
        mid: { x: bx + 6, y: (ya + yb) / 2 }, side: 'r',
        pts: [{ x: a.x, y: ya }, { x: bx, y: ya }, { x: bx, y: yb }, { x: xe, y: yb }],
      };
    } else if (!same && sideBySide(e)) {
      // Between two lanes side by side: a curve between the facing sides.
      const ax = a.x + W / 2, ay = cy(e.a), bx = b.x + W / 2, by = cy(e.b);
      const x1 = bx > ax ? a.x + W : a.x, x2 = bx > ax ? b.x - 1 : b.x + W + 1;
      const dir = bx > ax ? 1 : -1;
      const dx = Math.max(30, Math.abs(x2 - x1) * 0.45) * dir;
      const xe = x2 - dir * 7;
      r = { d: `M${x1},${ay} C${x1 + dx},${ay} ${xe - dx},${by} ${xe},${by}`, head: chevron(x2, by, dir > 0 ? 'r' : 'l'),
        mid: { x: (x1 + xe) / 2, y: (ay + by) / 2 }, side: 'c', pts: sampleCubic(x1, ay, x1 + dx, ay, xe - dx, by, xe, by) };
    } else {
      // Backwards inside a lane, or into a lane stacked above or below: along the CHANNELS, where no
      // event sits — the gap to the source's right, the gap between rows (or lanes) above the target,
      // the gap to the target's left.
      const x1 = a.x + W, ya = cy(e.a), yb = cy(e.b);
      const tx = x1 + o.colGap - 16;
      const bb = blocks[blockOf.get(e.b)!]!;
      const yc = same ? b.y - o.rowGap / 2
        : bb.y > blocks[blockOf.get(e.a)!]!.y ? bb.y - o.blockGap / 2 : bb.y + bb.h + o.blockGap / 2;
      const xl = b.x - 9, x2 = b.x - 1;
      const q = 5;
      const s1 = yc > ya ? 1 : -1, s2 = yb > yc ? 1 : -1, s3 = xl > tx ? 1 : -1;
      r = {
        d: `M${x1},${ya} H${tx - q} Q${tx},${ya} ${tx},${ya + s1 * q} V${yc - s1 * q} Q${tx},${yc} ${tx + s3 * q},${yc} H${xl - s3 * q} Q${xl},${yc} ${xl},${yc + s2 * q} V${yb - s2 * q} Q${xl},${yb} ${xl + q},${yb} H${x2 - 1}`,
        head: chevron(x2, yb, 'r'),
        mid: { x: (tx + xl) / 2, y: yc }, side: 'c',
        pts: [{ x: x1, y: ya }, { x: tx, y: ya }, { x: tx, y: yc }, { x: xl, y: yc }, { x: xl, y: yb }, { x: x2, y: yb }],
      };
    }
    routes.set(edgeKey(e.a, e.b), r);
  }

  const width = blocks.length ? Math.max(...blocks.map((b) => b.x + b.w)) : 0;
  const height = blocks.length ? Math.max(...blocks.map((b) => b.y + b.h)) : 0;
  return { pos, col, row, blocks, blockOf, routes, primary, width, height };
}

/** A stroked chevron whose tip is at (x, y), pointing right, left or down. */
function chevron(x: number, y: number, dir: 'r' | 'l' | 'd' | 'u'): string {
  const c = CHEVRON;
  if (dir === 'r') return `M${x - c - 2},${y - c} L${x - 1},${y} L${x - c - 2},${y + c}`;
  if (dir === 'l') return `M${x + c + 2},${y - c} L${x + 1},${y} L${x + c + 2},${y + c}`;
  if (dir === 'u') return `M${x - c},${y + c + 2} L${x},${y + 1} L${x + c},${y + c + 2}`;
  return `M${x - c},${y - c - 2} L${x},${y - 1} L${x + c},${y - c - 2}`;
}

export function sampleCubic(x0: number, y0: number, x1: number, y1: number, x2: number, y2: number,
  x3: number, y3: number, n = 16): { x: number; y: number }[] {
  const out: { x: number; y: number }[] = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n, u = 1 - t;
    out.push({
      x: u * u * u * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x3,
      y: u * u * u * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3,
    });
  }
  return out;
}

/** Measure a drawing: link crossings (pairs of links that share no event), links that pass through an
 *  event they do not belong to, and overlapping events. Used by the tests; cheap enough to keep here. */
export function measure(pos: Map<string, { x: number; y: number }>, links: { a: string; b: string; pts: { x: number; y: number }[] }[],
  nodeW: number, nodeH: number): { crossings: number; throughNodes: number; overlaps: number } {
  let crossings = 0;
  for (let i = 0; i < links.length; i++) {
    for (let j = i + 1; j < links.length; j++) {
      const p = links[i]!, q = links[j]!;
      if (p.a === q.a || p.a === q.b || p.b === q.a || p.b === q.b) continue;
      if (polyCross(p.pts, q.pts)) crossings++;
    }
  }
  let throughNodes = 0;
  for (const l of links) {
    for (const [k, r] of pos) {
      if (k === l.a || k === l.b) continue;
      if (polyHitsRect(l.pts, r.x + 2, r.y + 2, nodeW - 4, nodeH - 4)) throughNodes++;
    }
  }
  let overlaps = 0;
  const ps = [...pos.values()];
  for (let i = 0; i < ps.length; i++) for (let j = i + 1; j < ps.length; j++) {
    const a = ps[i]!, b = ps[j]!;
    if (a.x < b.x + nodeW && b.x < a.x + nodeW && a.y < b.y + nodeH && b.y < a.y + nodeH) overlaps++;
  }
  return { crossings, throughNodes, overlaps };
}
type P = { x: number; y: number };
function segX(a: P, b: P, c: P, d: P): boolean {
  const o = (p: P, q: P, r: P) => Math.sign((q.x - p.x) * (r.y - p.y) - (q.y - p.y) * (r.x - p.x));
  const o1 = o(a, b, c), o2 = o(a, b, d), o3 = o(c, d, a), o4 = o(c, d, b);
  return o1 * o2 < 0 && o3 * o4 < 0;
}
function polyCross(p: P[], q: P[]): boolean {
  for (let i = 1; i < p.length; i++) for (let j = 1; j < q.length; j++) if (segX(p[i - 1]!, p[i]!, q[j - 1]!, q[j]!)) return true;
  return false;
}
function polyHitsRect(p: P[], x: number, y: number, w: number, h: number): boolean {
  const inside = (q: P) => q.x > x && q.x < x + w && q.y > y && q.y < y + h;
  const corners: P[] = [{ x, y }, { x: x + w, y }, { x: x + w, y: y + h }, { x, y: y + h }];
  for (let i = 1; i < p.length; i++) {
    const a = p[i - 1]!, b = p[i]!;
    if (inside(a) || inside(b)) return true;
    for (let k = 0; k < 4; k++) if (segX(a, b, corners[k]!, corners[(k + 1) % 4]!)) return true;
  }
  return false;
}
