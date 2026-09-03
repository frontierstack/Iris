/* Canvas painter for the entity graph.
 *
 * The graph used to be SVG: roughly 16 DOM elements per node (disc, glyph, rings, label box, label text,
 * kind text, hit circle …) plus one <path> per edge, and the simulation wrote `transform`/`d` onto every
 * one of them on every tick. Measured headless on the real 1.22 M-event workspace that was 9.9 fps at 200
 * nodes, 4.6 at 500, 1.6 at 1,000 and 0.7 at 2,000 — the node cap goes to 2,000, so the top of the range
 * was a slideshow. The cost was not the layout (d3-force settles in milliseconds at these sizes); it was
 * style, layout and paint over 33,000 SVG elements.
 *
 * Everything is now drawn into ONE <canvas>: no per-node DOM, no per-tick attribute writes, and the
 * renderer can cull, quantise and cache. The visual vocabulary is unchanged — same discs, same type hues,
 * same severity rings, same curved edges with arrowheads, same label chips, same dashed AI links — because
 * the shapes are the same shapes, just rasterised here instead of by the SVG engine.
 *
 * Three things make it fast:
 *   * a SPRITE CACHE. A node disc is a radial gradient + a ring + a glow, which is expensive per draw and
 *     identical for every node with the same (radius, ring colour, ring width, state). Each distinct
 *     combination is rendered once into a small offscreen canvas and then blitted with drawImage.
 *   * CULLING. Anything outside the viewport (plus a margin) is skipped entirely.
 *   * LEVEL OF DETAIL. Glyphs are skipped when the node is too small on screen to read them, and labels
 *     are drawn only for the nodes the screen asked to label.
 */

export interface PaintPalette {
  edge: string; accent: string; accentHover: string; accentBorder: string; nodeRing: string; nodeFill: string;
  /** the lift at the top-left of a node disc — a flat panel tone, not a highlight */
  nodeFill2: string;
  nodeRingSel: string; graphBg: string; panel: string; accentBg: string; border: string; text2: string; textBright: string;
  muted2: string; onAccent: string; sevMedium: string; sevHigh: string; sevCritical: string; mono: string;
}

/** Per-node data that only changes when the query result changes. */
export interface PaintNode {
  id: string; hue: string; glyph: string; name: string; kind: string;
  sev: string; detections: number; inCase: boolean;
}
/** Per-edge data that only changes when the query result changes. */
export interface PaintEdge {
  id: string; width: number; opacity: number; arrow: boolean; bad: boolean; ai: boolean;
}
/** Interaction state — cheap to rebuild, read fresh on every frame. */
export interface PaintState {
  selected: string | null; hover: string | null; neighbours: Set<string>; pathNodes: Set<string>;
  pathEdges: Set<string>; proposed: Set<string>; labelled: Set<string>;
}
export interface PaintView { x: number; y: number; k: number }

export interface PaintSimNode { name: string; x?: number; y?: number; r: number; index?: number }
export interface PaintSimLink { id: string; source: PaintSimNode; target: PaintSimNode }

const EMPTY_STATE: PaintState = {
  selected: null, hover: null, neighbours: new Set(), pathNodes: new Set(),
  pathEdges: new Set(), proposed: new Set(), labelled: new Set(),
};

/** Read the theme's colours out of CSS custom properties once, so the canvas matches every theme.
 *
 *  EVERY colour the painter draws with arrives through this function — there is no literal in the
 *  drawing code, because a hex baked into a canvas call is a value that is wrong in eight of the
 *  nine themes and, unlike a stylesheet, nothing in the build can see it.
 *
 *  The second argument is a LAST RESORT, reached only if a theme fails to define the token at all.
 *  They used to be the previous palette's greens (#7ee2a8 accent, #242c25 edge, #1c2a1e node fill),
 *  which is the worst possible fallback: a missing token would not have degraded, it would have
 *  drawn the canvas in a colour scheme the app no longer has. They are the observability template's
 *  own values now — the same hexes themes.css states for `iris-dark`. */
export function readPalette(el: HTMLElement): PaintPalette {
  const cs = getComputedStyle(el);
  const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback;
  return {
    edge: v('--edge', '#2b3237'), accent: v('--accent', '#35c2c8'), accentHover: v('--accent-hover', '#4ad3d8'),
    accentBorder: v('--accent-border', '#2f7f86'), nodeRing: v('--node-ring', '#2f7f86'),
    nodeFill: v('--node-fill', '#17282b'), nodeFill2: v('--panel-2', '#161a1d'),
    nodeRingSel: v('--node-ring-sel', '#9fd9db'),
    graphBg: v('--graph-bg', '#0d0f11'), panel: v('--panel', '#101315'),
    accentBg: v('--accent-bg', '#122528'), border: v('--border', '#23282c'),
    text2: v('--text-2', '#d3dadd'), textBright: v('--text-bright', '#f1f5f6'), muted2: v('--muted-2', '#6d777c'),
    onAccent: v('--on-accent', '#08181a'), sevMedium: v('--sev-medium', '#c9b45f'),
    sevHigh: v('--sev-high', '#e0a33c'), sevCritical: v('--sev-critical', '#e2695f'),
    mono: v('--font-mono', 'ui-monospace, monospace'),
  };
}

/** The control point of the same quadratic bow the SVG renderer used, so the curves are identical. */
export function edgeControl(x1: number, y1: number, x2: number, y2: number, bow = 0.12): [number, number] {
  const dx = x2 - x1;
  const dy = y2 - y1;
  return [(x1 + x2) / 2 - dy * bow, (y1 + y2) / 2 + dx * bow];
}

interface SpriteKey { r: number; ring: string; width: number; selected: boolean; glow: boolean; inCase: boolean; proposed: boolean }

/* Edge style buckets — see the edge pass in `draw`. */
const S_PLAIN = 0, S_AI = 1, S_BAD = 2, S_ON = 3, S_ON_BAD = 4, S_PATH = 5, S_DIM = 6;
/** Extra CSS px rendered around the viewport in the cached edge layer, so a small pan is a blit. */
const EDGE_MARGIN = 160;

export class GraphPainter {
  private ctx: CanvasRenderingContext2D | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private dpr = 1;
  private w = 0;
  private h = 0;
  private palette: PaintPalette;
  private nodes = new Map<string, PaintNode>();
  private edges = new Map<string, PaintEdge>();
  private state: PaintState = EMPTY_STATE;
  private sprites = new Map<string, HTMLCanvasElement>();
  private glyphs = new Map<string, HTMLCanvasElement>();
  private strokeBatch = new Map<number, Path2D>();
  private fillBatch = new Map<number, Path2D>();
  private hues = new Map<string, string>();
  private pairSeen = new Set<number>();
  /* The EDGE LAYER of a settled graph, kept between frames. Once the layout is cold the edges only
   * change with the data, the selection/path state, the palette, the canvas size or the zoom — none of
   * which a hover, a pan or a tooltip touches. Rasterising 20,000 curves was the whole frame (the
   * profiler put the JS thread at 93 % idle — the time was the raster, not the script), so a settled
   * graph is blitted from this bitmap and only the nodes are redrawn. A pan at the same zoom is the
   * same bitmap at an offset; a zoom re-renders it once. */
  private edgeLayer: HTMLCanvasElement | null = null;
  private edgeLayerKey = '';
  private edgeLayerView: PaintView = { x: 0, y: 0, k: 1 };
  private dataVersion = 0;
  private paletteVersion = 0;

  constructor(palette: PaintPalette) {
    this.palette = palette;
  }

  attach(canvas: HTMLCanvasElement | null): void {
    this.canvas = canvas;
    this.ctx = canvas ? canvas.getContext('2d', { alpha: true }) : null;
  }

  setPalette(p: PaintPalette): void {
    this.palette = p;
    this.sprites.clear();          // colours are baked into the sprites
    this.glyphs.clear();
    this.hues.clear();
    this.paletteVersion++;
  }

  /** Type glyphs pre-rendered per (character, colour, size). Setting `ctx.font` re-parses a font shorthand
   *  and `fillText` shapes text — doing both once per node per frame was one of the two hot spots left
   *  after the SVG went away. Sizes are quantised to whole pixels, so this cache is a couple of dozen
   *  entries however many nodes there are. */
  private glyphSprite(ch: string, colour: string, size: number): HTMLCanvasElement {
    const id = `${ch}|${colour}|${size}`;
    const hit = this.glyphs.get(id);
    if (hit) return hit;
    const s = 2;
    const box = Math.ceil(size * 2.4);
    const c = document.createElement('canvas');
    c.width = box * s;
    c.height = box * s;
    const g = c.getContext('2d')!;
    g.scale(s, s);
    g.font = `600 ${size}px ${this.palette.mono}`;
    g.textAlign = 'center';
    g.textBaseline = 'middle';
    g.fillStyle = colour;
    g.fillText(ch, box / 2, box / 2);
    this.glyphs.set(id, c);
    return c;
  }

  setSize(w: number, h: number, dpr: number): void {
    this.w = w;
    this.h = h;
    this.dpr = dpr;
    const c = this.canvas;
    if (!c) return;
    const pw = Math.max(1, Math.round(w * dpr));
    const ph = Math.max(1, Math.round(h * dpr));
    if (c.width !== pw || c.height !== ph) { c.width = pw; c.height = ph; }
    c.style.width = `${w}px`;
    c.style.height = `${h}px`;
  }

  setData(nodes: PaintNode[], edges: PaintEdge[]): void {
    this.nodes = new Map(nodes.map((n) => [n.id, n]));
    this.edges = new Map(edges.map((e) => [e.id, e]));
    this.dataVersion++;
  }

  /** Force the next frame to re-rasterise the edge layer (a node was dragged while the layout was cold). */
  invalidateEdges(): void {
    this.edgeLayerKey = '';
  }

  setState(s: PaintState): void {
    this.state = s;
  }

  /** Type hues are mostly literal hex, but some are theme tokens ("var(--accent)"). Canvas cannot take a
   *  CSS variable, so resolve it once per theme and cache. */
  private hue(raw: string): string {
    if (raw.charCodeAt(0) !== 118 /* 'v' */) return raw;
    const hit = this.hues.get(raw);
    if (hit) return hit;
    const m = /^var\((--[a-z0-9-]+)\)$/i.exec(raw);
    const out = (m && getComputedStyle(document.documentElement).getPropertyValue(m[1]!).trim()) || this.palette.accent;
    this.hues.set(raw, out);
    return out;
  }

  /** Nearest node under a WORLD-space point, topmost first — the canvas equivalent of an SVG hit target. */
  hitTest(simNodes: readonly PaintSimNode[], wx: number, wy: number, slack = 6): string | null {
    let best: string | null = null;
    let bestD = Infinity;
    for (let i = simNodes.length - 1; i >= 0; i--) {
      const n = simNodes[i]!;
      if (n.x === undefined || n.y === undefined) continue;
      const dx = wx - n.x;
      const dy = wy - n.y;
      const d2 = dx * dx + dy * dy;
      const reach = n.r + slack;
      if (d2 <= reach * reach && d2 < bestD) { bestD = d2; best = n.name; }
    }
    return best;
  }

  // ------------------------------------------------------------------ sprites
  private spriteFor(k: SpriteKey): HTMLCanvasElement {
    const id = `${k.r}|${k.ring}|${k.width}|${k.selected ? 1 : 0}|${k.glow ? 1 : 0}|${k.inCase ? 1 : 0}|${k.proposed ? 1 : 0}`;
    const hit = this.sprites.get(id);
    if (hit) return hit;
    const p = this.palette;
    // Only pay for the padding this particular sprite needs. A flat 12 px margin made a 9 px node a
    // 42×42 blit — five times the pixels it draws — and blitting is the whole cost of the node layer.
    const pad = Math.ceil(k.width) + 2 + (k.proposed ? 8 : k.inCase ? 5 : 0) + (k.glow ? (k.selected ? 11 : 7) : 0);
    const size = Math.ceil((k.r + pad) * 2);
    const c = document.createElement('canvas');
    const s = 2;                                   // sprites are drawn at 2x and scaled down when blitted
    c.width = size * s;
    c.height = size * s;
    const g = c.getContext('2d')!;
    g.scale(s, s);
    g.translate(size / 2, size / 2);
    if (k.proposed) {
      // Dashed outer ring = NOT extracted from the logs. A proposed link's endpoint, or a node the
      // analyst/agent drew themselves (`manual`): what someone CONCLUDED, never what a log said.
      g.save(); g.setLineDash([1.5, 3]); g.strokeStyle = k.ring; g.lineWidth = 1; g.globalAlpha = 0.75;
      g.beginPath(); g.arc(0, 0, k.r + 6, 0, Math.PI * 2); g.stroke(); g.restore();
    }
    if (k.inCase) {
      g.save(); g.setLineDash([2, 3]); g.strokeStyle = p.accent; g.lineWidth = 1; g.globalAlpha = 0.8;
      g.beginPath(); g.arc(0, 0, k.r + 3.5, 0, Math.PI * 2); g.stroke(); g.restore();
    }
    // A flatter disc than the old strong radial: the gradient is a subtle top-left lift now, not a
    // 3D bead. Type is carried by the ring colour and the glyph; a heavily shaded sphere competed with
    // both and made a dense graph look like a bag of marbles.
    const grad = g.createRadialGradient(-k.r * 0.35, -k.r * 0.45, k.r * 0.2, 0, 0, k.r * 1.05);
    if (k.selected) { grad.addColorStop(0, p.accentHover); grad.addColorStop(1, p.accent); }
    else { grad.addColorStop(0, p.nodeFill2); grad.addColorStop(1, p.nodeFill); }
    if (k.glow) { g.shadowColor = k.ring; g.shadowBlur = k.selected ? 8 : 5; }
    g.beginPath(); g.arc(0, 0, k.r, 0, Math.PI * 2);
    g.fillStyle = grad; g.fill();
    g.strokeStyle = k.ring; g.lineWidth = k.width; g.stroke();
    this.sprites.set(id, c);
    if (this.sprites.size > 900) {                 // bounded: radius buckets × ring colours × state
      const first = this.sprites.keys().next().value;
      if (first !== undefined && first !== id) this.sprites.delete(first);
    }
    return c;
  }

  // ------------------------------------------------------------------ frame
  /** `hot` = the layout is still moving (or a node is being dragged): the edge layer cannot be cached. */
  draw(simNodes: readonly PaintSimNode[], simLinks: readonly PaintSimLink[], view: PaintView, hot = true): void {
    const ctx = this.ctx;
    if (!ctx) return;
    const st = this.state;
    const { w, h, dpr } = this;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    // world-space viewport for culling (generous margin so labels/arrows never pop at the edge)
    const m = 80 / view.k;
    const vx0 = -view.x / view.k - m;
    const vy0 = -view.y / view.k - m;
    const vx1 = (w - view.x) / view.k + m;
    const vy1 = (h - view.y) / view.k + m;

    // ---------------------------------------------------------------- edge layer
    // Hot: straight into the frame. Cold: from the cached bitmap when its key matches (same data,
    // selection, path, palette, size, zoom), re-rasterised once otherwise. The margin makes a small
    // pan at the same zoom a pure blit; a pan beyond it re-renders (one raster per pan stop, not one
    // per frame).
    const key = `${this.dataVersion}|${this.paletteVersion}|${st.selected ?? ''}|${st.pathEdges.size}|${w}x${h}@${dpr}|${view.k.toFixed(4)}`;
    if (hot || simLinks.length < 800) {
      this.edgeLayerKey = '';
      ctx.save();
      ctx.translate(view.x, view.y);
      ctx.scale(view.k, view.k);
      this.drawEdges(ctx, simLinks, view, vx0, vy0, vx1, vy1);
      ctx.restore();
    } else {
      const same = !!this.edgeLayer && this.edgeLayerKey === key;
      const dx = same ? view.x - this.edgeLayerView.x : 0;
      const dy = same ? view.y - this.edgeLayerView.y : 0;
      if (!same || Math.abs(dx) > EDGE_MARGIN || Math.abs(dy) > EDGE_MARGIN) {
        const layer = this.edgeLayer ?? (this.edgeLayer = document.createElement('canvas'));
        const lw = Math.max(1, Math.round((w + 2 * EDGE_MARGIN) * dpr));
        const lh = Math.max(1, Math.round((h + 2 * EDGE_MARGIN) * dpr));
        if (layer.width !== lw || layer.height !== lh) { layer.width = lw; layer.height = lh; }
        const g = layer.getContext('2d')!;
        g.setTransform(dpr, 0, 0, dpr, 0, 0);
        g.clearRect(0, 0, w + 2 * EDGE_MARGIN, h + 2 * EDGE_MARGIN);
        g.save();
        g.translate(view.x + EDGE_MARGIN, view.y + EDGE_MARGIN);
        g.scale(view.k, view.k);
        const mm = EDGE_MARGIN / view.k;
        this.drawEdges(g, simLinks, view, vx0 - mm, vy0 - mm, vx1 + mm, vy1 + mm);
        g.restore();
        this.edgeLayerKey = key;
        this.edgeLayerView = { ...view };
      }
      const ox = view.x - this.edgeLayerView.x - EDGE_MARGIN;
      const oy = view.y - this.edgeLayerView.y - EDGE_MARGIN;
      ctx.drawImage(this.edgeLayer!, ox, oy, w + 2 * EDGE_MARGIN, h + 2 * EDGE_MARGIN);
    }

    ctx.save();
    ctx.translate(view.x, view.y);
    ctx.scale(view.k, view.k);
    this.drawNodes(ctx, simNodes, view, vx0, vy0, vx1, vy1);
    ctx.restore();
  }

  private drawEdges(ctx: CanvasRenderingContext2D, simLinks: readonly PaintSimLink[], view: PaintView,
                    vx0: number, vy0: number, vx1: number, vy1: number): void {
    const p = this.palette;
    const st = this.state;
    const hasSel = !!st.selected;
    // ---------------------------------------------------------------- edges
    // Batched into Path2Ds by (style, quantised width, quantised opacity). Every canvas state change —
    // `strokeStyle` re-parses a CSS colour, `setLineDash` resets dash state, `lineWidth`/`globalAlpha`
    // flush the path — costs more than the stroke itself, and a 2,000-node view carries ~20,000 edges.
    // Batched, the whole edge layer is a few dozen state changes and a few dozen stroke calls.
    const strokes = this.strokeBatch;
    const fills = this.fillBatch;
    strokes.clear();
    fills.clear();
    // Arrowheads are a filled triangle each. Past a few thousand edges they are visual noise anyway
    // (the links overlap), and the fills cost more than the strokes — so they are a level-of-detail
    // decision, not a constant. Same for the round line caps.
    // `arrows` used to gate the per-edge chevrons at this zoom; they are gone (see below).
    ctx.lineCap = simLinks.length <= 3000 ? 'round' : 'butt';
    ctx.lineJoin = 'round';
    // LEVEL OF DETAIL, measured: rasterising the curves IS the frame at scale. Past a few thousand
    // edges, or zoomed out to where a 12 % bow is under a pixel, the curve is drawn as a straight
    // segment (a line rasterises several times faster than a quadratic). Two relations between the
    // same pair of nodes, in the same style, are ONE segment — the second is invisible under the first
    // and costs the same to draw. Edges shorter than a screen pixel are skipped outright.
    const straight = simLinks.length > 4000 || view.k < 0.5;
    const collapse = simLinks.length > 1500;
    const seen = this.pairSeen;
    seen.clear();
    const minLen2 = 1 / (view.k * view.k);
    for (let i = 0; i < simLinks.length; i++) {
      const l = simLinks[i]!;
      const a = l.source;
      const b = l.target;
      const ax = a.x, ay = a.y, bx = b.x, by = b.y;
      if (ax === undefined || ay === undefined || bx === undefined || by === undefined) continue;
      if (Math.max(ax, bx) < vx0 || Math.min(ax, bx) > vx1 || Math.max(ay, by) < vy0 || Math.min(ay, by) > vy1) continue;
      const e = this.edges.get(l.id);
      if (!e) continue;
      const ddx = bx - ax, ddy = by - ay;
      if (ddx * ddx + ddy * ddy < minLen2) continue;
      const on = hasSel && (a.name === st.selected || b.name === st.selected);
      const onPath = st.pathEdges.has(l.id);
      const style = onPath ? S_PATH
        : on ? (e.bad ? S_ON_BAD : S_ON)
        : hasSel ? S_DIM
        : e.ai ? S_AI
        : e.bad ? S_BAD : S_PLAIN;
      // A selected node's own links must READ as the answer to "what is this connected to", and the
      // way there is CONTRAST, not mass. Three passes were needed to land it:
      //   1. per-edge opacity + a dimmed background — too faint, a 1-2 px line carries almost no ink;
      //   2. width 4-6.5 px + a 6 px halo — legible, and reported as "too thick, doesn't look good";
      //   3. 2.5 px + e.width — still "very thick looking", because a busy edge is already 3.5 px
      //      before anything is added to it, so the heaviest links got heavier still;
      //   4. this: a FLAT 2 px, the same for every lit link whatever its weight, over a 2.5 px halo at
      //      0.12 and a background dimmed to 0.08. Weight is what the UNSELECTED graph uses to say how
      //      strong a link is; on the selected node it is not the question being asked, and letting it
      //      compound with the highlight is what made the answer look like plumbing.
      const lw = onPath ? 2.4 : on ? 2 : e.width;
      const wStep = Math.max(1, Math.min(16, Math.round(lw * 2)));            // 0.5 px buckets
      const aStep = style === S_DIM ? 1 : (on || onPath) ? 10 : Math.max(1, Math.min(10, Math.round(e.opacity * 10)));
      const key = style * 1000 + wStep * 16 + aStep;
      if (collapse && !(on || onPath)) {
        // node indices are stable within a frame; the pair key is order-independent
        const ia = a.index ?? 0, ib = b.index ?? 0;
        const pair = (ia < ib ? ia * 65536 + ib : ib * 65536 + ia) * 8192 + (key % 8192);
        if (seen.has(pair)) continue;
        seen.add(pair);
      }
      let path = strokes.get(key);
      if (!path) { path = new Path2D(); strokes.set(key, path); }
      path.moveTo(ax, ay);
      if (straight) {
        path.lineTo(bx, by);
      } else {
        const cx = (ax + bx) / 2 - (by - ay) * 0.12;
        const cy = (ay + by) / 2 + (bx - ax) * 0.12;
        path.quadraticCurveTo(cx, cy, bx, by);
      }
      // NO ARROWHEADS. Removed on request: at graph scale a chevron on every edge is a field of
      // little marks that reads as texture rather than direction, and the direction of a relation is
      // already stated in words — the side panel and the node detail both print `source -relation->
      // target`. The curve alone carries the pair. (The batching lesson is kept in `fillBatch` above:
      // if arrows ever come back they must be STROKED chevrons, never filled sub-paths.)
    }
    // Round joins and caps: at these widths a mitre on a quadratic curve leaves a visible spur where
    // the arrowhead meets the line, and butt caps leave a hard chopped end on every link.
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    for (const [key, path] of strokes) {
      const style = Math.floor(key / 1000);
      const wStep = Math.floor((key % 1000) / 16);
      const aStep = key % 16;
      const lit = style === S_ON || style === S_ON_BAD || style === S_PATH;
      const colour = style === S_PATH || style === S_ON ? p.accentHover
        : style === S_AI ? p.accent
        : style === S_ON_BAD ? p.sevCritical
        : style === S_BAD ? p.sevHigh : p.edge;
      ctx.strokeStyle = colour;
      // Dashes are reserved for AI-PROPOSED links. Selected links used to be dashed too, which both muddied
      // that meaning and cut their apparent brightness (a dash is ~half ink) exactly where we want weight.
      ctx.setLineDash(style === S_AI ? [5, 4] : []);
      ctx.lineWidth = wStep / 2;
      ctx.globalAlpha = style === S_DIM ? 0.08 : aStep / 10;
      if (lit) {
        // A HALO under the lit line: the same batched path stroked wider and faint, so the link reads as
        // lit even where it crosses a dense knot of dimmed edges. One extra stroke over a handful of
        // paths (only the selected node's own links are ever `lit`), not a per-edge shadowBlur — a
        // canvas shadow is re-rasterised per stroke and was the single most expensive thing here.
        // 3 px, not 6: the halo is a soft edge on the line, not a second line around it.
        ctx.globalAlpha = 0.12;
        ctx.lineWidth = wStep / 2 + 2.5;
        ctx.stroke(path);
        ctx.globalAlpha = 1;
        ctx.lineWidth = wStep / 2;
      }
      ctx.stroke(path);
      const head = fills.get(key);
      if (head) {
        ctx.setLineDash([]);                 // reserved: nothing populates this batch since arrows went
        ctx.stroke(head);
      }
    }
    ctx.setLineDash([]);
    ctx.globalAlpha = 1;
  }

  private drawNodes(ctx: CanvasRenderingContext2D, simNodes: readonly PaintSimNode[], view: PaintView,
                    vx0: number, vy0: number, vx1: number, vy1: number): void {
    const p = this.palette;
    const st = this.state;
    const hasSel = !!st.selected;
    // ---------------------------------------------------------------- nodes
    const showGlyphs = view.k > 0.45;
    for (let i = 0; i < simNodes.length; i++) {
      const nd = simNodes[i]!;
      if (nd.x === undefined || nd.y === undefined) continue;
      if (nd.x < vx0 || nd.x > vx1 || nd.y < vy0 || nd.y > vy1) continue;
      const gn = this.nodes.get(nd.name);
      if (!gn) continue;
      const on = nd.name === st.selected;
      const near = st.neighbours.has(nd.name);
      const onPath = st.pathNodes.has(nd.name);
      const isHover = nd.name === st.hover;
      ctx.globalAlpha = hasSel && !on && !near && !onPath ? 0.28 : 1;
      const hasDet = gn.detections > 0;
      const ring = on || isHover ? p.nodeRingSel : hasDet ? sevColour(p, gn.sev) : this.hue(gn.hue);
      const sprite = this.spriteFor({
        r: Math.round(nd.r * 2) / 2,
        ring,
        width: on ? 2.2 : hasDet ? 2 : near || isHover ? 1.6 : 1.2,
        selected: on,
        glow: on || near || isHover || onPath,
        inCase: gn.inCase,
        proposed: st.proposed.has(nd.name),
      });
      const half = sprite.width / 4;               // sprites are 2x
      ctx.drawImage(sprite, nd.x - half, nd.y - half, half * 2, half * 2);
      if (showGlyphs && nd.r * view.k > 7) {
        const gs = this.glyphSprite(gn.glyph, on ? p.onAccent : this.hue(gn.hue),
                                    Math.round(Math.max(7, Math.min(11, nd.r * 0.7))));
        const gh = gs.width / 4;
        ctx.drawImage(gs, nd.x - gh, nd.y - gh, gh * 2, gh * 2);
      }
      if (nd.r > 0 && this.isPinned(nd.name)) {
        ctx.beginPath();
        ctx.arc(nd.x + nd.r * 0.72, nd.y - nd.r * 0.72, 2.6, 0, Math.PI * 2);
        ctx.fillStyle = p.sevMedium;
        ctx.strokeStyle = p.graphBg;
        ctx.lineWidth = 1;
        ctx.fill();
        ctx.stroke();
      }
    }

    // ---------------------------------------------------------------- labels (always on top)
    ctx.globalAlpha = 1;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    for (let i = 0; i < simNodes.length; i++) {
      const nd = simNodes[i]!;
      if (nd.x === undefined || nd.y === undefined) continue;
      if (nd.x < vx0 || nd.x > vx1 || nd.y < vy0 || nd.y > vy1) continue;
      const on = nd.name === st.selected;
      const isHover = nd.name === st.hover;
      if (!(on || isHover || st.pathNodes.has(nd.name) || st.labelled.has(nd.name))) continue;
      const gn = this.nodes.get(nd.name);
      if (!gn) continue;
      const labelW = Math.min(240, gn.name.length * 6.9 + 18);
      const y = nd.y + nd.r + 7;
      // 3px, the template's tag radius. At 8.5 on a 17px-high chip this was a full capsule, and the
      // one capsule in this design is the numeric badge in the nav — a pill here is the loudest
      // thing on the canvas saying "different app". Geometry otherwise unchanged.
      roundRect(ctx, nd.x - labelW / 2, y, labelW, 17, 3);
      // The chip is what makes a label readable over edges running underneath it, so it is nearly opaque
      // and the selected one is tinted rather than merely outlined.
      ctx.fillStyle = on ? p.accentBg : p.panel;
      ctx.globalAlpha = on ? 0.96 : 0.92;
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.strokeStyle = on ? p.accentBorder : p.border;
      ctx.lineWidth = on ? 1 : 0.6;
      ctx.stroke();
      ctx.font = `${on ? '600 ' : ''}11px ${p.mono}`;   // 600 is the heaviest weight this design uses
      ctx.fillStyle = on ? p.accent : gn.inCase ? p.textBright : p.text2;
      ctx.fillText(gn.name, nd.x, y + 12);
      if (on || isHover) {
        ctx.font = `9px ${p.mono}`;
        ctx.fillStyle = p.muted2;
        ctx.fillText(gn.kind, nd.x, nd.y + nd.r + 32);
      }
    }
  }

  /** Overridden by the screen so the pin dot can be drawn without plumbing pin state through setState. */
  isPinned: (id: string) => boolean = () => false;
}

function sevColour(p: PaintPalette, sev: string): string {
  return sev === 'critical' ? p.sevCritical : sev === 'high' ? p.sevHigh : sev === 'medium' ? p.sevMedium : p.nodeRing;
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  ctx.beginPath();
  const rr = Math.min(r, w / 2, h / 2);
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}
