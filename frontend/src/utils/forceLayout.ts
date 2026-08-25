import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force';
import type { Simulation, SimulationLinkDatum, SimulationNodeDatum } from 'd3-force';
/** Layout-neutral input: anything with an id/count can be a node, anything joining two ids an edge. */
export interface LayoutNode { id: string; count: number }
/** `id` is the SERVER edge id, not a pair — two relations can join the same pair of nodes, so the pair is
 *  not an identity. Renderers key their elements off `SimLink.id`. */
export interface LayoutEdge { id: string; source: string; target: string; weight: number }

export interface SimNode extends SimulationNodeDatum {
  name: string;
  r: number;
  count: number;
  degree: number;
  /** true when the node entered the sim on the latest data update */
  fresh: boolean;
}
export interface SimLink extends SimulationLinkDatum<SimNode> {
  id: string;
  a: string;
  b: string;
  w: number;
  source: SimNode;
  target: SimNode;
}

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967295;
}

/** Radius from event count — sqrt scale into [9, 24] px. */
export function radiusFor(count: number, maxCount: number): number {
  const t = maxCount > 0 ? Math.sqrt(Math.max(0, count)) / Math.sqrt(maxCount) : 0.5;
  return 9 + t * 15;
}

/* `edgePath` / `nodeTransform` lived here to build SVG `d` and `transform` strings. The graph is drawn to
   a canvas now (utils/graphPaint.ts), which takes numbers, so the string formatting is gone with them. */

/**
 * Live force-directed graph simulation. Owns a d3-force Simulation, keeps node identity by name across data
 * updates (positions survive), and exposes drag / reheat / relayout helpers. Rendering is up to the caller
 * (subscribe with onTick).
 */
export class GraphSim {
  readonly sim: Simulation<SimNode, SimLink>;
  nodes: SimNode[] = [];
  links: SimLink[] = [];
  private byName = new Map<string, SimNode>();
  private byLink = new Map<string, SimLink>();
  private width = 900;
  private height = 560;
  private tickHandlers = new Set<() => void>();
  private endHandlers = new Set<() => void>();
  private raf = 0;
  /** true while the layout is being advanced — the painter uses it to decide whether the edge layer
   *  can be cached between frames. */
  running = false;
  /** Cumulative per-frame timing (diagnostics; see `frame`). */
  readonly stats = { frames: 0, ticks: 0, tickMs: 0, drawMs: 0, worstTickMs: 0, worstDrawMs: 0 };

  constructor() {
    // d3's own timer is NOT used: it advances the layout exactly one tick per animation frame, so on a
    // graph whose frame takes a second to rasterise (2,000 nodes, 20,000 edges) the ~200 ticks a layout
    // needs took minutes, and the analyst watched nodes drift the whole time. `frame()` below advances
    // as many ticks as fit in a time budget and draws ONCE — convergence is bought with layout time,
    // not with frames, and a small graph (one tick per frame, as before) still animates.
    this.sim = forceSimulation<SimNode>([])
      .alphaDecay(0.02)
      .alphaMin(0.002)
      .velocityDecay(0.22) // low friction → fluid, responsive motion
      .stop();
  }

  onTick(h: () => void): () => void {
    this.tickHandlers.add(h);
    return () => { this.tickHandlers.delete(h); };
  }
  onEnd(h: () => void): () => void {
    this.endHandlers.add(h);
    return () => { this.endHandlers.delete(h); };
  }

  /** Ticks per frame: one on a small graph (the motion is the point), a time budget on a big one. */
  private lastTickMs = 0;
  private lastFrameAt = 0;
  private lastDrawCost = 0;
  private frame = (): void => {
    this.raf = 0;
    const n = this.nodes.length;
    const maxTicks = n < 300 ? 1 : n < 1000 ? 3 : 60;
    const t0 = performance.now();
    // ADAPTIVE budget. The draw's real cost is not in the tick handlers (the JS side of a frame is a
    // few ms) but in the raster that follows them, which shows up as the gap until the NEXT frame.
    // Measured at 2,000 nodes / 20,000 edges in software raster: a tick 28 ms, the raster 280 ms —
    // so a fixed 7 ms budget bought ONE tick per 300 ms frame and the layout took a minute to settle.
    // Spending as long on ticks as the last frame's draw cost halves the frame rate at worst and
    // converges an order of magnitude sooner; on a small graph the draw is ~0 and this is 7 ms.
    if (this.lastFrameAt) this.lastDrawCost = Math.max(0, t0 - this.lastFrameAt - this.lastTickMs);
    const budgetMs = Math.min(250, Math.max(7, this.lastDrawCost));
    let ticks = 0;
    do {
      this.sim.tick();
      ticks++;
    } while (ticks < maxTicks && this.sim.alpha() >= this.sim.alphaMin() && performance.now() - t0 < budgetMs);
    const t1 = performance.now();
    this.lastTickMs = t1 - t0;
    this.lastFrameAt = t0;
    this.clamp();
    for (const h of this.tickHandlers) h();
    const t2 = performance.now();
    // per-frame cost split, readable from the console as `__iris.graphSim.stats` — the benchmark reads it
    const st = this.stats;
    st.frames++; st.ticks += ticks; st.tickMs += t1 - t0; st.drawMs += t2 - t1;
    if (t1 - t0 > st.worstTickMs) st.worstTickMs = t1 - t0;
    if (t2 - t1 > st.worstDrawMs) st.worstDrawMs = t2 - t1;
    if (this.sim.alpha() < this.sim.alphaMin()) {
      this.running = false;
      for (const h of this.endHandlers) h();
    } else {
      this.raf = requestAnimationFrame(this.frame);
    }
  };

  /** Stop advancing (the building overlay); `resume()` picks the layout up where it left off. */
  pause(): void {
    cancelAnimationFrame(this.raf);
    this.raf = 0;
    this.running = false;
  }
  resume(): void {
    if (this.nodes.length && this.sim.alpha() >= this.sim.alphaMin()) this.start();
  }

  /** Start (or keep) the loop. Replaces every `sim.restart()` — d3's timer must never run. */
  private start(): void {
    if (this.running) return;
    this.running = true;
    this.lastFrameAt = 0;          // a stale gap (the pause, a tab switch) must not become a budget
    if (!this.raf) this.raf = requestAnimationFrame(this.frame);
  }

  node(name: string): SimNode | undefined {
    return this.byName.get(name);
  }

  link(id: string): SimLink | undefined {
    return this.byLink.get(id);
  }

  setSize(width: number, height: number): void {
    const changed = Math.abs(width - this.width) > 2 || Math.abs(height - this.height) > 2;
    this.width = width;
    this.height = height;
    if (changed && this.nodes.length) {
      this.configureForces();
      this.sim.alpha(Math.max(this.sim.alpha(), 0.25));
      this.start();
    }
  }

  /** Merge new data: existing nodes keep position/velocity, new ones spawn near their neighbours (or a ring). */
  setData(entities: LayoutNode[], edges: LayoutEdge[]): void {
    // reduce, not Math.max(...spread): the spread is one argument per entity and blows the stack at scale
    let maxCount = 1;
    for (const e of entities) if (e.count > maxCount) maxCount = e.count;
    const cx = this.width / 2;
    const cy = this.height / 2;
    const prev = this.byName;
    const next = new Map<string, SimNode>();
    const degree = new Map<string, number>();
    for (const e of edges) {
      degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
      degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
    }
    const nodes: SimNode[] = entities.map((e, i) => {
      const r = radiusFor(e.count, maxCount);
      const old = prev.get(e.id);
      if (old) {
        old.r = r;
        old.count = e.count;
        old.degree = degree.get(e.id) ?? 0;
        old.fresh = false;
        next.set(e.id, old);
        return old;
      }
      const a = hash(e.id) * Math.PI * 2 + (i / Math.max(1, entities.length)) * Math.PI * 2;
      const rr = Math.min(this.width, this.height) * (0.12 + 0.28 * hash(e.id + '#r'));
      const nd: SimNode = { name: e.id, r, count: e.count, degree: degree.get(e.id) ?? 0, fresh: true, x: cx + Math.cos(a) * rr, y: cy + Math.sin(a) * rr };
      next.set(e.id, nd);
      return nd;
    });
    // spawn new nodes next to an already-placed neighbour when possible
    for (const e of edges) {
      const A = next.get(e.source);
      const B = next.get(e.target);
      if (!A || !B) continue;
      if (A.fresh && !B.fresh) { A.x = (B.x ?? cx) + (hash(A.name) - 0.5) * 40; A.y = (B.y ?? cy) + (hash(A.name + 'y') - 0.5) * 40; A.fresh = true; }
      if (B.fresh && !A.fresh) { B.x = (A.x ?? cx) + (hash(B.name) - 0.5) * 40; B.y = (A.y ?? cy) + (hash(B.name + 'y') - 0.5) * 40; B.fresh = true; }
    }
    // An edge is only kept when BOTH of its ends became nodes in this update, and only once per id.
    // A link to a node that is not in the sim has no position to draw to — that is a phantom line.
    const links: SimLink[] = [];
    const seenLink = new Set<string>();
    for (const e of edges) {
      const s = next.get(e.source);
      const t = next.get(e.target);
      if (!s || !t || s === t || seenLink.has(e.id)) continue;
      seenLink.add(e.id);
      links.push({ id: e.id, a: e.source, b: e.target, w: e.weight, source: s, target: t });
    }
    this.nodes = nodes;
    this.links = links;
    this.byName = next;
    this.byLink = new Map(links.map((l) => [l.id, l]));
    this.sim.nodes(nodes);
    this.configureForces();
    const anyFresh = nodes.some((n) => n.fresh);
    this.sim.alpha(prev.size === 0 ? 1 : anyFresh ? 0.6 : 0.3);
    this.start();
  }

  private configureForces(): void {
    const n = Math.max(1, this.nodes.length);
    const spread = Math.sqrt((this.width * this.height) / n);
    let maxW = 1;
    for (const l of this.links) if (l.w > maxW) maxW = l.w;
    const cx = this.width / 2;
    const cy = this.height / 2;
    // A big layout converges in fewer ticks with a faster decay (0.035 ≈ 170 ticks against ≈ 300):
    // past a thousand nodes the last hundred ticks move nothing anyone can see.
    this.sim.alphaDecay(n > 1500 ? 0.05 : n > 1000 ? 0.035 : 0.02);
    this.sim
      .force('charge', forceManyBody<SimNode>().strength((d) => -Math.max(220, spread * 3.2 + d.r * 10)).distanceMax(spread * 5).theta(0.9))
      .force('link', forceLink<SimNode, SimLink>(this.links)
        .id((d) => d.name)
        .distance((l) => spread * (0.85 - 0.3 * (l.w / maxW)) + l.source.r + l.target.r + 8)
        .strength((l) => 0.7 / Math.max(1, Math.min(l.source.degree || 1, l.target.degree || 1))))
      // Collision is the most expensive force here — it rebuilds a quadtree per iteration. Two passes
      // give a tidier packing and are worth it while the graph is small; past ~600 nodes the second pass
      // costs more frame time than the tidiness is worth (the node cap goes to 2,000).
      .force('collide', forceCollide<SimNode>().radius((d) => d.r + 14).strength(0.85).iterations(n > 600 ? 1 : 2))
      .force('x', forceX<SimNode>(cx).strength((d) => (d.degree === 0 ? 0.06 : 0.02)))
      .force('y', forceY<SimNode>(cy).strength((d) => (d.degree === 0 ? 0.09 : 0.035)));
  }

  /** Loose bounds only (±1 canvas around the viewport) — nodes move freely; the view pans/zooms to follow. */
  private clamp(): void {
    const W = this.width;
    const H = this.height;
    const minX = -W, maxX = 2 * W, minY = -H, maxY = 2 * H;
    for (const nd of this.nodes) {
      if (nd.x === undefined || nd.y === undefined) continue;
      if (nd.fx != null || nd.fy != null) continue; // never fight the user's drag
      if (nd.x < minX) { nd.x = minX; if (nd.vx && nd.vx < 0) nd.vx *= -0.3; }
      else if (nd.x > maxX) { nd.x = maxX; if (nd.vx && nd.vx > 0) nd.vx *= -0.3; }
      if (nd.y < minY) { nd.y = minY; if (nd.vy && nd.vy < 0) nd.vy *= -0.3; }
      else if (nd.y > maxY) { nd.y = maxY; if (nd.vy && nd.vy > 0) nd.vy *= -0.3; }
    }
  }

  /** Bounding box of all nodes (world coords) — used for fit-to-view. */
  bounds(): { minX: number; minY: number; maxX: number; maxY: number } | null {
    if (!this.nodes.length) return null;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const nd of this.nodes) {
      if (nd.x === undefined || nd.y === undefined) continue;
      minX = Math.min(minX, nd.x - nd.r); maxX = Math.max(maxX, nd.x + nd.r);
      minY = Math.min(minY, nd.y - nd.r); maxY = Math.max(maxY, nd.y + nd.r);
    }
    return { minX, minY, maxX, maxY };
  }

  reheat(target = 0.3): void {
    this.sim.alphaTarget(target);
    this.start();
  }
  cool(): void {
    this.sim.alphaTarget(0);
  }

  dragStart(name: string): void {
    const nd = this.byName.get(name);
    if (!nd) return;
    nd.fx = nd.x;
    nd.fy = nd.y;
    this.reheat(0.3);
  }
  drag(name: string, x: number, y: number): void {
    const nd = this.byName.get(name);
    if (!nd) return;
    nd.fx = x;
    nd.fy = y;
  }
  dragEnd(name: string, keepPinned: boolean): void {
    const nd = this.byName.get(name);
    if (!nd) return;
    if (!keepPinned) { nd.fx = null; nd.fy = null; }
    this.cool();
  }
  unpinAll(): void {
    for (const nd of this.nodes) { nd.fx = null; nd.fy = null; }
    this.sim.alpha(0.3);
    this.start();
  }
  isPinned(name: string): boolean {
    const nd = this.byName.get(name);
    return !!nd && nd.fx !== null && nd.fx !== undefined;
  }

  /** Scatter and re-run the layout from scratch (keeps pinned nodes). */
  relayout(): void {
    const cx = this.width / 2;
    const cy = this.height / 2;
    for (const nd of this.nodes) {
      if (nd.fx !== null && nd.fx !== undefined) continue;
      const a = hash(nd.name + Date.now()) * Math.PI * 2;
      const rr = Math.min(this.width, this.height) * (0.1 + 0.3 * hash(nd.name + '#r2' + Date.now()));
      nd.x = cx + Math.cos(a) * rr;
      nd.y = cy + Math.sin(a) * rr;
      nd.vx = 0;
      nd.vy = 0;
    }
    this.sim.alpha(1);
    this.start();
  }

  destroy(): void {
    cancelAnimationFrame(this.raf);
    this.raf = 0;
    this.running = false;
    this.sim.stop();
    this.tickHandlers.clear();
    this.endHandlers.clear();
  }
}
