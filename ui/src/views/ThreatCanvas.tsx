import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ThreatModelDetail } from "../api";

const NODE_W = 160;
const NODE_H = 54;
const BND_W = 300;
const BND_H = 220;
const CANVAS_W = 1200;
const CANVAS_H = 640;

function clamp(v: number, min: number, max: number) {
  return Math.max(min, Math.min(max, v));
}

export function ThreatCanvas({ detail, canEdit, onSavePositions, onAddFlow, onRemoveFlow, onSelectComponent }: {
  detail: ThreatModelDetail;
  canEdit: boolean;
  onSavePositions: (positions: { componentId: string; x: number; y: number }[]) => void;
  onAddFlow: (fromId: string, toId: string, label: string) => void;
  onRemoveFlow: (flowId: string) => void;
  onSelectComponent?: (id: string) => void;
}): JSX.Element {
  const [pos, setPos] = useState<Record<string, { x: number; y: number }>>({});
  const [flowMode, setFlowMode] = useState(false);
  const [flowLabel, setFlowLabel] = useState("");
  const [flowFrom, setFlowFrom] = useState<string | null>(null);
  const dragId = useRef<string | null>(null);
  const dragOff = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const dragStart = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement>(null);
  // Mirrors the live position of the dragged node, written synchronously in
  // pointermove so pointerup reads the final position even when React has not
  // yet committed the setPos update (fast drags / batched events).
  const livePos = useRef<{ x: number; y: number } | null>(null);

  // ONE initializer per model: seed saved positions, then auto-lay the
  // unplaced (x<0) ones — boundaries across the top, other nodes on a grid.
  // Doing both in a single pass avoids two setPos effects racing and one
  // clobbering the other's snapshot (which stranded saved nodes at 0,0).
  useEffect(() => {
    const next: Record<string, { x: number; y: number }> = {};
    detail.components.forEach((c) => {
      if (c.x >= 0 && c.y >= 0) next[c.id] = { x: c.x, y: c.y };
    });
    let bi = 0;
    detail.components.filter((c) => c.kind === "boundary" && !next[c.id]).forEach((c) => {
      next[c.id] = { x: 40 + bi * 340, y: 40 };
      bi++;
    });
    let ni = 0;
    detail.components.filter((c) => c.kind !== "boundary" && !next[c.id]).forEach((c) => {
      next[c.id] = { x: 40 + (ni % 5) * 220, y: 320 + Math.floor(ni / 5) * 110 };
      ni++;
    });
    setPos(next);
    setFlowFrom(null);
    setFlowMode(false);
    setFlowLabel("");
  }, [detail.id, detail.components]);

  const threatCounts = useMemo(() => {
    const m: Record<string, number> = {};
    detail.threats.forEach((t) => {
      if (t.componentId) m[t.componentId] = (m[t.componentId] || 0) + 1;
    });
    return m;
  }, [detail.threats]);

  const handlePointerDown = useCallback((e: React.PointerEvent, id: string) => {
    if (!canEdit) return;
    e.preventDefault();
    try { (e.target as Element).setPointerCapture(e.pointerId); } catch { /* pointer already gone */ }
    const svg = svgRef.current;
    if (!svg) return;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const p = pt.matrixTransform(svg.getScreenCTM()!.inverse());
    const cur = pos[id] || { x: 0, y: 0 };
    dragOff.current = { x: p.x - cur.x, y: p.y - cur.y };
    dragStart.current = { x: p.x, y: p.y };
    dragId.current = id;
  }, [canEdit, pos]);

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    const id = dragId.current;
    if (!id || !svgRef.current) return;
    const svg = svgRef.current;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const p = pt.matrixTransform(svg.getScreenCTM()!.inverse());
    const comp = detail.components.find((c) => c.id === id);
    if (!comp) return;
    const w = comp.kind === "boundary" ? BND_W : NODE_W;
    const h = comp.kind === "boundary" ? BND_H : NODE_H;
    const next = { x: clamp(p.x - dragOff.current.x, 0, CANVAS_W - w), y: clamp(p.y - dragOff.current.y, 0, CANVAS_H - h) };
    livePos.current = next;
    setPos((prev) => ({ ...prev, [id]: next }));
  }, [detail.components]);

  const handlePointerUp = useCallback((e: React.PointerEvent) => {
    const id = dragId.current;
    if (!id || !svgRef.current) return;
    try { (e.target as Element).releasePointerCapture(e.pointerId); } catch { /* already released */ }
    const svg = svgRef.current;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const p = pt.matrixTransform(svg.getScreenCTM()!.inverse());
    const dist = Math.hypot(p.x - dragStart.current.x, p.y - dragStart.current.y);
    dragId.current = null;
    const final = livePos.current;
    livePos.current = null;
    const comp = detail.components.find((c) => c.id === id);
    if (dist > 3 && final) {
      onSavePositions([{ componentId: id, x: final.x, y: final.y }]);
    } else if (canEdit && flowMode) {
      if (!comp || comp.kind === "boundary") return;
      if (!flowFrom) setFlowFrom(id);
      else if (flowFrom !== id) {
        onAddFlow(flowFrom, id, flowLabel);
        setFlowFrom(null);
        setFlowLabel("");
        setFlowMode(false);
      }
    } else if (comp && comp.kind !== "boundary") {
      onSelectComponent?.(id);
    }
  }, [canEdit, flowMode, flowFrom, flowLabel, detail.components, onSavePositions, onAddFlow, onSelectComponent]);

  const getPos = useCallback((id: string) => pos[id] || { x: 0, y: 0 }, [pos]);
  const getComp = useCallback((id: string) => detail.components.find((c) => c.id === id), [detail.components]);

  if (detail.components.length === 0) {
    return <div className="flex h-[560px] items-center justify-center rounded-lg border border-gray-200 bg-gray-50/50 dark:border-gray-800 dark:bg-gray-950/40"><p className="text-sm text-gray-500">No components to draw yet.</p></div>;
  }

  return (
    <div className="overflow-auto rounded-lg border border-gray-200 bg-gray-50/50 dark:border-gray-800 dark:bg-gray-950/40">
      {canEdit && (
        <div className="flex items-center gap-2 p-2 text-xs">
          <button onClick={() => setFlowMode(!flowMode)} className={`rounded px-2 py-1 ${flowMode ? "bg-accent-600 text-white" : "border border-gray-300 dark:border-gray-700"}`}>Add flow</button>
          <input value={flowLabel} onChange={(e) => setFlowLabel(e.target.value)} placeholder="flow label (optional)" className="min-w-0 flex-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-900" />
          {flowMode && <span className="text-gray-400">click a source node, then a target</span>}
        </div>
      )}
      <svg ref={svgRef} viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`} className="w-full" style={{ height: 560 }}>
        <defs>
          <marker id="tc-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" className="fill-gray-400 dark:fill-gray-600" />
          </marker>
        </defs>
        {detail.components.filter((c) => c.kind === "boundary").map((c) => {
          const p = getPos(c.id);
          return (
            <g key={c.id} onPointerDown={(e) => handlePointerDown(e, c.id)} onPointerMove={handlePointerMove} onPointerUp={handlePointerUp} style={{ cursor: canEdit ? "grab" : "default" }}>
              <rect x={p.x} y={p.y} width={BND_W} height={BND_H} rx={12} className="fill-amber-500/5 stroke-amber-500/50" strokeWidth={1.5} strokeDasharray="6 4" />
              <text x={p.x + 10} y={p.y + 18} className="fill-amber-600 dark:fill-amber-400" fontSize={11} fontWeight={600}>{c.name}</text>
            </g>
          );
        })}
        {detail.flows.map((f) => {
          const fromComp = getComp(f.fromId);
          const toComp = getComp(f.toId);
          if (!fromComp || !toComp) return null;
          const fp = getPos(f.fromId);
          const tp = getPos(f.toId);
          const fromW = fromComp.kind === "boundary" ? BND_W : NODE_W;
          const fromH = fromComp.kind === "boundary" ? BND_H : NODE_H;
          const toW = toComp.kind === "boundary" ? BND_W : NODE_W;
          const toH = toComp.kind === "boundary" ? BND_H : NODE_H;
          const cx1 = fp.x + fromW / 2, cy1 = fp.y + fromH / 2;
          const cx2 = tp.x + toW / 2, cy2 = tp.y + toH / 2;
          const dxc = cx2 - cx1, dyc = cy2 - cy1;
          const dist = Math.hypot(dxc, dyc) || 1;
          // Pull both endpoints in toward each other so the arrow tip lands
          // near the node edge; short edges keep the full center-to-center line.
          const off = dist > 100 ? 40 : 0;
          const nx = dxc / dist, ny = dyc / dist;
          const x1 = cx1 + nx * off, y1 = cy1 + ny * off;
          const x2 = cx2 - nx * off, y2 = cy2 - ny * off;
          const mx = (x1 + x2) / 2;
          const my = (y1 + y2) / 2;
          return (
            <g key={f.id}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} className="stroke-gray-400 dark:stroke-gray-600" strokeWidth={1.2} markerEnd="url(#tc-arrow)" />
              {f.label && (
                <text x={mx} y={my - 5} textAnchor="middle" className="fill-gray-500" fontSize={10}>{f.label}</text>
              )}
              {canEdit && (
                <text x={mx + 12} y={my - 5} textAnchor="start" className="fill-gray-400 hover:fill-red-600 cursor-pointer" fontSize={10} onClick={() => onRemoveFlow(f.id)}>✕</text>
              )}
            </g>
          );
        })}
        {detail.components.filter((c) => c.kind !== "boundary").map((c) => {
          const p = getPos(c.id);
          const isFlowSource = flowFrom === c.id;
          const rx = c.kind === "asset" ? 20 : 8;
          const dash = c.kind === "external-entity" ? "4 3" : undefined;
          return (
            <g key={c.id} onPointerDown={(e) => handlePointerDown(e, c.id)} onPointerMove={handlePointerMove} onPointerUp={handlePointerUp} onClick={() => { if (!canEdit) onSelectComponent?.(c.id); }} style={{ cursor: canEdit ? "grab" : "pointer" }}>
              <rect x={p.x} y={p.y} width={NODE_W} height={NODE_H} rx={rx} className={`fill-white stroke-gray-300 dark:fill-gray-900 dark:stroke-gray-700 ${isFlowSource ? "stroke-accent-500" : ""}`} strokeWidth={isFlowSource ? 2 : 1} strokeDasharray={dash} />
              <text x={p.x + 10} y={p.y + 22} className="fill-gray-900 dark:fill-gray-100" fontSize={12} fontWeight={600}>{c.name.length > 20 ? c.name.slice(0, 20) + "…" : c.name}</text>
              {c.tech && <text x={p.x + 10} y={p.y + 40} className="fill-gray-400" fontSize={10}>{c.tech}</text>}
              {threatCounts[c.id] ? (
                <>
                  <circle cx={p.x + NODE_W - 4} cy={p.y + 4} r={9} className="fill-red-600" />
                  <text x={p.x + NODE_W - 4} y={p.y + 8} textAnchor="middle" className="fill-white" fontSize={10}>{threatCounts[c.id]}</text>
                </>
              ) : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
