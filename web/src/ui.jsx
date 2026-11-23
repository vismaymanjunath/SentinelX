import React, { useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fmtT } from './api'

const useT = () => { const { t } = useTranslation(); return (x) => (typeof x === 'string' ? t(x) : x) }

export const STATE_COLOR = { Excellent: '#2ecc71', Good: '#38bdf8', Fair: '#f5a524', Poor: '#ef4444' }

export const Badge = ({ kind, children }) => { const t = useT(); return <span className={`badge b-${kind}`}><i />{t(children ?? kind)}</span> }
export const PriorityBadge = ({ p }) => <span className={`badge b-${p || 'P4'}`}><i />{p || 'P4'}</span>
export const StateBadge = ({ s }) => { const t = useT(); return <span className={`badge b-${s}`}><i />{t(s)}</span> }
export const Card = ({ title, right, children, style, className = '' }) => {
  const t = useT()
  return (
  <div className={'card ' + className} style={style}>
    {(title || right) && <div className="row" style={{ marginBottom: 8 }}><h3 style={{ margin: 0 }}>{t(title)}</h3><div className="sp" />{right}</div>}
    {children}
  </div>
  )
}
export const Kpi = ({ label, value, sub, color }) => { const t = useT(); return (
  <div className="card kpi"><div className="l">{t(label)}</div><div className="v" style={{ color }}>{value}</div><div className="mut small">{t(sub)}</div></div>
) }
export const Tabs = ({ tabs, value, onChange }) => { const t = useT(); return (
  <div className="tabs">{tabs.map(([k, l]) => <div key={k} className={'tab' + (value === k ? ' on' : '')} onClick={() => onChange(k)}>{t(l)}</div>)}</div>
) }

/** Interactive SVG line chart: baseline band, threshold lines, alert shading, replay cursor, hover read-out. */
export function LineChart({ points, band, alerts = [], threshold, height = 150, unit = '', color = '#4f8cff', cursor, xDomain, title, lateMark = true }) {
  const ref = useRef(null)
  const [hover, setHover] = useState(null)
  const W = 640, H = height, L = 40, R = 8, T = 8, B = 18
  const pts = points || []
  const { x0, x1, y0, y1 } = useMemo(() => {
    const xs = pts.map(p => p[0])
    let a = xDomain ? xDomain[0] : Math.min(...xs), b = xDomain ? xDomain[1] : Math.max(...xs)
    if (!isFinite(a)) { a = 0; b = 1 }
    let lo = Math.min(...pts.map(p => p[1]), ...(threshold ? [threshold.warn * 0] : [])), hi = Math.max(...pts.map(p => p[1]), threshold ? Math.min(threshold.warn, (lo + 1) * 3) : 0)
    if (!isFinite(lo)) { lo = 0; hi = 1 }
    const padv = (hi - lo) * 0.12 || 1
    return { x0: a, x1: b === a ? a + 1 : b, y0: Math.max(0, lo - padv), y1: hi + padv }
  }, [pts, xDomain, threshold])
  const sx = x => L + ((x - x0) / (x1 - x0)) * (W - L - R)
  const sy = y => T + (1 - (y - y0) / (y1 - y0)) * (H - T - B)
  const path = pts.length ? 'M' + pts.map(p => `${sx(p[0]).toFixed(1)},${sy(p[1]).toFixed(1)}`).join('L') : ''
  const bandPts = (band || []).filter(b => b[1] != null)
  const bandPath = bandPts.length > 1 ? 'M' + bandPts.map(b => `${sx(b[0]).toFixed(1)},${sy(b[2]).toFixed(1)}`).join('L') + 'L' + [...bandPts].reverse().map(b => `${sx(b[0]).toFixed(1)},${sy(Math.max(b[1], y0)).toFixed(1)}`).join('L') + 'Z' : ''
  const onMove = e => {
    const r = ref.current.getBoundingClientRect()
    const x = ((e.clientX - r.left) / r.width) * W
    const t = x0 + ((x - L) / (W - L - R)) * (x1 - x0)
    let best = null
    for (const p of pts) if (!best || Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p
    setHover(best)
  }
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => x0 + f * (x1 - x0))
  const yt = [0, 0.5, 1].map(f => y0 + f * (y1 - y0))
  return (
    <div>
      {title && <div className="small mut" style={{ marginBottom: 2 }}>{title}</div>}
      <svg ref={ref} viewBox={`0 0 ${W} ${H}`} width="100%" onMouseMove={onMove} onMouseLeave={() => setHover(null)} style={{ display: 'block' }}>
        {yt.map((v, i) => <g key={i}><line x1={L} x2={W - R} y1={sy(v)} y2={sy(v)} stroke="#1f2c4a" /><text x={L - 4} y={sy(v) + 3} textAnchor="end" fontSize="9" fill="#8da0c4">{v >= 100 ? v.toFixed(0) : v.toFixed(1)}</text></g>)}
        {ticks.map((t, i) => <text key={i} x={sx(t)} y={H - 4} textAnchor="middle" fontSize="9" fill="#8da0c4">{fmtT(t)}</text>)}
        {alerts.map(a => <rect key={a.id} x={sx(Math.max(a.event_ms - 2000, x0))} width={Math.max(2, sx(Math.min(a.end_ms, x1)) - sx(Math.max(a.event_ms - 2000, x0)))} y={T} height={H - T - B} fill={a.severity === 'critical' ? '#ef4444' : '#f5a524'} opacity=".13" />)}
        {bandPath && <path d={bandPath} fill="#4f8cff" opacity=".13" />}
        {threshold && threshold.warn >= y0 && threshold.warn <= y1 && <line x1={L} x2={W - R} y1={sy(threshold.warn)} y2={sy(threshold.warn)} stroke="#f5a524" strokeDasharray="4 3" opacity=".7" />}
        {threshold && threshold.crit >= y0 && threshold.crit <= y1 && <line x1={L} x2={W - R} y1={sy(threshold.crit)} y2={sy(threshold.crit)} stroke="#ef4444" strokeDasharray="4 3" opacity=".7" />}
        <path d={path} fill="none" stroke={color} strokeWidth="1.6" />
        {lateMark && pts.filter(p => p[2]).map((p, i) => <circle key={i} cx={sx(p[0])} cy={sy(p[1])} r="2.6" fill="#c084fc" />)}
        {cursor != null && cursor >= x0 && cursor <= x1 && <line x1={sx(cursor)} x2={sx(cursor)} y1={T} y2={H - B} stroke="#fff" strokeWidth="1.2" />}
        {hover && <g><circle cx={sx(hover[0])} cy={sy(hover[1])} r="3.5" fill="#fff" /><rect x={Math.min(sx(hover[0]) + 6, W - 130)} y={T} width="124" height="30" rx="4" fill="#0b1220" stroke="#24324f" /><text x={Math.min(sx(hover[0]) + 12, W - 124)} y={T + 12} fontSize="10" fill="#e6ecf8">{hover[1].toFixed(2)} {unit}</text><text x={Math.min(sx(hover[0]) + 12, W - 124)} y={T + 24} fontSize="9" fill="#8da0c4">{fmtT(hover[0])} UTC{hover[2] ? ' · late' : ''}</text></g>}
      </svg>
    </div>
  )
}

export function Sparkline({ points, color = '#4f8cff', w = 90, h = 22 }) {
  if (!points || points.length < 2) return <svg width={w} height={h} />
  const ys = points.map(p => p[1]); const lo = Math.min(...ys), hi = Math.max(...ys) || 1
  const d = points.map((p, i) => `${(i / (points.length - 1)) * w},${h - 2 - ((p[1] - lo) / (hi - lo || 1)) * (h - 4)}`).join(' ')
  return <svg width={w} height={h}><polyline points={d} fill="none" stroke={color} strokeWidth="1.4" /></svg>
}

const layerOf = (nodes, edges) => {
  const deps = {}, rdeps = {}
  nodes.forEach(n => { deps[n.id] = []; rdeps[n.id] = [] })
  edges.forEach(([a, b]) => { deps[a]?.push(b); rdeps[b]?.push(a) })
  const memo = {}
  const depth = (id, seen = new Set()) => { // longest path from a top-level consumer
    if (memo[id] != null) return memo[id]
    if (seen.has(id)) return 0
    seen.add(id)
    const v = rdeps[id].length ? 1 + Math.max(...rdeps[id].map(x => depth(x, new Set(seen)))) : 0
    return (memo[id] = v)
  }
  const L = {}; nodes.forEach(n => (L[n.id] = depth(n.id)))
  return L
}

/** Dependency graph: edges point from a component to what it depends on. Colours = health; outlines = incident role. */
export function Topology({ nodes = [], edges = [], onSelect, selected, height = 360, activeIds, stateOf }) {
  const W = 760
  const L = useMemo(() => layerOf(nodes, edges), [nodes, edges])
  const maxL = Math.max(0, ...Object.values(L))
  const byL = {}; nodes.forEach(n => (byL[L[n.id]] = byL[L[n.id]] || []).push(n))
  const pos = {}
  Object.entries(byL).forEach(([l, ns]) => ns.sort((a, b) => a.id.localeCompare(b.id)).forEach((n, i) => {
    pos[n.id] = { x: ((i + 1) / (ns.length + 1)) * W, y: 40 + (maxL ? (+l / maxL) * (height - 90) : 0) }
  }))
  const st = n => (stateOf ? stateOf(n) : n.state)
  return (
    <svg viewBox={`0 0 ${W} ${height}`} width="100%" style={{ display: 'block' }}>
      <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0L10,5L0,10z" fill="#4a5f8f" /></marker></defs>
      {edges.map(([a, b], i) => pos[a] && pos[b] && {
        a, b, i
      }).filter(Boolean).map(({ a, b, i }) => {
        const hot = (activeIds && activeIds.has(a) && activeIds.has(b))
        return <line key={i} x1={pos[a].x} y1={pos[a].y + 18} x2={pos[b].x} y2={pos[b].y - 18} stroke={hot ? '#ef4444' : '#3a4d7a'} strokeWidth={hot ? 2 : 1.2} markerEnd="url(#arr)" opacity={hot ? 1 : .75} />
      })}
      {nodes.map(n => {
        const p = pos[n.id]; if (!p) return null
        const c = STATE_COLOR[st(n)] || '#8da0c4'
        const role = n.role
        const stroke = role === 'root' ? '#ff3b3b' : role === 'affected' ? '#ff9f43' : role === 'blast' ? '#ffd166' : (selected === n.id ? '#fff' : c)
        return (
          <g key={n.id} transform={`translate(${p.x - 62},${p.y - 18})`} onClick={() => onSelect && onSelect(n)} style={{ cursor: 'pointer' }} className={role === 'root' ? 'node-root' : ''}>
            <rect width="124" height="36" rx="8" fill="#0f1a31" stroke={stroke} strokeWidth={role ? 3 : 1.6} strokeDasharray={role === 'blast' ? '5 3' : undefined} />
            <rect width="6" height="36" rx="3" fill={c} />
            <text x="14" y="15" fontSize="11" fill="#e6ecf8" fontWeight="700">{n.label || n.id}</text>
            <text x="14" y="29" fontSize="9.5" fill="#8da0c4">{n.type} · {st(n)}{role ? ` · ${role === 'blast' ? 'at risk' : role}` : ''}</text>
          </g>
        )
      })}
    </svg>
  )
}

export const Json = ({ v }) => <pre className="mono" style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{JSON.stringify(v, null, 2)}</pre>

/** Render text with [REDACTED:x] markers highlighted. */
export const RedText = ({ t }) => {
  const parts = String(t ?? '').split(/(\[REDACTED:[a-z_0-9]+\])/)
  return <>{parts.map((p, i) => p.startsWith('[REDACTED:') ? <span key={i} className="grn">{p}</span> : <React.Fragment key={i}>{p}</React.Fragment>)}</>
}
