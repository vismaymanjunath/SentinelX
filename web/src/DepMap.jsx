import React, { useMemo, useState } from 'react'
import { api, usePoll, num, fmtDT } from './api'
import { Badge, Card, Kpi, PriorityBadge, StateBadge, STATE_COLOR } from './ui'

// System Dependency Map. Nodes = the entities the platform actually monitors; solid edges = dependencies DECLARED by the collectors' own
// topology (heartbeats); dashed edges (optional) = the OBSERVED telemetry path (device -> collector -> SENTINEL X host). Impact analysis walks only
// those edges. A node with no declared edge is "unknown", which is NOT evidence that it is independent.
const TYPE_ICON = { service: '⚙️', host: '🖥️', network: '🌐', collector: '📡', platform: '☁️' }
const HOST = { id: 'platform:sentinel-host', type: 'platform', label: 'SENTINEL X host', state: 'Good', metrics: {}, reasons: [], synthetic: true }

function walk(adj, start) {            // transitive reach with depth
  const seen = new Map(), q = [[start, 0]]
  while (q.length) { const [id, d] = q.shift(); for (const n of adj[id] || []) if (!seen.has(n) && n !== start) { seen.set(n, d + 1); q.push([n, d + 1]) } }
  return seen
}

function Map2({ nodes, edges, sel, setSel, dim, up, down, incNodes, roles }) {
  const W = 980
  const { pos, H } = useMemo(() => {
    const rd = {}; nodes.forEach(n => (rd[n.id] = [])); edges.forEach(([a, b]) => rd[b] && rd[b].push(a))
    const memo = {}
    const depth = (id, seen) => { if (memo[id] != null) return memo[id]; if (seen.has(id)) return 0; seen.add(id); const v = rd[id].length ? 1 + Math.max(...rd[id].map(x => depth(x, new Set(seen)))) : 0; return (memo[id] = v) }
    const L = {}; nodes.forEach(n => (L[n.id] = depth(n.id, new Set())))
    const by = {}; nodes.forEach(n => (by[L[n.id]] = by[L[n.id]] || []).push(n))
    const maxL = Math.max(0, ...Object.keys(by).map(Number)), pos = {}
    Object.entries(by).forEach(([l, ns]) => ns.sort((a, b) => a.id.localeCompare(b.id)).forEach((n, i) => { pos[n.id] = { x: ((i + 1) / (ns.length + 1)) * W, y: 36 + l * 78 } }))
    return { pos, H: 36 + maxL * 78 + 50 }
  }, [nodes, edges])
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: 'block', minHeight: 240 }}>
      <defs><marker id="dm-arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0L10,5L0,10z" fill="#4a5f8f" /></marker>
        <marker id="dm-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0L10,5L0,10z" fill="#f5a524" /></marker></defs>
      {edges.map(([a, b, kind], i) => {
        if (!pos[a] || !pos[b]) return null
        const hot = sel && ((a === sel && up.has(b)) || (b === sel && down.has(a)) || (up.has(a) && (up.has(b) || b === sel)) || (down.has(b) && (down.has(a) || a === sel)))
        const dimmed = (dim.has(a) || dim.has(b)) && !hot
        return <line key={i} x1={pos[a].x} y1={pos[a].y + 17} x2={pos[b].x} y2={pos[b].y - 19} stroke={hot ? '#f5a524' : '#3a4d7a'} strokeWidth={hot ? 2.4 : 1.3} strokeDasharray={kind === 'telemetry' ? '4 4' : undefined}
          markerEnd={hot ? 'url(#dm-hot)' : 'url(#dm-arr)'} opacity={dimmed ? 0.12 : 1} className={hot ? 'dm-flow' : ''} />
      })}
      {nodes.map(n => {
        const p = pos[n.id]; if (!p) return null
        const c = STATE_COLOR[n.state] || '#8da0c4', isSel = sel === n.id, role = roles[n.id]
        const isUp = up.has(n.id), isDown = down.has(n.id), inc = incNodes.has(n.id)
        const stroke = role === 'root' ? '#ff3b3b' : isSel ? '#fff' : isDown ? '#f5a524' : isUp ? '#4f8cff' : inc ? '#ef4444' : c
        return (
          <g key={n.id} transform={`translate(${p.x - 64},${p.y - 18})`} onClick={() => setSel(isSel ? null : n.id)} style={{ cursor: 'pointer' }} opacity={dim.has(n.id) && !isSel && !isUp && !isDown ? 0.2 : 1} className={inc ? 'dm-inc' : ''}>
            <rect width="128" height="36" rx="8" fill="#0f1a31" stroke={stroke} strokeWidth={isSel || inc || role ? 2.6 : 1.5} strokeDasharray={n.unknown ? '3 3' : undefined} />
            <rect width="6" height="36" rx="3" fill={c} />
            <text x="14" y="15" fontSize="11" fill="#e6ecf8" fontWeight="700">{TYPE_ICON[n.type] || '•'} {(n.label || n.id).slice(0, 15)}</text>
            <text x="14" y="29" fontSize="9.5" fill="#8da0c4">{n.type} · {n.state}{n.unknown ? ' · deps unknown' : ''}</text>
            {inc && <circle cx="122" cy="6" r="4" fill="#ef4444" />}
          </g>)
      })}
    </svg>
  )
}

export default function DepMap({ ver, go }) {
  const [incSel, setIncSel] = useState('')
  const [topo] = usePoll(() => api('/api/topology' + (incSel ? `?incident_id=${incSel}` : '')), 3000, [ver, incSel])
  const [ov] = usePoll(() => api('/api/overview'), 5000, [ver])
  const [incs] = usePoll(() => api('/api/incidents?status=open'), 5000, [ver])
  const [alerts] = usePoll(() => api('/api/alerts?limit=200'), 5000, [ver])
  const [sel, setSel] = useState(null)
  const [q, setQ] = useState(''), [ft, setFt] = useState('all'), [fs, setFs] = useState('all'), [onlyInc, setOnlyInc] = useState(false), [tele, setTele] = useState(false)
  const data = useMemo(() => {
    if (!topo) return null
    const declared = topo.edges.map(([a, b]) => [a, b, 'declared'])
    let nodes = topo.nodes.map(n => ({ ...n })), edges = declared
    const connected = new Set(declared.flat())
    nodes.forEach(n => { n.unknown = !connected.has(n.id) })
    if (tele && ov) {
      const cols = ov.collectors || []
      nodes.push(HOST)
      cols.forEach(c => { nodes.push({ id: 'collector:' + c.id, type: 'collector', label: c.name, state: c.state, metrics: {}, reasons: c.reasons || [], synthetic: true }); edges = [...edges, ['collector:' + c.id, HOST.id, 'telemetry']] })
      ;(ov.entities || []).forEach(e => { if (e.collector_id && nodes.some(n => n.id === e.id)) edges = [...edges, [e.id, 'collector:' + e.collector_id, 'telemetry']] })
    }
    return { nodes, edges }
  }, [topo, ov, tele])
  const adjDown = useMemo(() => { const m = {}; data?.edges.forEach(([a, b]) => (m[a] = m[a] || []).push(b)); return m }, [data])   // a depends on b
  const adjUp = useMemo(() => { const m = {}; data?.edges.forEach(([a, b]) => (m[b] = m[b] || []).push(a)); return m }, [data])     // b is depended on by a
  if (!data) return <div className="mut">loading…</div>
  const incByNode = {}
  ;(incs || []).forEach(i => { new Set([...(i.entities || []), i.root_entity, ...((i.affected || []).map?.(a => a.entity || a) || [])].filter(Boolean)).forEach(e => (incByNode[e] = incByNode[e] || []).push(i)) })
  const incNodes = new Set(Object.keys(incByNode))
  const alertBy = {}; (alerts || []).filter(a => a.cleared_ms == null && a.severity !== 'info').forEach(a => { const e = (data.nodes.find(n => n.id === a.source_id) || {}).id || a.source_id; (alertBy[e] = alertBy[e] || []).push(a) })
  const ql = q.trim().toLowerCase()
  const match = (n) => (!ql || (n.label + n.id).toLowerCase().includes(ql)) && (ft === 'all' || n.type === ft) && (fs === 'all' || n.state === fs) && (!onlyInc || incNodes.has(n.id))
  const dim = new Set(data.nodes.filter(n => !match(n)).map(n => n.id))
  const roles = Object.fromEntries(data.nodes.filter(n => n.role).map(n => [n.id, n.role]))
  const node = data.nodes.find(n => n.id === sel)
  const up = sel ? walk(adjDown, sel) : new Map()        // what the selection depends on
  const down = sel ? walk(adjUp, sel) : new Map()        // what depends on the selection = blast radius if it fails
  const byId = Object.fromEntries(data.nodes.map(n => [n.id, n]))
  const list = (m) => [...m.entries()].sort((a, b) => a[1] - b[1]).map(([id, d]) => ({ n: byId[id], d })).filter(x => x.n)
  const unknown = data.nodes.filter(n => n.unknown && !n.synthetic)
  const types = [...new Set(data.nodes.map(n => n.type))]
  const poor = data.nodes.filter(n => n.state === 'Poor').length
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g4">
        <Kpi label="Components" value={data.nodes.filter(n => !n.synthetic).length} sub={`${topo.edges.length} declared dependencies`} />
        <Kpi label="Unhealthy (Poor)" value={poor} color={poor ? '#ef4444' : '#2ecc71'} sub="from observed telemetry" />
        <Kpi label="Components in open incidents" value={incNodes.size} color={incNodes.size ? '#ef4444' : undefined} sub={`${(incs || []).length} open incidents`} />
        <Kpi label="Unknown dependencies" value={unknown.length} color={unknown.length ? '#f5a524' : undefined} sub="no declared edges (not proof of independence)" />
      </div>
      <Card title="System dependency map" right={<div className="row wrap">
        <input placeholder="search device / service…" value={q} onChange={e => setQ(e.target.value)} style={{ width: 170 }} />
        <select value={ft} onChange={e => setFt(e.target.value)}><option value="all">all types</option>{types.map(t => <option key={t}>{t}</option>)}</select>
        <select value={fs} onChange={e => setFs(e.target.value)}><option value="all">any severity</option><option value="Poor">Poor (critical)</option><option value="Fair">Fair (warning)</option><option value="Good">Good</option><option value="Excellent">Excellent</option></select>
        <select value={incSel} onChange={e => setIncSel(e.target.value)}><option value="">highlight: all open incidents</option>{(incs || []).map(i => <option key={i.id} value={i.id}>#{i.id} {i.title.slice(0, 40)}</option>)}</select>
        <label className="small"><input type="checkbox" checked={onlyInc} onChange={e => setOnlyInc(e.target.checked)} /> incidents only</label>
        <label className="small"><input type="checkbox" checked={tele} onChange={e => setTele(e.target.checked)} /> show telemetry path</label></div>}>
        <Map2 nodes={data.nodes} edges={data.edges} sel={sel} setSel={setSel} dim={dim} up={up} down={down} incNodes={incNodes} roles={roles} />
        <div className="legend small" style={{ marginTop: 6 }}>{Object.entries(STATE_COLOR).map(([k, c]) => <span key={k}><i className="dot" style={{ background: c }} />{k}</span>)}
          <span style={{ color: '#4f8cff' }}>▭ upstream (selected depends on it)</span><span style={{ color: '#f5a524' }}>▭ downstream (breaks if selected fails)</span><span style={{ color: '#ef4444' }}>● open incident</span><span>- - dashed = unknown dependencies / observed telemetry path</span></div>
        <div className="small mut" style={{ marginTop: 4 }}>Arrow A → B means “A depends on B”. Solid edges are declared by the collectors’ configured topology; dashed edges (when shown) are the observed telemetry path. Click a component for impact analysis.</div>
      </Card>
      {node ? <div className="grid g2" style={{ alignItems: 'start' }}>
        <Card title={`${TYPE_ICON[node.type] || ''} ${node.label}`} right={<button className="btn sm" onClick={() => setSel(null)}>Close</button>}>
          <div className="row wrap"><StateBadge s={node.state} /><span className="mut small">{node.type} · <span className="mono">{node.id}</span></span></div>
          {Object.entries(node.metrics || {}).map(([m, v]) => <div key={m} className="row small"><span className="sp">{m}</span><b>{num(v, 2)}</b></div>)}
          {(node.reasons || []).map((r, i) => <div key={i} className="small" style={{ color: '#f5a524' }}>{r}</div>)}
          {node.unknown && <div className="callout small" style={{ marginTop: 6 }}>No dependency is declared for this component. Its upstream/downstream impact is <b>unknown</b>, not zero.</div>}
          <h3 style={{ margin: '10px 0 4px' }}>Related incidents</h3>
          {(incByNode[node.id] || []).length === 0 ? <div className="mut small">None open.</div> : incByNode[node.id].map(i => <div key={i.id} className="row small" style={{ cursor: 'pointer' }} onClick={() => go('incidents', i.id)}><PriorityBadge p={i.priority_level} /><b>#{i.id}</b> {i.title}</div>)}
          <h3 style={{ margin: '10px 0 4px' }}>Active alerts</h3>
          {(alertBy[node.id] || []).length === 0 ? <div className="mut small">None.</div> : alertBy[node.id].slice(0, 5).map(a => <div key={a.id} className="small"><Badge kind={a.severity} /> {a.title} <span className="mut">{fmtDT(a.event_ms)}</span></div>)}
          <div className="row" style={{ marginTop: 10 }}><button className="btn sm pri" onClick={() => go('remediation')}>Plan a fix in Remediation</button><button className="btn sm" onClick={() => go('intel')}>Global Intelligence</button></div>
        </Card>
        <Card title="Impact & blast-radius analysis">
          <div className="small"><b style={{ color: '#f5a524' }}>If {node.label} fails →</b> {down.size ? <><b>{down.size}</b> component(s) that depend on it, directly or indirectly, are at risk:</> : 'no declared component depends on it.'}</div>
          <table><tbody>{list(down).map(({ n, d }) => <tr key={n.id}><td className="small"><span className="mut">{d === 1 ? 'direct' : `${d} hops`}</span></td><td className="small"><b>{n.label}</b> <span className="mut">{n.type}</span></td><td><StateBadge s={n.state} /></td></tr>)}</tbody></table>
          <div className="small" style={{ marginTop: 8 }}><b style={{ color: '#4f8cff' }}>{node.label} depends on →</b> {up.size ? <><b>{up.size}</b> upstream component(s):</> : 'nothing declared (unknown).'}</div>
          <table><tbody>{list(up).map(({ n, d }) => <tr key={n.id}><td className="small"><span className="mut">{d === 1 ? 'direct' : `${d} hops`}</span></td><td className="small"><b>{n.label}</b> <span className="mut">{n.type}</span></td><td><StateBadge s={n.state} /></td></tr>)}</tbody></table>
          {list(up).some(x => x.n.state === 'Poor') && <div className="callout small" style={{ marginTop: 6 }}>An upstream dependency is already Poor: <b>{list(up).filter(x => x.n.state === 'Poor').map(x => x.n.label).join(', ')}</b> — a likely contributor to this component’s state.</div>}
          <div className="small mut" style={{ marginTop: 6 }}>Computed from declared dependencies only; real impact may be larger if dependencies exist that no collector declared.</div>
        </Card>
      </div> : <Card title="Select a component"><div className="mut small">Click any node to see its upstream/downstream dependencies, blast radius, related incidents and alerts. Use the filters to focus on a device, service or severity.</div>
        {unknown.length > 0 && <div className="small" style={{ marginTop: 8 }}><b>Unknown dependencies</b> (no declared edges): {unknown.map(n => n.label).join(', ')}</div>}</Card>}
    </div>
  )
}
