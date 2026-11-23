import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, usePoll, fmtDT, fmtT, ago, num } from './api'
import { Badge, Card, Kpi, StateBadge, STATE_COLOR, PriorityBadge } from './ui'

// SaaS-layer views built ONLY from the platform's real APIs (/api/overview, /api/alerts, /api/incidents, /api/history, /api/perf, /api/series).
// Nothing here is invented: where a number is not reported by any device it says so.
const SEV = { critical: '#ef4444', high: '#f97316', warning: '#f5a524', medium: '#f5a524', low: '#38bdf8', info: '#8da0c4' }
const alertType = (a) => ({ cpu_percent: 'CPU threshold', memory_percent: 'Memory overload', disk_percent: 'Disk usage', collector_offline: 'Device offline' }[a.metric] || 'Abnormal performance')

const median = (xs) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)] }

/** Device -> latest CPU/RAM/Disk/network, from real stored telemetry. */
function deviceRows(ov) {
  const ents = ov?.entities || []
  return (ov?.collectors || []).map(c => {
    const mine = ents.filter(e => e.collector_id === c.id)
    const get = (m) => { for (const e of mine) if (e.metrics[m]) return e.metrics[m]; return null }
    return { c, cpu: get('cpu_percent'), ram: get('memory_percent'), disk: get('disk_percent'), net: get('bandwidth_mbps') }
  })
}

export function FleetKpis({ ov }) {
  if (!ov) return null
  const rows = deviceRows(ov), cs = ov.collectors
  const on = cs.filter(c => c.status === 'online').length
  const st = (s) => cs.filter(c => c.state === s).length
  const avg = (k) => { const v = rows.map(r => r[k]?.value).filter(v => v != null); return v.length ? num(v.reduce((a, b) => a + b, 0) / v.length, 0) + '%' : '—' }
  const net = rows.map(r => r.net?.value).filter(v => v != null)
  return (
    <>
      <div className="grid g5">
        <Kpi label="Connected devices" value={cs.length} sub="registered to this organisation" />
        <Kpi label="Online / offline" value={`${on} / ${cs.length - on}`} color={cs.length - on ? '#ef4444' : '#2ecc71'} sub="by heartbeat" />
        <Kpi label="Healthy · Warning · Critical" value={`${st('Excellent') + st('Good')} · ${st('Fair')} · ${st('Poor')}`} sub="Excellent+Good · Fair · Poor" color={st('Poor') ? '#ef4444' : undefined} />
        <Kpi label="Overall system health" value={ov.health.state} color={STATE_COLOR[ov.health.state]} sub={`${ov.kpis.open_incidents} open incidents`} />
        <Kpi label="Fleet availability" value={cs.length ? num(100 * on / cs.length, 0) + '%' : '—'} sub="online now (uptime history: Analytics)" />
      </div>
      <div className="grid g4">
        <Kpi label="Avg CPU" value={avg('cpu')} sub="devices that report CPU" />
        <Kpi label="Avg RAM" value={avg('ram')} sub="devices that report RAM" />
        <Kpi label="Avg disk" value={avg('disk')} sub="devices that report disk" />
        <Kpi label="Network activity" value={net.length ? num(net.reduce((a, b) => a + b, 0), 2) + ' Mbps' : '—'} sub={`${ov.kpis.events_per_min} metadata events/min`} />
      </div>
    </>
  )
}

/** LOCAL DEVICE -> LOCAL ANALYSIS -> PRIVACY FILTER -> METADATA -> CLOUD SAAS -> DASHBOARD, with live counters from the platform. */
export function FlowStrip({ ov, go }) {
  if (!ov) return null
  const k = ov.kpis
  const stages = [
    ['LOCAL DEVICE', 'raw logs, files, identities stay here', `${k.collectors_online}/${k.collectors_total} online`, '#38bdf8'],
    ['LOCAL ANALYSIS', 'metrics + log scanning on the device', 'runs on the device', '#4f8cff'],
    ['PRIVACY FILTER', 'allow-list · redact · anonymise', `${k.rejected_payloads} payloads refused`, '#c084fc'],
    ['METADATA', 'numbers, categories, severity only', `${k.events_per_min} events/min`, '#a78bfa'],
    ['CLOUD SAAS', 'multi-tenant ingest · incidents · alerts', k.ingest_p95_ms != null ? `p95 ${num(k.ingest_p95_ms, 0)} ms` : 'ingesting', '#22d3ee'],
    ['DASHBOARD', 'what you are looking at', k.render_p95_ms != null ? `p95 ${num(k.render_p95_ms, 0)} ms` : 'live', '#2ecc71'],
  ]
  return (
    <Card title="Metadata transmission — how data reaches this dashboard" right={<a href="#" onClick={e => { e.preventDefault(); go('privacy') }}>open Privacy Center →</a>}>
      <div className="flow">
        {stages.map(([t, d, live, col], i) => <React.Fragment key={t}>
          <div className="flow-node" style={{ borderColor: col + '88' }}><b style={{ color: col }}>{t}</b><div className="small mut">{d}</div><div className="small mono" style={{ marginTop: 4 }}>{live}</div></div>
          {i < stages.length - 1 && <div className="flow-arrow"><i style={{ background: col }} /></div>}
        </React.Fragment>)}
      </div>
    </Card>
  )
}

/** Devices table: ID, status, CPU, RAM, Disk, last heartbeat, health score (the platform's own health state). */
export function DeviceTable({ ov, onSelect, selected }) {
  const { t } = useTranslation()
  const rows = deviceRows(ov)
  const [q, setQ] = useState(''), [f, setF] = useState('all')
  const shown = rows.filter(r => (f === 'all' || (f === 'online' ? r.c.status === 'online' : f === 'offline' ? r.c.status !== 'online' : r.c.state === f)) && (r.c.name + r.c.id).toLowerCase().includes(q.toLowerCase()))
  const cell = (m, unit = '%') => m ? <span style={{ color: m.state === 'Poor' ? '#ef4444' : m.state === 'Fair' ? '#f5a524' : undefined }}>{num(m.value, 0)}{unit}</span> : <span className="mut" title="not reported by this device">—</span>
  return (
    <Card title="Devices" right={<div className="row"><input placeholder={t('search device…')} value={q} onChange={e => setQ(e.target.value)} style={{ width: 170 }} />
      <select value={f} onChange={e => setF(e.target.value)}><option value="all">{t('all')}</option><option value="online">{t('online')}</option><option value="offline">{t('offline')}</option><option value="Excellent">Excellent</option><option value="Good">Good</option><option value="Fair">Fair (warning)</option><option value="Poor">Poor (critical)</option></select></div>}>
      <table><thead><tr><th>{t('Device')}</th><th>{t('Status')}</th><th>{t('CPU')}</th><th>{t('RAM')}</th><th>{t('Disk')}</th><th>{t('Last heartbeat')}</th><th>{t('Health score')}</th></tr></thead><tbody>
        {shown.map(({ c, cpu, ram, disk }) => <tr key={c.id} className={'click' + (selected === c.id ? ' sel' : '')} onClick={() => onSelect(c.id === selected ? null : c.id)}>
          <td><b>{c.name}</b><div className="mut small mono">{c.id}</div></td><td><Badge kind={c.status === 'online' ? 'delivered' : 'blocked'}>{c.status}</Badge></td>
          <td>{cell(cpu)}</td><td>{cell(ram)}</td><td>{cell(disk)}</td><td className="small">{ago(c.age_s)}<div className="mono mut">{fmtT(c.last_seen_ms)}Z</div></td>
          <td><StateBadge s={c.state} /></td></tr>)}
        {shown.length === 0 && <tr><td colSpan={7} className="mut">No devices match.</td></tr>}
      </tbody></table>
      <div className="small mut" style={{ marginTop: 6 }}>Click a device for its detailed metrics and history. “—” means that device does not report the metric (e.g. Android does not expose CPU to apps).</div>
    </Card>
  )
}

/** Alert Center: real alerts, typed, filterable, live. */
export function AlertsPage({ ver, go }) {
  const { t } = useTranslation()
  const [rows] = usePoll(() => api('/api/alerts?limit=300'), 3000, [ver])
  const [sev, setSev] = useState('all'), [typ, setTyp] = useState('all'), [st, setSt] = useState('active')
  const list = (rows || []).filter(a => a.severity !== 'info' || sev === 'info')
  const shown = list.filter(a => (sev === 'all' || a.severity === sev) && (typ === 'all' || alertType(a) === typ) && (st === 'all' || (st === 'active') === (a.cleared_ms == null)))
  const types = ['CPU threshold', 'Memory overload', 'Disk usage', 'Device offline', 'Abnormal performance']
  const count = (t) => list.filter(a => alertType(a) === t && a.cleared_ms == null).length
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g5">{types.map(t => <Kpi key={t} label={t} value={count(t)} sub="active now" color={count(t) ? '#f5a524' : undefined} />)}</div>
      <Card title="Alert center" right={<div className="row"><select value={st} onChange={e => setSt(e.target.value)}><option value="active">{t('active')}</option><option value="cleared">{t('cleared')}</option><option value="all">{t('all')}</option></select>
        <select value={sev} onChange={e => setSev(e.target.value)}><option value="all">{t('all severities')}</option><option value="critical">{t('critical')}</option><option value="high">{t('high')}</option><option value="warning">{t('warning')}</option><option value="low">{t('low')}</option></select>
        <select value={typ} onChange={e => setTyp(e.target.value)}><option value="all">{t('all types')}</option>{types.map(x => <option key={x} value={x}>{t(x)}</option>)}</select></div>}>
        <table><thead><tr><th>{t('Severity')}</th><th>{t('Type')}</th><th>{t('Alert')}</th><th>{t('Source')}</th><th>{t('Detected (UTC)')}</th><th>{t('Status')}</th><th>{t('Incident')}</th></tr></thead><tbody>
          {shown.map(a => <tr key={a.id}><td><Badge kind={a.severity} /></td><td className="small">{alertType(a)}</td><td className="small"><b>{a.title}</b><div className="mut">{a.message}</div></td><td className="small mono">{a.source_id}</td>
            <td className="mono small">{fmtDT(a.event_ms)}</td><td>{a.cleared_ms == null ? <Badge kind="warning">active</Badge> : <Badge kind="delivered">cleared {fmtT(a.cleared_ms)}Z</Badge>}</td>
            <td>{a.incident_id ? <a href="#" onClick={e => { e.preventDefault(); go('incidents', a.incident_id) }}>#{a.incident_id}</a> : ''}</td></tr>)}
          {shown.length === 0 && <tr><td colSpan={7} className="mut">No alerts match these filters.</td></tr>}
        </tbody></table>
        <div className="small mut" style={{ marginTop: 6 }}>Alerts come from local detection and the platform's baseline engine; thresholds are editable under Settings. Updates live.</div>
      </Card>
    </div>
  )
}

/** Toast notifications for NEW alerts, in real time (polls the real alert feed; first load is not announced). */
export function AlertToasts({ ver, go }) {
  const [rows] = usePoll(() => api('/api/alerts?limit=15'), 3000, [ver])
  const seen = useRef(null), [toasts, setToasts] = useState([])
  useEffect(() => {
    if (!rows) return
    const ids = new Set(rows.map(a => a.id))
    if (seen.current) {
      const fresh = rows.filter(a => !seen.current.has(a.id) && a.severity !== 'info' && a.cleared_ms == null)
      if (fresh.length) { setToasts(t => [...fresh.slice(0, 3).map(a => ({ id: a.id, sev: a.severity, text: a.title, type: alertType(a) })), ...t].slice(0, 4)); fresh.slice(0, 3).forEach(a => setTimeout(() => setToasts(t => t.filter(x => x.id !== a.id)), 9000)) }
    }
    seen.current = ids
  }, [rows])
  if (!toasts.length) return null
  return <div className="toasts">{toasts.map(t => <div key={t.id} className="toast" style={{ borderLeftColor: SEV[t.sev] || '#8da0c4' }} onClick={() => { go('alerts'); setToasts(x => x.filter(y => y.id !== t.id)) }}><b>{t.type}</b><div className="small">{t.text}</div></div>)}</div>
}

const Bars = ({ data, colors, h = 120, label }) => {
  const max = Math.max(1, ...data.map(d => d.v.reduce((a, b) => a + b, 0)))
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: h }}>
        {data.map((d, i) => <div key={i} title={`${d.t}: ${d.v.join(' / ')}`} style={{ flex: 1, display: 'flex', flexDirection: 'column-reverse', height: '100%' }}>
          {d.v.map((v, j) => <div key={j} style={{ height: (100 * v / max) + '%', background: colors[j], minHeight: v ? 2 : 0 }} />)}</div>)}
      </div>
      <div className="row small mut" style={{ justifyContent: 'space-between' }}><span>{data[0]?.t}</span><span>{label}</span><span>{data[data.length - 1]?.t}</span></div>
    </div>
  )
}

/** Analytics: all graphs derive from stored telemetry, incidents, health transitions and outages. */
export function AnalyticsPage({ ov, ver, MetricChart }) {
  const [incs] = usePoll(() => api('/api/incidents'), 10000, [ver])
  const [hist] = usePoll(() => api('/api/history?limit=500'), 10000, [ver])
  const [perf] = usePoll(() => api('/api/perf'), 10000)
  const [secs, setSecs] = useState(3600)
  const hostEnts = (ov?.entities || []).filter(e => e.type === 'host' && (e.metrics.cpu_percent || e.metrics.memory_percent)).sort((a, b) => (!!b.metrics.cpu_percent - !!a.metrics.cpu_percent) || ((a.state === 'Poor') - (b.state === 'Poor')))
  const [pick, setPick] = useState('')
  const host = hostEnts.find(e => e.id === pick) || hostEnts[0]
  const buckets = 24, now = Date.now(), span = 3600_000
  const bucketize = (items, key, cls) => Array.from({ length: buckets }, (_, i) => {
    const a = now - (buckets - i) * span, b = a + span
    return { t: fmtT(b).slice(0, 5), v: cls.map(c => items.filter(x => x[key] >= a && x[key] < b && c(x)).length) }
  })
  const incData = useMemo(() => bucketize(incs || [], 'opened_ms', [x => x.priority_level === 'P1' || x.priority_level === 'P2', x => x.priority_level === 'P3', x => x.priority_level === 'P4']), [incs])
  const healthData = useMemo(() => bucketize(hist || [], 'ts_ms', [x => x.new_state === 'Poor', x => x.new_state === 'Fair', x => x.new_state === 'Good' || x.new_state === 'Excellent']), [hist])
  const outages = useMemo(() => (perf?.offline_detection || []).map(o => ({ ms: Date.parse(o.detected_at) || 0, rec: o.recovered })), [perf])
  const outData = useMemo(() => bucketize(outages, 'ms', [x => !x.rec, x => x.rec]), [outages])
  const cs = ov?.collectors || [], on = cs.filter(c => c.status === 'online').length
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row"><h2 style={{ margin: 0 }}>Monitoring trends</h2><div className="sp" />
        {hostEnts.length > 1 && <select value={host?.id || ''} onChange={e => setPick(e.target.value)}>{hostEnts.map(e => <option key={e.id} value={e.id}>{e.label}</option>)}</select>}
        <select value={secs} onChange={e => setSecs(+e.target.value)}><option value={900}>15 min</option><option value={3600}>1 hour</option><option value={21600}>6 hours</option><option value={86400}>24 hours</option></select></div>
      <div className="grid g2">
        {host?.metrics.cpu_percent ? <MetricChart source={host.id} metric="cpu_percent" seconds={secs} title={`CPU trend · ${host.label}`} /> : <Card title="CPU trend"><div className="mut small">No monitored host reports CPU.</div></Card>}
        {host?.metrics.memory_percent ? <MetricChart source={host.id} metric="memory_percent" seconds={secs} title={`RAM trend · ${host.label}`} /> : <Card title="RAM trend"><div className="mut small">No monitored host reports RAM.</div></Card>}
      </div>
      <div className="grid g2">
        <Card title="Incident trend (opened per hour, last 24 h)" right={<span className="small legend"><span style={{ color: '#ef4444' }}>■ P1–P2</span> <span style={{ color: '#f5a524' }}>■ P3</span> <span style={{ color: '#38bdf8' }}>■ P4</span></span>}>
          <Bars data={incData} colors={['#ef4444', '#f5a524', '#38bdf8']} label="hours (UTC)" /></Card>
        <Card title="Device health over time (state changes per hour)" right={<span className="small legend"><span style={{ color: '#ef4444' }}>■ to Poor</span> <span style={{ color: '#f5a524' }}>■ to Fair</span> <span style={{ color: '#2ecc71' }}>■ recovered</span></span>}>
          <Bars data={healthData} colors={['#ef4444', '#f5a524', '#2ecc71']} label="hours (UTC)" /></Card>
      </div>
      <div className="grid g2">
        <Card title="Online versus offline devices"><div className="row" style={{ gap: 18 }}>
          <svg width="110" height="110" viewBox="0 0 36 36"><circle cx="18" cy="18" r="15.9" fill="none" stroke="#ef4444" strokeWidth="4" />
            <circle cx="18" cy="18" r="15.9" fill="none" stroke="#2ecc71" strokeWidth="4" strokeDasharray={`${cs.length ? 100 * on / cs.length : 0} 100`} transform="rotate(-90 18 18)" /></svg>
          <div><div><b style={{ color: '#2ecc71' }}>{on}</b> online</div><div><b style={{ color: '#ef4444' }}>{cs.length - on}</b> offline</div><div className="small mut">{cs.length} devices in this organisation</div></div></div></Card>
        <Card title="Offline detections per hour (last 24 h)"><Bars data={outData} colors={['#ef4444', '#2ecc71']} label="hours (UTC)" />
          <div className="small mut" style={{ marginTop: 4 }}>red = still offline · green = recovered. From the platform's outage log.</div></Card>
      </div>
      <div className="small mut">All charts use stored telemetry, incidents and health transitions of this organisation. Empty bars mean nothing happened in that hour; no demo data is shown.</div>
    </div>
  )
}
