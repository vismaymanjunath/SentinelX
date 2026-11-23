import React, { useState } from 'react'
import { api, usePoll, fmtDT, ago } from './api'
import { Badge, Card, Json, Kpi, Tabs } from './ui'

// Global Intelligence. The browser only ever calls THIS server's /api/intel/*; it never contacts an external feed.
export const SEV = { critical: 'critical', high: 'Poor', medium: 'warning', low: 'info', unrated: 'neutral' }
const FRESH = { live: 'delivered', cached: 'warning', stale: 'warning', delayed: 'warning', rate_limited: 'warning', unavailable: 'blocked', pending: 'neutral' }
const CORR = { confirmed: 'critical', possible: 'warning' }
const REL = { worldwide: ['neutral', 'worldwide'], relevant: ['warning', 'may affect our devices'], correlated: ['critical', 'tied to a local incident'] }
const RANGES = [['1', 'last hour'], ['6', 'last 6 h'], ['24', 'last 24 h'], ['168', 'last 7 days'], ['720', 'last 30 days'], ['0', 'all stored']]
const tAgo = ms => (ms ? ago((Date.now() - ms) / 1000) : '—')
const interval = s => (s >= 3600 ? s / 3600 + ' h' : s >= 60 ? s / 60 + ' min' : s + ' s')

// Never sit on "loading…" forever: a failed request is shown as an error (and polling keeps retrying).
export const Wait = ({ err }) => err ? <div className="callout small">Could not load this data from the SENTINEL X backend: {String(err.message || err)}. If the backend was started before Global Intelligence was installed, restart it (python run_host.py). Retrying…</div> : <div className="mut">loading…</div>

export const FreshBadge = ({ s }) => s && s.freshness ? <Badge kind={FRESH[s.freshness] || 'neutral'}>{s.freshness.replace('_', ' ')}{s.age_s != null ? ` · ${s.age_s < 90 ? s.age_s + 's' : Math.round(s.age_s / 60) + 'm'} old` : ''}</Badge> : null
const RelBadge = ({ e }) => <><Badge kind={REL[e.relevance || 'worldwide'][0]}>{REL[e.relevance || 'worldwide'][1]}</Badge>{e.correlation_status && <Badge kind={CORR[e.correlation_status]}>{e.correlation_status}</Badge>}</>

function SourceStrip({ sources, category, title = 'Data sources — freshness and attribution' }) {
  const rows = (sources || []).filter(x => !category || x.category === category)
  return (
    <Card title={title}>
      <table><thead><tr><th>Source</th><th>Status</th><th>Last successful update</th><th>Poll interval</th><th>Events stored</th><th>Newest event</th><th>Notes</th></tr></thead><tbody>
        {rows.map(x => <tr key={x.source}><td><a href={x.url} target="_blank" rel="noreferrer noopener"><b>{x.name}</b></a></td>
          <td><FreshBadge s={x} /></td><td className="small">{x.last_success_ms ? `${fmtDT(x.last_success_ms)} (${tAgo(x.last_success_ms)})` : 'never'}</td>
          <td className="small">{x.category === 'routing' ? 'live stream' : interval(x.interval_s)}</td>
          <td>{x.events_stored}</td><td className="small">{x.newest_event_ms ? fmtDT(x.newest_event_ms) : '—'}</td>
          <td className="small">{x.last_error ? <span style={{ color: '#ff8a8a' }}>last error: {x.last_error}</span> : x.note || (x.cache_hits ? `${x.cache_hits} cache hit(s)` : '')}</td></tr>)}
      </tbody></table>
    </Card>
  )
}

function Filters({ f, setF, sources, extra, noRel }) {
  const set = (k, v) => setF({ ...f, [k]: v })
  return (
    <div className="row wrap small" style={{ gap: 10 }}>
      <label className="mut">Source <select value={f.source} onChange={e => set('source', e.target.value)}><option value="">all</option>{sources.map(s => <option key={s.source} value={s.source}>{s.name}</option>)}</select></label>
      <label className="mut">Severity <select value={f.severity} onChange={e => set('severity', e.target.value)}><option value="">all</option>{Object.keys(SEV).map(s => <option key={s}>{s}</option>)}</select></label>
      <label className="mut">Time <select value={f.since_h} onChange={e => set('since_h', e.target.value)}>{RANGES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
      <label className="mut">Country/region <input style={{ width: 70 }} placeholder="e.g. IN" value={f.country} onChange={e => set('country', e.target.value)} /></label>
      {!noRel && <label className="mut">Relevance <select value={f.relevance} onChange={e => set('relevance', e.target.value)}><option value="">all</option><option value="worldwide">worldwide only</option><option value="relevant">may affect our devices</option><option value="correlated">tied to a local incident</option></select></label>}
      <label className="mut">Search <input style={{ width: 150 }} placeholder="CVE, vendor, text…" value={f.q} onChange={e => set('q', e.target.value)} /></label>
      {extra}
    </div>
  )
}

export function EventTable({ category, sources, cols, defaults = {}, extraFilters, limit = 60, noRel }) {
  const [f, setF] = useState({ source: '', severity: '', since_h: '720', country: '', q: '', relevance: '', ...defaults })
  const [sel, setSel] = useState(null)
  const qs = new URLSearchParams({ limit, order: 'event', ...(category ? { category } : {}), ...Object.fromEntries(Object.entries(f).filter(([, v]) => v !== '' && v !== false)) }).toString()
  const [d, derr] = usePoll(() => api('/api/intel/events?' + qs), 8000, [qs])
  const catSources = sources.filter(s => !category || s.category === category)
  return (
    <div className="col" style={{ gap: 12 }}>
      <Filters f={f} setF={setF} sources={catSources} extra={extraFilters && extraFilters(f, setF)} noRel={noRel} />
      <Card title={`Events (${d ? d.total : '…'} match)`}>
        {!d ? <Wait err={derr} /> : d.events.length === 0 ? <div className="mut small">No stored events match these filters. Nothing is invented: if a feed reported nothing, nothing is shown.</div> :
          <table><thead><tr>{cols.map(c => <th key={c.h}>{c.h}</th>)}<th>Relevance</th><th>Source · last updated</th></tr></thead><tbody>
            {d.events.map(e => <tr key={e.id} style={{ cursor: 'pointer' }} onClick={() => setSel(sel === e.id ? null : e.id)}>
              {cols.map(c => <td key={c.h} className={c.cls}>{c.f(e)}</td>)}
              <td><RelBadge e={e} /></td>
              <td className="small"><a href={e.source_url} target="_blank" rel="noreferrer noopener" onClick={ev => ev.stopPropagation()}>{e.source_name}</a><br /><span className="mut">{e.source_last_updated_ms ? tAgo(e.source_last_updated_ms) : '—'}</span> <FreshBadge s={{ freshness: e.source_freshness }} /></td></tr>)}
          </tbody></table>}
      </Card>
      {sel && <EventDetail id={sel} onClose={() => setSel(null)} />}
    </div>
  )
}

export function EventDetail({ id, onClose }) {
  const [e] = usePoll(() => api('/api/intel/events/' + encodeURIComponent(id)), 15000, [id])
  if (!e) return null
  return (
    <Card title={e.title} right={<button className="btn sm" onClick={onClose}>close</button>}>
      <div className="row wrap small" style={{ marginBottom: 6 }}><Badge kind={SEV[e.severity]}>{e.severity}</Badge>{e.exploited ? <Badge kind="critical">exploited in the wild</Badge> : null}
        <Badge kind="neutral">{e.kind}</Badge><span className="mut">status: {e.status || '—'}</span>{e.cve && <span className="mono">{e.cve}</span>}{e.score != null && <span>score {Math.round(e.score * 10) / 10}</span>}</div>
      <p className="small" style={{ whiteSpace: 'pre-wrap', margin: '0 0 8px' }}>{e.summary || '—'}</p>
      <div className="small" style={{ lineHeight: 1.7 }}>
        <div><b>Source:</b> <a href={e.source_url} target="_blank" rel="noreferrer noopener">{e.source_name}</a> · event time {fmtDT(e.event_ms)} · source-reported update {fmtDT(e.updated_ms)} · first seen here {fmtDT(e.first_seen_ms)} · version {e.version}</div>
        {(e.vendor || e.product) && <div><b>Affected:</b> {e.vendor} {e.product}</div>}
        {(e.country || e.provider || e.asn || e.prefix || e.region) && <div><b>Scope:</b> {[e.provider, e.country, e.asn && 'AS' + e.asn, e.prefix, e.region].filter(Boolean).join(' · ')}</div>}
      </div>
      <details style={{ marginTop: 8 }}><summary className="small">All normalised fields and update history</summary><div style={{ maxHeight: 280, overflow: 'auto' }}><Json v={{ data: e.data, history: e.history }} /></div></details>
    </Card>
  )
}

const sevCol = { h: 'Severity', f: e => <Badge kind={SEV[e.severity]}>{e.severity}</Badge> }
const when = { h: 'Time (UTC)', cls: 'small mono', f: e => fmtDT(e.event_ms).slice(0, 16) }
const cyberCols = [sevCol,
  { h: 'CVE / ID', f: e => <span className="mono small">{e.cve || e.id.split(':').slice(1).join(':')}</span> },
  { h: 'Description', cls: 'small', f: e => <><b>{e.title.length > 90 ? e.title.slice(0, 90) + '…' : e.title}</b><div className="mut">{(e.summary || '').slice(0, 170)}{(e.summary || '').length > 170 ? '…' : ''}</div></> },
  { h: 'CVSS', f: e => e.score != null ? Math.round(e.score * 10) / 10 : <span className="mut">—</span> },
  { h: 'Affected', cls: 'small', f: e => [e.vendor, e.product].filter(Boolean).join(' / ').slice(0, 70) || '—' },
  { h: 'Exploited', f: e => e.exploited ? <Badge kind="critical">in the wild</Badge> : <span className="mut small">no known exploitation</span> },
  { h: 'Published', cls: 'small mono', f: e => fmtDT(e.event_ms).slice(0, 10) }]
const routeCols = [sevCol, when, { h: 'Routing observation', cls: 'small', f: e => <><b>{e.title}</b><div className="mut">{(e.summary || '').slice(0, 200)}</div></> },
  { h: 'AS / prefix', cls: 'small mono', f: e => [e.asn && 'AS' + e.asn, e.prefix].filter(Boolean).join(' ') || '—' }, { h: 'Class', cls: 'small', f: e => e.kind.replace('_', ' ') }]
const outageCols = [sevCol, { h: 'Where', f: e => <b>{e.title.split(':')[0]}</b> }, { h: 'Level', cls: 'small', f: e => e.kind.replace('_outage', '') }, { h: 'Signal', cls: 'small', f: e => e.title.split(': ')[1] },
  { h: 'Detected (UTC)', cls: 'small mono', f: e => fmtDT(e.event_ms).slice(0, 16) }, { h: 'Status', f: e => <Badge kind={e.status === 'ongoing' ? 'warning' : 'resolved'}>{e.status}</Badge> },
  { h: 'Detail', cls: 'small', f: e => (e.summary || '').slice(0, 150) }]
const cloudCols = [sevCol, { h: 'Provider', f: e => <b>{e.provider}</b> }, { h: 'Incident', cls: 'small', f: e => <><b>{e.title.slice(0, 110)}</b><div className="mut">{(e.summary || '').slice(0, 160)}</div></> },
  { h: 'Region / services', cls: 'small', f: e => e.region || '—' }, { h: 'Status', f: e => <Badge kind={e.status === 'resolved' ? 'resolved' : 'warning'}>{e.status}</Badge> }, when]
const measCols = [{ h: 'Severity', f: e => <Badge kind={SEV[e.severity]}>{e.status}</Badge> }, { h: 'Country', f: e => <b>{e.country}</b> }, { h: 'Measurement', cls: 'small', f: e => e.title }, when]

function RisLive() {
  const [d] = usePoll(() => api('/api/intel/ris/live'), 3000)
  if (!d) return null
  const st = d.state
  const g = d.rollups.filter(r => r.scope === 'global').slice(0, 10).reverse()
  const max = Math.max(1, ...g.map(r => r.withdrawals))
  return (
    <Card title="RIPE RIS Live — the real BGP stream" right={<Badge kind={st.connected ? 'delivered' : 'blocked'}>{st.connected ? `connected · ${Math.round(st.rate)} msg/s` : 'disconnected'}</Badge>}>
      <div className="small mut" style={{ marginBottom: 6 }}>{st.watched.length ? `Targeted subscriptions for ${st.watched.map(a => 'AS' + a).join(', ')} (this host's network and connected devices).` : 'No ASN watched yet.'} {st.error && <span style={{ color: '#ff8a8a' }}>error: {st.error}</span>}</div>
      <div className="row" style={{ alignItems: 'flex-end', height: 54, gap: 3, marginBottom: 8 }} title="withdrawals per minute at rrc00">{g.map((r, i) => <div key={i} style={{ flex: 1, background: '#4f8cff', height: Math.max(2, 50 * r.withdrawals / max), borderRadius: 2 }} title={`${r.withdrawals} withdrawals, ${r.announcements} announcements`} />)}</div>
      <table><thead><tr><th>Time</th><th>RRC</th><th>Peer AS</th><th>Announced</th><th>Withdrawn</th><th>AS path (last hops)</th></tr></thead><tbody>
        {d.messages.slice(0, 12).map((m, i) => <tr key={i}><td className="mono small">{fmtDT(m.ts_ms).slice(11, 19)}</td><td className="small">{m.host}</td><td className="mono small">AS{m.peer_asn}</td>
          <td className="mono small">{m.announced.join(', ') || '—'}</td><td className="mono small">{m.withdrawn.join(', ') || '—'}</td><td className="mono small">{m.path.slice(-5).join(' → ') || '—'}</td></tr>)}</tbody></table>
      <div className="small mut" style={{ marginTop: 6 }}>Live view of real messages (kept in memory, not stored). Stored: per-minute rollups and notable events only. Routing changes are normal; nothing here is called an attack.</div>
    </Card>
  )
}

function OutageRanking() {
  const [d] = usePoll(() => api('/api/intel/events?category=outage&kind=country_outage&status=ongoing&limit=100&since_h=0'), 20000)
  if (!d) return null
  const by = {}
  d.events.forEach(e => { const c = e.country; by[c] = by[c] || { name: e.title.split(':')[0], n: 0, high: false, since: e.event_ms }; by[c].n++; by[c].high = by[c].high || e.severity === 'high'; by[c].since = Math.min(by[c].since, e.event_ms) })
  const rows = Object.entries(by).sort((a, b) => b[1].n - a[1].n || a[1].since - b[1].since)
  return (
    <Card title={`Countries with ongoing outage signals (${rows.length})`}>
      <div className="small mut" style={{ marginBottom: 6 }}>Ranked by number of independent IODA signals (BGP, active probing, traffic, telescope). A country ranking, not a map.</div>
      {rows.slice(0, 18).map(([cc, r]) => <div key={cc} className="row small" style={{ marginBottom: 3 }}><b style={{ width: 150 }}>{r.name} ({cc})</b>
        <div style={{ flex: 1 }}><div className="bar"><div style={{ width: Math.min(100, r.n * 34) + '%', background: r.high ? '#ef4444' : '#f5a524' }} /></div></div><span className="mut" style={{ width: 140 }}>{r.n} signal(s) · since {fmtDT(r.since).slice(5, 10)}</span></div>)}
    </Card>
  )
}

function CloudCards({ sources, events }) {
  const prov = ['aws', 'azure', 'cloudflare', 'gcp', 'github']
  return (
    <div className="grid" style={{ gridTemplateColumns: 'repeat(5,1fr)' }}>
      {prov.map(p => { const s = sources.find(x => x.source === p); const act = (events || []).filter(e => e.provider === p && e.status !== 'resolved' && e.status !== 'postmortem').length
        return <Kpi key={p} label={s ? s.name : p} value={act ? `${act} active` : 'none active'} color={act ? '#f5a524' : '#2ecc71'} sub={s ? <><FreshBadge s={s} /> {s.note || ''}</> : ''} /> })}
    </div>
  )
}

export function CorrelationCard({ c, me }) {
  const [open, setOpen] = useState(false)
  const [ai, , reload] = usePoll(() => open ? api(`/api/intel/correlations/${c.id}/ai`) : Promise.resolve(null), 3000, [open, c.id])
  const [msg, setMsg] = useState('')
  const g = c.global_event || {}
  const a = ai?.analysis
  const run = async () => { setMsg(''); try { await api(`/api/intel/correlations/${c.id}/ai`, { method: 'POST' }); reload() } catch (e) { setMsg(e.message) } }
  return (
    <div className="card" style={{ marginBottom: 8 }}>
      <div className="row wrap"><Badge kind={CORR[c.status]}>{c.status}</Badge><Badge kind="neutral">{c.kind}</Badge><b>score {Math.round(c.score)}</b><span className="mut small">{c.confidence} confidence</span><div className="sp" />
        <button className="btn sm" onClick={() => setOpen(!open)}>{open ? 'hide evidence' : 'show evidence'}</button></div>
      <div className="b" style={{ margin: '4px 0' }}>{g.title}</div>
      <div className="small mut">{g.source} · original event {fmtDT(g.event_ms)} · {c.device?.name}{c.incident_id ? ` · incident #${c.incident_id}` : ''} · <a href={g.source_url} target="_blank" rel="noreferrer noopener">source</a></div>
      {open && <div style={{ marginTop: 8 }}>
        <table><thead><tr><th>Matching factor</th><th>Points</th><th>Evidence</th></tr></thead><tbody>
          {c.factors.map((f, i) => <tr key={i}><td><b>{f.factor}</b> {!f.matched && <Badge kind="neutral">not verified</Badge>}</td><td>{f.points}/{f.max}</td><td className="small">{f.detail}</td></tr>)}
          <tr><td><b>Total</b></td><td><b>{Math.round(c.score)}/100</b></td><td className="small mut">confirmed = shared identifier + overlapping time/verified version + local evidence · possible = partial evidence</td></tr></tbody></table>
        <div className="small" style={{ marginTop: 6 }}><b>Claim:</b> {c.claim}. {c.note} <b>Causation is never claimed.</b></div>
        {c.controls && c.controls.their_samples > 0 && <div className="small mut">Control probes (same provider, other endpoints): {c.controls.their_failures}/{c.controls.their_samples} failed.</div>}
        <div className="row" style={{ marginTop: 8 }}>{me.role === 'admin' ? <button className="btn pri sm" disabled={a?.status === 'running' || ai?.ollama?.available === false} onClick={run}>{a ? 'Re-explain with local AI' : 'Explain with local AI'}</button> : <span className="mut small">only admins can run the AI explanation</span>}
          {ai?.ollama?.available === false && <span className="mut small">local AI unavailable: {ai.ollama.reason}</span>}</div>
        {msg && <div className="callout small">{msg}</div>}
        {a?.status === 'running' && <div className="small">⏳ the local model is explaining the computed result…</div>}
        {a && ['error', 'unavailable', 'blocked', 'malformed'].includes(a.status) && <div className="callout small">AI explanation {a.status}: {a.error}</div>}
        {a?.status === 'ready' && a.result && <div className="callout small" style={{ marginTop: 6 }}>
          <b>AI explanation (advisory; the scores above were computed by Python)</b> {a.stale && <Badge kind="warning">stale</Badge>}
          <p style={{ margin: '4px 0' }}>{a.result.summary}</p>
          {a.result.possible_impact && <div><b>Possible impact:</b> {a.result.possible_impact}</div>}
          {a.result.evidence_explanation && <div><b>Evidence:</b> {a.result.evidence_explanation}</div>}
          {a.result.investigation_steps?.length > 0 && <><b>Investigation steps (manual):</b><ol style={{ margin: 0, paddingLeft: 18 }}>{a.result.investigation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></>}
          <div className="mut">cites factors: {(a.result.cited_factors || []).join(', ') || '—'} · model {a.model}</div></div>}
      </div>}
    </div>
  )
}

function MyInfrastructure({ me }) {
  const [f, setF] = useState({ kind: '', status: '' })
  const qs = new URLSearchParams(Object.fromEntries(Object.entries(f).filter(([, v]) => v))).toString()
  const [d, derr] = usePoll(() => api('/api/intel/correlations?limit=60&' + qs), 6000, [qs])
  const [dev] = usePoll(() => api('/api/intel/devices'), 15000)
  const [msg, setMsg] = useState('')
  const run = async () => { try { const r = await api('/api/intel/correlate', { method: 'POST' }); setMsg(`Correlation run: ${r.correlations} match(es), ${r.new_or_changed} new or changed`) } catch (e) { setMsg(e.message) } }
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="callout small"><b>How to read this:</b> every row is a match between a <i>worldwide</i> event and something <i>your devices actually reported</i>. <b>Confirmed</b> = a shared identifier (ASN, region, installed version) + overlapping time or verified version + local evidence. <b>Possible</b> = partial evidence. Events with no matching evidence stay <b>worldwide</b>. No row claims a cause, and none changes an incident's priority.</div>
      <div className="row wrap small"><label className="mut">Type <select value={f.kind} onChange={e => setF({ ...f, kind: e.target.value })}><option value="">all</option><option value="vuln">vulnerability exposure</option><option value="cloud">cloud provider</option><option value="network">network / routing / outage</option></select></label>
        <label className="mut">Status <select value={f.status} onChange={e => setF({ ...f, status: e.target.value })}><option value="">all</option><option value="confirmed">confirmed</option><option value="possible">possible</option></select></label>
        {me.role === 'admin' && <button className="btn sm" onClick={run}>Run correlation now</button>}{msg && <span className="mut">{msg}</span>}</div>
      <Card title={`Events potentially affecting connected devices (${d ? d.total : '…'})`}>
        {!d ? <Wait err={derr} /> : d.correlations.length === 0 ? <div className="mut small">No worldwide event currently matches evidence from your devices. (Devices must report their network and software; cloud checks need their reachability probes.)</div> : d.correlations.map(c => <CorrelationCard key={c.id} c={c} me={me} />)}
      </Card>
      <Card title="What connected devices tell the host (for correlation)">
        <table><thead><tr><th>Device</th><th>Network</th><th>Software inventory</th></tr></thead><tbody>
          {(dev || []).map(x => <tr key={x.collector_id}><td><b>{x.name}</b></td><td className="small">{x.asn ? 'AS' + x.asn : '—'} · {x.country || '—'}</td>
            <td className="small">{x.software.length ? x.software.slice(0, 8).map(s => `${s.vendor}/${s.product} ${s.version}`).join(', ') + (x.software.length > 8 ? ` … (+${x.software.length - 8})` : '') : <span className="mut">not reported</span>}</td></tr>)}</tbody></table>
        <div className="small mut" style={{ marginTop: 6 }}>Only coarse public identifiers: ASN and country (never the IP address) and vendor/product/version of the OS, runtime and a few well-known packages/browsers.</div>
      </Card>
    </div>
  )
}

function Measurements({ sources }) {
  const [d, derr] = usePoll(() => api('/api/intel/events?category=measurement&since_h=1&limit=200&order=event'), 15000)
  if (!d) return <Wait err={derr} />
  const by = {}
  d.events.forEach(e => { by[e.country] = by[e.country] || {}; if (!by[e.country][e.kind] || by[e.country][e.kind].event_ms < e.event_ms) by[e.country][e.kind] = e })
  const cell = e => e ? <span><Badge kind={e.status === 'degraded' ? 'warning' : 'delivered'}>{e.status}</Badge> <span className="small">{e.title.split(': ')[1]}</span></span> : '—'
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="Regional connectivity — latest real RIPE Atlas measurements to k.root-servers.net">
        <table><thead><tr><th>Country</th><th>Ping</th><th>DNS</th><th>Traceroute</th></tr></thead><tbody>
          {Object.entries(by).sort().map(([cc, r]) => <tr key={cc}><td><b>{cc}</b></td><td>{cell(r.ping)}</td><td>{cell(r.dns)}</td><td>{cell(r.traceroute)}</td></tr>)}</tbody></table>
        <div className="small mut" style={{ marginTop: 6 }}>Aggregated from the latest results of public built-in measurements 1001 (ping), 10001 (DNS) and 5001 (traceroute) by up to 12 connected probes per country. 'degraded' appears only when loss, failures or RTT numbers show it.</div>
      </Card>
      <EventTable category="measurement" sources={sources} cols={measCols} defaults={{ since_h: '6' }} noRel />
    </div>
  )
}

export function ExternalIntel({ items, me }) {
  if (!items || !items.length) return null
  return (
    <Card title="Global intelligence related to this incident (does not change its priority)">
      <div className="small mut" style={{ marginBottom: 6 }}>Each item below was matched on evidence from this incident's devices. It shows the source and original timestamp; correlation is not causation.</div>
      {items.map(c => <CorrelationCard key={c.id} c={c} me={me} />)}
    </Card>
  )
}

function OverviewAI({ me }) {
  const [d, , reload] = usePoll(() => api('/api/intel/ai/overview'), 4000)
  const [msg, setMsg] = useState('')
  const a = d?.analysis
  const run = async () => { setMsg(''); try { await api('/api/intel/ai/overview', { method: 'POST' }); reload() } catch (e) { setMsg(e.message) } }
  return (
    <Card title="Local AI summary of global events (advisory)" right={me.role === 'admin' ? <button className="btn pri sm" disabled={a?.status === 'running' || d?.ollama?.available === false} onClick={run}>{a ? 'Re-summarise' : 'Summarise with local AI'}</button> : <span className="mut small">admins only</span>}>
      <div className="small mut">Python counted and matched everything on this page; the local model ({d?.ollama?.model}) only words it. Third-party feed text is treated as untrusted data.</div>
      {d?.ollama?.available === false && <div className="callout small">AI unavailable: {d.ollama.reason}. Everything else on this page is unaffected.</div>}
      {msg && <div className="callout small">{msg}</div>}
      {a?.status === 'running' && <div className="small">⏳ summarising…</div>}
      {a && ['error', 'unavailable', 'blocked', 'malformed'].includes(a.status) && <div className="callout small">AI summary {a.status}: {a.error}</div>}
      {a?.status === 'ready' && a.result && <><p className="small" style={{ margin: '6px 0' }}>{a.result.summary}</p>
        {a.result.what_matters?.length > 0 && <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{a.result.what_matters.map((x, i) => <li key={i}>{x}</li>)}</ul>}
        {a.result.investigation_steps?.length > 0 && <><b className="small">Suggested investigation (manual):</b><ol className="small" style={{ margin: 0, paddingLeft: 18 }}>{a.result.investigation_steps.map((x, i) => <li key={i}>{x}</li>)}</ol></>}
        {a.stale && <Badge kind="warning">stale — data changed since</Badge>}</>}
    </Card>
  )
}

function CloudTab({ sources }) {
  const [d] = usePoll(() => api('/api/intel/events?category=cloud&since_h=0&limit=200'), 15000)
  return <>
    <CloudCards sources={sources} events={d?.events} />
    <EventTable category="cloud" sources={sources} cols={cloudCols} defaults={{ since_h: '720' }} extraFilters={(f, setF) => <label className="small mut">Provider <select value={f.provider || ''} onChange={e => setF({ ...f, provider: e.target.value })}><option value="">all</option>{['aws', 'azure', 'cloudflare', 'gcp', 'github'].map(p => <option key={p}>{p}</option>)}</select></label>} />
    <SourceStrip sources={sources} category="cloud" />
  </>
}

export default function GlobalIntel({ me, param }) {
  const [tab, setTab] = useState(param === 'mine' ? 'mine' : 'overview')
  const [ov, oerr] = usePoll(() => api('/api/intel/overview?hours=24'), 8000)
  if (!ov) return <Wait err={oerr} />
  const sources = ov.sources
  const w = ov.in_window.by_category
  const cl = ov.correlations
  const nconf = Object.entries(cl).filter(([k]) => k.endsWith('/confirmed')).reduce((a, [, v]) => a + v, 0)
  const npos = Object.entries(cl).filter(([k]) => k.endsWith('/possible')).reduce((a, [, v]) => a + v, 0)
  return (
    <div className="col" style={{ gap: 12 }}>
      <Tabs value={tab} onChange={setTab} tabs={[['overview', 'Global overview'], ['mine', `Affects my infrastructure${nconf + npos ? ` (${nconf + npos})` : ''}`], ['cyber', 'Cybersecurity'], ['routing', 'Routing (BGP)'], ['outages', 'Internet outages'], ['cloud', 'Cloud providers'], ['meas', 'Measurements'], ['timeline', 'Event timeline']]} />
      {tab === 'overview' && <>
        <div className="grid g4">
          <Kpi label="Worldwide events (24 h)" value={Object.values(w).reduce((a, b) => a + b, 0)} sub={`${w.cyber || 0} vulns · ${w.cloud || 0} cloud · ${w.outage || 0} outages · ${w.routing || 0} routing · ${w.measurement || 0} measurements`} />
          <Kpi label="May affect our devices" value={ov.relevance.relevant + ov.relevance.correlated} color={ov.relevance.relevant + ov.relevance.correlated ? '#f5a524' : undefined} sub={`${npos} possible · ${nconf} confirmed matches`} />
          <Kpi label="Tied to a local incident" value={ov.relevance.correlated} color={ov.relevance.correlated ? '#ef4444' : undefined} sub="see the incident's detail page" />
          <Kpi label="Sources live" value={`${sources.filter(s => s.freshness === 'live').length}/${sources.length}`} sub={`${ov.exploited_known} known-exploited CVEs tracked (CISA KEV)`} />
        </div>
        <div className="callout small"><b>Three levels, kept separate.</b> <Badge kind="neutral">worldwide</Badge> real events from public feeds, no claim about us · <Badge kind="warning">may affect our devices</Badge> a possible or confirmed match with evidence from a connected device · <Badge kind="critical">tied to a local incident</Badge> the matching device also has an open incident. Feeds are fetched by this server only; every row shows its source and last-updated time.</div>
        <OverviewAI me={me} />
        <SourceStrip sources={sources} />
      </>}
      {tab === 'mine' && <MyInfrastructure me={me} />}
      {tab === 'cyber' && <><EventTable category="cyber" sources={sources} cols={cyberCols} extraFilters={(f, setF) => <label className="small mut"><input type="checkbox" checked={!!f.exploited} onChange={e => setF({ ...f, exploited: e.target.checked ? 1 : '' })} /> known exploited only</label>} /><SourceStrip sources={sources} category="cyber" /></>}
      {tab === 'routing' && <><RisLive /><EventTable category="routing" sources={sources} cols={routeCols} defaults={{ since_h: '24' }} /><SourceStrip sources={sources} category="routing" /></>}
      {tab === 'outages' && <><OutageRanking /><EventTable category="outage" sources={sources} cols={outageCols} defaults={{ since_h: '168', status: 'ongoing' }} extraFilters={(f, setF) => <label className="small mut">Status <select value={f.status} onChange={e => setF({ ...f, status: e.target.value })}><option value="">any</option><option value="ongoing">ongoing</option><option value="ended">ended</option></select></label>} /><SourceStrip sources={sources} category="outage" /></>}
      {tab === 'cloud' && <CloudTab sources={sources} />}
      {tab === 'meas' && <><Measurements sources={sources} /><SourceStrip sources={sources} category="measurement" /></>}
      {tab === 'timeline' && <EventTable category="" sources={sources} cols={[when, { h: 'Category', f: e => <Badge kind="neutral">{e.category}</Badge> }, sevCol, { h: 'Event', cls: 'small', f: e => <b>{e.title.slice(0, 120)}</b> }]} defaults={{ since_h: '24' }} limit={100} />}
    </div>
  )
}
