import { useTranslation } from 'react-i18next'
import { LANGS, setLang } from './i18n'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, auth, usePoll, fmtDT, fmtT, ago, num } from './api'
import { Badge, Card, Json, Kpi, LineChart, PriorityBadge, Sparkline, StateBadge, STATE_COLOR, Tabs, Topology } from './ui'
import { Simulator } from './Collector'
import GlobalIntel, { ExternalIntel } from './Intel'
import { VoiceInput } from './Voice'
import DataFlow, { BeforeAfter } from './DataFlow'
import DepMap from './DepMap'
import JudgePage, { ReliabilityCard } from './Judge'
import { PrivacyStatus, Inventory, RetentionAudit } from './PrivacyCenter'
import { FleetKpis, FlowStrip, DeviceTable, AlertsPage, AlertToasts, AnalyticsPage } from './Platform'
import { RemediationEngine } from './Remediation'

const METRIC_LABEL = { battery_percent: 'Battery %', battery_charging: 'Charging', cpu_percent: 'CPU %', memory_percent: 'Memory %', disk_percent: 'Disk %', latency_ms: 'Latency ms', packet_loss_pct: 'Packet loss %', bandwidth_mbps: 'Bandwidth Mbps', response_ms: 'Response ms', error_rate_pct: 'Error rate %', availability: 'Availability', failed_logins: 'Failed logins / 60s' }
const UNIT = { battery_percent: '%', cpu_percent: '%', memory_percent: '%', disk_percent: '%', latency_ms: 'ms', packet_loss_pct: '%', bandwidth_mbps: 'Mbps', response_ms: 'ms', error_rate_pct: '%', availability: '', failed_logins: '' }
const COLOR = { battery_percent: '#2ecc71', cpu_percent: '#4f8cff', memory_percent: '#c084fc', latency_ms: '#f5a524', packet_loss_pct: '#ef4444', response_ms: '#38bdf8', bandwidth_mbps: '#2ecc71', error_rate_pct: '#fb7185', disk_percent: '#94a3b8', availability: '#2ecc71', failed_logins: '#f97316' }

function Login({ onDone }) {
  const [u, setU] = useState(''), [p, setP] = useState(''), [err, setErr] = useState('')
  const go = async e => {
    e.preventDefault()
    try { const r = await api('/api/login', { method: 'POST', body: { username: u, password: p }, token: null }); auth.set(r.token); onDone() } catch (x) { setErr(x.message) }
  }
  return (
    <div className="login card">
      <div className="brand" style={{ fontSize: 22 }}>SENTINEL <span>X</span><small>Privacy-first AIOps observability · central SaaS</small></div>
      <form className="col" onSubmit={go}>
        <input placeholder="username" value={u} onChange={e => setU(e.target.value)} autoFocus />
        <input placeholder="password" type="password" value={p} onChange={e => setP(e.target.value)} />
        <button className="btn pri">Sign in</button>
        {err && <div className="err">{err}</div>}
      </form>
      <div className="mut small" style={{ marginTop: 14 }}>Demo tenants — <b>acme</b>: acme-admin / Acme#Admin2026 · acme-viewer / Acme#View2026 · <b>globex</b>: globex-admin / Globex#Admin2026</div>
    </div>
  )
}

function MetricChart({ source, metric, seconds = 300, height = 140, title }) {
  const [d] = usePoll(() => api(`/api/series?source_id=${encodeURIComponent(source)}&metric=${metric}&seconds=${seconds}`), 2000, [source, metric, seconds])
  const last = d?.points?.length ? d.points[d.points.length - 1][1] : null
  return (
    <Card title={title || `${source} · ${METRIC_LABEL[metric] || metric}`} right={<span className="mono b">{last != null ? num(last, 1) + ' ' + (UNIT[metric] || '') : '—'}</span>}>
      {d && d.points.length > 1 ? <LineChart points={d.points} band={d.band} alerts={d.alerts} threshold={d.threshold} unit={UNIT[metric]} color={COLOR[metric]} height={height} /> : <div className="mut">waiting for telemetry…</div>}
    </Card>
  )
}

function Overview({ ov, go, ver, live }) {
  const { t } = useTranslation()
  const [secs, setSecs] = useState(300)
  const [alerts] = usePoll(() => api('/api/alerts?limit=40'), 3000, [ver])
  const [pick, setPick] = useState('api-gateway|response_ms')
  if (!ov) return null
  const k = ov.kpis, h = ov.health
  const active = (alerts || []).filter(a => a.cleared_ms == null && a.severity !== 'info')
  const groups = { 'Infrastructure': ov.entities.filter(e => e.type === 'host'), 'Network': ov.entities.filter(e => e.type === 'network'), 'Services': ov.entities.filter(e => e.type === 'service') }
  const opts = ov.entities.flatMap(e => Object.keys(e.metrics).map(m => `${e.id}|${m}`))
  const [ps, pm] = pick.split('|')
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="banner" style={{ borderColor: STATE_COLOR[h.state], background: STATE_COLOR[h.state] + '12' }}>
        <div><div className="mut small">{t('TENANT HEALTH')}</div><div className="big-state" style={{ color: STATE_COLOR[h.state] }}>{h.state}</div></div>
        <div className="sp">
          {h.reasons.length === 0 ? <span className="mut">Collectors reporting; all metrics within expected baselines.</span> :
            h.reasons.map((r, i) => <div key={i} className="small"><StateBadge s={r.state} /> <b>{r.entity}</b> — {r.why}</div>)}
        </div>
        <div className="mut small">Excellent · Good · Fair · Poor<br />reasons are shown; stale data downgrades state</div>
      </div>
      <FleetKpis ov={ov} />
      <FlowStrip ov={ov} go={go} />
      <div className="grid g5">
        <Kpi label="Collectors online" value={`${k.collectors_online}/${k.collectors_total}`} color={k.collectors_online < k.collectors_total ? '#ef4444' : '#2ecc71'} />
        <Kpi label="Open incidents" value={k.open_incidents} color={k.open_incidents ? '#ef4444' : undefined} sub={`${k.active_alerts} active alerts`} />
        <Kpi label="Alert noise reduction" value={k.alerts_1h ? `${k.alerts_1h} → ${k.incidents_1h}` : '—'} sub="raw alerts → incidents (1h)" />
        <Kpi label="Collection → SaaS p95" value={k.ingest_p95_ms != null ? num(k.ingest_p95_ms, 0) + ' ms' : '—'} sub="target ≤ 10 s" color="#2ecc71" />
        <Kpi label="Collection → dashboard p95" value={k.render_p95_ms != null ? num(k.render_p95_ms, 0) + ' ms' : '—'} sub={`${k.events_per_min} events/min · measured at render`} color="#2ecc71" />
      </div>
      <div className="grid g3">
        {Object.entries(groups).map(([g, es]) => (
          <Card key={g} title={g}>
            {es.map(e => (
              <div key={e.id} style={{ padding: '6px 0', borderBottom: '1px solid #1b2745' }} title={e.reasons.join('; ')}>
                <div className="row"><StateBadge s={e.state} /><b>{e.label}</b><div className="sp" /><span className="mut small">{e.metrics && Object.values(e.metrics)[0] ? ago(Object.values(e.metrics)[0].age_s) : ''}</span></div>
                <div className="row wrap small mut" style={{ marginTop: 3 }}>{Object.entries(e.metrics).map(([m, v]) => <span key={m} style={{ color: v.state === 'Poor' ? '#ef4444' : v.state === 'Fair' ? '#f5a524' : undefined }}>{m === 'battery_charging' ? (v.value >= 0.5 ? '⚡ charging' : 'on battery') : <>{(METRIC_LABEL[m] || m).replace(' %', '').replace(' ms', '')} <b>{num(v.value, v.value > 50 ? 0 : 1)}</b></>}</span>)}</div>
                {e.reasons[0] && <div className="small" style={{ color: '#f5a524' }}>{e.reasons[0]}</div>}
              </div>))}
          </Card>))}
      </div>
      <div className="row"><h2 style={{ margin: 0 }}>Live telemetry</h2><div className="sp" />
        <span className="small mut">window</span><select value={secs} onChange={e => setSecs(+e.target.value)}><option value={120}>2 min</option><option value={300}>5 min</option><option value={900}>15 min</option></select>
        <span className="legend small"><span><i style={{ width: 14, height: 8, background: '#4f8cff33', display: 'inline-block' }} /> rolling baseline band</span><span><i style={{ width: 14, height: 8, background: '#ef444433', display: 'inline-block' }} /> anomaly</span><span><i className="dot" style={{ background: '#c084fc', width: 7, height: 7 }} /> out-of-order (placed by event time)</span></span></div>
      <div className="grid g2">
        <MetricChart source="host:app-node" metric="cpu_percent" seconds={secs} />
        <MetricChart source="host:app-node" metric="memory_percent" seconds={secs} />
        <MetricChart source="net:wan-link" metric="latency_ms" seconds={secs} />
        <MetricChart source="net:wan-link" metric="packet_loss_pct" seconds={secs} />
        <MetricChart source="net:wan-link" metric="bandwidth_mbps" seconds={secs} />
        <div className="col"><select value={pick} onChange={e => setPick(e.target.value)}>{opts.map(o => <option key={o} value={o}>{o.replace('|', ' · ')}</option>)}</select><MetricChart source={ps} metric={pm} seconds={secs} /></div>
      </div>
      <Card title="Active alerts" right={<a href="#" onClick={e => { e.preventDefault(); go('incidents') }}>see incidents →</a>}>
        {active.length === 0 ? <div className="mut">No active alerts.</div> : <table><thead><tr><th>Sev</th><th>Alert</th><th>Detected by</th><th>Evidence</th><th>Event time (UTC)</th><th>Incident</th></tr></thead><tbody>
          {active.map(a => <tr key={a.id}><td><Badge kind={a.severity} /></td><td><b>{a.title}</b></td><td className="small">{a.detected_by.join(' + ')}</td><td className="small mut">{a.message}</td><td className="mono small">{fmtT(a.event_ms)}</td><td>{a.incident_id ? <a href="#" onClick={e => { e.preventDefault(); go('incidents', a.incident_id) }}>#{a.incident_id}</a> : ''}</td></tr>)}
        </tbody></table>}
      </Card>
    </div>
  )
}

const PLATFORMS = { windows: ['Windows', '#38bdf8'], macos: ['macOS', '#c084fc'], linux: ['Linux', '#f5a524'], android: ['Android', '#2ecc71'], other: ['Other', '#8da0c4'] }
function PlatformBadge({ p }) {
  const [label, color] = PLATFORMS[p] || ['Unknown', '#8da0c4']
  return <span className="badge" style={{ color, background: color + '18', borderColor: color + '55' }}>{label}</span>
}

/** Device details: descriptor tiles (battery / RAM / storage / network) + charts for every metric the device reports. */
function DeviceDetail({ id, onClose }) {
  const [d] = usePoll(() => api('/api/collectors/' + encodeURIComponent(id)), 2000, [id])
  const [secs, setSecs] = useState(null)
  if (!d) return null
  const c = d.collector
  const m = (metric) => d.metrics.find(x => x.metric === metric)
  const win = secs ?? ((c.interval_s || 0) >= 300 ? 21600 : 300)
  const isPhone = c.platform === 'android'
  const tile = (label, mt, fmt) => <Kpi label={label} value={mt ? fmt(mt.value) : '—'} sub={mt ? `${ago(mt.age_s)} · ${mt.state}` : 'not reported'} color={mt && STATE_COLOR[mt.state]} />
  const bat = m('battery_percent'), chg = m('battery_charging')
  const order = ['battery_percent', 'cpu_percent', 'memory_percent', 'disk_percent', 'bandwidth_mbps', 'latency_ms', 'packet_loss_pct']
  const charts = d.metrics.filter(x => order.includes(x.metric)).sort((a, b) => order.indexOf(a.metric) - order.indexOf(b.metric))
  return (
    <Card title={<span className="row"><PlatformBadge p={c.platform} /> <b>{c.name}</b></span>} right={<button className="btn sm" onClick={onClose}>Close</button>}>
      <div className="row wrap small mut" style={{ marginBottom: 10 }}>
        <span>{c.os_version || '—'}</span>{c.device_model && <span>· model <b style={{ color: '#e6ecf8' }}>{c.device_model}</b></span>}
        <span>· app/collector v{c.version || '—'}</span><span>· last seen {fmtDT(c.last_seen_ms)}</span>
        {c.interval_s ? <span>· syncs every {c.interval_s >= 120 ? Math.round(c.interval_s / 60) + ' min' : c.interval_s + ' s'}</span> : null}
        <StateBadge s={c.state} />
      </div>
      <div className="grid g5">
        {bat || chg ? <Kpi label="Battery" value={bat ? num(bat.value, 0) + '%' : '—'} color={bat && STATE_COLOR[bat.state]}
          sub={chg ? (chg.value >= 0.5 ? '⚡ charging' : 'on battery') : ''} /> : <Kpi label="Battery" value="n/a" sub="no battery reported" />}
        {tile('RAM used', m('memory_percent'), v => num(v, 0) + '%')}
        {tile('Storage used', m('disk_percent'), v => num(v, 0) + '%')}
        {tile('Network traffic', m('bandwidth_mbps'), v => num(v, 2) + ' Mbps')}
        {isPhone ? <Kpi label="CPU" value="n/a" sub="not exposed by Android to apps" /> : tile('CPU', m('cpu_percent'), v => num(v, 0) + '%')}
      </div>
      <div className="row" style={{ margin: '12px 0 6px' }}><h3 style={{ margin: 0 }}>History</h3><div className="sp" />
        <select value={win} onChange={e => setSecs(+e.target.value)}><option value={300}>5 min</option><option value={3600}>1 hour</option><option value={21600}>6 hours</option><option value={86400}>24 hours</option></select></div>
      <div className="grid g2">{charts.map(x => <MetricChart key={x.source_id + x.metric} source={x.source_id} metric={x.metric} seconds={win} height={120} title={`${METRIC_LABEL[x.metric] || x.metric}`} />)}</div>
    </Card>
  )
}

function Fleet({ ver }) {
  const [c] = usePoll(() => api('/api/collectors'), 2000, [ver])
  const [sel, setSel] = useState(null)
  const [perf] = usePoll(() => api('/api/perf'), 5000)
  const [ov] = usePoll(() => api('/api/overview'), 3000, [ver])
  const localTime = (ms, tz) => { try { return new Date(ms).toLocaleTimeString('en-GB', { timeZone: tz }) } catch { return '' } }
  return (
    <div className="col" style={{ gap: 12 }}>
      <DeviceTable ov={ov} selected={sel} onSelect={setSel} />
      <Card title="Collector fleet health">
        <table><thead><tr><th>Collector</th><th>Platform</th><th>State</th><th>Status</th><th>Last seen (UTC)</th><th>Source local time</th><th>Region / tz</th><th>Version</th><th>Collector CPU / mem</th><th>Buffer</th><th>Link</th><th>Config</th><th>Pseudonymous host</th></tr></thead><tbody>
          {(c || []).map(x => <tr key={x.id} className={'click' + (sel === x.id ? ' sel' : '')} onClick={() => setSel(x.id === sel ? null : x.id)}><td><b>{x.name}</b><div className="mut small mono">{x.id}</div></td>
            <td><PlatformBadge p={x.platform} /><div className="mut small">{x.device_model || x.os_version || ''}</div></td>
            <td><StateBadge s={x.state} /><div className="small" style={{ color: '#f5a524' }}>{x.reasons[0]}</div></td><td><Badge kind={x.status === 'online' ? 'delivered' : 'blocked'}>{x.status}</Badge></td>
            <td className="mono small">{fmtDT(x.last_seen_ms)}<div className="mut">{ago(x.age_s)}</div></td><td className="mono small">{localTime(x.last_seen_ms, x.source_tz)}</td><td>{x.region}<div className="mut small">{x.source_tz}</div></td><td>{x.version}</td>
            <td className="small">{num(x.proc_cpu, 1)}% · {num(x.proc_mem_mb, 0)} MB</td><td>{x.buffer_depth ?? '—'}<div className="mut small">oldest {num(x.oldest_pending_s, 0)}s</div></td><td className="small">{x.link_state}</td><td className="small">v{x.config_version}<div className="mut">retention {x.retention_s}s</div></td><td className="mono small">{x.host_id}</td></tr>)}
        </tbody></table>
        <div className="mut small" style={{ marginTop: 6 }}>Click a device for details.</div>
      </Card>
      {sel && <DeviceDetail id={sel} onClose={() => setSel(null)} />}
      <Card title="Outage history — detection latency (target ≤ 60 s from last heartbeat)">
        <table><thead><tr><th>Collector</th><th>Detected (UTC)</th><th>Silent for at detection</th><th>Since outage start</th><th>Recovered</th></tr></thead><tbody>
          {(perf?.offline_detection || []).map((o, i) => <tr key={i}><td>{o.collector_id}</td><td className="mono small">{o.detected_at}</td><td>{num(o.since_last_heartbeat_ms / 1000, 1)} s <Badge kind={o.since_last_heartbeat_ms < 60000 ? 'delivered' : 'blocked'}>{o.since_last_heartbeat_ms < 60000 ? 'PASS' : 'FAIL'}</Badge></td><td>{o.since_outage_start_ms ? num(o.since_outage_start_ms / 1000, 1) + ' s' : '—'}</td><td>{o.recovered ? 'yes' : 'no'}</td></tr>)}
        </tbody></table>
        {!perf?.offline_detection?.length && <div className="mut small">No outages yet. Use Scenario Lab → “Collector disconnection”.</div>}
      </Card>
    </div>
  )
}

function RemCard({ r, admin, refresh }) {
  const [err, setErr] = useState('')
  const act = async (p, body) => { try { setErr(''); await api(p, { method: 'POST', body: body || {} }); refresh && refresh() } catch (e) { setErr(e.message) } }
  return (
    <div className="card" style={{ background: 'var(--panel2)' }}>
      <div className="row wrap"><Badge kind={r.status} /><b>#{r.id} {r.title}</b><div className="sp" /><span className="mut small">proposed by {r.proposed_by} · {fmtDT(r.proposed_ms)}</span></div>
      <div className="small mut" style={{ margin: '4px 0' }}>{r.rationale}</div>
      <details open={r.status === 'proposed' || r.status === 'blocked_by_policy'}><summary>Policy checks ({r.policy.filter(c => c.passed).length}/{r.policy.length} passed)</summary>
        {r.policy.map((c, i) => <div key={i} className="small"><span style={{ color: c.passed ? '#2ecc71' : '#ef4444' }}>{c.passed ? '✓' : '✗'}</span> {c.rule} <span className="mut">{c.detail}</span></div>)}</details>
      <div className="small" style={{ marginTop: 4 }}><b>Rollback plan:</b> {r.rollback_plan}</div>
      {r.approved_by && <div className="small mut">{r.status === 'rejected' ? 'rejected' : 'approved'} by {r.approved_by} at {fmtDT(r.approved_ms)}</div>}
      {r.result && <div className="small"><b>Execution:</b> {r.result.detail} <span className="mut">({fmtDT(r.executed_ms)})</span></div>}
      {r.outcome && <div className="small"><Badge kind={r.outcome.startsWith('effective') ? 'effective' : 'blocked'}>outcome</Badge> {r.outcome}</div>}
      {r.rolled_back_ms && <div className="small mut">rolled back at {fmtDT(r.rolled_back_ms)}</div>}
      <div className="row" style={{ marginTop: 6 }}>
        {r.status === 'proposed' && <><button className="btn pri sm" disabled={!admin} onClick={() => act(`/api/remediation/${r.id}/approve`, { note: 'approved from console' })}>Approve & execute in sandbox</button><button className="btn sm" disabled={!admin} onClick={() => act(`/api/remediation/${r.id}/reject`)}>Reject</button>{!admin && <span className="mut small">admin role required</span>}</>}
        {r.status === 'executed' && <button className="btn dng sm" disabled={!admin} onClick={() => act(`/api/remediation/${r.id}/rollback`)}>Roll back</button>}
        {err && <span className="err small">{err}</span>}
      </div>
    </div>
  )
}

// Local AI investigation (Ollama, on this machine). Everything rendered here is plain text: React escapes model output.
function AiPanel({ id, me }) {
  const [d, err, reload] = usePoll(() => api(`/api/incidents/${id}/ai`), 2500, [id])
  const [msg, setMsg] = useState('')
  const [showCtx, setShowCtx] = useState(false)
  // never sit on "loading…" forever: a failed status request is shown as an error (and keeps retrying in the background)
  if (!d && err) return <Card title="Local AI investigation (advisory)"><div className="callout small">Could not load AI status from the SENTINEL X backend: {String(err.message || err)}. Monitoring and incidents are unaffected. If the backend was started before the AI feature was installed, restart it (python run_host.py). Retrying…</div></Card>
  if (!d) return <Card title="Local AI investigation (advisory)"><div className="mut">loading…</div></Card>
  const a = d.analysis, running = a?.status === 'running', admin = me.role === 'admin'
  const run = async () => { setMsg(''); try { await api(`/api/incidents/${id}/ai`, { method: 'POST' }); reload() } catch (e) { setMsg(e.message) } }
  const label = running ? 'Analysing…' : a ? 'Re-analyse' : 'Analyse with local AI'
  return (
    <Card title="Local AI investigation (advisory)" right={admin
      ? <button className="btn pri sm" disabled={running || !d.ollama.available} onClick={run}>{label}</button>
      : <span className="mut small">only admins can run analysis</span>}>
      <div className="small mut" style={{ marginBottom: 6 }}>Model {d.ollama.model} running locally via Ollama · data never leaves this machine · priority and category above are computed by deterministic rules and are not changed by the AI.</div>
      {!d.ollama.available && <div className="callout small">AI unavailable: {d.ollama.reason}. Monitoring and incidents are unaffected.</div>}
      {msg && <div className="callout small">{msg}</div>}
      {running && <div className="small">⏳ The local model is analysing this incident (a small CPU model can take 10–60 s)…</div>}
      {a && ['error', 'unavailable', 'blocked', 'malformed'].includes(a.status) && <div className="callout small">Analysis {a.status === 'malformed' ? 'rejected (malformed model output)' : 'failed'}: {a.error}</div>}
      {a && a.status === 'ready' && a.result && <>
        {a.stale && <div className="callout small">⚠ Stale: the incident changed after this analysis ran. {admin ? 'Re-analyse to refresh.' : 'Ask an admin to re-analyse.'}</div>}
        <h3>Observed facts (from telemetry and deterministic engine)</h3>
        <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
          {Object.entries(a.signal_map).map(([sid, v]) => { const s = d_signal(a, sid); return <li key={sid}><b>{sid}</b> {v.entity} · {v.metric}{s ? ` — value ${s.value ?? 'n/a'}, baseline ${s.baseline ?? 'n/a'}, z ${s.z_score ?? 'n/a'}, ${s.severity}` : ''}</li> })}
        </ul>
        <h3 style={{ marginTop: 10 }}>AI hypotheses <span className="mut small">(unverified guesses by {a.model})</span></h3>
        <p className="small" style={{ margin: '0 0 6px' }}>{a.result.summary}</p>
        {a.result.hypotheses.map((h, i) => <div key={i} className="small" style={{ marginBottom: 4 }}>• {h.statement} <Badge kind="neutral">model confidence: {h.model_confidence}</Badge> <span className="mut">evidence: {h.evidence_refs.join(', ')}</span></div>)}
        {a.result.investigation_steps.length > 0 && <><h3 style={{ marginTop: 10 }}>Suggested investigation steps</h3><ol className="small" style={{ margin: 0, paddingLeft: 18 }}>{a.result.investigation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></>}
        {a.result.recommendations.length > 0 && <><h3 style={{ marginTop: 10 }}>Suggested actions (manual — nothing is executed)</h3>{a.result.recommendations.map((r, i) => <div key={i} className="small"><b>{r.title}</b> <span className="mut">— {r.rationale}</span></div>)}</>}
        <div className="small mut" style={{ marginTop: 8 }}>Generated {fmtDT(a.finished_ms)} in {Math.round((a.duration_ms || 0) / 1000)} s · requested by {a.requested_by} · context {a.context_hash}</div>
      </>}
      {a && <div style={{ marginTop: 6 }}><a href="#" className="small" onClick={e => { e.preventDefault(); setShowCtx(!showCtx) }}>{showCtx ? 'hide' : 'show'} exactly what the model was given</a>
        {showCtx && <pre className="small" style={{ whiteSpace: 'pre-wrap', maxHeight: 220, overflow: 'auto' }}>{JSON.stringify(a.context_sent, null, 1)}</pre>}</div>}
    </Card>
  )
}
const d_signal = (a, sid) => (a.context_sent?.signals || []).find(s => s.id === sid)

function IncidentDetail({ id, me, ver, goReplay }) {
  const [d, , reload] = usePoll(() => api('/api/incidents/' + id), 2000, [id, ver])
  const [topo] = usePoll(() => api('/api/topology?incident_id=' + id), 3000, [id])
  const [msg, setMsg] = useState('')
  if (!d) return <div className="mut">loading…</div>
  const a = d.analysis, root = a.root, tri = a.triage
  const propose = async (rec) => {
    try { await api(`/api/incidents/${id}/remediation`, { method: 'POST', body: { action: rec.action, target: rec.target } }); setMsg('Proposed — see below. Nothing runs until an admin approves.'); reload() } catch (e) { setMsg(e.message) }
  }
  const lbl = e => topo?.nodes.find(n => n.id === e)?.label || e
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card>
        <div className="row wrap"><PriorityBadge p={d.priority_level} /><Badge kind="neutral">{d.category}</Badge><Badge kind={d.severity} /><Badge kind={d.status === 'open' ? 'warning' : 'resolved'}>{d.status}</Badge><h2 style={{ margin: 0 }}>#{d.id} {d.title}</h2><div className="sp" />
          <button className="btn pri sm" onClick={() => goReplay(d.id)}>▶ Replay in Time Machine</button></div>
        <div className="row wrap small mut" style={{ marginTop: 6 }}><span>opened {fmtDT(d.opened_ms)}</span><span>priority score <b>{d.priority}</b></span><span><b>{d.alert_count}</b> raw alerts merged into this one incident</span>{d.resolved_ms && <span>resolved {fmtDT(d.resolved_ms)}</span>}</div>
      </Card>
      {tri && <Card title={`Classification & priority — ${tri.priority.level}: ${tri.priority.meaning}`}>
        <div className="small" style={{ marginBottom: 6 }}><b>Category: {tri.category}.</b> {tri.category_reason}.</div>
        <table><thead><tr><th>Factor</th><th>Points</th><th>Why</th></tr></thead><tbody>
          {tri.priority.reasons.map(r => <tr key={r.factor}><td><b>{r.factor.replace('_', ' ')}</b></td><td>{r.points ? '+' + r.points : '0'}</td><td className="small">{r.detail}</td></tr>)}
          <tr><td><b>Total</b></td><td><b>{tri.priority.score}</b></td><td className="small mut">P1 ≥ {tri.priority.thresholds.P1} · P2 ≥ {tri.priority.thresholds.P2} · P3 ≥ {tri.priority.thresholds.P3} · else P4</td></tr>
        </tbody></table>
        <div className="small" style={{ marginTop: 6 }}><b>Affected devices:</b> {tri.priority.devices.map(x => `${x.name}${x.platform ? ' (' + x.platform + ')' : ''}`).join(', ') || '—'}</div>
      </Card>}
      <ExternalIntel items={d.external} me={me} />
      <AiPanel id={id} me={me} />
      <div className="grid g2" style={{ gridTemplateColumns: '1.1fr 1fr', alignItems: 'start' }}>
        <Card title="Probable root cause">
          <div className="row"><div style={{ flex: 1 }}><div className="b" style={{ fontSize: 16 }}>{root.cause}</div><div className="mut small">{root.entity} · {root.metric}</div></div>
            <div style={{ width: 150 }}><div className="small mut">Confidence <b style={{ color: '#e6ecf8' }}>{Math.round(root.confidence * 100)}%</b></div><div className="bar"><div style={{ width: root.confidence * 100 + '%', background: root.confidence > .7 ? '#2ecc71' : root.confidence > .5 ? '#f5a524' : '#ef4444' }} /></div></div></div>
          <h3 style={{ marginTop: 12 }}>Reasoning path</h3>
          <ol style={{ margin: 0, paddingLeft: 18 }}>{a.reasoning.map((r, i) => <li key={i} className="small" style={{ marginBottom: 4 }}>{r}</li>)}</ol>
          <h3 style={{ marginTop: 12 }}>Hypothesis ranking (score breakdown)</h3>
          <table><thead><tr><th>Candidate</th><th>Score</th><th>Temporal</th><th>Downstream</th><th>No alerting upstream</th><th>Signal</th></tr></thead><tbody>
            {a.ranking.map((r, i) => <tr key={r.entity} style={{ fontWeight: i === 0 ? 700 : 400 }}><td>{r.label}</td><td>{r.score}</td><td>{r.breakdown.temporal_precedence}</td><td>{r.breakdown.downstream_coverage}</td><td>{r.breakdown.no_alerting_upstream}</td><td>{r.breakdown.signal_strength}</td></tr>)}
          </tbody></table>
        </Card>
        <Card title="Dependency graph — blast radius">
          {topo && <Topology nodes={topo.nodes} edges={topo.edges} height={330} activeIds={new Set(topo.nodes.filter(n => n.role).map(n => n.id))} />}
          <div className="legend small" style={{ marginTop: 4 }}><span><i style={{ width: 12, height: 12, border: '3px solid #ff3b3b', display: 'inline-block', borderRadius: 3 }} /> root cause</span><span><i style={{ width: 12, height: 12, border: '3px solid #ff9f43', display: 'inline-block', borderRadius: 3 }} /> affected</span><span><i style={{ width: 12, height: 12, border: '3px dashed #ffd166', display: 'inline-block', borderRadius: 3 }} /> at risk (downstream)</span></div>
          {a.blast_radius.length > 0 && <div className="small" style={{ marginTop: 6 }}><b>At risk:</b> {a.blast_radius.map(lbl).join(', ')}</div>}
          <div className="small" style={{ marginTop: 4 }}><b>Affected:</b> {a.affected.map(lbl).join(', ') || '—'}</div>
        </Card>
      </div>
      <Card title="Contributing signals (evidence)">
        <table><thead><tr><th>+t</th><th>Entity · metric</th><th>Detection</th><th>Value</th><th>Baseline</th><th>z</th><th>Sev</th><th>Seen by</th><th></th></tr></thead><tbody>
          {a.signals.map(s => <tr key={s.alert_id}><td className="mono">+{s.t_offset_s}s</td><td><b>{s.label}</b> · {s.metric}</td><td className="small">{s.kinds.join(', ')}</td><td>{s.value != null ? num(s.value, 1) : '—'}</td><td>{s.baseline != null ? num(s.baseline, 1) : '—'}</td><td>{s.z_score ?? '—'}</td><td><Badge kind={s.severity} /></td><td className="small">{s.detected_by.join(' + ')}</td><td>{s.cleared ? <Badge kind="resolved">cleared</Badge> : <Badge kind="warning">active</Badge>}</td></tr>)}
        </tbody></table>
      </Card>
      <Card title="Recommended actions (explainable)">
        {a.recommendations.map((r, i) => (
          <div key={i} className="row" style={{ alignItems: 'flex-start', padding: '6px 0', borderBottom: '1px solid #1b2745' }}>
            <div className="sp"><b>{r.title}</b><div className="small mut">Why: {r.rationale}</div><div className="small mut">risk: {r.risk} · reversible: {String(r.reversible)}{r.executable ? ' · sandbox execution after approval' : ' · manual'}</div></div>
            {r.executable && <button className="btn sm" disabled={d.status !== 'open'} onClick={() => propose(r)}>Propose remediation</button>}
          </div>))}
        {msg && <div className="callout small" style={{ marginTop: 8 }}>{msg}</div>}
        {d.remediation.length > 0 && <div className="col" style={{ marginTop: 10 }}>{d.remediation.map(r => <RemCard key={r.id} r={r} admin={me.role === 'admin'} refresh={reload} />)}</div>}
      </Card>
      <Card title="Incident timeline">
        <div className="timeline">{d.timeline.map((t, i) => <div key={i} className="it"><span className="mono small mut">{fmtT(t.event_ms)}</span> <Badge kind="neutral">{t.kind}</Badge> <span className="small">{t.detail}</span></div>)}</div>
      </Card>
    </div>
  )
}

function Incidents({ me, ver, initial, goReplay }) {
  const [list] = usePoll(() => api('/api/incidents'), 2500, [ver])
  const [sel, setSel] = useState(initial)
  useEffect(() => { if (initial) setSel(initial) }, [initial])
  const cur = sel || list?.[0]?.id
  return (
    <div className="grid" style={{ gridTemplateColumns: '330px 1fr', alignItems: 'start' }}>
      <Card title="Incidents (prioritised)" style={{ maxHeight: '80vh', overflow: 'auto' }}>
        {(list || []).length === 0 && <div className="mut">No incidents. Inject a scenario in Scenario Lab.</div>}
        {(list || []).map(i => (
          <div key={i.id} className={'card'} style={{ marginBottom: 8, cursor: 'pointer', borderColor: cur === i.id ? '#4f8cff' : undefined, background: cur === i.id ? '#1c2c52' : undefined }} onClick={() => setSel(i.id)}>
            <div className="row wrap"><PriorityBadge p={i.priority_level} /><Badge kind="neutral">{i.category || 'Infrastructure'}</Badge><Badge kind={i.status === 'open' ? 'warning' : 'resolved'}>{i.status}</Badge><div className="sp" /><span className="mut small">#{i.id}</span></div>
            <div className="b" style={{ margin: '4px 0' }}>{i.title}</div>
            <div className="small mut">{i.alert_count} alerts · {(i.devices || []).length} device(s){(i.devices || []).length ? ': ' + i.devices.map(d => d.name).join(', ') : ''} · conf {Math.round((i.confidence || 0) * 100)}% · score {i.priority}</div>
            <div className="small mut mono">{fmtDT(i.opened_ms)}</div>
          </div>))}
      </Card>
      {cur ? <IncidentDetail key={cur} id={cur} me={me} ver={ver} goReplay={goReplay} /> : <div />}
    </div>
  )
}

function TopologyPage({ ver }) {
  const [t] = usePoll(() => api('/api/topology'), 2000, [ver])
  const [sel, setSel] = useState(null)
  if (!t) return null
  const n = t.nodes.find(x => x.id === sel)
  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr 300px', alignItems: 'start' }}>
      <Card title="Infrastructure dependency graph (arrow = depends on)"><Topology nodes={t.nodes} edges={t.edges} height={420} onSelect={x => setSel(x.id)} selected={sel} />
        <div className="legend small">{Object.entries(STATE_COLOR).map(([k, c]) => <span key={k}><i className="dot" style={{ background: c }} />{k}</span>)}</div></Card>
      <Card title={n ? n.label : 'Select a component'}>
        {n ? <><StateBadge s={n.state} /><div className="mut small" style={{ margin: '6px 0' }}>{n.type} · {n.id}</div>
          {Object.entries(n.metrics).map(([m, v]) => <div key={m} className="row small"><span className="sp">{METRIC_LABEL[m] || m}</span><b>{num(v, 2)}</b></div>)}
          {n.reasons.map((r, i) => <div key={i} className="small" style={{ color: '#f5a524', marginTop: 4 }}>{r}</div>)}</> : <div className="mut small">Click a node. Open an incident to see root cause, affected services and downstream blast radius highlighted on this graph.</div>}
      </Card>
    </div>
  )
}

function Replay({ initial, ver }) {
  const [incs] = usePoll(() => api('/api/incidents'), 5000)
  const [id, setId] = useState(initial)
  const [rp, setRp] = useState(null)
  const [topo, setTopo] = useState(null)
  const [cur, setCur] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(4)
  useEffect(() => { if (!id && incs?.length) setId(incs[0].id) }, [incs])
  useEffect(() => { setId(initial || id) }, [initial])
  useEffect(() => {
    if (!id) return
    Promise.all([api(`/api/incidents/${id}/replay`), api(`/api/topology?incident_id=${id}`)]).then(([r, t]) => { setRp(r); setTopo(t); setCur(r.start_ms); setPlaying(false) })
  }, [id])
  useEffect(() => {
    if (!playing || !rp) return
    const t = setInterval(() => setCur(c => { const n = c + speed * 100; if (n >= rp.end_ms) { setPlaying(false); return rp.end_ms } return n }), 100)
    return () => clearInterval(t)
  }, [playing, rp, speed])
  const view = useMemo(() => {
    if (!rp || !topo) return null
    const active = {}
    rp.alerts.forEach(a => { if (a.event_ms <= cur && (!a.resolved || cur <= a.end_ms)) active[a.source_id] = a.severity === 'critical' ? 'Poor' : (active[a.source_id] === 'Poor' ? 'Poor' : 'Fair') })
    const hyp = [...rp.timeline].filter(t => t.snapshot && t.event_ms <= cur).pop()
    const roles = {}
    if (hyp) { roles[hyp.snapshot.root.entity] = 'root'; (hyp.snapshot.affected || []).forEach(e => (roles[e] = roles[e] || 'affected')) }
    const nodes = topo.nodes.map(n => ({ ...n, role: roles[n.id] || null }))
    const keys = [...new Set([...rp.alerts.map(a => `${a.source_id}|${a.metric}`).filter(k => rp.series[k]), ...Object.keys(rp.series)])].slice(0, 6)
    return { active, hyp, nodes, keys, events: rp.timeline.filter(t => t.event_ms <= cur).slice(-12).reverse() }
  }, [rp, topo, cur])
  const dur = rp ? (rp.end_ms - rp.start_ms) : 1
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="Incident Time Machine — replays actual stored telemetry in event-time order">
        <div className="row wrap">
          <select value={id || ''} onChange={e => setId(+e.target.value)}>{(incs || []).map(i => <option key={i.id} value={i.id}>#{i.id} {i.title}</option>)}</select>
          <button className="btn pri sm" onClick={() => { if (cur >= rp.end_ms) setCur(rp.start_ms); setPlaying(!playing) }} disabled={!rp}>{playing ? '❚❚ Pause' : '▶ Play'}</button>
          <button className="btn sm" onClick={() => { setCur(rp.start_ms); setPlaying(false) }} disabled={!rp}>⟲ Restart</button>
          <select value={speed} onChange={e => setSpeed(+e.target.value)}>{[1, 2, 4, 8, 16].map(s => <option key={s} value={s}>{s}×</option>)}</select>
          <span className="mono">{rp ? fmtDT(cur) : ''}</span><span className="mut small">+{rp ? Math.round((cur - rp.start_ms) / 1000) : 0}s of {Math.round(dur / 1000)}s</span>
        </div>
        {rp && <input type="range" style={{ width: '100%', marginTop: 8 }} min={rp.start_ms} max={rp.end_ms} value={cur} onChange={e => { setCur(+e.target.value); setPlaying(false) }} />}
      </Card>
      {!rp && <div className="mut">Select an incident (inject a scenario first).</div>}
      {view && <>
        <div className="grid g2" style={{ gridTemplateColumns: '1.2fr 1fr', alignItems: 'start' }}>
          <Card title="System state at cursor"><Topology nodes={view.nodes} edges={topo.edges} height={340} stateOf={n => view.active[n.id] || 'Excellent'} activeIds={new Set(Object.keys(view.active))} /></Card>
          <div className="col">
            <Card title="Hypothesis at this moment">{view.hyp ? <><div className="b">{view.hyp.snapshot.root.cause}</div><div className="small mut">confidence {Math.round(view.hyp.snapshot.root.confidence * 100)}% · {view.hyp.snapshot.n_alerts} alerts correlated so far</div></> : <div className="mut small">no alert yet — incident has not started</div>}</Card>
            <Card title="Events up to cursor"><div className="timeline" style={{ maxHeight: 250, overflow: 'auto' }}>{view.events.map((t, i) => <div className="it" key={i}><span className="mono small mut">{fmtT(t.event_ms)}</span> <Badge kind="neutral">{t.kind}</Badge> <span className="small">{t.detail}</span></div>)}{view.events.length === 0 && <div className="mut small">—</div>}</div></Card>
          </div>
        </div>
        <div className="grid g2">{view.keys.map(k => {
          const [s, m] = k.split('|')
          return <Card key={k} title={`${s} · ${METRIC_LABEL[m] || m}`}><LineChart points={rp.series[k].filter(p => p[0] <= cur)} alerts={rp.alerts.filter(a => `${a.source_id}|${a.metric}` === k).map(a => ({ id: a.id, severity: a.severity, event_ms: a.event_ms, end_ms: a.end_ms }))} xDomain={[rp.start_ms, rp.end_ms]} cursor={cur} unit={UNIT[m]} color={COLOR[m]} height={120} /></Card>
        })}</div>
      </>}
    </div>
  )
}

function LegacyRemediation({ me, ver }) {
  const [list, , reload] = usePoll(() => api('/api/remediation'), 2000, [ver])
  const [audit] = usePoll(() => api('/api/audit?limit=60'), 3000, [ver])
  return (
    <div className="grid" style={{ gridTemplateColumns: '1.3fr 1fr', alignItems: 'start' }}>
      <Card title="Controlled remediation — policy-checked, human-approved, sandbox-executed, reversible">
        <div className="col">{(list || []).length === 0 && <div className="mut">Open an incident and propose a recommended action.</div>}{(list || []).map(r => <RemCard key={r.id} r={r} admin={me.role === 'admin'} refresh={reload} />)}</div>
      </Card>
      <Card title="Audit trail">
        <table><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th></tr></thead><tbody>{(audit || []).map(a => <tr key={a.id}><td className="mono small">{fmtT(a.ts_ms)}</td><td className="small">{a.actor}</td><td className="small"><b>{a.action}</b><div className="mut">{a.detail}</div></td></tr>)}</tbody></table>
      </Card>
    </div>
  )
}

function RemediationPage({ me, ver }) {
  const [t, setT] = useState('engine')
  return (
    <div className="col" style={{ gap: 12 }}>
      <Tabs value={t} onChange={setT} tabs={[['engine', 'AI remediation engine'], ['proposals', 'Incident proposals (simulated sandbox) & audit trail']]} />
      {t === 'engine' ? <RemediationEngine me={me} ver={ver} /> : <LegacyRemediation me={me} ver={ver} />}
    </div>
  )
}

function Inspector({ ver }) {
  const [led] = usePoll(() => api('/api/ledger?limit=60'), 2000, [ver])
  const [rej] = usePoll(() => api('/api/rejections'), 4000)
  const [sel, setSel] = useState(null)
  const cur = sel || led?.[0]?.payload_id
  const [d] = usePoll(() => (cur ? api('/api/ledger/' + cur) : Promise.resolve(null)), 3000, [cur])
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="callout small"><b>What the SaaS actually received.</b> Compare a payload ID here with the collector’s Egress Proof Panel: same payload ID, same SHA-256, same fields. Nothing else exists in this tenant’s store.</div>
      <div className="grid" style={{ gridTemplateColumns: '420px 1fr', alignItems: 'start' }}>
        <Card title="Received payload ledger" style={{ maxHeight: '60vh', overflow: 'auto' }}>
          <table><thead><tr><th>Seq</th><th>Received (UTC)</th><th>Ev</th><th>Dup ev</th></tr></thead><tbody>{(led || []).map(p => <tr key={p.payload_id} className={'click' + (cur === p.payload_id ? ' sel' : '')} onClick={() => setSel(p.payload_id)}><td className="mono">{p.seq}</td><td className="mono small">{fmtT(p.received_ms)}<div className="mut" style={{ fontSize: 10 }}>{p.payload_id.slice(0, 13)}…</div></td><td>{p.event_count}</td><td>{p.dup_events}</td></tr>)}</tbody></table>
        </Card>
        <Card title="Payload as stored (allow-listed fields only)">{d ? <><div className="mono small">id {d.payload.payload_id}</div><div className="mono small">sha256 {d.payload.sha256}</div>
          <div className="pane" style={{ marginTop: 8, maxHeight: 420 }}><table><thead><tr><th>Type</th><th>Source</th><th>Metric</th><th>Value</th><th>Event time (UTC)</th><th>tz</th><th>Context</th></tr></thead><tbody>
            {d.events.map(e => <tr key={e.event_id}><td>{e.type}</td><td>{e.source_id}</td><td>{e.metric}</td><td>{e.value}</td><td className="mono small">{e.event_time}</td><td className="small">{e.source_tz}</td><td className="small mono mut">{JSON.stringify(e.context)}</td></tr>)}</tbody></table></div></> : <div className="mut">—</div>}</Card>
      </div>
      <Card title="Payloads rejected / ignored by the SaaS">
        <table><thead><tr><th>Time (UTC)</th><th>Collector</th><th>Payload</th><th>Reason</th></tr></thead><tbody>{(rej || []).map(r => <tr key={r.id}><td className="mono small">{fmtT(r.ts_ms)}</td><td className="small">{r.collector_id}</td><td className="mono small">{(r.payload_id || '').slice(0, 13)}</td><td className="small">{r.reason}</td></tr>)}</tbody></table>
        {!rej?.length && <div className="mut small">none yet</div>}
      </Card>
    </div>
  )
}

function Perf({ ver }) {
  const [p] = usePoll(() => api('/api/perf'), 3000, [ver])
  if (!p) return null
  const T = p.targets
  const pass = (v, t) => v == null ? <Badge kind="neutral">n/a</Badge> : <Badge kind={v <= t ? 'delivered' : 'blocked'}>{v <= t ? 'PASS' : 'FAIL'}</Badge>
  return (
    <div className="col" style={{ gap: 12 }}>
      <ReliabilityCard />
      <div className="callout small">All numbers are <b>measured</b> from event timestamps stamped at collection and the clocks of the receiving tiers / the browser render — not claimed.</div>
      <div className="grid g4">
        <Kpi label="Collection → SaaS p50 / p95" value={`${num(p.ingest.p50, 0)} / ${num(p.ingest.p95, 0)} ms`} sub={`n=${p.ingest.live_n} live events · max ${num(p.ingest.max, 0)} ms`} />
        <Kpi label="Collection → dashboard render p95" value={`${num(p.render.p95, 0)} ms`} sub={`target ≤ ${T.collection_to_dashboard_p95_ms / 1000}s · n=${p.render.n}`} color="#2ecc71" />
        <Kpi label="Backlog (delayed) events" value={p.ingest.delayed_backlog_n} sub="delivered after an outage; excluded from live p95" />
        <Kpi label="Render p50 / max" value={`${num(p.render.p50, 0)} / ${num(p.render.max, 0)} ms`} sub="browser paint measured" />
      </div>
      <div className="row small"><b>Dashboard render target (p95 ≤ 10 s):</b> {pass(p.render.p95, T.collection_to_dashboard_p95_ms)} <b style={{ marginLeft: 16 }}>Ingest p95:</b> {pass(p.ingest.p95, T.collection_to_dashboard_p95_ms)}</div>
      <Card title="Threshold breach → alert raised (target ≤ 15 s)">
        <table><thead><tr><th>Injected scenario</th><th>Injected (UTC)</th><th>First alert after</th><th>Alert</th><th></th></tr></thead><tbody>
          {p.alert_latency.map((a, i) => <tr key={i}><td><b>{a.scenario}</b></td><td className="mono small">{a.injected_at}</td><td>{a.alert_after_ms != null ? num(a.alert_after_ms / 1000, 1) + ' s' : '—'}</td><td className="small">{a.alert || <span className="mut">no alert expected / raised</span>}</td><td>{a.alert_after_ms != null && pass(a.alert_after_ms, T.alert_ms)}</td></tr>)}
        </tbody></table>
      </Card>
      <Card title="Delivery reliability — zero loss / zero duplicates">
        <table><thead><tr><th>Collector</th><th>Payloads</th><th>Seq range</th><th>Missing seq</th><th>Seq gaps</th><th>Duplicates ignored</th><th>Rejected (allow-list)</th><th>Events</th><th>Out-of-order events</th></tr></thead><tbody>
          {p.delivery.map(d => <tr key={d.collector_id}><td>{d.name}</td><td>{d.payloads}</td><td>{d.first_seq}–{d.last_seq}</td><td>{d.missing_seq.length ? d.missing_seq.join(',') : <Badge kind="delivered">none</Badge>}</td><td>{d.seq_gaps}</td><td>{d.duplicates_ignored}</td><td>{d.rejected_by_allowlist}</td><td>{d.events}</td><td>{d.out_of_order_events}</td></tr>)}
        </tbody></table>
      </Card>
    </div>
  )
}

function Settings({ me }) {
  const [t, , reload] = usePoll(() => api('/api/thresholds'), 10000)
  const [hist] = usePoll(() => api('/api/history?limit=80'), 3000)
  const [edit, setEdit] = useState({})
  const [msg, setMsg] = useState('')
  if (!t) return null
  const admin = me.role === 'admin'
  const val = (m, k) => edit[m]?.[k] ?? t.thresholds[m][k]
  const save = async () => {
    try { await api('/api/thresholds', { method: 'PUT', body: { thresholds: edit, settings: edit.__s } }); setEdit({}); setMsg('Saved and audited.'); reload() } catch (e) { setMsg(e.message) }
  }
  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', alignItems: 'start' }}>
      <div className="col">
        <Card title="Health thresholds (configurable per tenant)" right={<button className="btn pri sm" disabled={!admin || !Object.keys(edit).length} onClick={save}>Save</button>}>
          <div className="small mut" style={{ marginBottom: 6 }}>Excellent &lt; good-max ≤ Good &lt; warn ≤ Fair &lt; critical ≤ Poor. Anomaly detection against rolling baselines runs in addition to these limits.</div>
          <table><thead><tr><th>Metric</th><th>Good max</th><th>Warn (Fair)</th><th>Critical (Poor)</th></tr></thead><tbody>
            {Object.keys(t.thresholds).map(m => <tr key={m}><td>{METRIC_LABEL[m] || m}</td>{['good_max', 'warn', 'crit'].map(k => <td key={k}><input style={{ width: 70 }} disabled={!admin} value={val(m, k)} onChange={e => setEdit({ ...edit, [m]: { good_max: val(m, 'good_max'), warn: val(m, 'warn'), crit: val(m, 'crit'), [k]: e.target.value } })} /></td>)}</tr>)}
          </tbody></table><div className="mut small" style={{ marginTop: 6 }}>Battery is lower-is-worse: Good ≤ good-max, Fair ≤ warn, Poor ≤ critical (ignored while charging).</div>{msg && <div className="callout small" style={{ marginTop: 8 }}>{msg}</div>}{!admin && <div className="mut small">viewer role: read-only</div>}
        </Card>
        <Card title="Timing & correlation settings">
          {Object.entries(t.settings).map(([k, v]) => <div key={k} className="row" style={{ marginBottom: 4 }}><span className="sp small">{k}</span><input style={{ width: 80 }} disabled={!admin} defaultValue={v} onBlur={e => { if (+e.target.value !== v) api('/api/thresholds', { method: 'PUT', body: { settings: { [k]: +e.target.value } } }).then(reload) }} /></div>)}
          <div className="mut small">stale_after_s → Fair · offline_after_s → Poor (collector offline)</div>
        </Card>
      </div>
      <Card title="Health state-change history (UTC)" style={{ maxHeight: '80vh', overflow: 'auto' }}>
        <table><thead><tr><th>Time (UTC)</th><th>Entity</th><th>Change</th><th>Reason</th></tr></thead><tbody>
          {(hist || []).map(h => <tr key={h.id}><td className="mono small">{h.ts?.slice(11, 23)}Z</td><td className="small">{h.entity_id}</td><td><StateBadge s={h.new_state} /> <span className="mut small">from {h.old_state}</span></td><td className="small">{h.reasons}</td></tr>)}
        </tbody></table>
      </Card>
    </div>
  )
}

// Ask SENTINEL X: read-only Q&A answered by the local Ollama model from this tenant's own data. All model output is plain text.
const SUGGEST = ['What are the highest priority incidents right now?', 'Which devices are offline?', 'Which devices have low battery?', 'Are there any security incidents?', 'Summarise the current situation']
function Ask() {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const [hist, setHist] = useState([])
  const [open, setOpen] = useState(null)
  const send = async (text) => {
    const question = (text ?? q).trim()
    if (!question || busy) return
    setBusy(true)
    try {
      const r = await api('/api/ask', { method: 'POST', body: { question } })
      setHist(h => [{ question, r }, ...h]); setQ('')
    } catch (e) { setHist(h => [{ question, err: e.message }, ...h]) }
    setBusy(false)
  }
  return (
    <div className="col" style={{ gap: 12, maxWidth: 900 }}>
      <Card title="Ask SENTINEL X (local AI · read-only)">
        <div className="small mut" style={{ marginBottom: 8 }}>Answers come from your own incidents, alerts and device data, written by the local model {hist[0]?.r?.model || 'qwen2.5:1.5b'} on this machine. Device names are replaced by placeholders before the model sees anything. Nothing is executed and priorities are never changed.</div>
        <div className="row wrap">
          <input style={{ flex: 1, minWidth: 200 }} maxLength={300} placeholder="e.g. Why is Demo-Laptop in trouble? / Show incident #22" value={q} disabled={busy}
            onChange={e => setQ(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') send() }} />
          <VoiceInput value={q} setValue={setQ} disabled={busy} />
          <button className="btn pri" disabled={busy || !q.trim()} onClick={() => send()}>{busy ? t('Thinking…') : t('Ask')}</button>
        </div>
        <div className="row wrap" style={{ marginTop: 8 }}>{SUGGEST.map(x => <button key={x} className="btn sm" disabled={busy} onClick={() => send(x)}>{t(x)}</button>)}</div>
        {busy && <div className="small" style={{ marginTop: 8 }}>⏳ Looking up your data and asking the local model (can take 10–60 s on CPU)…</div>}
      </Card>
      {hist.map((h, i) => (
        <Card key={i} title={`Q: ${h.question}`}>
          {h.err && <div className="callout small">Could not ask: {h.err}</div>}
          {h.r && <>
            <h3>{t('AI answer')} <span className="mut small">(advisory, written by {h.r.model})</span></h3>
            {h.r.answer
              ? <><p className="small" style={{ margin: '0 0 6px', whiteSpace: 'pre-wrap' }}>{h.r.answer}</p>
                {h.r.enough_data === false && <Badge kind="warning">model says the data is insufficient</Badge>}
                {h.r.sources.length > 0 && <div className="small mut">sources: {h.r.sources.join(' · ')}</div>}</>
              : <div className="callout small">{h.r.status === 'nodata' ? h.r.error : `AI answer unavailable (${h.r.status}): ${h.r.error}. The observed data below is still correct.`}</div>}
            <h3 style={{ marginTop: 10 }}>Observed data used <span className="mut small">({h.r.topics.join(', ')})</span></h3>
            <ul className="small mono" style={{ margin: 0, paddingLeft: 18, maxHeight: 180, overflow: 'auto' }}>{h.r.facts.map(f => <li key={f.id} style={{ wordBreak: 'break-all' }}><b>{f.id}</b> {f.text}</li>)}</ul>
            {h.r.question_sent && <div style={{ marginTop: 6 }}><a href="#" className="small" onClick={e => { e.preventDefault(); setOpen(open === i ? null : i) }}>{open === i ? 'hide' : 'show'} the question text the model received</a>
              {open === i && <pre className="small" style={{ whiteSpace: 'pre-wrap' }}>{h.r.question_sent}</pre>}</div>}
            <div className="small mut" style={{ marginTop: 4 }}>{Math.round((h.r.duration_ms || 0) / 1000)} s</div>
          </>}
        </Card>))}
    </div>
  )
}

// Cloud - Local Anonymisation. The host never sees raw identifiers: this page shows what collectors declare, a BEFORE/AFTER sample
// produced by the same anonymiser the collectors run, the exact payload shape that leaves a laptop, and what the host actually received.
const Fld = ({ k, v }) => <div className="small" style={{ display: 'flex', gap: 8 }}><span className="mut" style={{ minWidth: 112 }}>{k}</span><span className="mono" style={{ wordBreak: 'break-all' }}>{String(v)}</span></div>
const ANON_BADGE = { enabled: 'delivered', disabled: 'blocked', 'not declared': 'warning' }

function Cloud() {
  const [d] = usePoll(() => api('/api/cloud'), 4000)
  const [f, setF] = useState({ device_name: 'Rahul-Laptop', username: 'Rahul', laptop_id: 'LAP-104', ip: '192.168.1.15', cpu: '95', error: 'Server timeout' })
  const [pv, setPv] = useState(null)
  const [coll, setColl] = useState('')
  const [view, setView] = useState('sample')
  useEffect(() => { const t = setTimeout(() => api('/api/cloud/preview?' + new URLSearchParams(f).toString()).then(setPv).catch(() => { }), 250); return () => clearTimeout(t) }, [f])
  const [lp] = usePoll(() => api('/api/cloud/last-payload' + (coll ? '?collector_id=' + encodeURIComponent(coll) : '')), 5000, [coll])
  if (!d) return <div className="mut">loading…</div>
  const T = d.transport
  const ctxMsg = e => e?.context?.message
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g4">
        <Kpi label="Anonymisation" value={d.status} color={d.status === 'Enabled' ? '#2ecc71' : d.status === 'Disabled' ? '#ef4444' : '#f5a524'} sub={`${d.collectors_enabled}/${d.collectors_total} collectors declare it`} />
        <Kpi label="Telemetry records processed" value={d.totals.records} sub="on the laptops, before sending" />
        <Kpi label="Identifying fields removed" value={d.totals.removed} sub="usernames, IPs, IDs, raw samples…" />
        <Kpi label="Fields pseudonymised" value={d.totals.pseudonymised} sub="device names/IDs → Device-NN" />
      </div>
      <div className="callout small">Anonymisation runs <b>on each laptop</b>, before the outgoing queue. The mapping from real names to pseudonyms stays on that laptop and is never sent. This is <b>pseudonymisation</b>, not perfect anonymity: a device keeps the same pseudonym over time. Host policy: <b>{d.policy.mode}</b>.</div>

      <Card title="BEFORE vs AFTER (sample data, same code the collectors run)">
        <div className="row wrap small" style={{ marginBottom: 8 }}>{[['device_name', 'Device name'], ['username', 'Username'], ['laptop_id', 'Laptop ID'], ['ip', 'IP address'], ['cpu', 'CPU %'], ['error', 'Error']].map(([k, l]) => (
          <label key={k} className="small mut">{l} <input style={{ width: k === 'error' ? 150 : 110 }} value={f[k]} onChange={e => setF({ ...f, [k]: e.target.value })} /></label>))}</div>
        {pv && <div className="grid g2">
          <div><h3>BEFORE (stays on the laptop)</h3>
            <Fld k="Username" v={pv.sample.username} /><Fld k="Laptop ID" v={pv.sample.laptop_id} /><Fld k="Device name" v={pv.sample.device_name} /><Fld k="IP address" v={pv.sample.ip} />
            <Fld k="CPU usage" v={pv.sample.cpu + '%'} /><Fld k="Error" v={pv.sample.error} /></div>
          <div><h3>AFTER (what leaves the laptop)</h3>
            <Fld k="Device ID" v={pv.alias} /><Fld k="CPU usage" v={pv.after.value + '%'} /><Fld k="Error" v={ctxMsg(pv.after)} />
            <div className="small mut" style={{ marginTop: 6 }}>{pv.removed} identifying item(s) removed · {pv.pseudonymised} replaced by the pseudonym · no username, laptop ID or IP remains.</div></div>
        </div>}
      </Card>

      <Card title="Egress preview — the exact payload" right={<div className="row"><Tabs value={view} onChange={setView} tabs={[['sample', 'Sample payload'], ['real', 'Last payload this host received']]} /></div>}>
        {view === 'sample' && pv && <><div className="small mut" style={{ marginBottom: 6 }}>Exactly the structure and anonymised content a collector queues and transmits for the sample above.</div><Json v={pv.payload} /></>}
        {view === 'real' && <>
          <div className="row small" style={{ marginBottom: 6 }}><span className="mut">Collector</span>
            <select value={coll} onChange={e => setColl(e.target.value)}><option value="">most recent</option>{d.fleet.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
            {lp?.policy_findings && <Badge kind={lp.policy_findings.length ? 'blocked' : 'delivered'}>{lp.policy_findings.length ? 'policy findings: ' + lp.policy_findings.join(', ') : 'passes the outgoing-data policy'}</Badge>}</div>
          {lp?.payload ? <div style={{ maxHeight: 340, overflow: 'auto' }}><Json v={lp.payload} /></div> : <div className="mut">No payload received yet.</div>}
          <div className="small mut" style={{ marginTop: 6 }}>For the true BEFORE (raw) view of one laptop, open that laptop's local console → Local Anonymisation tab: raw data never reaches this host.</div></>}
      </Card>

      <div className="grid g2">
        <Card title="Retained">{<ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{d.retained.map(x => <li key={x}>{x}</li>)}</ul>}</Card>
        <Card title="Removed or pseudonymised before sending">{<ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{d.removed.map(x => <li key={x}>{x}</li>)}</ul>}</Card>
      </div>
      <Card title="Limitations (stated plainly)"><ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{d.caveats.map(x => <li key={x}>{x}</li>)}</ul></Card>

      <Card title="Collectors">
        <table><thead><tr><th>Device (as the host knows it)</th><th>Platform</th><th>Status</th><th>Anonymisation</th><th>Records</th><th>Removed</th><th>Pseudonymised</th><th></th></tr></thead><tbody>
          {d.fleet.map(c => <tr key={c.id}><td><b>{c.name}</b></td><td>{c.platform || '—'}</td><td><Badge kind={c.status === 'online' ? 'delivered' : 'blocked'}>{c.status}</Badge></td>
            <td><Badge kind={ANON_BADGE[c.anonymisation]}>{c.anonymisation}</Badge></td><td>{c.records}</td><td>{c.removed}</td><td>{c.pseudonymised}</td>
            <td>{c.identity_exposed_at_enrolment && <Badge kind="warning">enrolled under real name — re-enrol</Badge>}</td></tr>)}
        </tbody></table>
      </Card>

      <Card title="Policy violations (codes only — never the offending value)">
        {d.violations.length === 0 ? <div className="mut small">None recorded. Rejected always: {d.policy.always_rejected.join('; ')}. Flagged: {d.policy.flagged.join('; ')}.</div> :
          <table><thead><tr><th>Collector</th><th>Action</th><th>Code</th><th>Field</th><th>Count</th><th>Last</th></tr></thead><tbody>
            {d.violations.map((v, i) => <tr key={i}><td>{v.collector}</td><td><Badge kind={v.level === 'reject' ? 'blocked' : 'warning'}>{v.level === 'reject' ? 'rejected' : 'flagged'}</Badge></td><td className="mono small">{v.code}</td><td className="mono small">{v.field}</td><td>{v.count}</td><td className="mono small">{fmtDT(v.last_ms)}</td></tr>)}</tbody></table>}
      </Card>

      <Card title="Transport security (what is and is not encrypted)">
        <div className="small" style={{ lineHeight: 1.6 }}>
          <div><b>Collector → host:</b> {T.collector_to_host}</div>
          <div style={{ marginTop: 6 }}><b>Direct/local path:</b> {T.direct_local.description} Server certificate valid for <b>{T.direct_local.tls.server_days_left ?? '?'}</b> more days, CA for <b>{T.direct_local.tls.ca_days_left ?? '?'}</b> days. CA fingerprint (SHA-256): <span className="mono" style={{ wordBreak: 'break-all' }}>{T.direct_local.tls.ca_fingerprint_sha256 || '—'}</span></div>
          <div style={{ marginTop: 6 }}><b>Via ngrok:</b> <span className="mut">(only when the ingest listener is tunnelled)</span>
            <ul style={{ margin: '2px 0 0', paddingLeft: 18 }}><li>Collector ↔ ngrok: {T.via_ngrok.collector_to_ngrok}</li><li>ngrok ↔ this host: {T.via_ngrok.ngrok_to_host}</li>
              <li><b>End-to-end TLS: {T.via_ngrok.end_to_end_tls ? 'yes' : 'NO'}.</b> {T.via_ngrok.note}</li></ul></div>
          <div style={{ marginTop: 6 }}><b>Dashboard:</b> {T.dashboard} <b>Ollama:</b> {T.ollama} Public enrollment: {T.public_enrollment_enabled ? 'enabled (join code set)' : 'disabled'}.</div>
        </div>
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------------------------------------------------------------------
// Privacy & Security: ONE place for fleet/per-device anonymisation, firewall events, TLS status and egress proof.
// Everything here comes from data the HOST already holds (heartbeat counters, accepted anonymised payloads, violation codes).
// Raw originals, usernames, private IPs, MACs, original hostnames and the pseudonym mapping never reach this dashboard.
const secAgo = ms => (ms ? ago((Date.now() - ms) / 1000) : '—')
const Yes = ({ v, yes = 'yes', no = 'no', unknown = 'not reported' }) => v == null ? <Badge kind="warning">{unknown}</Badge> : <Badge kind={v ? 'delivered' : 'blocked'}>{v ? yes : no}</Badge>
const chips = o => Object.entries(o || {}).filter(([, v]) => v).map(([k, v]) => <Badge key={k} kind="neutral">{k.replace('_', ' ')}: {v}</Badge>)

function PrivacySecurity({ param, go, me }) {
  const [tab, setTab] = useState(param ? 'devices' : 'overview')
  const [sel, setSel] = useState(param || null)
  const [ov] = usePoll(() => api('/api/privacy/overview'), 4000)
  const [tlsInfo] = usePoll(() => api('/api/tls/status'), 30000)
  useEffect(() => { if (param) { setSel(param); setTab('devices') } }, [param])
  if (!ov) return <div className="mut">loading…</div>
  const open = id => { setSel(id); setTab('devices') }
  const cur = sel || ov.devices.find(d => d.status === 'online')?.id || ov.devices[0]?.id
  const fw = ov.firewall_totals, tl = ov.tls_totals
  return (
    <div className="col" style={{ gap: 12 }}>
      <PrivacyStatus ov={ov} tls={tlsInfo} />
      <Tabs value={tab} onChange={setTab} tabs={[['overview', 'Fleet overview'], ['inventory', 'Data inventory'], ['ba', 'Before / after'], ['flow', 'Data flow'], ['retention', 'Retention, audit & deletion'], ['devices', 'Device privacy details'], ['egress', 'Egress proof'], ['firewall', 'Privacy firewall events'], ['tls', 'TLS & transport'], ['guide', 'Anonymisation guide']]} />
      {tab === 'overview' && <>
        <div className="grid g4">
          <Kpi label="Fleet anonymisation" value={ov.status} color={ov.status === 'Enabled' ? '#2ecc71' : ov.status === 'Disabled' ? '#ef4444' : '#f5a524'} sub={`${ov.collectors_enabled}/${ov.collectors_total} devices declare it`} />
          <Kpi label="Records processed" value={ov.totals.records} sub="anonymised on the laptops" />
          <Kpi label="Identifying fields removed" value={ov.totals.removed} sub="usernames, IPs, IDs, raw samples…" />
          <Kpi label="Fields pseudonymised" value={ov.totals.pseudonymised} sub="device names/IDs → Device-NN" />
          <Kpi label="Privacy firewall events" value={fw.blocked_events + fw.blocked_fields + fw.redactions + fw.policy_blocked} sub={`${fw.blocked_fields} fields blocked · ${fw.redactions} redactions`} />
          <Kpi label="Policy violations (host)" value={ov.violations.reduce((a, v) => a + v.count, 0)} sub="rejected or flagged at the host" color={ov.violations.length ? '#f5a524' : undefined} />
          <Kpi label="TLS verified" value={`${tl.verified}/${tl.reporting || ov.devices.length}`} sub={`${tl.direct} direct · ${tl.tunnel} via tunnel`} />
          <Kpi label="Egress hash proofs" value={ov.egress_totals.verified_match} sub={ov.egress_totals.mismatch ? `${ov.egress_totals.mismatch} MISMATCH` : 'collector hash = host hash'} color={ov.egress_totals.mismatch ? '#ef4444' : undefined} />
        </div>
        <div className="callout small">Everything on this page was <b>received by the host</b>: pseudonymous IDs, counters, hashes and the payloads themselves. The original data and the name↔pseudonym mapping stay on each laptop (its local console remains available for raw BEFORE/AFTER debugging). This is pseudonymisation, not perfect anonymity.</div>
        <Card title="Devices (click one for its privacy details)">
          <table><thead><tr><th>Device ID</th><th>Platform</th><th>Status</th><th>Anonymisation</th><th>Records</th><th>Removed</th><th>Pseudonymised</th><th>Firewall</th><th>TLS</th><th>Last transmission</th></tr></thead><tbody>
            {ov.devices.map(d => <tr key={d.id} style={{ cursor: 'pointer' }} onClick={() => open(d.id)}>
              <td><b>{d.device_id}</b> {d.pseudonymous ? <Badge kind="delivered">pseudonym</Badge> : <Badge kind="warning">real name visible</Badge>}</td><td>{d.platform || '—'}</td>
              <td><Badge kind={d.status === 'online' ? 'delivered' : 'blocked'}>{d.status}</Badge></td><td><Badge kind={ANON_BADGE[d.anonymisation]}>{d.anonymisation}</Badge></td>
              <td>{d.records}</td><td>{d.removed}</td><td>{d.pseudonymised}</td>
              <td className="small">{d.privacy_reported ? `${d.firewall.blocked_fields} blocked · ${d.firewall.redactions} redacted` : <span className="mut">not reported</span>}</td>
              <td>{d.tls.reported_by_collector ? <Yes v={d.tls.verified} yes="verified" no="FAILED" /> : <span className="mut small">{d.tls.via === 'tunnel' ? 'via tunnel' : d.tls.via === 'direct_tls' ? 'direct TLS' : '—'}</span>}</td>
              <td className="small">{d.last_transmission ? secAgo(d.last_transmission.received_ms) : '—'}</td></tr>)}
          </tbody></table>
        </Card>
      </>}

      {tab === 'devices' && <div className="grid" style={{ gridTemplateColumns: '260px 1fr', alignItems: 'start' }}>
        <Card title="Devices">{ov.devices.map(d => <div key={d.id} className="card" style={{ marginBottom: 6, cursor: 'pointer', borderColor: cur === d.id ? '#4f8cff' : undefined, background: cur === d.id ? '#1c2c52' : undefined }} onClick={() => setSel(d.id)}>
          <div className="b">{d.device_id}</div><div className="small mut">{d.platform || '—'} · {d.status} · {d.anonymisation}</div></div>)}</Card>
        {cur && <DevicePrivacy key={cur} id={cur} />}
      </div>}

      {tab === 'inventory' && <Inventory />}
      {tab === 'ba' && <BeforeAfter />}
      {tab === 'flow' && <DataFlow go={go} />}
      {tab === 'retention' && <RetentionAudit me={me} />}
      {tab === 'egress' && <EgressProof devices={ov.devices} initial={cur} />}
      {tab === 'firewall' && <FirewallEvents />}
      {tab === 'tls' && <TlsTransport ov={ov} />}
      {tab === 'guide' && <Cloud />}
    </div>
  )
}

function DevicePrivacy({ id }) {
  const [d] = usePoll(() => api('/api/privacy/devices/' + encodeURIComponent(id)), 3000, [id])
  const [pid, setPid] = useState(null)
  const use = pid || d?.payloads?.[0]?.payload_id
  const [p] = usePoll(() => use ? api(`/api/privacy/devices/${encodeURIComponent(id)}/payloads/${encodeURIComponent(use)}`) : Promise.resolve(null), 6000, [id, use])
  if (!d) return <div className="mut">loading…</div>
  const t = d.tls, ep = d.egress_proof
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g4">
        <Kpi label="Pseudonymous device ID" value={d.device_id} sub={d.pseudonymous ? 'host knows only this pseudonym' : 'NOT a pseudonym - real name visible'} color={d.pseudonymous ? '#2ecc71' : '#f5a524'} />
        <Kpi label="Anonymisation" value={d.anonymisation} color={d.anonymisation === 'enabled' ? '#2ecc71' : '#ef4444'} sub={d.identity_exposed_at_enrolment ? 'enrolled under real name - re-enrol' : `policy v${d.policy || '—'}`} />
        <Kpi label="Records processed" value={d.records} sub="on the laptop, before sending" />
        <Kpi label="Identifying fields removed" value={d.removed} sub={`${d.pseudonymised} pseudonymised`} />
      </div>
      <Card title="Privacy summary">
        <div className="small" style={{ lineHeight: 1.9 }}>
          <div><b>Removed by type:</b> {chips(d.breakdown).length ? chips(d.breakdown) : <span className="mut">{d.privacy_reported ? 'none yet' : 'this collector build does not report a breakdown'}</span>}</div>
          <div><b>Privacy firewall (on the laptop):</b> {d.privacy_reported ? <>{d.firewall.blocked_fields} fields blocked by the allow-list · {d.firewall.redactions} secret/PII redactions · {d.firewall.blocked_events} events blocked · {d.firewall.policy_blocked} stopped by the outgoing-data policy {chips(d.firewall.redaction_labels)}</> : <span className="mut">not reported by this collector build</span>}</div>
          <div><b>Privacy violations at the host:</b> <Badge kind={d.violations.rejected ? 'blocked' : 'delivered'}>{d.violations.rejected} rejected</Badge> <Badge kind={d.violations.flagged ? 'warning' : 'delivered'}>{d.violations.flagged} flagged</Badge></div>
          <div><b>Last successful transmission:</b> {d.last_transmission ? <>{fmtDT(d.last_transmission.received_ms)} ({secAgo(d.last_transmission.received_ms)}) · payload #{d.last_transmission.seq} · {d.last_transmission.events} events</> : 'none received'}</div>
          <div><b>Connection:</b> {t.host_observed}</div>
          <div><b>TLS (reported by the collector):</b> {t.reported_by_collector ? <><Yes v={t.verified} yes="certificate verification ON" no="verification FAILED" /> trust anchor: {t.trust === 'pinned_ca' ? 'pinned private CA' : 'system store (public CA)'} · min TLS {t.min_tls}{t.last_error ? <> · last certificate problem: <Badge kind="warning">{t.last_error}</Badge></> : ' · no certificate problems'}</> : <span className="mut">not reported by this collector build</span>}</div>
          <div><b>Egress proof:</b> {ep.reported ? (ep.match === true ? <Badge kind="delivered">collector's hash of payload {ep.payload_id.slice(0, 8)}… = hash of what the host received</Badge> : ep.match === false ? <Badge kind="blocked">HASH MISMATCH</Badge> : <Badge kind="warning">payload not (yet) at the host</Badge>) : <span className="mut">not reported by this collector build</span>}</div>
        </div>
      </Card>
      {d.violations.items.length > 0 && <Card title="Privacy violations (codes only)"><table><thead><tr><th>Action</th><th>Code</th><th>Field</th><th>Count</th><th>Last</th></tr></thead><tbody>
        {d.violations.items.map((v, i) => <tr key={i}><td><Badge kind={v.level === 'reject' ? 'blocked' : 'warning'}>{v.level === 'reject' ? 'rejected' : 'flagged'}</Badge></td><td className="mono small">{v.code}</td><td className="mono small">{v.field}</td><td>{v.count}</td><td className="mono small">{fmtDT(v.last_ms)}</td></tr>)}</tbody></table></Card>}
      <Card title="Actual anonymised payload received by the host" right={<select value={use || ''} onChange={e => setPid(e.target.value)}>{d.payloads.map(x => <option key={x.payload_id} value={x.payload_id}>#{x.seq} · {fmtT(x.received_ms)} · {x.event_count} events</option>)}</select>}>
        {p ? <PayloadView p={p} /> : <div className="mut">No payload received yet.</div>}
      </Card>
    </div>
  )
}

function PayloadView({ p }) {
  return <>
    <div className="row wrap small" style={{ marginBottom: 6 }}>
      <Badge kind={p.exact ? 'delivered' : 'warning'}>{p.exact ? 'exact body as received' : 'rebuilt from stored events'}</Badge>
      {p.integrity_ok != null && <Badge kind={p.integrity_ok ? 'delivered' : 'blocked'}>{p.integrity_ok ? 'body hash verified' : 'BODY HASH MISMATCH'}</Badge>}
      {p.collector_reported_match != null && <Badge kind={p.collector_reported_match ? 'delivered' : 'blocked'}>{p.collector_reported_match ? "matches the collector's own hash" : 'differs from the collector hash'}</Badge>}
      <Badge kind={p.policy_findings.length ? 'blocked' : 'delivered'}>{p.policy_findings.length ? 'policy findings: ' + p.policy_findings.join(', ') : 'passes the outgoing-data policy'}</Badge>
      <span className="mono mut" style={{ wordBreak: 'break-all' }}>sha256 {p.sha256_host}</span></div>
    {p.note && <div className="small mut">{p.note}</div>}
    <div style={{ maxHeight: 320, overflow: 'auto' }}><Json v={p.payload} /></div>
  </>
}

function EgressProof({ devices, initial }) {
  const [id, setId] = useState(initial)
  const [d] = usePoll(() => id ? api('/api/privacy/devices/' + encodeURIComponent(id)) : Promise.resolve(null), 4000, [id])
  const [contract] = usePoll(() => api('/api/privacy/contract'), 60000)
  const [pid, setPid] = useState(null)
  const use = pid || d?.payloads?.[0]?.payload_id
  const [p] = usePoll(() => use ? api(`/api/privacy/devices/${encodeURIComponent(id)}/payloads/${encodeURIComponent(use)}`) : Promise.resolve(null), 6000, [id, use])
  const stage = (n, title, color, children) => <Card title={<span><span className="badge" style={{ background: color, color: '#fff', borderColor: color, marginRight: 8 }}>{n}</span>{title}</span>}>{children}</Card>
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row small"><span className="mut">Device</span><select value={id || ''} onChange={e => { setId(e.target.value); setPid(null) }}>{devices.map(x => <option key={x.id} value={x.id}>{x.device_id}</option>)}</select>
        {d && <select value={use || ''} onChange={e => setPid(e.target.value)}>{d.payloads.map(x => <option key={x.payload_id} value={x.payload_id}>payload #{x.seq} · {fmtT(x.received_ms)}</option>)}</select>}</div>
      <div className="callout small">Egress proof, end to end. The central dashboard can show stages 2 and 3 only; stage 1 (the originals) <b>never leaves the laptop by design</b>.</div>
      {stage(1, 'Original local fields — stay on the laptop', '#64748b', <div className="small" style={{ lineHeight: 1.7 }}>
        <div><b>Not available here, by design.</b> The raw hostname, username, private IPs, MAC addresses, raw log lines and the original→pseudonym mapping are never sent to this host and are not requested from the collector. To inspect the raw BEFORE/AFTER, open that laptop's own local console (Local Anonymisation / Egress Proof tabs) on the laptop itself.</div>
        <div style={{ marginTop: 6 }}><b>What the laptop reports about this stage (counts only):</b> {d ? <>{d.removed} identifying fields removed, {d.pseudonymised} values pseudonymised {chips(d.breakdown)}</> : '…'}</div></div>)}
      {stage(2, 'Redacted and allow-listed on the laptop', '#4f8cff', <div className="small" style={{ lineHeight: 1.7 }}>
        <div>The privacy firewall keeps only fields in this contract and redacts secrets/PII inside allowed strings. Laptop-reported activity: {d?.privacy_reported ? <>{d.firewall.blocked_fields} fields dropped by the allow-list · {d.firewall.redactions} redactions · {d.firewall.blocked_events} events blocked · {d.firewall.policy_blocked} stopped by the outgoing-data policy {chips(d.firewall.redaction_labels)}</> : <span className="mut">not reported by this collector build</span>}</div>
        {contract && <details style={{ marginTop: 6 }}><summary>The allow-list (data contract) enforced on the laptop and re-checked by the host</summary>
          <div className="small"><b>Event fields:</b> <span className="mono">{contract.top_fields.join(', ')}</span></div>
          {Object.entries(contract.context_allow).map(([t, f]) => <div key={t} className="small"><b>{t}.context:</b> <span className="mono">{Object.keys(f).join(', ')}</span></div>)}
          <div className="small"><b>Always removed locally:</b> <span className="mono">{contract.identifying_fields_removed_locally.join(', ')}</span></div></details>}</div>)}
      {stage(3, 'Exact final payload received by the host', '#2ecc71', p ? <PayloadView p={p} /> : <div className="mut">No payload received yet.</div>)}
    </div>
  )
}

function FirewallEvents() {
  const [f] = usePoll(() => api('/api/privacy/firewall'), 4000)
  if (!f) return <div className="mut">loading…</div>
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="Privacy firewall activity per device (reported by each laptop: counters only)">
        <table><thead><tr><th>Device</th><th>Fields blocked</th><th>Redactions</th><th>Events blocked</th><th>Stopped by policy</th><th>Removed by type</th></tr></thead><tbody>
          {f.devices.map(d => <tr key={d.id}><td><b>{d.device_id}</b></td>{d.privacy_reported ? <><td>{d.firewall.blocked_fields}</td><td>{d.firewall.redactions}</td><td>{d.firewall.blocked_events}</td><td>{d.firewall.policy_blocked}</td><td className="small">{chips(d.breakdown)}</td></> : <td colSpan={5} className="mut small">not reported by this collector build</td>}</tr>)}</tbody></table>
        {Object.keys(f.redaction_labels).length > 0 && <div className="small" style={{ marginTop: 8 }}><b>Secret/PII types redacted fleet-wide:</b> {chips(f.redaction_labels)}</div>}
      </Card>
      <Card title="Rejected by the host (allow-list / outgoing-data policy) — field names and codes only">
        {f.host_rejections.length === 0 ? <div className="mut small">No payload has been rejected.</div> : <table><thead><tr><th>When</th><th>Device</th><th>Reason</th></tr></thead><tbody>
          {f.host_rejections.map((r, i) => <tr key={i}><td className="mono small">{fmtDT(r.ts_ms)}</td><td>{r.device}</td><td className="small">{r.reason}</td></tr>)}</tbody></table>}
      </Card>
      <Card title="Policy violations (rejected or flagged at the host)">
        {f.violations.length === 0 ? <div className="mut small">None.</div> : <table><thead><tr><th>Device</th><th>Action</th><th>Code</th><th>Field</th><th>Count</th><th>Last</th></tr></thead><tbody>
          {f.violations.map((v, i) => <tr key={i}><td>{v.device}</td><td><Badge kind={v.level === 'reject' ? 'blocked' : 'warning'}>{v.level === 'reject' ? 'rejected' : 'flagged'}</Badge></td><td className="mono small">{v.code}</td><td className="mono small">{v.field}</td><td>{v.count}</td><td className="mono small">{fmtDT(v.last_ms)}</td></tr>)}</tbody></table>}
      </Card>
    </div>
  )
}

function TlsTransport({ ov }) {
  const T = ov.transport
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="Per-device TLS connection and certificate verification">
        <table><thead><tr><th>Device</th><th>Reached the host via</th><th>Certificate verification</th><th>Trust anchor</th><th>Min TLS</th><th>Last certificate problem</th><th>End-to-end TLS</th></tr></thead><tbody>
          {ov.devices.map(d => <tr key={d.id}><td><b>{d.device_id}</b> <span className="mut small">({d.status})</span></td><td className="small">{d.tls.host_observed}</td>
            <td>{d.tls.reported_by_collector ? <Yes v={d.tls.verified} yes="ON" no="FAILED" /> : <span className="mut small">not reported</span>}</td>
            <td className="small">{d.tls.trust ? (d.tls.trust === 'pinned_ca' ? 'pinned private CA' : 'system store (public CA)') : '—'}</td><td>{d.tls.min_tls || '—'}</td>
            <td>{d.tls.last_error ? <Badge kind="warning">{d.tls.last_error}</Badge> : <span className="mut small">none</span>}</td>
            <td>{d.tls.end_to_end_tls == null ? '—' : <Badge kind={d.tls.end_to_end_tls ? 'delivered' : 'warning'}>{d.tls.end_to_end_tls ? 'yes (direct)' : 'NO (ngrok terminates TLS)'}</Badge>}</td></tr>)}</tbody></table>
        <div className="small mut" style={{ marginTop: 6 }}>Verification status is self-reported by each collector (it always verifies and refuses to send on failure, so a failing collector cannot report until it recovers). The route (direct vs tunnel) is observed by the host.</div>
      </Card>
      <Card title="Transport security (what is and is not encrypted)">
        <div className="small" style={{ lineHeight: 1.6 }}>
          <div><b>Collector → host:</b> {T.collector_to_host}</div>
          <div style={{ marginTop: 6 }}><b>Host certificate:</b> valid for <b>{T.direct_local.tls.server_days_left ?? '?'}</b> more days (CA {T.direct_local.tls.ca_days_left ?? '?'}). CA fingerprint (SHA-256): <span className="mono" style={{ wordBreak: 'break-all' }}>{T.direct_local.tls.ca_fingerprint_sha256 || '—'}</span></div>
          <div style={{ marginTop: 6 }}><b>Via ngrok:</b><ul style={{ margin: '2px 0 0', paddingLeft: 18 }}><li>Collector ↔ ngrok: {T.via_ngrok.collector_to_ngrok}</li><li>ngrok ↔ this host: {T.via_ngrok.ngrok_to_host}</li><li><b>End-to-end TLS: NO.</b> {T.via_ngrok.note}</li></ul></div>
          <div style={{ marginTop: 6 }}><b>Dashboard:</b> {T.dashboard} <b>Ollama:</b> {T.ollama} <b>Collector consoles (port 9001 etc.):</b> never tunnelled and never contacted by this dashboard.</div>
        </div>
      </Card>
    </div>
  )
}

function Lab({ me }) {
  const [base, setBase] = useState(me.tenant_id === 'globex' ? 'http://127.0.0.1:9002' : 'http://127.0.0.1:9001')
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row"><span className="small mut">Collector under test:</span>
        <select value={base} onChange={e => setBase(e.target.value)}><option value="http://127.0.0.1:9001">acme collector · :9001</option><option value="http://127.0.0.1:9002">globex collector · :9002</option></select>
        <span className="mut small">Scenarios are injected at the customer-side collector (the data source) and travel through the real pipeline to this SaaS.</span></div>
      <Simulator base={base} ranking />
    </div>
  )
}

export default function SaasApp() {
  const [me, setMe] = useState(null)
  const [authed, setAuthed] = useState(!!auth.token)
  const [page, setPage] = useState('overview')
  const [param, setParam] = useState(null)
  const [ver, setVer] = useState(0)
  const [ws, setWs] = useState('connecting')
  const pending = useRef([])
  const lastBump = useRef(0)
  const [ov, setOv] = useState(null)
  const [clock, setClock] = useState(Date.now())

  useEffect(() => { const t = setInterval(() => setClock(Date.now()), 1000); return () => clearInterval(t) }, [])
  useEffect(() => { if (authed) api('/api/me').then(setMe).catch(() => { }) }, [authed])
  useEffect(() => {
    if (!authed) return
    let sock, alive = true, retry
    const open = () => {
      sock = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws?token=${auth.token}`)
      sock.onopen = () => setWs('live')
      sock.onmessage = m => {
        const j = JSON.parse(m.data)
        if (j.type === 'events') pending.current.push(...j.events.filter(e => e.metric === 'cpu_percent' || e.metric === 'latency_ms').slice(0, 4))
        const now = Date.now()
        if (now - lastBump.current > 900) { lastBump.current = now; setVer(v => v + 1) }
      }
      sock.onclose = () => { setWs('reconnecting'); if (alive) retry = setTimeout(open, 2000) }
    }
    open()
    return () => { alive = false; clearTimeout(retry); sock && sock.close() }
  }, [authed])

  // overview poll lives here so we can measure collection -> dashboard render latency
  useEffect(() => {
    if (!authed) return
    let stop = false
    api('/api/overview').then(o => { if (!stop) setOv(o) }).catch(() => { })
    return () => { stop = true }
  }, [authed, ver])
  useEffect(() => {
    if (!ov || !pending.current.length) return
    const maxMs = Math.max(0, ...ov.entities.flatMap(e => Object.values(e.metrics).map(m => m.event_ms)))
    const ready = pending.current.filter(p => Date.parse(p.event_time) <= maxMs).slice(0, 8)
    if (!ready.length) { if (pending.current.length > 200) pending.current = pending.current.slice(-50); return }
    pending.current = pending.current.filter(p => !ready.includes(p))
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const now = Date.now()
      api('/api/perf/render', { method: 'POST', body: { samples: ready.map(r => ({ event_id: r.event_id, event_time: r.event_time, rendered_ms: now })) } }).catch(() => { })
    }))
  }, [ov])

  const { t, i18n } = useTranslation()
  const go = (p, prm) => { setPage(p); setParam(prm || null) }
  if (!authed) return <Login onDone={() => setAuthed(true)} />
  if (!me) return <div className="mut" style={{ padding: 30 }}>loading…</div>
  const nav = [['overview', 'Overview'], ['fleet', 'Devices'], ['incidents', 'Incidents'], ['alerts', 'Alerts'], ['analytics', 'Analytics'], ['topology', 'Dependency Map'], ['replay', 'Incident Time Machine'], ['remediation', 'Remediation'], ['inspector', 'Data Inspector'], ['perf', 'Performance'], ['settings', 'Settings'], ['ask', 'Ask SENTINEL X'], ['privacy', 'Privacy Center'], ['intel', 'Global Intelligence'], ['lab', 'Scenario Lab'], ['judge', 'Live Judge Mode']]
  return (
    <div className="app">
      <div className="side">
        <div className="brand">SENTINEL <span>X</span><small>{t('Metadata-only AIOps SaaS')}</small></div>
        {nav.map(([k, l]) => <div key={k} className={'nav' + (page === k ? ' on' : '')} onClick={() => go(k)}>{t(l)}{k === 'incidents' && ov?.kpis.open_incidents > 0 && <span className="cnt">{ov.kpis.open_incidents}</span>}</div>)}
        <div className="sp" />
        <div className="mut small" style={{ padding: 8 }}>{me.tenant_name}<br />{me.username} ({me.role})<br />region {me.region}</div>
        <button className="btn sm" onClick={() => { auth.set(null); location.reload() }}>{t('Sign out')}</button>
      </div>
      <div className="main">
        <div className="top">
          <b>{t(nav.find(n => n[0] === page)?.[1] || '')}</b>
          {ov && <><StateBadge s={ov.health.state} /><span className="mut small">{ov.kpis.collectors_online}/{ov.kpis.collectors_total} {t('collectors online')}</span></>}
          <div className="sp" />
          <select aria-label={t('Language')} title={t('Language')} value={i18n.language} onChange={e => setLang(e.target.value)} style={{ minWidth: 90 }}>{LANGS.map(([k, n]) => <option key={k} value={k}>{n}</option>)}</select>
          <Badge kind={ws === 'live' ? 'delivered' : 'buffered'}>{t('stream')} {ws}</Badge>
          <span className="mono small">{fmtDT(clock)}</span>
        </div>
        <AlertToasts ver={ver} go={go} />
        <div className="page">
          {page === 'overview' && <Overview ov={ov} go={go} ver={ver} />}
          {page === 'fleet' && <Fleet ver={ver} />}
          {page === 'alerts' && <AlertsPage ver={ver} go={go} />}
          {page === 'analytics' && <AnalyticsPage ov={ov} ver={ver} MetricChart={MetricChart} />}
          {page === 'incidents' && <Incidents me={me} ver={ver} initial={param} goReplay={id => go('replay', id)} />}
          {page === 'topology' && <DepMap ver={ver} go={go} />}
          {page === 'replay' && <Replay initial={param} ver={ver} />}
          {page === 'remediation' && <RemediationPage me={me} ver={ver} />}
          {page === 'inspector' && <Inspector ver={ver} />}
          {page === 'perf' && <Perf ver={ver} />}
          {page === 'settings' && <Settings me={me} />}
          {page === 'ask' && <Ask />}
          {page === 'privacy' && <PrivacySecurity param={param} go={go} me={me} />}
          {page === 'intel' && <GlobalIntel me={me} param={param} />}
          {page === 'judge' && <JudgePage me={me} go={go} />}
          {page === 'lab' && <Lab me={me} />}
        </div>
      </div>
    </div>
  )
}
