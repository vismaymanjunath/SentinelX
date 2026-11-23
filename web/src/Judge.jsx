import React, { useEffect, useRef, useState } from 'react'
import { api, usePoll, fmtDT, num } from './api'
import { Badge, Card, Kpi, StateBadge } from './ui'

// Live Judge Mode. Scenarios are injected into a SIMULATED collector through its own console API (the same path as Scenario Lab); every
// number shown is measured from timestamps the real pipeline recorded. Targets are compared with the measured values - never assumed.
const SCEN = [
  ['cpu_spike', 'CPU spike', '+60 pts CPU on the application host'],
  ['memory_anomaly', 'Memory spike', 'memory ramps up ~35 pts'],
  ['latency_increase', 'Network latency increase', '+250 ms on the WAN link'],
  ['failed_logins', 'Repeated failed logins', 'credential-stuffing burst; raw auth lines stay local'],
  ['collector_disconnect', 'Collector offline', 'collector stops: no collection, no heartbeat'],
  ['saas_disconnect', 'SaaS connectivity loss', 'network partition: collector keeps monitoring and buffers'],
  ['duplicate_ooo', 'Duplicate event delivery', 're-sends acked payloads + reversed batch order'],
  ['recovery', 'Recovery after outage', 'ends the outage; measures backlog delivery'],
]
const TARGETS = [['collection_to_dashboard', 'Collection → dashboard', 'collection_to_saas_p95_ms', 'collection_to_dashboard_ms', 'p95 ≤ 10 s'], ['breach_to_alert', 'Breach → alert', 'breach_to_alert_ms', 'breach_to_alert_ms', '≤ 15 s'], ['offline_detect', 'Offline detection', 'offline_detect_ms', 'offline_detect_ms', '≤ 60 s']]
const sec = ms => (ms == null ? '—' : num(ms / 1000, 1) + ' s')
const tm = ms => new Date(ms).toISOString().slice(11, 23) + 'Z'

export function ReliabilityCard() {
  const [r, e] = usePoll(() => api('/api/reliability'), 5000)
  if (!r) return <Card title="Global reliability"><div className={e ? 'callout small' : 'mut small'}>{e ? `Could not load reliability data (${e.message}). If this says “not found”, the SaaS host is still running an older build: restart the host once to enable this section and Live Judge Mode results.` : 'loading…'}</div></Card>
  const g = r.regional, o = r.ordering, i = r.idempotency
  return (
    <Card title="Global reliability" right={<Badge kind="neutral">UTC · {tm(r.time.server_utc_ms)}</Badge>}>
      <div className="grid g4">
        <Kpi label="Out-of-order handling" value={`${o.late_events_total} late`} sub={`${o.arrival_order_inversions} arrival-order inversions in ${o.events_checked} recent events; ordered by event time`} />
        <Kpi label="Duplicate prevention" value={i.duplicates_ignored} sub={`duplicates ignored · ${i.duplicate_payloads_stored + i.duplicate_events_stored} duplicates stored`} color={i.duplicate_payloads_stored + i.duplicate_events_stored ? '#ef4444' : '#2ecc71'} />
        <Kpi label="Tenant region" value={g.tenant_region} sub={g.region_mismatches.length ? `${g.region_mismatches.length} collector(s) in another region` : 'all collectors match; mismatches are refused at ingest'} />
        <Kpi label="Collector regions" value={g.collector_regions.join(', ') || '—'} sub="declared by each collector" />
      </div>
      <table style={{ marginTop: 8 }}><thead><tr><th>Source</th><th>Event time (UTC)</th><th>Source timezone</th><th>Region</th><th>Arrival (UTC)</th><th>Transit</th><th>Late?</th></tr></thead><tbody>
        {r.recent.map(e => <tr key={e.event_id + e.arrival_ms}><td className="small">{e.source} · {e.metric}</td><td className="mono small">{e.event_time_utc}</td><td className="small">{e.source_tz}</td><td className="small">{e.region || '—'}</td><td className="mono small">{tm(e.arrival_ms)}</td><td className="small">{e.transit_ms} ms</td><td>{e.late ? <Badge kind="warning">late (placed by event time)</Badge> : <span className="mut small">no</span>}</td></tr>)}
      </tbody></table>
      <div className="small mut" style={{ marginTop: 6 }}>Processing time is not recorded separately: payloads are stored synchronously on arrival, so “transit” (arrival − event time) is the measurable delay. {o.method}</div>
      <div className="small" style={{ marginTop: 6 }}><Badge kind="delivered">implemented</Badge> {g.residency_check}<br />
        <Badge kind="warning">Not configured</Badge> Regional ingest: {g.regional_ingest_endpoints}<br /><Badge kind="warning">Not configured</Badge> Regional storage: {g.regional_storage}</div>
    </Card>
  )
}

export default function JudgePage({ me, go }) {
  const [base, setBase] = useState('http://127.0.0.1:9011')
  const [info, setInfo] = useState(null), [err, setErr] = useState('')
  const [run, setRun] = useState(null)             // { name, since, clicked }
  const [res, setRes] = useState(null), [col, setCol] = useState(null), [logs, setLogs] = useState([]), [anon, setAnon] = useState(null), [inc, setInc] = useState(null)
  const [rec, setRec] = useState(null)             // recovery measurement
  const [busy, setBusy] = useState(false)
  const [hostErr, setHostErr] = useState('')
  const admin = me.role === 'admin'
  const cget = (p) => api(p, { base, token: null })
  const check = async () => { setErr(''); try { const w = await cget('/api/whoami'); setInfo(w); if (w.remote || w.host_mode !== 'simulated') setErr('This collector is not a simulated one. Judge Mode only injects into a SIMULATED collector, so your real devices are never touched.') } catch { setInfo(null); setErr('No collector answers at ' + base + '. Start the simulated Acme collector (see the note below).') } }
  useEffect(() => { check() }, [base])
  const safe = info && !info.remote && info.host_mode === 'simulated'

  useEffect(() => {
    if (!run && !rec) return
    let alive = true
    const tick = async () => {
      try {
        const [s, l, a] = await Promise.all([cget('/api/status'), cget('/api/logs?limit=80'), cget('/api/anon')])
        if (!alive) return
        setCol(s); setLogs(l); setAnon(a)
        if (rec && !rec.done) {
          const p = s.outbox.pending, now = Date.now()
          if (p === 0 && s.sync.state === 'ONLINE') { const h = await api('/api/perf'); const d = h.delivery.find(x => x.collector_id === info.collector_id); setRec(r => ({ ...r, done: true, drain_ms: now - r.t0, delivery: d })) }
          else setRec(r => ({ ...r, pending: p, state: s.sync.state }))
        }
        if (run && !['recovery'].includes(run.name)) {
          const r = await api(`/api/judge/result?scenario=${run.name}&since_ms=${run.since}&collector_id=${info.collector_id}`).catch(e => { if (alive) setHostErr(e.message); return null })
          if (!alive || !r) return
          setHostErr('')
          setRes(r)
          if (r.found && r.incident && (!inc || inc.id !== r.incident.id || Date.now() % 5 === 0)) setInc(await api('/api/incidents/' + r.incident.id))
        }
      } catch (e) { /* keep polling */ }
    }
    tick(); const t = setInterval(tick, 1000); return () => { alive = false; clearInterval(t) }
  }, [run?.name, run?.since, rec?.t0, base])

  const fire = async (name) => {
    if (!safe || !admin) return
    setBusy(true); setErr('')
    try {
      if (name === 'recovery') {
        const before = await cget('/api/status')
        await api('/api/sim/clear', { method: 'POST', base, token: null, body: {} })
        setRun({ name, since: Date.now() }); setRes(null); setInc(null)
        setRec({ t0: Date.now(), pending_at_start: before.outbox.pending, pending: before.outbox.pending, done: false, state: before.sync.state })
      } else {
        setRec(null); setRes(null); setInc(null)
        const since = Date.now() - 3000
        await api('/api/sim/' + name, { method: 'POST', base, token: null, body: {} })
        setRun({ name, since })
      }
    } catch (e) { setErr(e.message) }
    setBusy(false)
  }
  const reset = async () => { try { await api('/api/sim/clear', { method: 'POST', base, token: null, body: {} }) } catch { /* ignore */ } setRun(null); setRes(null); setInc(null); setRec(null); setCol(null) }

  const lab = SCEN.find(s => s[0] === run?.name)?.[1]
  const localAlerts = (col?.local_alerts || []).filter(a => run && Date.parse(a.time) >= run.since - 5000)
  // privacy proof: every identifier the collector knows locally (names, IPs from raw logs) must be absent from what the host received
  const idents = new Set()
  Object.values(anon?.mapping_local_only?.identifiers || {}).flat().forEach(x => x && String(x).length > 2 && idents.add(String(x)))
  logs.forEach(l => (l.raw.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []).forEach(x => idents.add(x)))
  const sent = res?.payload ? JSON.stringify(res.payload) : ''
  const leaked = [...idents].filter(x => sent.includes(x))
  const rawSample = logs.filter(l => l.secrets || l.pii || /\d+\.\d+\.\d+\.\d+/.test(l.raw)).slice(0, 3)

  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="Live Judge Mode" right={<div className="row"><span className="small mut">simulated collector</span><input value={base} onChange={e => setBase(e.target.value)} style={{ width: 200 }} />{safe && <Badge kind="delivered">simulated · safe</Badge>}</div>}>
        {hostErr && <div className="callout small" style={{ borderColor: '#ef4444', marginBottom: 8 }}>The SaaS host could not return Judge results ({hostErr}). If this says “not found”, the host is running an older build: restart it once so the new /api/judge routes load. The collector side still works.</div>}
        {err && <div className="callout small" style={{ borderColor: '#ef4444', marginBottom: 8 }}>{err}{!info && <div className="mono">python -m collector.main with COLLECTOR_CONFIG=data/collector-acme.json and COLLECTOR_PORT=9011</div>}</div>}
        <div className="small mut" style={{ marginBottom: 8 }}>Each button perturbs the <b>sources</b> of a <b>SIMULATED</b> collector; detection, redaction, buffering, delivery, alerting and correlation then run through the real pipeline. Results below are measured from recorded timestamps. Your real devices are never touched{!admin && ' · admin role required to trigger'}.</div>
        <div className="grid g4">{SCEN.map(([k, l, d]) => <button key={k} className={'btn' + (run?.name === k ? ' pri' : '')} disabled={!safe || !admin || busy} onClick={() => fire(k)} style={{ textAlign: 'left', padding: 10 }}><b>{l}</b><div className="small mut" style={{ whiteSpace: 'normal' }}>{d}</div></button>)}</div>
        <div className="row" style={{ marginTop: 8 }}><button className="btn dng" disabled={!safe || !admin} onClick={reset}>Reset demo</button><span className="small mut">Clears active scenarios on the simulated collector and this screen. Stored data is not deleted.</span></div>
      </Card>

      {run && run.name !== 'recovery' && <>
        <Card title={`Scenario: ${lab}`} right={<div className="row"><Badge kind="warning">SIMULATED SCENARIO</Badge><Badge kind="delivered">real pipeline</Badge></div>}>
          {!res?.found ? <div className="small mut">⏳ Waiting for the injection marker to reach the SaaS… {col && ['saas_disconnect', 'collector_disconnect'].includes(run.name) ? <b style={{ color: '#f5a524' }}>The collector is {col.sync.state} with {col.sync.pending} payload(s) queued locally: the marker is buffered behind the outage by design, and the SaaS-side measurements appear when delivery resumes (or use “Recovery after outage”).</b> : res?.note}</div> : <>
            <div className="grid g3">{TARGETS.map(([k, label, mk, tk, tt]) => {
              const v = res.metrics[mk], ok = res.verdicts[k]
              const na = v == null
              const offl = ['collector_disconnect', 'saas_disconnect'].includes(run.name)
              return <Kpi key={k} label={label} value={sec(v)} color={na ? undefined : ok ? '#2ecc71' : '#ef4444'} sub={na ? (k === 'breach_to_alert' && offl ? 'not applicable: outages use the offline-detection target' : `not measured in this scenario (target ${tt})`) : `${ok ? 'PASS' : 'FAIL'} · target ${tt}`} />
            })}</div>
            <div className="small mut" style={{ marginTop: 4 }}>Collection → dashboard = {res.metrics.collection_to_dashboard_basis}, p95. SaaS arrival p95 {sec(res.metrics.ingest_p95_ms)} over {res.metrics.samples} samples{res.backlog_events ? ` · ${res.backlog_events} buffered backlog events excluded (delivered late by design; see Recovery)` : ''}. Breach → alert = alert creation time − injection time.</div>
          </>}
        </Card>
        {res?.found && <div className="grid g2" style={{ alignItems: 'start' }}>
          <Card title="Timeline (UTC, measured)">
            <table><tbody>{[...res.timeline, ...localAlerts.map(a => ({ t: Date.parse(a.time), what: `Detected locally at the collector: ${a.source} · ${a.metric}`, measured: true }))].sort((a, b) => a.t - b.t).map((e, i) =>
              <tr key={i}><td className="mono small">{tm(e.t)}</td><td className="small mono">+{sec(e.t - res.injected_ms)}</td><td className="small">{e.what}</td></tr>)}</tbody></table>
            {res.delivery.duplicates_ignored > 0 && <div className="small" style={{ marginTop: 6 }}><Badge kind="delivered">duplicates ignored by the SaaS: {res.delivery.duplicates_ignored}</Badge> idempotent by payload ID.</div>}
            {res.delivery.out_of_order_events > 0 && <div className="small"><Badge kind="warning">out-of-order events placed by event time: {res.delivery.out_of_order_events}</Badge></div>}
            {col && <div className="small mut" style={{ marginTop: 6 }}>Collector link: <b>{col.sync.state}</b> · queue {col.sync.pending} · {col.sync.last_sync_error || 'no sync error'}</div>}
          </Card>
          <Card title="Alert and correlated incident">
            {res.alerts.length === 0 ? <div className="mut small">{res.already_active_alert ? `No NEW alert: an earlier alert is still active ("${res.already_active_alert.title}", created ${tm(res.already_active_alert.created_ms)}), so the platform de-duplicates. Reset and wait for it to clear, or open the existing incident.` : ['saas_disconnect', 'duplicate_ooo'].includes(run.name) ? 'No alert is expected for this scenario unless the outage is long enough to be detected as offline.' : 'No alert yet…'}</div> :
              <table><thead><tr><th>Severity</th><th>Alert</th><th>Created</th></tr></thead><tbody>{res.alerts.map(a => <tr key={a.id}><td><Badge kind={a.severity} /></td><td className="small"><b>{a.title}</b><div className="mut">{a.message}</div></td><td className="mono small">{tm(a.created_ms)}</td></tr>)}</tbody></table>}
            {inc && <div style={{ marginTop: 8 }}>
              <div className="row wrap"><b>Incident #{inc.id}</b><Badge kind={inc.severity} /><span className="small">priority {inc.priority_level}</span><span className="small mut">{inc.title}</span></div>
              <div className="small" style={{ marginTop: 4 }}><b>Affected device/service:</b> {(inc.analysis?.root?.label) || inc.root_entity}{(inc.analysis?.affected || []).length ? ' → ' + inc.analysis.affected.join(', ') : ''}</div>
              <div className="small"><b>Root cause:</b> {inc.root_cause} <span className="mut">(confidence {num((inc.confidence || 0) * 100, 0)}%)</span></div>
              <div className="small" style={{ marginTop: 4 }}><b>Contributing signals</b></div>
              <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{(inc.analysis?.signals || []).slice(0, 5).map(s => <li key={s.id}><span className="mono">{s.id}</span> {s.label || s.entity} · {s.metric} = {num(s.value, 1)}{s.baseline != null ? ` (baseline ${num(s.baseline, 1)})` : ''}</li>)}</ul>
              <div className="small" style={{ marginTop: 4 }}><b>Recommended remediation</b></div>
              <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{(inc.analysis?.recommendations || []).map((r, i) => <li key={i}><b>{r.title}</b> <span className="mut">{r.rationale}</span></li>)}</ul>
              <div className="row" style={{ marginTop: 6 }}><button className="btn sm" onClick={() => go('incidents', inc.id)}>Open incident</button><button className="btn sm pri" onClick={() => go('remediation')}>Plan a fix (Remediation)</button></div></div>}
          </Card>
        </div>}
        {res?.found && <div className="grid g2" style={{ alignItems: 'start' }}>
          <Card title="Metadata sent to the SaaS (exact payload as stored by the host)" right={<Badge kind={res.policy_findings.length ? 'blocked' : 'delivered'}>{res.policy_findings.length ? 'policy findings: ' + res.policy_findings.join(', ') : 'passes the outgoing-data policy'}</Badge>}>
            {res.payload ? <><div className="mono small mut" style={{ wordBreak: 'break-all' }}>sha256 {res.payload._sha256}</div><pre className="mono small df-json" style={{ maxHeight: 260 }}>{JSON.stringify({ ...res.payload, _sha256: undefined, _received_ms: undefined }, null, 1)}</pre></> : <div className="mut small">payload not available yet</div>}
          </Card>
          <Card title="Sensitive data stays local" right={res.payload && <Badge kind={leaked.length ? 'blocked' : 'delivered'}>{leaked.length ? `${leaked.length} local identifier(s) FOUND in the payload` : `0 of ${idents.size} local identifiers found in the payload`}</Badge>}>
            <div className="small mut">Left: what the collector holds locally (its own console). Right: what the host received. The check compares every identifier the collector knows (mapped names, IP addresses in raw logs) against the payload shown.</div>
            {rawSample.length > 0 ? <div className="grid g2" style={{ marginTop: 6 }}>
              <div><Badge kind="warning">LOCAL RAW (never leaves)</Badge>{rawSample.map(l => <pre key={l.id} className="mono small df-json">{l.raw}</pre>)}</div>
              <div><Badge kind="delivered">REDACTED LOCALLY</Badge>{rawSample.map(l => <pre key={l.id} className="mono small df-json">{l.redacted}</pre>)}</div></div>
              : anon?.pairs?.length ? <div className="grid g2" style={{ marginTop: 6 }}><div><Badge kind="warning">BEFORE (local)</Badge><pre className="mono small df-json">{JSON.stringify(anon.pairs[0].before, null, 1).slice(0, 500)}</pre></div><div><Badge kind="delivered">AFTER (sent)</Badge><pre className="mono small df-json">{JSON.stringify(anon.pairs[0].after, null, 1).slice(0, 500)}</pre></div></div>
                : <div className="mut small" style={{ marginTop: 6 }}>This scenario carries only numeric telemetry; no raw log line or identifier was involved. The payload on the left is the complete metadata sent.</div>}
          </Card>
        </div>}
      </>}

      {rec && <Card title="Recovery after outage" right={<Badge kind="warning">SIMULATED OUTAGE · real delivery</Badge>}>
        <div className="grid g4">
          <Kpi label="Queued during outage" value={rec.pending_at_start} sub="payloads buffered locally" />
          <Kpi label="Still pending" value={rec.pending} color={rec.pending ? '#f5a524' : '#2ecc71'} sub={rec.state} />
          <Kpi label="Backlog delivered in" value={rec.done ? sec(rec.drain_ms) : '…'} sub={rec.done ? 'measured: click → queue empty + ONLINE' : 'draining…'} color={rec.done ? '#2ecc71' : undefined} />
          <Kpi label="Lost / duplicate" value={rec.done && rec.delivery ? `${rec.delivery.missing_seq.length} / ${rec.delivery.duplicates_ignored}` : '—'} sub="missing sequence numbers / duplicates ignored by the host (cumulative)" color={rec.done && rec.delivery && rec.delivery.missing_seq.length ? '#ef4444' : undefined} /></div>
        {rec.done && rec.delivery && <div className="small" style={{ marginTop: 6 }}>Host view: payloads {rec.delivery.payloads}, sequence {rec.delivery.first_seq}–{rec.delivery.last_seq}, missing {rec.delivery.missing_seq.length ? rec.delivery.missing_seq.join(',') : 'none'}, events {rec.delivery.events}.</div>}
      </Card>}
      <ReliabilityCard />
    </div>
  )
}
