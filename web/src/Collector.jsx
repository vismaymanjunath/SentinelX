import React, { useState } from 'react'
import { api, usePoll, fmtDT, fmtT, num } from './api'
import { Badge, Card, Json, Kpi, PriorityBadge, RedText, Tabs } from './ui'

const CB = ''  // collector API base (same origin)

// Order is decided by the backend (triage rank); scenarios it has not ranked yet stay Pending after ranked ones.
function orderActive(active, ranked) {
  if (!ranked) return active.map(a => [a, null])
  const pos = new Map(ranked.map((r, i) => [r.name, i]))
  return active.map(a => [a, ranked.find(r => r.name === a.name) || null])
    .sort((x, y) => (pos.has(x[0].name) ? pos.get(x[0].name) : 1e9) - (pos.has(y[0].name) ? pos.get(y[0].name) : 1e9))
}

export function Simulator({ base = CB, ranking = false }) {
  const [st] = usePoll(() => api('/api/status', { base, token: null }), 1000, [base])
  const [dur, setDur] = useState({})
  const [msg, setMsg] = useState('')
  // priority order comes from the SaaS (triage engine) when this simulator is embedded in the SaaS dashboard
  const names = (st?.sim.active || []).map(a => a.name).join(',')
  const [ranked] = usePoll(() => ranking && names ? api('/api/scenarios/priority?active=' + names) : Promise.resolve([]), 2000, [names, ranking])
  const [line, setLine] = useState('WARN auth-service debug dump password=Tr0ub4dor&3 api_key=sk_live_abcdef1234567890 user=jane@corp.com ip=203.0.113.50')
  if (!st) return <div className="mut">connecting to collector…</div>
  const fire = async (n) => {
    try { await api('/api/sim/' + n, { method: 'POST', body: dur[n] ? { duration_s: +dur[n] } : {}, base, token: null }); setMsg(`Injected "${st.scenarios[n].label}" — flows through the live pipeline`) } catch (e) { setMsg(String(e)) }
  }
  return (
    <div className="grid g2" style={{ gridTemplateColumns: '1.3fr 1fr' }}>
      <Card title="Live scenario simulator" right={<button className="btn dng sm" onClick={() => api('/api/sim/clear', { method: 'POST', base, token: null })}>Clear all</button>}>
        <div className="mut small" style={{ marginBottom: 8 }}>Every scenario perturbs the <b>sources</b> (metrics, logs, network link) — detection, redaction, buffering and delivery then run through the real pipeline.</div>
        <div className="scn">
          {Object.entries(st.scenarios).map(([n, s]) => (
            <div key={n} className="row">
              <button className="btn sp" onClick={() => fire(n)}><b>{s.label}</b><div className="mut small">{s.desc}</div></button>
              {s.duration > 0 && <input style={{ width: 62 }} placeholder={s.duration + 's'} value={dur[n] || ''} onChange={e => setDur({ ...dur, [n]: e.target.value })} title="duration (s)" />}
            </div>
          ))}
        </div>
        {msg && <div className="callout small" style={{ marginTop: 10 }}>{msg}</div>}
      </Card>
      <div className="col">
        <Card title="Active scenarios">
          {st.sim.active.length === 0 ? <div className="mut">none</div> : orderActive(st.sim.active, ranking ? ranked : null).map(([a, r]) => (
            <div key={a.name} className="row wrap" style={{ marginBottom: 4 }}>
              {r?.state === 'incident' ? <PriorityBadge p={r.priority_level} /> : ranking && <Badge kind="neutral">Pending</Badge>}
              <Badge kind="warning">{a.label}</Badge>
              {r?.state === 'incident' && <span className="small"><Badge kind="neutral">{r.category}</Badge> score {r.priority_score} · incident #{r.incident_id}{r.shared_with.length > 0 && <span className="mut"> (shared with {r.shared_with.join(', ')})</span>}</span>}
              {ranking && r?.state !== 'incident' && <span className="mut small">no incident yet</span>}
              <span className="mut small">{a.remaining_s}s left</span></div>))}
          <h3 style={{ marginTop: 12 }}>Sandbox mitigations (approved remediation)</h3>
          <div className="row wrap">{Object.entries(st.sim.mitigations).filter(([k]) => k !== 'restarted').map(([k, v]) => <Badge key={k} kind={v ? 'executed' : 'neutral'}>{k}: {String(v)}</Badge>)}
            {Object.keys(st.sim.mitigations.restarted).map(k => <Badge key={k} kind="executed">restarted: {k}</Badge>)}</div>
        </Card>
        <Card title="Inject a custom raw log line">
          <textarea style={{ width: '100%', height: 70 }} value={line} onChange={e => setLine(e.target.value)} />
          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn pri sm" onClick={() => api('/api/logs/inject', { method: 'POST', body: { line }, base, token: null }).then(() => setMsg('Custom line queued: see Console → raw vs redacted'))}>Inject through pipeline</button>
            <span className="mut small">type your own secret and watch it get redacted</span></div>
        </Card>
        <Card title="Pipeline status">
          <div className="row wrap"><Badge kind={st.sync?.state === 'ONLINE' ? 'delivered' : 'buffered'}>{st.sync?.state || 'ONLINE'}</Badge>{st.sync?.queue_full && <Badge kind="blocked">queue FULL: {st.sync.not_queued_payloads} payload(s) not recorded</Badge>}<span className="small mut">last successful sync: {st.sync?.last_successful_sync || 'never'}</span>{st.sync?.last_sync_error && <span className="small" style={{ color: '#f5a524' }}>last error: {st.sync.last_sync_error}</span>}<Badge kind={st.link.state.startsWith('connected') ? 'delivered' : 'buffered'}>link: {st.link.state}</Badge><Badge kind="neutral">outbox pending: {st.outbox.pending}</Badge><Badge kind="neutral">sent: {st.outbox.sent}</Badge></div>
        </Card>
      </div>
    </div>
  )
}

function Console() {
  const [st] = usePoll(() => api('/api/status', { token: null }), 1500)
  const [only, setOnly] = useState(false)
  const [logs] = usePoll(() => api(`/api/logs?limit=40&only_secrets=${only}`, { token: null }), 1500, [only])
  if (!st) return null
  const s = st.stats
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g5">
        <Kpi label="Log lines processed" value={st.logproc.lines} sub="raw logs never leave this host" />
        <Kpi label="Secrets caught" value={st.logproc.secrets} color="#2ecc71" sub="redacted locally" />
        <Kpi label="PII redacted" value={st.logproc.pii} sub="emails / IPs" />
        <Kpi label="Fields blocked" value={s.blocked_fields} color="#f5a524" sub="by allow-list" />
        <Kpi label="Events blocked" value={s.blocked_events} color={s.blocked_events ? '#ef4444' : undefined} sub="by last-line guard" />
      </div>
      <div className="grid g2">
        <Card title="Local anomaly detections (edge AIOps)">
          {st.local_alerts.length === 0 ? <div className="mut">no local anomalies</div> : (
            <table><thead><tr><th>Time (UTC)</th><th>Signal</th><th>Sev</th><th>Why</th></tr></thead><tbody>
              {st.local_alerts.map((a, i) => <tr key={i}><td className="mono">{a.time?.slice(11, 19)}</td><td>{a.source} · {a.metric}</td><td><Badge kind={a.severity} /></td><td className="small">{a.message} <span className="mut">[{a.kind}, baseline {a.baseline_mean}±{a.baseline_std}]</span></td></tr>)}
            </tbody></table>)}
        </Card>
        <Card title="Trust boundary">
          <div className="callout small">Collect → <b>filter / redact</b> → aggregate → analyze locally → <b>apply data policy</b> → transmit.<br />
            Payloads built: <b>{s.payloads_built}</b> · acked by SaaS: <b>{s.payloads_sent}</b> · events delivered: <b>{s.events_sent}</b> · retries: <b>{s.retries}</b> · duplicates acked: <b>{s.duplicates_acked}</b></div>
          <div className="mut small" style={{ marginTop: 6 }}>Only allow-listed metadata (metric values, UTC timestamps, pseudonymous IDs, health, severity, concise alert context) is ever sent.</div>
        </Card>
      </div>
      <Card title="Raw logs (LOCAL ONLY) vs what is allowed to leave" right={<label className="small"><input type="checkbox" checked={only} onChange={e => setOnly(e.target.checked)} /> only lines with secrets</label>}>
        <div className="grid g2">
          <div><h3>Raw — stays in the customer environment</h3><div className="pane" style={{ maxHeight: 360 }}>{(logs || []).map(l => <pre key={l.id} className={l.secrets ? 'hl' : ''}>{l.raw}</pre>)}</div></div>
          <div><h3>Redacted — safe form (what any summary is derived from)</h3><div className="pane" style={{ maxHeight: 360 }}>{(logs || []).map(l => <pre key={l.id} className={l.secrets ? 'hl' : ''}><RedText t={l.redacted} />{l.secrets && <span className="mut"> ‹{l.secrets}›</span>}</pre>)}</div></div>
        </div>
      </Card>
    </div>
  )
}

const evLine = e => `${e.type}${e.metric ? ' · ' + e.metric : ''} @ ${e.source_id}${e.value != null ? ' = ' + e.value : ''}`

function EgressDetail({ id }) {
  const [d] = usePoll(() => api('/api/egress/' + id, { token: null }), 2000, [id])
  const [raw, setRaw] = useState(false)
  if (!d) return <div className="mut">loading…</div>
  const bf = {}; (d.blocked?.fields || []).forEach(b => (bf[b.event_index] = b.fields))
  const rd = {}; (d.redactions || []).forEach(r => (rd[r.event_index] = [...(rd[r.event_index] || []), r]))
  const be = {}; (d.blocked?.events || []).forEach(b => (be[b.event_index] = b.reason))
  const att = d.attempts || []
  return (
    <div className="col">
      <div className="row wrap"><Badge kind={d.status.split(' ')[0]}>{d.status}</Badge><span className="mono small">payload {d.payload_id}</span><span className="mut small">seq {d.seq} · {fmtDT(d.created_ms)}</span>
        <div className="sp" /><label className="small"><input type="checkbox" checked={raw} onChange={e => setRaw(e.target.checked)} /> raw JSON</label></div>
      <div className="grid g3" style={{ alignItems: 'start' }}>
        <div><h3>① Original local events ({d.original.length})</h3>
          <div className="pane" style={{ maxHeight: 470 }}>{raw ? <Json v={d.original} /> : d.original.map((e, i) => (
            <div key={i} style={{ marginBottom: 5 }}>
              <div className="small"><b>{evLine(e)}</b></div>
              {(bf[i] || []).map(f => <div key={f} className="small"><span className="red">✕ {f}</span> <span className="mut mono">{String(JSON.stringify(f.startsWith('context.') ? e.context?.[f.slice(8)] : e[f])).slice(0, 90)}</span></div>)}
              {be[i] && <div className="small red">BLOCKED: {be[i]}</div>}
            </div>))}</div></div>
        <div><h3>② After firewall — allow-listed + redacted</h3>
          <div className="pane" style={{ maxHeight: 470 }}>
            {(d.redactions || []).length > 0 && <div style={{ marginBottom: 8 }}><b className="small">Redactions applied</b>{d.redactions.map((r, i) => <div key={i} className="small"><span className="grn">{r.label}</span> in <span className="mono">{r.field}</span> (event {r.event_index})</div>)}</div>}
            {raw ? <Json v={d.redacted} /> : d.redacted.map((e, i) => <div key={i} className="small mono">{evLine(e)} {e.context && Object.keys(e.context).length ? <span className="mut">{JSON.stringify(e.context).slice(0, 110)}</span> : null}</div>)}
          </div></div>
        <div><h3>③ Final transmitted payload</h3>
          <div className="pane" style={{ maxHeight: 470 }}>{d.final ? <Json v={d.final} /> : <div className="red">nothing transmitted — payload blocked</div>}</div></div>
      </div>
      <div className="grid g2">
        <Card title="Integrity">
          <div className="small mono">collector sha256: {d.sha256 || '—'}</div>
          <div className="small mono">SaaS received sha256: {d.saas_sha256 || '—'}</div>
          {d.saas_sha256 && <div style={{ marginTop: 6 }}>{d.saas_sha256 === d.sha256 ? <Badge kind="delivered">SaaS received exactly what is shown above</Badge> : <Badge kind="blocked">hash mismatch</Badge>}</div>}
        </Card>
        <Card title="Transmission attempts (TX IDs)">
          {att.length === 0 ? <div className="mut small">not yet attempted</div> : <table><thead><tr><th>TX id</th><th>Time</th><th>Outcome</th><th>HTTP</th></tr></thead><tbody>
            {att.map((a, i) => <tr key={i}><td className="mono small">{a.tx_id}{a.replay ? ' (deliberate re-send)' : ''}</td><td className="mono small">{a.ts?.slice(11, 23)}</td><td><Badge kind={a.outcome === 'accepted' ? 'delivered' : a.outcome === 'duplicate_acked' ? 'neutral' : 'buffered'}>{a.outcome}</Badge></td><td>{a.http_status ?? ''} <span className="mut small">{a.ms ? a.ms + 'ms' : (a.detail || '')}</span></td></tr>)}
          </tbody></table>}
        </Card>
      </div>
    </div>
  )
}

function Egress() {
  const [list] = usePoll(() => api('/api/egress?limit=60', { token: null }), 1500)
  const [sel, setSel] = useState(null)
  const [only, setOnly] = useState(false)
  const rows = (list || []).filter(r => !only || r.blocked_count > 0 || r.status.startsWith('blocked'))
  const cur = sel || rows[0]?.payload_id
  return (
    <div className="grid" style={{ gridTemplateColumns: '360px 1fr', alignItems: 'start' }}>
      <Card title="Egress log — every payload" right={<label className="small"><input type="checkbox" checked={only} onChange={e => setOnly(e.target.checked)} /> blocked only</label>} style={{ maxHeight: '78vh', overflow: 'auto' }}>
        <table><thead><tr><th>Seq</th><th>Time</th><th>Status</th><th>Ev</th><th>Blk</th></tr></thead><tbody>
          {rows.map(r => <tr key={r.payload_id} className={'click' + (cur === r.payload_id ? ' sel' : '')} onClick={() => setSel(r.payload_id)}>
            <td className="mono">{r.seq || '—'}</td><td className="mono small">{fmtT(r.created_ms)}</td><td><Badge kind={r.status.split(' ')[0]}>{r.status.split(' ')[0]}</Badge></td><td>{r.event_count}</td><td className={r.blocked_count ? 'red' : 'mut'}>{r.blocked_count}</td></tr>)}
        </tbody></table>
      </Card>
      <Card title="Egress Proof — exactly what this payload contained before it left">{cur ? <EgressDetail id={cur} /> : <div className="mut">no payloads yet</div>}</Card>
    </div>
  )
}

function Buffer() {
  const [st] = usePoll(() => api('/api/status', { token: null }), 1000)
  const [ob] = usePoll(() => api('/api/outbox?limit=30', { token: null }), 1500)
  const [rec, setRec] = useState(null)
  const [err, setErr] = useState('')
  if (!st) return null
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g4">
        <Kpi label="Link to SaaS" value={st.link.state} color={st.link.state === 'connected' ? '#2ecc71' : '#f5a524'} sub={st.link.last_error || 'TLS · API-key authenticated'} />
        <Kpi label="Buffered payloads" value={st.outbox.pending} sub={`oldest ${st.outbox.oldest_pending_s}s · seq ${st.outbox.pending_seq_range?.join('–') || '—'}`} />
        <Kpi label="Delivered (acked)" value={st.outbox.sent} sub={`last seq ${st.last_seq}`} />
        <Kpi label="Retry attempts" value={st.stats.retries} sub={`fail streak ${st.link.fail_streak}`} />
      </div>
      <Card title="Delivery reconciliation — sent IDs vs received IDs" right={<button className="btn pri sm" onClick={() => api('/api/reconcile', { method: 'POST', token: null }).then(setRec).catch(e => setErr(String(e)))}>Reconcile with SaaS</button>}>
        {err && <div className="err">{err}</div>}
        {rec ? <div className="grid g4">
          <Kpi label="Local payloads" value={rec.local_payloads} sub={`${rec.pending_in_buffer} still buffered`} />
          <Kpi label="SaaS received" value={rec.saas_received} sub={`${rec.duplicates_ignored_by_saas} duplicates ignored`} />
          <Kpi label="Zero loss" value={rec.zero_loss ? 'YES' : 'NO'} color={rec.zero_loss ? '#2ecc71' : '#ef4444'} sub={`missing: ${rec.missing_at_saas.length}`} />
          <Kpi label="Zero duplicates" value={rec.zero_duplicates ? 'YES' : 'NO'} color={rec.zero_duplicates ? '#2ecc71' : '#ef4444'} sub="stored once per payload id" />
        </div> : <div className="mut small">Run after an outage: every acked payload ID must exist at the SaaS exactly once.</div>}
      </Card>
      <Card title="Outbox (durable SQLite queue)">
        <table><thead><tr><th>Seq</th><th>Payload ID</th><th>Status</th><th>Attempts</th><th>Events</th><th>Created</th><th>Acked</th></tr></thead><tbody>
          {(ob || []).map(r => <tr key={r.seq}><td>{r.seq}</td><td className="mono small">{r.payload_id}</td><td><Badge kind={r.status} /></td><td>{r.attempts}</td><td>{r.event_count}</td><td className="mono small">{fmtT(r.created_ms)}</td><td className="mono small">{fmtT(r.sent_ms)}</td></tr>)}
        </tbody></table>
      </Card>
    </div>
  )
}

function Firewall() {
  const [rules] = usePoll(() => api('/api/firewall/rules', { token: null }), 60000)
  const [txt, setTxt] = useState('db_url=postgres://admin:S3cr3tP@ss@10.0.0.5/prod Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk card=4111 1111 1111 1111')
  const [out, setOut] = useState(null)
  const [done, setDone] = useState(false)
  return (
    <div className="grid g2" style={{ alignItems: 'start' }}>
      <Card title="Allow-list (data contract across the trust boundary)">
        {rules && <><div className="small mut">Top-level fields: <span className="mono">{rules.top_fields.join(', ')}</span></div>
          <table style={{ marginTop: 8 }}><thead><tr><th>Event type</th><th>Allowed context keys</th></tr></thead><tbody>
            {Object.entries(rules.context_allow).map(([k, v]) => <tr key={k}><td><b>{k}</b></td><td className="mono small">{Object.entries(v).map(([a, b]) => `${a}:${b}`).join(', ') || '—'}</td></tr>)}
          </tbody></table>
          <div className="callout small" style={{ marginTop: 8 }}>Anything else is dropped. Allowed strings are scanned for secrets/PII, truncated to 140 chars, and re-scanned. The SaaS re-validates the same contract and <b>rejects</b> non-conforming payloads.</div></>}
      </Card>
      <div className="col">
        <Card title="Redaction tester">
          <textarea style={{ width: '100%', height: 80 }} value={txt} onChange={e => setTxt(e.target.value)} />
          <button className="btn pri sm" style={{ marginTop: 6 }} onClick={() => api('/api/redact-preview', { method: 'POST', body: { text: txt }, token: null }).then(setOut)}>Scan & redact</button>
          {out && <div className="pane" style={{ marginTop: 8 }}><pre><RedText t={out.redacted} /></pre><div className="small mut">{out.findings.map(f => f.label).join(', ')}</div></div>}
        </Card>
        <Card title="Firewall self-test (attack the firewall)">
          <div className="small mut">Submits an unsafe candidate event: secrets and PII inside allowed fields, extra raw fields, and a raw token smuggled into a message. Inspect the result in the Egress Proof tab (filter: blocked only).</div>
          <button className="btn dng sm" style={{ marginTop: 8 }} onClick={() => api('/api/firewall/selftest', { method: 'POST', token: null }).then(() => setDone(true))}>Attempt unsafe egress</button>
          {done && <span className="small" style={{ marginLeft: 10 }}>submitted — see Egress Proof</span>}
        </Card>
      </div>
    </div>
  )
}

function AuditCfg() {
  const [a] = usePoll(() => api('/api/audit?limit=100', { token: null }), 2000)
  const [cfg, , reload] = usePoll(() => api('/api/config', { token: null }), 5000)
  const [ret, setRet] = useState('')
  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr 320px', alignItems: 'start' }}>
      <Card title="Local audit trail (data-transfer & control actions)">
        <table><thead><tr><th>Time (UTC)</th><th>Kind</th><th>Detail</th></tr></thead><tbody>
          {(a || []).map(r => <tr key={r.id}><td className="mono small">{fmtDT(r.ts_ms)}</td><td><Badge kind="neutral">{r.kind}</Badge></td><td className="small">{r.detail}</td></tr>)}
        </tbody></table>
      </Card>
      <Card title="Local retention controls">
        {cfg && <><div className="small">Raw log retention: <b>{cfg.config.retention_s}s</b></div><div className="small">Egress log retention: <b>{cfg.config.egress_retention_s}s</b></div><div className="small mut">config version {cfg.version}</div>
          <div className="row" style={{ marginTop: 8 }}><input style={{ width: 100 }} placeholder="seconds" value={ret} onChange={e => setRet(e.target.value)} />
            <button className="btn sm" onClick={() => api('/api/config', { method: 'PUT', body: { retention_s: +ret }, token: null }).then(reload)}>Set raw-log retention</button></div></>}
      </Card>
    </div>
  )
}

function LocalAnon() {
  const [a] = usePoll(() => api('/api/anon', { base: CB, token: null }), 3000)
  if (!a) return <div className="mut">loading…</div>
  const fld = (k, v) => <div className="small" style={{ display: 'flex', gap: 8 }}><span className="mut" style={{ minWidth: 120 }}>{k}</span><span className="mono" style={{ wordBreak: 'break-all' }}>{String(v)}</span></div>
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g4">
        <Kpi label="Local anonymisation" value={a.enabled ? 'Enabled' : 'Disabled'} color={a.enabled ? '#2ecc71' : '#ef4444'} sub={a.enabled ? `host sees: ${a.alias || a.public_label}` : 'host will flag this collector'} />
        <Kpi label="Records processed" value={a.stats.records} />
        <Kpi label="Identifying fields removed" value={a.stats.removed} />
        <Kpi label="Fields pseudonymised" value={a.stats.pseudonymised} />
      </div>
      {a.legacy_identity_at_host && <div className="callout small">This laptop was enrolled under its real name before anonymisation existed, so the host's collector id still contains it. Re-enrol with the setup page to get a pseudonymous id.</div>}
      <Card title="BEFORE vs AFTER — real events from this laptop (BEFORE never leaves it)">
        {a.pairs.length === 0 ? <div className="mut small">No event with identifying content has been queued yet (metrics are already pseudonymous at the source). Use the Scenario Simulator → failed logins, or the custom log line box, to see log-derived data being anonymised.</div> :
          a.pairs.map((p, i) => <div key={i} className="grid g2" style={{ marginBottom: 10 }}>
            <div><h3>BEFORE (local only)</h3><div style={{ maxHeight: 220, overflow: 'auto' }}><Json v={p.before} /></div></div>
            <div><h3>AFTER (queued for transmission)</h3><div style={{ maxHeight: 220, overflow: 'auto' }}><Json v={p.after} /></div></div></div>)}
      </Card>
      <div className="grid g2">
        <Card title="Retained"><ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{a.retained.map(x => <li key={x}>{x}</li>)}</ul></Card>
        <Card title="Removed or replaced before sending"><ul className="small" style={{ margin: 0, paddingLeft: 18 }}>{a.removed.map(x => <li key={x}>{x}</li>)}</ul></Card>
      </div>
      <Card title="Local pseudonym mapping (stays on this laptop — never transmitted)">
        {fld('Pseudonym', a.mapping_local_only.alias)}
        {Object.entries(a.mapping_local_only.identifiers).map(([k, v]) => <div key={k}>{fld(k.replace('_', ' '), v.join(', '))}</div>)}
        <div className="small mut" style={{ marginTop: 6 }}>Stored in a local file with restricted permissions. Anyone with access to this laptop's files can reverse the pseudonym.</div>
      </Card>
      <Card title="Transport (TLS)">
        {fld('Scheme', a.transport.scheme)}{fld('Certificate verification', a.transport.certificate_verification)}{fld('Trust anchor', a.transport.trust)}{fld('Minimum TLS', a.transport.min_tls)}
        {a.transport.end_to_end === false && <div className="small" style={{ marginTop: 4 }}>This host is reached through ngrok: your connection to ngrok is TLS-verified, but ngrok terminates TLS, so this is <b>not end-to-end TLS</b>. That is why identifiers are removed before sending.</div>}
        {a.transport.last_error && <div className="callout small" style={{ marginTop: 6 }}>Last TLS problem: {a.transport.last_error}</div>}
      </Card>
    </div>
  )
}

export default function CollectorApp({ who }) {
  const [tab, setTab] = useState('console')
  const [st] = usePoll(() => api('/api/status', { token: null }), 1500)
  return (
    <div className="app" style={{ flexDirection: 'column' }}>
      <div className="top">
        <div className="brand" style={{ padding: 0 }}>SENTINEL <span>X</span> <small style={{ display: 'inline', marginLeft: 8 }}>Local Collector · customer environment</small></div>
        <Badge kind="neutral">{who.collector_id}</Badge><Badge kind="neutral">tenant: {who.tenant}</Badge><Badge kind="neutral">{who.region}</Badge><Badge kind="neutral">tz {who.source_tz}</Badge>
        <Badge kind="neutral">host metrics: {who.host_mode}</Badge>
        <div className="sp" />
        {st && <Badge kind={st.link.state === 'connected' ? 'delivered' : 'buffered'}>SaaS link: {st.link.state}</Badge>}
        {who.saas_ui && <a href={who.saas_ui} target="_blank" rel="noreferrer">Open SaaS dashboard ↗</a>}
      </div>
      <div className="page">
        <Tabs value={tab} onChange={setTab} tabs={[['console', 'Console'], ['egress', 'Egress Proof Panel'], ['buffer', 'Buffer & Delivery'], ['sim', 'Scenario Simulator'], ['fw', 'Privacy Firewall'], ['anon', 'Local Anonymisation'], ['audit', 'Audit & Retention']]} />
        {tab === 'console' && <Console />}{tab === 'egress' && <Egress />}{tab === 'buffer' && <Buffer />}{tab === 'sim' && <Simulator />}{tab === 'fw' && <Firewall />}{tab === 'anon' && <LocalAnon />}{tab === 'audit' && <AuditCfg />}
      </div>
    </div>
  )
}
