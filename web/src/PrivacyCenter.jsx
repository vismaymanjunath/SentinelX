import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, usePoll, fmtDT, num } from './api'
import { Badge, Card, Kpi } from './ui'

// Enterprise Privacy Center additions. Everything is read from the platform; each indicator says WHO established it:
//  HOST-VERIFIED = the host measured/checked it itself;  COLLECTOR-REPORTED = a device told us (the host cannot independently confirm it).
const HV = <Badge kind="delivered">host-verified</Badge>
const CR = <Badge kind="info">collector-reported</Badge>

export function PrivacyStatus({ ov, tls }) {
  const { t } = useTranslation()
  const tt = ov.tls_totals, eg = ov.egress_totals, viol = ov.violations.reduce((a, v) => a + v.count, 0)
  const checks = [
    { k: 'Local anonymisation', who: CR, ok: ov.status === 'Enabled' ? 2 : ov.status === 'Disabled' ? 0 : 1, text: `${ov.status}: ${ov.collectors_enabled}/${ov.collectors_total} devices declare it enabled` },
    { k: 'Host re-check of payloads (policy)', who: HV, ok: viol ? 1 : 2, text: viol ? `${viol} policy violation(s) rejected or flagged` : 'no violations found in received data' },
    { k: 'Egress hash proof', who: HV, ok: eg.mismatch ? 0 : eg.verified_match ? 2 : 1, text: eg.mismatch ? `${eg.mismatch} MISMATCH between collector and host hash` : `${eg.verified_match} device(s): collector hash = host hash` },
    { k: 'Certificate verification by collectors', who: CR, ok: tt.reporting && tt.verified === tt.reporting && !tt.errors ? 2 : tt.reporting ? 0 : 1, text: tt.reporting ? `${tt.verified}/${tt.reporting} reporting devices verified${tt.errors ? `, ${tt.errors} with errors` : ''}` : 'no device has reported yet' },
    { k: 'Host certificate validity', who: HV, ok: tls && tls.server_days_left > 30 ? 2 : 0, text: tls ? `${num(tls.server_days_left, 0)} days left (CA ${num(tls.ca_days_left, 0)})` : '…' },
    { k: 'End-to-end TLS on the ngrok route', who: HV, ok: tt.tunnel ? 1 : 2, text: tt.tunnel ? `${tt.tunnel} device(s) reach the host via ngrok: TLS ends at the ngrok edge, so this is NOT end-to-end. Anonymisation is what limits exposure there.` : 'no device uses the ngrok route' },
  ]
  const worst = Math.min(...checks.map(c => c.ok))
  const lvl = worst === 0 ? ['AT RISK', '#ef4444'] : worst === 1 ? ['PARTIALLY PROTECTED', '#f5a524'] : ['PROTECTED', '#2ecc71']
  const dot = ['#ef4444', '#f5a524', '#2ecc71']
  return (
    <div className="banner" style={{ borderColor: lvl[1], background: lvl[1] + '12', alignItems: 'flex-start' }}>
      <div><div className="mut small">{t('PRIVACY PROTECTION STATUS')}</div><div className="big-state" style={{ color: lvl[1] }}>{t(lvl[0])}</div>
        <div className="small mut" style={{ maxWidth: 200 }}>Worst of the checks on the right. Nothing here is a score we made up.</div></div>
      <div className="sp">{checks.map(c => <div key={c.k} className="row small" style={{ padding: '2px 0', alignItems: 'flex-start' }}>
        <i className="dot" style={{ background: dot[c.ok], marginTop: 4 }} /><div style={{ flex: 1 }}><b>{c.k}</b> {c.who}<div className="mut">{c.text}</div></div></div>)}</div>
    </div>
  )
}

export function Inventory() {
  const [c] = usePoll(() => api('/api/privacy/contract'), 60000)
  const [ov] = usePoll(() => api('/api/privacy/overview'), 10000)
  if (!c || !ov) return <div className="mut">loading…</div>
  const col = (t, color, items, foot) => <Card title={t} style={{ borderTop: '3px solid ' + color }}><ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.5 }}>{items.map(x => <li key={x}>{x}</li>)}</ul>{foot && <div className="small mut" style={{ marginTop: 6 }}>{foot}</div>}</Card>
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="grid g3" style={{ alignItems: 'start' }}>
        {col('Collected on connected devices', '#38bdf8', ['CPU, RAM, disk, battery and network readings', 'Log lines and error messages (scanned locally)', 'Device name, OS/platform, IP addresses and account names present on the machine', 'Service and link health measurements'], 'Collection happens on the device, by the collector. The device owner controls it.')}
        {col('Stays local on the collector', '#2ecc71', [...ov.removed, 'the name ↔ pseudonym mapping', 'raw (unredacted) log lines'], `Removed/pseudonymised locally so far: ${ov.totals.removed} identifying values across ${ov.totals.records} records.`)}
        {col('Transmitted to the SaaS host', '#c084fc', ov.retained, 'Only fields on the data-contract allow-list below, after anonymisation, over TLS.')}
      </div>
      <Card title="The data contract (allow-list) — enforced on the device and re-checked by the host">
        <div className="small" style={{ lineHeight: 1.6 }}>
          <div><b>Event fields allowed:</b> <span className="mono">{c.top_fields.join(', ')}</span></div>
          <div><b>Event types:</b> <span className="mono">{c.event_types.join(', ')}</span></div>
          <div><b>Heartbeat fields:</b> <span className="mono">{c.heartbeat_fields.join(', ')}</span></div>
          <div><b>Identifying fields removed on the device:</b> <span className="mono">{c.identifying_fields_removed_locally.join(', ')}</span></div>
          <div><b>Host policy:</b> v{ov.policy.version} · {ov.policy.mode}</div>
          <div><b>Always rejected by the host:</b> {ov.policy.always_rejected.join(' · ')}</div></div>
      </Card>
      <Card title="Sensitive-data detection and blocked fields (per device, as reported by each collector's privacy firewall)">
        <table><thead><tr><th>Device</th><th>Anonymisation <span className="mut">(reported)</span></th><th>Fields blocked</th><th>Redactions</th><th>Events blocked</th><th>Host policy blocks <span className="mut">(host)</span></th></tr></thead><tbody>
          {ov.devices.map(d => <tr key={d.id}><td><b>{d.device_id}</b></td><td className="small">{d.anonymisation}</td>
            <td>{d.privacy_reported ? d.firewall.blocked_fields : <span className="mut small">not reported</span>}</td><td>{d.privacy_reported ? d.firewall.redactions : '—'}</td><td>{d.privacy_reported ? d.firewall.blocked_events : '—'}</td><td>{d.firewall.policy_blocked}</td></tr>)}</tbody></table>
      </Card>
    </div>
  )
}

export function RetentionAudit({ me }) {
  const [r] = usePoll(() => api('/api/privacy/retention'), 15000)
  const [aud] = usePoll(() => api('/api/audit?limit=300'), 8000)
  const [dels, , reload] = usePoll(() => api('/api/privacy/deletions'), 4000)
  const [ov] = usePoll(() => api('/api/privacy/overview'), 20000)
  const [dev, setDev] = useState(''), [why, setWhy] = useState(''), [msg, setMsg] = useState(''), [conf, setConf] = useState({}), [f, setF] = useState('privacy')
  const admin = me?.role === 'admin'
  const act = async (path, body) => { setMsg(''); try { await api(path, { method: 'POST', body }); reload() } catch (e) { setMsg(e.message) } }
  const logs = (aud || []).filter(a => f === 'all' || a.action.startsWith(f) || (f === 'privacy' && /^(privacy|config|tls|rem\.)/.test(a.action)))
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="Data retention (actual configuration)">
        {!r ? <div className="mut">loading…</div> : <><div className="grid g4">
          <Kpi label="Telemetry retention" value={`${r.telemetry_retention_hours} h`} sub="older events are deleted automatically" />
          <Kpi label="Events stored" value={r.events_stored} sub={r.oldest_event_ms ? `oldest ${fmtDT(r.oldest_event_ms)}` : ''} />
          <Kpi label="Exact payload bodies" value={r.payload_bodies_kept} sub={`newest ${r.payload_bodies_kept_per_device} per device; older keep a hash only`} />
          <Kpi label="Audit entries" value={r.audit_entries} sub="append-only" /></div>
          <ul className="small" style={{ paddingLeft: 18 }}>{r.notes.map(n => <li key={n}>{n}</li>)}</ul></>}
      </Card>
      <Card title="Data-deletion requests">
        <div className="small mut" style={{ marginBottom: 6 }}>Request deletion of all telemetry this host holds for a device. An admin approves with a typed confirmation; approval really deletes it from this host and is audited. Data on the device itself is not reachable from here.</div>
        <div className="row wrap"><select value={dev} onChange={e => setDev(e.target.value)}><option value="">choose a device…</option>{(ov?.devices || []).map(d => <option key={d.id} value={d.id}>{d.device_id}</option>)}</select>
          <input placeholder="reason (required)" value={why} onChange={e => setWhy(e.target.value)} style={{ width: 280 }} maxLength={200} />
          <button className="btn pri" disabled={!dev || why.trim().length < 5} onClick={() => { act('/api/privacy/deletions', { collector_id: dev, reason: why }); setWhy('') }}>Submit request</button></div>
        {msg && <div className="callout small" style={{ marginTop: 6, borderColor: '#ef4444' }}>{msg}</div>}
        <table style={{ marginTop: 8 }}><thead><tr><th>#</th><th>Device</th><th>Reason</th><th>Requested by</th><th>Status</th><th>Outcome</th></tr></thead><tbody>
          {(dels || []).map(d => <tr key={d.id}><td className="mono">{d.id}</td><td className="small">{d.collector_id}</td><td className="small">{d.reason}</td><td className="small">{d.requested_by}<div className="mut mono">{fmtDT(d.requested_ms)}</div></td>
            <td><Badge kind={d.status === 'completed' ? 'delivered' : d.status === 'rejected' ? 'blocked' : 'warning'}>{d.status}</Badge></td>
            <td className="small">{d.status === 'pending' ? (admin ? <div className="row wrap"><input placeholder="type DELETE" value={conf[d.id] || ''} onChange={e => setConf({ ...conf, [d.id]: e.target.value })} style={{ width: 100 }} />
              <button className="btn sm dng" disabled={(conf[d.id] || '') !== 'DELETE'} onClick={() => act(`/api/privacy/deletions/${d.id}/approve`, { confirm_text: conf[d.id] })}>Approve & delete</button>
              <button className="btn sm" onClick={() => act(`/api/privacy/deletions/${d.id}/reject`, {})}>Reject</button></div> : <span className="mut">awaiting an admin</span>)
              : d.result ? <>deleted {Object.entries(d.result.deleted).map(([k, v]) => `${v} ${k.replace(/_/g, ' ')}`).join(', ')}<div className="mut">kept: {d.result.kept.join('; ')}</div></> : <span className="mut">nothing was deleted · by {d.decided_by}</span>}</td></tr>)}
          {(dels || []).length === 0 && <tr><td colSpan={6} className="mut">No requests yet.</td></tr>}</tbody></table>
      </Card>
      <Card title="Privacy & configuration audit log" right={<select value={f} onChange={e => setF(e.target.value)}><option value="privacy">privacy / config / TLS / remediation</option><option value="all">everything</option></select>}>
        <div style={{ maxHeight: 320, overflow: 'auto' }}><table><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>
          {logs.slice(0, 120).map(a => <tr key={a.id}><td className="mono small">{fmtDT(a.ts_ms)}</td><td className="small">{a.actor}</td><td className="small"><b>{a.action}</b></td><td className="small mut" style={{ wordBreak: 'break-all' }}>{String(a.detail).slice(0, 160)}</td></tr>)}
          {logs.length === 0 && <tr><td colSpan={4} className="mut">No matching entries.</td></tr>}</tbody></table></div>
      </Card>
    </div>
  )
}
