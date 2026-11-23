import React, { useEffect, useMemo, useState } from 'react'
import { api, usePoll, num } from './api'
import { Badge, Card, Kpi } from './ui'

// "Data Flow & Security": an explanatory walkthrough. Every status/number on it comes from the live platform
// (/api/privacy/overview, /api/tls/status, /api/cloud/preview [the real anonymiser], /api/cloud/last-payload). Illustrations are labelled as such.
const ZONE = { local: ['#2ecc71', 'PLAINTEXT · on the device'], net: ['#c084fc', 'ENCRYPTED · in transit'], host: ['#22d3ee', 'DECRYPTED · on the host'] }
const STAGES = [
  { id: 1, zone: 'local', icon: '💻', title: 'Original data', sub: 'on the source device' },
  { id: 2, zone: 'local', icon: '🧹', title: 'Local anonymisation', sub: 'before anything is sent' },
  { id: 3, zone: 'net', icon: '🔒', title: 'TLS encryption', sub: 'payload sealed' },
  { id: 4, zone: 'net', icon: '🌐', title: 'Network transmission', sub: 'ciphertext only' },
  { id: 5, zone: 'host', icon: '🪪', title: 'Certificate check & decrypt', sub: 'at the receiving endpoint' },
  { id: 6, zone: 'host', icon: '🛡️', title: 'Privacy firewall', sub: 'validation on the host' },
  { id: 7, zone: 'host', icon: '📊', title: 'Dashboard', sub: 'pseudonymised data' },
]
const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, '0')).join('')
const Yn = ({ v, y = 'yes', n = 'no' }) => v == null ? <Badge kind="warning">not reported</Badge> : <Badge kind={v ? 'delivered' : 'blocked'}>{v ? y : n}</Badge>

function Pipeline({ sel, setSel, route }) {
  return (
    <div className="df-pipe">
      {STAGES.map((s, i) => {
        const [col] = ZONE[s.zone]
        return <React.Fragment key={s.id}>
          <div className={'df-node' + (sel === s.id ? ' on' : '')} style={{ '--c': col }} onClick={() => setSel(s.id)} role="button" tabIndex={0} onKeyDown={e => e.key === 'Enter' && setSel(s.id)}>
            <div className="df-ico">{s.icon}</div><div className="df-n">STAGE {s.id}</div><b>{s.title}</b><div className="small mut">{s.sub}</div>
            <div className="df-zone" style={{ color: col, borderColor: col + '66' }}>{ZONE[s.zone][1]}</div>
          </div>
          {i < STAGES.length - 1 && <div className={'df-arrow ' + (STAGES[i + 1].zone === 'net' || s.zone === 'net' ? 'enc' : 'plain')}><i /><i /><i /></div>}
        </React.Fragment>
      })}
    </div>
  )
}

function Anonymiser() {
  const [f, setF] = useState({ username: 'alice', device_name: 'Alices-Laptop', laptop_id: 'LAPTOP-7X', ip: '10.1.2.3', error: 'login failed for alice' })
  const [r, setR] = useState(null), [err, setErr] = useState('')
  useEffect(() => {
    const t = setTimeout(() => api('/api/cloud/preview?' + new URLSearchParams({ ...f, cpu: 95 })).then(x => { setR(x); setErr('') }).catch(e => setErr(e.message)), 300)
    return () => clearTimeout(t)
  }, [f])
  const J = ({ v }) => <pre className="mono small df-json">{JSON.stringify(v, null, 2)}</pre>
  const strip = (o) => { if (!o) return o; const { event_id, event_time, source_tz, ...rest } = o; return rest }
  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="small mut">Edit the sample values: this runs the <b>same anonymiser the collectors run</b> (server endpoint, stateless, nothing stored). Sample data typed here is not telemetry.</div>
      <div className="row wrap">{Object.keys(f).map(k => <label key={k} className="small mut">{k} <input value={f[k]} maxLength={80} onChange={e => setF({ ...f, [k]: e.target.value })} style={{ width: 150 }} /></label>)}</div>
      {err && <div className="callout small">{err}</div>}
      {r && <div className="grid g2">
        <div><Badge kind="warning">BEFORE · plaintext, stays on the device</Badge><J v={strip(r.before)} /></div>
        <div><Badge kind="delivered">AFTER · what is allowed to leave</Badge><J v={strip(r.after)} /></div></div>}
      {r && <div className="small">Result: <b>{r.removed}</b> identifying field(s)/values removed, <b>{r.pseudonymised}</b> name(s) replaced by the pseudonym <b>{r.alias}</b>. The name↔pseudonym mapping stays on the device.</div>}
    </div>
  )
}

function Handshake({ tls, route }) {
  const [step, setStep] = useState(0)
  const T = tls?.transport
  const steps = [
    ['ClientHello', 'The collector opens a TCP connection and offers TLS 1.2+ and its cipher suites. Plain HTTP is refused by the host (HTTP 426).'],
    ['Server certificate', route === 'ngrok' ? "ngrok's edge presents its public certificate." : `The host presents its certificate for ${(tls?.server_names || []).join(', ') || 'its configured names'}, valid ${tls ? num(tls.server_days_left, 0) : '?'} more days.`],
    ['Trust verification', route === 'ngrok' ? "The collector checks the chain against the operating system's public CA store and the host name. Verification can never be switched off; if it fails, the collector refuses to send." : `The collector checks the chain against the pinned private CA (SHA-256 ${tls?.ca_fingerprint_sha256 ? tls.ca_fingerprint_sha256.slice(0, 23) + '…' : '?'}) and the host name. If anything differs, it refuses to send.`],
    ['Key agreement', 'Both sides derive fresh session keys (ephemeral key exchange); the keys are never sent over the network.'],
    ['Encrypted records', 'The anonymised JSON payload is sealed into encrypted, integrity-protected records. Anyone on the path sees only ciphertext and its size.'],
  ]
  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="row wrap">{steps.map((s, i) => <button key={i} className={'btn sm' + (step === i ? ' pri' : '')} onClick={() => setStep(i)}>{i + 1}. {s[0]}</button>)}</div>
      <div className="callout small"><b>{steps[step][0]}.</b> {steps[step][1]}</div>
      <div className="small mut">Certificate details shown are the host's real configuration{T ? '' : ' (unavailable)'}. <b>Transport encryption protects data in transit; it is not anonymisation</b>, and anonymisation does not encrypt anything.</div>
    </div>
  )
}

export default function DataFlow({ go }) {
  const [ov] = usePoll(() => api('/api/privacy/overview'), 5000)
  const [tls] = usePoll(() => api('/api/tls/status'), 30000)
  const [lp] = usePoll(() => api('/api/cloud/last-payload'), 5000)
  const [kp] = usePoll(() => api('/api/overview'), 10000)
  const [sel, setSel] = useState(1)
  const [route, setRoute] = useState('direct')
  const [who, setWho] = useState('cloud')
  const payloadText = useMemo(() => lp?.payload ? JSON.stringify(lp.payload) : '', [lp?.payload?.payload_id])
  const cipher = useMemo(() => hex(Math.min(96, Math.max(24, Math.round(payloadText.length / 8)))), [payloadText])
  const T = ov?.transport, tt = ov?.tls_totals, fw = ov?.firewall_totals, eg = ov?.egress_totals
  const stage = STAGES.find(s => s.id === sel)
  const J = ({ v }) => <pre className="mono small df-json">{JSON.stringify(v, null, 2)}</pre>
  const SEE = {
    cloud: { title: 'SENTINEL X cloud / host', can: ['Pseudonymous device IDs (Device-NN)', 'Metric values, severities, categories, timestamps', 'Redacted messages with [REMOVED:…] markers', 'Collector health: version, buffer, link state, TLS result (self-reported)'], cannot: ['Usernames, real hostnames, IP addresses (removed or pseudonymised on the device)', 'Raw log lines and file contents', 'Passwords, API keys, tokens (detected and redacted locally; the host firewall refuses anything that still matches)', 'The name↔pseudonym mapping'] },
    ngrok: { title: 'ngrok edge (remote collectors only)', can: ['The anonymised payload in plaintext: ngrok terminates TLS at its edge', 'Source IP of the connection and request timing/size'], cannot: ['Original (pre-anonymisation) data: it never left the device', 'The dashboard, Ollama, or collector consoles: never tunnelled'] },
    net: { title: 'Anyone on the network path', can: ['That a connection exists, its endpoints, timing and size'], cannot: ['Payload contents (TLS ciphertext)', 'Anything that was removed before encryption'] },
  }[who]
  const info = {
    1: <><p className="small">Telemetry is produced and read on the device: CPU/RAM/disk numbers, network counters and log lines. Raw logs and identities <b>never leave this stage</b>.</p><div className="small mut">Collectors reporting now: <b>{kp ? `${kp.kpis.collectors_online}/${kp.kpis.collectors_total}` : '…'}</b>. The collector's own local console shows the raw data; this dashboard cannot.</div></>,
    2: <><p className="small">Before sending, the collector strips or pseudonymises identifying fields, redacts secrets/PII patterns inside messages and keeps only fields on the allow-list. Fleet status: <b>{ov?.status || '…'}</b> ({ov ? `${ov.collectors_enabled}/${ov.collectors_total}` : '…'} devices declare it enabled; {ov?.totals.removed ?? '…'} identifying fields removed so far).</p><Anonymiser /></>,
    3: <><p className="small">The anonymised JSON is encrypted by TLS on the way out. <b>Encryption is separate from anonymisation</b>: it hides content from observers on the path, it does not remove sensitive values.</p>
      <div className="grid g2"><div><Badge kind="warning">plaintext payload (after anonymisation, before TLS)</Badge><pre className="mono small df-json" style={{ maxHeight: 130 }}>{payloadText ? payloadText.slice(0, 420) + (payloadText.length > 420 ? '…' : '') : 'no payload received yet'}</pre><div className="small mut">Real: the latest payload the host received.</div></div>
        <div><Badge kind="info">what an observer on the wire sees</Badge><pre className="mono small df-json df-cipher" style={{ maxHeight: 130 }}>{cipher}…</pre><div className="small mut"><b>Illustration:</b> random bytes of similar size. A real capture is unreadable the same way; this page does not capture traffic.</div></div></div></>,
    4: <><p className="small">Only encrypted TLS records cross the network. Choose a route to see what is actually protected where.</p>
      <div className="row"><button className={'btn sm' + (route === 'direct' ? ' pri' : '')} onClick={() => setRoute('direct')}>Direct TLS (LAN/local)</button><button className={'btn sm' + (route === 'ngrok' ? ' pri' : '')} onClick={() => setRoute('ngrok')}>Remote via ngrok</button>
        <span className="small mut">devices now: {tt ? `${tt.direct} direct · ${tt.tunnel} via tunnel` : '…'}</span></div>
      <div className="df-route">
        {route === 'direct'
          ? <><div className="df-seg" style={{ '--c': '#2ecc71' }}>Collector</div><div className="df-link enc">TLS end to end</div><div className="df-seg" style={{ '--c': '#22d3ee' }}>Host (TLS endpoint)</div></>
          : <><div className="df-seg" style={{ '--c': '#2ecc71' }}>Collector</div><div className="df-link enc">TLS (ngrok public cert)</div><div className="df-seg" style={{ '--c': '#f5a524' }}>ngrok edge<br /><span className="small">TLS ends here</span></div><div className="df-link plain">ngrok tunnel → agent → plain HTTP on 127.0.0.1</div><div className="df-seg" style={{ '--c': '#22d3ee' }}>Host</div></>}
      </div>
      {T && (route === 'direct' ? <div className="small">{T.collector_to_host}</div> : <ul className="small" style={{ paddingLeft: 18 }}><li>{T.via_ngrok.collector_to_ngrok}</li><li>{T.via_ngrok.ngrok_to_host}</li><li><b>End-to-end TLS: {T.via_ngrok.end_to_end_tls ? 'yes' : 'NO'}.</b> {T.via_ngrok.note}</li></ul>)}</>,
    5: <><p className="small">The collector verifies the receiver before sending anything, then the endpoint decrypts the TLS records. Verification is self-reported by each collector (a collector that fails refuses to send).</p><Handshake tls={tls} route={route} />
      <div className="row"><button className={'btn sm' + (route === 'direct' ? ' pri' : '')} onClick={() => setRoute('direct')}>Direct TLS</button><button className={'btn sm' + (route === 'ngrok' ? ' pri' : '')} onClick={() => setRoute('ngrok')}>Via ngrok</button></div></>,
    6: <><p className="small">After decryption, the host re-checks every payload against the same data contract and policy, independent of what the collector claims. Violations are rejected or flagged, never stored silently.</p>
      <div className="grid g4"><Kpi label="Fields blocked (device firewall)" value={fw?.blocked_fields ?? '…'} sub="removed before sending" /><Kpi label="Redactions" value={fw?.redactions ?? '…'} /><Kpi label="Host policy blocks" value={fw?.policy_blocked ?? '…'} sub="payloads refused" /><Kpi label="Allow-list rejections" value={kp?.kpis.rejected_payloads ?? '…'} sub="host-side" /></div>
      <div className="small mut">Host policy violations observed: {ov ? (ov.violations.length ? ov.violations.map(v => `${v.code || v.reason || 'violation'} ×${v.count}`).join(', ') : 'none') : '…'}</div></>,
    7: <><p className="small">What you see on the dashboard is the post-firewall data: pseudonymous device IDs, numbers, categories and redacted text. Below: the latest payload exactly as the host stored it.</p>
      {lp?.payload ? <><div className="row wrap small"><Badge kind="delivered">{lp.payload.collector_id}</Badge><span className="mono mut">payload {lp.payload.payload_id.slice(0, 8)}… · seq {lp.payload.seq}</span><Badge kind={lp.policy_findings.length ? 'blocked' : 'delivered'}>{lp.policy_findings.length ? 'findings: ' + lp.policy_findings.join(', ') : 'passes outgoing-data policy'}</Badge></div><div style={{ maxHeight: 220, overflow: 'auto' }}><J v={{ ...lp.payload, events: lp.payload.events.slice(0, 3) }} /></div></> : <div className="mut small">No payload received yet.</div>}
      <div className="row" style={{ marginTop: 6 }}><button className="btn sm" onClick={() => go('overview')}>Open the dashboard</button><button className="btn sm" onClick={() => go('privacy')}>Privacy Center</button></div></>,
  }[sel]
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="How telemetry travels from a collector to this dashboard" right={<span className="small mut">click any stage</span>}>
        <Pipeline sel={sel} setSel={setSel} route={route} />
        <div className="legend small" style={{ marginTop: 8 }}><span style={{ color: '#2ecc71' }}>■ plaintext (stays on the device)</span> <span style={{ color: '#c084fc' }}>■ encrypted in transit (TLS)</span> <span style={{ color: '#22d3ee' }}>■ decrypted on the host</span> · arrows animate in the direction of travel</div>
      </Card>
      <Card title={`Stage ${stage.id} · ${stage.title}`} right={<Badge kind={stage.zone === 'net' ? 'info' : stage.zone === 'local' ? 'delivered' : 'pending'}>{ZONE[stage.zone][1]}</Badge>}>
        <div className="row" style={{ marginBottom: 6 }}><button className="btn sm" disabled={sel <= 1} onClick={() => setSel(sel - 1)}>← Previous</button><button className="btn sm pri" disabled={sel >= 7} onClick={() => setSel(sel + 1)}>Next →</button></div>
        {info}
      </Card>
      <div className="grid g2" style={{ alignItems: 'start' }}>
        <Card title="What can each party see?">
          <div className="row wrap">{[['cloud', 'SaaS host'], ['ngrok', 'ngrok edge'], ['net', 'Network observer']].map(([k, l]) => <button key={k} className={'btn sm' + (who === k ? ' pri' : '')} onClick={() => setWho(k)}>{l}</button>)}</div>
          <h3 style={{ margin: '8px 0 4px' }}>{SEE.title}</h3>
          <div className="small"><b style={{ color: '#2ecc71' }}>Can see</b><ul style={{ margin: '2px 0 8px', paddingLeft: 18 }}>{SEE.can.map(x => <li key={x}>{x}</li>)}</ul>
            <b style={{ color: '#ef4444' }}>Cannot see</b><ul style={{ margin: '2px 0 0', paddingLeft: 18 }}>{SEE.cannot.map(x => <li key={x}>{x}</li>)}</ul></div>
        </Card>
        <Card title="Security status (from this platform's live configuration)">
          {!ov ? <div className="mut">loading…</div> : <table><tbody>
            <tr><td className="small">Local anonymisation</td><td><Badge kind={ov.status === 'Enabled' ? 'delivered' : ov.status === 'Disabled' ? 'blocked' : 'warning'}>{ov.status}</Badge> <span className="small mut">{ov.collectors_enabled}/{ov.collectors_total} devices declare it</span></td></tr>
            <tr><td className="small">Plain HTTP to ingest</td><td><Badge kind="delivered">refused (426)</Badge></td></tr>
            <tr><td className="small">Collector TLS verification</td><td><Badge kind={tt.verified && tt.verified === tt.reporting ? 'delivered' : 'warning'}>{tt.verified}/{tt.reporting} reporting verified</Badge> {tt.errors > 0 && <Badge kind="warning">{tt.errors} with errors</Badge>}</td></tr>
            <tr><td className="small">Routes in use</td><td className="small">{tt.direct} direct TLS · {tt.tunnel} via ngrok tunnel</td></tr>
            <tr><td className="small">End-to-end TLS</td><td><Badge kind="delivered">direct route: yes</Badge> <Badge kind="warning">ngrok route: NO (terminates at ngrok edge)</Badge></td></tr>
            <tr><td className="small">Host certificate</td><td className="small">{tls ? `${num(tls.server_days_left, 0)} days left · CA ${num(tls.ca_days_left, 0)} days` : '…'}</td></tr>
            <tr><td className="small">Egress hash proofs</td><td><Badge kind={eg.mismatch ? 'blocked' : 'delivered'}>{eg.verified_match} match{eg.mismatch ? ` · ${eg.mismatch} MISMATCH` : ''}</Badge></td></tr>
            <tr><td className="small">Host policy violations</td><td><Badge kind={ov.violations.length ? 'warning' : 'delivered'}>{ov.violations.reduce((a, v) => a + v.count, 0)}</Badge></td></tr>
            <tr><td className="small">Dashboard / Ollama</td><td className="small">127.0.0.1 only; never tunnelled</td></tr>
          </tbody></table>}
          {ov?.caveats?.length > 0 && <div className="small mut" style={{ marginTop: 6 }}>Caveats reported by the platform: {ov.caveats.join(' · ')}</div>}
        </Card>
      </div>
    </div>
  )
}

const DEMO = { username: 'alice', device_name: 'Alices-Laptop', laptop_id: 'LAPTOP-7X', ip: '10.1.2.3', error: 'login failed for alice' }
/** Separate page: a form for sample values, and a side-by-side BEFORE (local device) / AFTER (what the cloud receives) result from the real anonymiser. */
export function BeforeAfter() {
  const [f, setF] = useState(DEMO), [r, setR] = useState(null), [err, setErr] = useState(''), [busy, setBusy] = useState(false)
  const run = async (e) => {
    e && e.preventDefault(); setBusy(true); setErr('')
    try { setR(await api('/api/cloud/preview?' + new URLSearchParams({ ...f, cpu: 95 }))) } catch (x) { setErr(x.message) }
    setBusy(false)
  }
  useEffect(() => { run() }, [])
  const strip = (o) => { if (!o) return o; const { event_id, event_time, source_tz, ...rest } = o; return rest }
  const J = ({ v }) => <pre className="mono small df-json" style={{ minHeight: 220 }}>{JSON.stringify(v, null, 2)}</pre>
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title="Try it: enter sample data on a device">
        <form onSubmit={run} className="row wrap" style={{ alignItems: 'end' }}>
          {Object.keys(f).map(k => <label key={k} className="small mut" style={{ display: 'block' }}>{k}<br /><input value={f[k]} maxLength={80} onChange={e => setF({ ...f, [k]: e.target.value })} style={{ width: 170 }} /></label>)}
          <button className="btn pri" type="submit" disabled={busy}>{busy ? 'Working…' : 'Show before / after'}</button>
          <button className="btn" type="button" onClick={() => { setF(DEMO); setTimeout(run, 0) }}>Reset example</button>
        </form>
        <div className="small mut" style={{ marginTop: 6 }}>Sample values only (not real telemetry). They go through the same anonymiser the collectors run; nothing is stored.</div>
        {err && <div className="callout small">{err}</div>}
      </Card>
      {r && <div className="grid g2" style={{ alignItems: 'start' }}>
        <Card title="BEFORE — on the local device" right={<Badge kind="warning">plaintext, never leaves</Badge>}><J v={strip(r.before)} /></Card>
        <Card title="AFTER — what the cloud receives" right={<Badge kind="delivered">anonymised</Badge>}><J v={strip(r.after)} />
          <div className="small">Removed <b>{r.removed}</b> identifying value(s) · pseudonymised <b>{r.pseudonymised}</b> name(s) as <b>{r.alias}</b>. The name↔pseudonym mapping stays on the device. TLS then encrypts this in transit (a separate protection).</div></Card>
      </div>}
    </div>
  )
}
