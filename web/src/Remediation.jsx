import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, usePoll, fmtDT, fmtT, ago } from './api'
import { Badge, Card, Kpi, Tabs, PriorityBadge } from './ui'

// ─── constants ───────────────────────────────────────────────────────────────
// Step kind display
const KIND_LABEL = { real: 'AUTOMATED (REAL)', simulated: 'SIMULATED', manual: 'MANUAL' }
const KIND_COLOR = { real: 'delivered', simulated: 'warning', manual: 'neutral' }

// Plan / step status → badge kind
const PLAN_KIND = {
  proposed: 'warning', running: 'pending', executed: 'delivered', failed: 'critical',
  rejected: 'neutral', rolled_back: 'rolled_back', rolling_back: 'pending',
  rollback_failed: 'critical', expired: 'neutral',
}
const PLAN_LABEL = {
  proposed: 'Awaiting Decision', running: 'Executing', executed: 'Completed',
  failed: 'Failed', rejected: 'Rejected', rolled_back: 'Rolled Back',
  rolling_back: 'Rolling Back', rollback_failed: 'Rollback Failed', expired: 'Expired',
}
const STEP_KIND = {
  pending: 'neutral', running: 'pending', succeeded: 'delivered', failed: 'critical',
  skipped: 'neutral', not_executed: 'neutral', manual_pending: 'warning', manual_done: 'delivered',
}
const RISK_KIND = { low: 'delivered', medium: 'warning', high: 'critical' }
const RISK_LABEL = { low: 'Low risk', medium: 'Medium risk', high: 'High risk' }

// Category icons (text-based, no external deps)
const CAT_ICON = {
  Infrastructure: '⚙', Network: '🌐', Security: '🔒', Service: '⚡',
  Collector: '📡', Intelligence: '🧠', Cloud: '☁',
}

// ─── helpers ─────────────────────────────────────────────────────────────────
const age = ms => ms ? ago((Date.now() - ms) / 1000) : '—'

function targetOptions(problem, ov, intel) {
  const ents = (ov?.entities || [])
  if (!problem) return []
  if (problem.metrics.length) return ents.map(e => ({ id: e.id, label: `${e.label || e.id} (${e.type})` }))
  if (problem.id === 'tls_expiry') return [{ id: 'host:tls', label: 'Host TLS certificate' }]
  if (problem.id === 'stale_global_data') return (intel || []).map(s => ({ id: 'intel:' + s.source, label: s.name }))
  return (ov?.collectors || []).map(c => ({ id: 'collector:' + c.id, label: c.name }))
}

// ─── Problem catalogue card ───────────────────────────────────────────────────
function ProblemCard({ p, selected, onSelect, onGenerate, busy, admin, ov, intel }) {
  const observed = p.observed_count > 0
  const catIcon = CAT_ICON[p.category] || '●'
  const stepCounts = p.steps_preview.reduce((acc, [, k]) => { acc[k] = (acc[k] || 0) + 1; return acc }, {})
  return (
    <div
      className="rem-problem-card"
      style={{
        borderLeft: `4px solid ${observed ? '#ef4444' : '#24324f'}`,
        background: selected ? '#131f3a' : '#111a2e',
        cursor: 'pointer',
        transition: 'background .15s',
      }}
      onClick={() => onSelect(p.id)}
    >
      {/* header row */}
      <div className="row" style={{ marginBottom: 6 }}>
        <span style={{ fontSize: 16, marginRight: 6 }}>{catIcon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 13 }}>{p.title}</div>
          <div className="small mut">{p.category}</div>
        </div>
        <Badge kind={observed ? 'critical' : 'neutral'}>
          {observed ? `${p.observed_count} observed` : 'not observed'}
        </Badge>
      </div>

      {/* description */}
      <div className="small mut" style={{ marginBottom: 8 }}>{p.description}</div>

      {/* affected targets */}
      {observed && (
        <div className="small" style={{ marginBottom: 8 }}>
          <span className="mut">Affected: </span>
          {p.observed.slice(0, 3).map((o, i) => (
            <span key={i} style={{ marginRight: 6 }}>
              <span style={{ color: '#ef4444' }}>●</span> {o.label}
              {o.value != null ? <span className="mut"> ({o.metric} {o.value})</span> : null}
            </span>
          ))}
          {p.observed_count > 3 && <span className="mut">+{p.observed_count - 3} more</span>}
        </div>
      )}

      {/* step type pills */}
      <div className="row wrap" style={{ gap: 4, marginBottom: 10 }}>
        {Object.entries(stepCounts).map(([kind, n]) => (
          <span key={kind} className={`badge b-${KIND_COLOR[kind]}`} style={{ fontSize: 10 }}>
            {KIND_LABEL[kind]}{n > 1 ? ` ×${n}` : ''}
          </span>
        ))}
      </div>

      {/* action */}
      <button
        className={`btn sm ${observed ? 'pri' : ''}`}
        disabled={!admin || busy}
        onClick={e => { e.stopPropagation(); onGenerate(p) }}
        style={{ width: '100%' }}
        title={observed ? 'Generate diagnosis plan from real telemetry' : 'Generate plan (problem not currently observed)'}
      >
        {busy ? 'Generating…' : observed ? '▶ Diagnose & Fix' : '▶ Analyse'}
      </button>
    </div>
  )
}

// ─── Execution progress stepper ───────────────────────────────────────────────
function Stepper({ steps }) {
  const icons = { pending: '○', running: '⏳', succeeded: '✓', failed: '✗', skipped: '·', not_executed: '·', manual_pending: '…', manual_done: '✓' }
  const colors = { pending: '#8da0c4', running: '#f5a524', succeeded: '#2ecc71', failed: '#ef4444', skipped: '#8da0c4', not_executed: '#8da0c4', manual_pending: '#38bdf8', manual_done: '#2ecc71' }
  return (
    <div className="rem-stepper">
      {steps.map((s, i) => (
        <div key={s.id} className="rem-step-item" style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 8 }}>
          {/* connector line */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              background: colors[s.status] + '22',
              border: `2px solid ${colors[s.status]}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 13, color: colors[s.status], fontWeight: 700,
            }}>
              {icons[s.status] || '·'}
            </div>
            {i < steps.length - 1 && <div style={{ width: 2, flex: 1, minHeight: 12, background: '#24324f', marginTop: 2 }} />}
          </div>
          {/* step content */}
          <div style={{ flex: 1, paddingBottom: 4 }}>
            <div className="row wrap" style={{ gap: 6, marginBottom: 2 }}>
              <span style={{ fontWeight: 700, fontSize: 12 }}>
                {s.kind === 'manual' ? s.manual_text?.split('.')[0] || s.title : s.title}
              </span>
              <Badge kind={KIND_COLOR[s.kind]} style={{ fontSize: 10 }}>{KIND_LABEL[s.kind]}</Badge>
              {s.destructive && <Badge kind="critical" style={{ fontSize: 10 }}>Destructive</Badge>}
              {s.kind !== 'manual' && <Badge kind={s.reversible ? 'delivered' : 'neutral'} style={{ fontSize: 10 }}>{s.reversible ? 'Reversible' : 'Irreversible'}</Badge>}
            </div>
            <div className="small mut">{s.rationale}</div>
            {/* result */}
            {s.result?.detail && (
              <div className={`small ${s.status === 'failed' ? '' : 'mut'}`} style={{ marginTop: 3, color: s.status === 'failed' ? '#ff8a8a' : undefined }}>
                {s.result.detail}
              </div>
            )}
            {/* rollback */}
            {s.rollback_status && (
              <div className="small" style={{ marginTop: 2, color: s.rollback_status === 'rolled_back' ? '#38bdf8' : '#ff8a8a' }}>
                Rollback: {s.rollback_status.replace(/_/g, ' ')}{s.rollback_result?.detail ? ` — ${s.rollback_result.detail}` : ''}
              </div>
            )}
            {/* manual step full text */}
            {s.kind === 'manual' && s.manual_text && s.status === 'manual_pending' && (
              <div className="callout small" style={{ marginTop: 6, borderColor: '#38bdf8' }}>
                {s.manual_text}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Before / After metric comparison ────────────────────────────────────────
function MetricCompare({ ver, planStatus }) {
  if (!ver && (planStatus === 'running' || planStatus === 'executed')) {
    return (
      <div className="small mut" style={{ padding: 8 }}>
        ⏳ Collecting post-remediation telemetry for comparison… (available within ~30 s of completion)
      </div>
    )
  }
  if (!ver) return null
  const overallColor = { improved: '#2ecc71', no_change: '#f5a524', worse: '#ef4444', not_measurable: '#8da0c4' }
  const overallLabel = { improved: '✓ Improved', no_change: '→ No measurable change', worse: '↓ Worsened', not_measurable: '— Not measurable' }
  return (
    <div>
      <div className="row" style={{ marginBottom: 10, gap: 8 }}>
        <div style={{ fontSize: 20, fontWeight: 800, color: overallColor[ver.overall] }}>
          {overallLabel[ver.overall] || ver.overall}
        </div>
        <div className="small mut">{ver.method}</div>
      </div>
      {ver.metrics.length > 0 && (
        <div className="grid g2" style={{ gap: 8, marginBottom: 8 }}>
          {ver.metrics.map(m => (
            <div key={m.metric} style={{ background: '#0b1426', borderRadius: 6, padding: '8px 12px', border: '1px solid #24324f' }}>
              <div className="small mut" style={{ marginBottom: 4 }}>{m.metric}</div>
              <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                <div>
                  <div className="small mut">Before</div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>{m.before_median}</div>
                </div>
                <div style={{ fontSize: 20, color: '#8da0c4' }}>→</div>
                <div>
                  <div className="small mut">After ({m.samples_after} samples)</div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: m.below_warning_threshold ? '#2ecc71' : '#ef4444' }}>{m.after_median}</div>
                </div>
                <div style={{ marginLeft: 'auto' }}>
                  <div className="small mut">Change</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: m.delta < 0 ? '#2ecc71' : m.delta > 0 ? '#ef4444' : '#8da0c4' }}>
                    {m.delta > 0 ? '+' : ''}{m.delta}
                  </div>
                </div>
              </div>
              <div className="small" style={{ marginTop: 4, color: m.below_warning_threshold ? '#2ecc71' : '#8da0c4' }}>
                {m.below_warning_threshold ? '✓ Below warning threshold' : '✗ Still above threshold'}
              </div>
            </div>
          ))}
        </div>
      )}
      {ver.caveats.map((c, i) => (
        <div key={i} className="callout small" style={{ marginBottom: 4 }}>ℹ {c}</div>
      ))}
    </div>
  )
}

// ─── Full plan view ───────────────────────────────────────────────────────────
function PlanView({ id, me, onChanged }) {
  const { t } = useTranslation()
  const [p, , reload] = usePoll(() => api('/api/rem/plans/' + id), 1500, [id])
  const [confirm, setConfirm] = useState('')
  const [note, setNote] = useState('')
  const [msg, setMsg] = useState('')
  useEffect(() => { setConfirm(''); setNote(''); setMsg('') }, [id])
  if (!p) return <div className="mut small" style={{ padding: 16 }}>Loading plan…</div>

  const admin = me.role === 'admin'
  const act = async (path, body) => {
    setMsg('')
    try {
      await api(`/api/rem/plans/${id}/${path}`, { method: 'POST', body: body || {} })
      reload()
      onChanged && onChanged()
    } catch (e) { setMsg(e.message) }
  }

  const ev = p.evidence?.items || []
  const cited = new Set(p.evidence?.cited || [])
  const canRollback = ['executed', 'failed'].includes(p.status) && p.steps.some(s => s.status === 'succeeded' && s.reversible && !s.rollback_status)
  const ver = p.verification
  const exeSteps = p.steps.filter(s => s.kind !== 'manual')
  const doneCount = exeSteps.filter(s => ['succeeded', 'failed', 'skipped'].includes(s.status)).length
  const pct = exeSteps.length ? Math.round(100 * doneCount / exeSteps.length) : 0
  const isProposed = p.status === 'proposed' && !p.expired

  return (
    <div className="col" style={{ gap: 14 }}>

      {/* ── Plan header ── */}
      <div style={{ background: '#111a2e', border: '1px solid #24324f', borderRadius: 8, padding: '14px 16px' }}>
        <div className="row wrap" style={{ gap: 8, marginBottom: 8 }}>
          <Badge kind={PLAN_KIND[p.status]}>{PLAN_LABEL[p.status] || p.status}</Badge>
          <Badge kind={RISK_KIND[p.risk]}>{RISK_LABEL[p.risk]}</Badge>
          {p.ai?.used && <Badge kind="delivered">✓ AI-enhanced analysis</Badge>}
          {p.needs_confirm && isProposed && <Badge kind="critical">Requires typed confirmation</Badge>}
          <div className="sp" />
          <div className="small mut">Plan #{p.id} · created {age(p.created_ms)}{p.incident_id ? ` · incident #${p.incident_id}` : ''}</div>
        </div>
        <h2 style={{ margin: '0 0 4px' }}>{p.title}</h2>
        {p.diagnosis_summary && <div className="small mut">{p.diagnosis_summary}</div>}
        {/* progress bar */}
        {p.status === 'running' && (
          <div style={{ marginTop: 10 }}>
            <div className="small mut" style={{ marginBottom: 4 }}>Executing step {doneCount + 1} of {exeSteps.length}…</div>
            <div className="bar"><div style={{ width: pct + '%', background: '#4f8cff', transition: 'width .4s' }} /></div>
          </div>
        )}
        {p.status === 'proposed' && (
          <div className="small mut" style={{ marginTop: 6 }}>
            ⚠ Nothing has run. Review the plan below and approve or reject it.
            {p.expired && ' This plan has expired — please generate a fresh one.'}
          </div>
        )}
      </div>

      {/* ── Diagnosis ── */}
      <div className="grid g2" style={{ gap: 14, alignItems: 'start' }}>
        <Card title="Evidence from your telemetry">
          {ev.length === 0
            ? <div className="small mut">No stored telemetry matched this problem at the time of generation.</div>
            : (
              <div>
                {ev.map(e => (
                  <div key={e.id} style={{
                    padding: '7px 10px', borderRadius: 6, marginBottom: 4,
                    background: cited.has(e.id) ? '#1a2a4a' : '#0d1527',
                    border: `1px solid ${cited.has(e.id) ? '#4f8cff55' : '#1b2745'}`,
                  }}>
                    <div className="row" style={{ gap: 8 }}>
                      <span className="mono small" style={{ color: '#4f8cff', flexShrink: 0 }}>{e.id}</span>
                      {cited.has(e.id) && <span className="small" style={{ color: '#4f8cff', fontSize: 10 }}>cited</span>}
                    </div>
                    <div className="small" style={{ marginTop: 2 }}>{e.text}</div>
                  </div>
                ))}
                {p.evidence?.caveats?.length > 0 && p.evidence.caveats.map((c, i) => (
                  <div key={i} className="small mut" style={{ marginTop: 4 }}>ℹ {c}</div>
                ))}
              </div>
            )}
        </Card>

        <Card title="Diagnosis">
          <div style={{ marginBottom: 12 }}>
            <div className="small mut" style={{ marginBottom: 3, textTransform: 'uppercase', letterSpacing: '.06em', fontSize: 10 }}>Root Cause</div>
            <div className="small">{p.root_cause}</div>
          </div>
          <div style={{ marginBottom: 12 }}>
            <div className="small mut" style={{ marginBottom: 3, textTransform: 'uppercase', letterSpacing: '.06em', fontSize: 10 }}>Recommended Fix</div>
            <div className="small">{p.solution}</div>
          </div>
          <div>
            <div className="small mut" style={{ marginBottom: 3, textTransform: 'uppercase', letterSpacing: '.06em', fontSize: 10 }}>Expected Outcome</div>
            <div className="small">{p.expected_outcome}</div>
          </div>
        </Card>
      </div>

      {/* ── Implementation steps ── */}
      <Card title="Implementation steps">
        <div className="small mut" style={{ marginBottom: 10 }}>
          Steps are executed in order. Each step is predefined and allow-listed — no arbitrary commands run.
        </div>
        <Stepper steps={p.steps} />
        {/* manual step acknowledgement */}
        {['running', 'executed', 'failed'].includes(p.status) && admin && p.steps.filter(s => s.kind === 'manual' && s.status === 'manual_pending').length > 0 && (
          <div style={{ marginTop: 10 }}>
            {p.steps.filter(s => s.kind === 'manual' && s.status === 'manual_pending').map(s => (
              <div key={s.id} className="row" style={{ gap: 8, marginBottom: 6 }}>
                <span className="small">{s.manual_text?.split('.')[0] || s.title}</span>
                <button className="btn sm" onClick={() => act(`steps/${s.id}/manual-done`, { note: 'done' })}>
                  Mark as done
                </button>
              </div>
            ))}
          </div>
        )}
        {/* legend */}
        <div className="small mut" style={{ marginTop: 10, display: 'flex', gap: 14, flexWrap: 'wrap' }}>
          <span><Badge kind="delivered">REAL</Badge> automated action on the device</span>
          <span><Badge kind="warning">SIMULATED</Badge> test environment only, no real change</span>
          <span><Badge kind="neutral">MANUAL</Badge> instructions for an operator</span>
        </div>
      </Card>


      {/* ── Decision bar (proposed only) ── */}
      {isProposed && (
        <Card title="Your decision — nothing runs until you approve">
          {p.needs_confirm && (
            <div className="callout" style={{ marginBottom: 12, borderColor: '#ef4444' }}>
              <div className="small" style={{ marginBottom: 6 }}>
                <strong>Additional confirmation required.</strong> This plan includes destructive or high-risk steps:
                {' '}{p.steps.filter(s => s.destructive || s.risk === 'high').map(s => s.title).join('; ')}.
                Type <strong>CONFIRM</strong> below to enable execution.
              </div>
              <input
                placeholder="Type CONFIRM to proceed"
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
                style={{ width: 220 }}
              />
            </div>
          )}
          <div className="row wrap" style={{ gap: 10 }}>
            <input
              style={{ flex: 1, minWidth: 200 }}
              placeholder="Optional note for the audit log"
              value={note}
              onChange={e => setNote(e.target.value)}
            />
            <button
              className="btn pri"
              disabled={!admin || (p.needs_confirm && confirm.trim() !== 'CONFIRM')}
              onClick={() => act('approve', { confirm_text: confirm, note })}
              title={admin ? 'Approve and execute the predefined steps in order' : 'Admin role required'}
            >
              Approve and execute
            </button>
            <button
              className="btn dng"
              disabled={!admin}
              onClick={() => act('reject', { note })}
            >
              Reject
            </button>
            {!admin && <span className="small mut">Admin role required to decide</span>}
          </div>
          <div className="small mut" style={{ marginTop: 8 }}>
            Approving runs only the predefined steps above, in order.
            Rejecting executes nothing and records your decision in the audit log.
          </div>
        </Card>
      )}

      {/* expired notice */}
      {p.expired && (
        <div className="callout small" style={{ borderColor: '#ef4444' }}>
          This plan is older than 30 minutes and can no longer be approved. Generate a fresh plan from the current telemetry.
        </div>
      )}

      {/* error message */}
      {msg && (
        <div className="callout small" style={{ borderColor: '#ef4444' }}>{msg}</div>
      )}

      {/* ── Rollback ── */}
      {canRollback && (
        <Card title="Rollback">
          <div className="row" style={{ gap: 10 }}>
            <div className="small" style={{ flex: 1 }}>
              {p.steps.filter(s => s.status === 'succeeded' && s.reversible && !s.rollback_status).length} reversible step(s) can be restored to their recorded before-state.
              Irreversible steps and deleted data cannot be recovered.
            </div>
            <button className="btn dng" disabled={!admin} onClick={() => act('rollback')}>
              Roll back reversible steps
            </button>
          </div>
        </Card>
      )}

      {/* ── Before / after ── */}
      {(p.status === 'running' || p.status === 'executed' || p.status === 'failed' || ver) && (
        <Card title="Before / after telemetry">
          <MetricCompare ver={ver} planStatus={p.status} />
          {/* per-step before/after */}
          {p.steps.filter(s => s.before_state || s.after_state).map(s => (
            <div key={s.id} style={{ marginTop: 12, borderTop: '1px solid #24324f', paddingTop: 10 }}>
              <div className="small mut" style={{ marginBottom: 6 }}>{s.title} — measured by the device</div>
              <div className="grid g2" style={{ gap: 8 }}>
                <div>
                  <div className="small mut" style={{ marginBottom: 3 }}>Before</div>
                  {s.before_state ? (
                    Object.entries(s.before_state).map(([k, v]) => (
                      <div key={k} className="small"><span className="mut">{k}</span> {String(v)}</div>
                    ))
                  ) : <div className="small mut">—</div>}
                </div>
                <div>
                  <div className="small mut" style={{ marginBottom: 3 }}>After</div>
                  {s.after_state ? (
                    Object.entries(s.after_state).map(([k, v]) => (
                      <div key={k} className="small"><span className="mut">{k}</span> {String(v)}</div>
                    ))
                  ) : <div className="small mut">—</div>}
                </div>
              </div>
            </div>
          ))}
        </Card>
      )}

      {/* ── Audit trail ── */}
      <Card title="Audit trail">
        <table>
          <thead>
            <tr><th>Time</th><th>Actor</th><th>Event</th></tr>
          </thead>
          <tbody>
            {(p.audit || []).map((a, i) => (
              <tr key={i}>
                <td className="mono small">{fmtT(a.ts_ms)}</td>
                <td className="small">{a.actor}</td>
                <td className="small">
                  <div style={{ fontWeight: 600 }}>{a.action.replace(/^rem\./, '').replace(/\./g, ' → ')}</div>
                  <div className="mut">{a.detail.replace(/^plan#\d+ /, '')}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}

// ─── Main RemediationEngine component ────────────────────────────────────────
export function RemediationEngine({ me, ver }) {
  const { t } = useTranslation()
  const [cat] = usePoll(() => api('/api/rem/catalogue'), 5000, [ver])
  const [plans, , reloadPlans] = usePoll(() => api('/api/rem/plans'), 2500, [ver])
  const [incs] = usePoll(() => api('/api/incidents?status=open'), 5000, [ver])
  const [ov] = usePoll(() => api('/api/overview'), 10000)
  const [intel] = usePoll(() => api('/api/intel/sources'), 30000)
  const [tab, setTab] = useState('engine')
  const [sel, setSel] = useState(null)
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [open, setOpen] = useState(null)
  const admin = me.role === 'admin'
  const problem = cat?.problems.find(p => p.id === sel)
  const opts = targetOptions(problem, ov, intel)

  const make = async body => {
    setBusy(true); setMsg('')
    try {
      const p = await api('/api/rem/plans', { method: 'POST', body })
      setOpen(p.id)
      setTab('engine')
      reloadPlans()
    } catch (e) { setMsg(e.message) }
    setBusy(false)
  }

  const handleGenerate = p => {
    setSel(p.id)
    const t = p.observed[0]?.target || targetOptions(p, ov, intel)[0]?.id || ''
    setTarget(t)
    if (t) make({ problem_id: p.id, target: t })
    else setMsg('No target available. Select one below.')
  }

  const stats = plans ? {
    wait: plans.filter(p => p.status === 'proposed').length,
    run: plans.filter(p => p.status === 'running').length,
    ok: plans.filter(p => p.status === 'executed').length,
    fail: plans.filter(p => ['failed', 'rollback_failed'].includes(p.status)).length,
  } : {}


  return (
    <div className="col" style={{ gap: 14 }}>

      {/* ── KPI bar ── */}
      <div className="grid g4">
        <Kpi label="Awaiting Decision" value={stats.wait ?? '…'} color={stats.wait ? '#f5a524' : undefined} sub="Nothing runs until approved" />
        <Kpi label="Executing Now" value={stats.run ?? '…'} color={stats.run ? '#4f8cff' : undefined} sub="Steps running in sequence" />
        <Kpi label="Completed" value={stats.ok ?? '…'} color="#2ecc71" sub="Verified from real telemetry" />
        <Kpi label="Failed" value={stats.fail ?? '…'} color={stats.fail ? '#ef4444' : undefined} sub="Failures reported, never hidden" />
      </div>

      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          ['engine', 'Problem Catalogue & Diagnosis'],
          ['history', `Plans & History${plans ? ` (${plans.length})` : ''}`],
        ]}
      />

      {/* ══════════════ DIAGNOSE & FIX TAB ══════════════ */}
      {tab === 'engine' && (
        <div>
          {/* ── Active Incidents ── */}
          {(incs || []).length > 0 && (
            <Card title="Active incidents — generate a plan directly" style={{ marginBottom: 14 }}>
              <table>
                <thead><tr><th>Priority</th><th>Incident</th><th>Root cause</th><th>Age</th><th></th></tr></thead>
                <tbody>
                  {incs.map(i => (
                    <tr key={i.id}>
                      <td><PriorityBadge p={i.priority_level} /></td>
                      <td className="small"><strong>#{i.id}</strong> {i.title}</td>
                      <td className="small mut">{i.root?.cause}</td>
                      <td className="small mut">{age(i.created_ms)}</td>
                      <td>
                        <button className="btn sm pri" disabled={!admin || busy}
                          onClick={() => make({ incident_id: i.id })}>
                          {busy ? t('Generating…') : t('Generate AI Fix')}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}

          {/* ── Split layout: catalogue + plan ── */}
          <div style={{ display: 'grid', gridTemplateColumns: open ? '340px 1fr' : '1fr', gap: 14, alignItems: 'start' }}>

            {/* Problem catalogue */}
            <div>
              <div className="small mut" style={{ marginBottom: 10 }}>
                Problem catalogue — select a problem to diagnose.
                "Observed now" comes from your real stored telemetry only.
                All automated actions are predefined and require your approval.
              </div>

              {/* target selector (shown when problem selected) */}
              {problem && (
                <div style={{ background: '#131f3a', border: '1px solid #24324f', borderRadius: 8, padding: 12, marginBottom: 10 }}>
                  <div className="small mut" style={{ marginBottom: 6 }}>Selected: <strong style={{ color: '#e6ecf8' }}>{problem.title}</strong></div>
                  <div className="row wrap" style={{ gap: 8 }}>
                    <select value={target} onChange={e => setTarget(e.target.value)} style={{ flex: 1 }}>
                      <option value="">Choose a target…</option>
                      {problem.observed.map(o => (
                        <option key={'o' + o.target} value={o.target}>
                          ● {o.label} — {o.metric} {o.value ?? ''} (observed now)
                        </option>
                      ))}
                      {opts.filter(o => !problem.observed.some(x => x.target === o.id)).map(o => (
                        <option key={o.id} value={o.id}>{o.label}</option>
                      ))}
                    </select>
                    <button
                      className="btn pri"
                      disabled={!admin || busy || !target}
                      onClick={() => make({ problem_id: problem.id, target })}
                    >
                      {busy ? t('Generating…') : t('Generate AI Fix')}
                    </button>
                  </div>
                  {!admin && <div className="small mut" style={{ marginTop: 4 }}>Admin role required</div>}
                </div>
              )}

              {msg && <div className="callout small" style={{ borderColor: '#ef4444', marginBottom: 10 }}>{msg}</div>}

              {/* Problem cards */}
              <div className="col" style={{ gap: 8 }}>
                {(cat?.problems || []).map(p => (
                  <ProblemCard
                    key={p.id}
                    p={p}
                    selected={sel === p.id}
                    onSelect={id => { setSel(id); setTarget(p.observed[0]?.target || ''); setMsg('') }}
                    onGenerate={handleGenerate}
                    busy={busy}
                    admin={admin}
                    ov={ov}
                    intel={intel}
                  />
                ))}
              </div>

            </div>

            {/* Plan view panel */}
            {open && (
              <div>
                <div className="row" style={{ marginBottom: 10 }}>
                  <h3 style={{ margin: 0 }}>Remediation Plan #{open}</h3>
                  <div className="sp" />
                  <button className="btn sm" onClick={() => setOpen(null)}>✕ Close</button>
                </div>
                <PlanView id={open} me={me} onChanged={reloadPlans} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══════════════ HISTORY TAB ══════════════ */}
      {tab === 'history' && (
        <div className="col" style={{ gap: 12 }}>
          <Card title="Remediation plans">
            {(plans || []).length === 0
              ? <div className="mut small">No plans yet. Use the Problem Catalogue tab to generate one.</div>
              : (
                <table>
                  <thead>
                    <tr><th>#</th><th>Plan</th><th>Status</th><th>Risk</th><th>AI</th><th>Created</th><th>Decided</th><th>Steps</th></tr>
                  </thead>
                  <tbody>
                    {plans.map(p => (
                      <tr key={p.id} className="click" onClick={() => { setOpen(p.id); setTab('engine') }}>
                        <td className="mono small">{p.id}</td>
                        <td className="small"><strong>{p.title}</strong></td>
                        <td><Badge kind={PLAN_KIND[p.status]}>{PLAN_LABEL[p.status] || p.status}</Badge></td>
                        <td><Badge kind={RISK_KIND[p.risk]}>{p.risk}</Badge></td>
                        <td>{p.ai?.used ? <Badge kind="delivered">✓</Badge> : <Badge kind="neutral">—</Badge>}</td>
                        <td className="small mono">{fmtDT(p.created_ms)}</td>
                        <td className="small mono">{p.decided_by ? `${p.decided_by} ${fmtDT(p.decided_ms)}` : '—'}</td>
                        <td className="small">
                          {p.steps.map(s => ({
                            succeeded: '✓', failed: '✗', skipped: '·', not_executed: '·',
                            pending: '○', running: '⏳', manual_pending: '…', manual_done: '✓',
                          }[s.status] || '·')).join(' ')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
          </Card>
        </div>
      )}
    </div>
  )
}
