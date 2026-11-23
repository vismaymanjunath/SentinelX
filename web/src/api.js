import { useEffect, useRef, useState } from 'react'

export const auth = {
  token: (() => { try { return localStorage.getItem('sx_token') } catch { return null } })(),
  set(t) { this.token = t; try { t ? localStorage.setItem('sx_token', t) : localStorage.removeItem('sx_token') } catch {} },
}

export async function api(path, { method = 'GET', body, base = '', token = auth.token } = {}) {
  const r = await fetch(base + path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-UI-Lang': (() => { try { return localStorage.getItem('sx_lang') || 'en' } catch { return 'en' } })(), ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (r.status === 401 && !base && token) { auth.set(null); window.location.reload() }
  const txt = await r.text()
  let j = null
  try { j = txt ? JSON.parse(txt) : null } catch { j = { detail: txt } }
  if (!r.ok) throw new Error((j && (j.detail || j.problems?.join('; '))) || r.statusText)
  return j
}

export function usePoll(fn, ms, deps = []) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  const ref = useRef(fn)
  ref.current = fn
  useEffect(() => {
    let alive = true, t
    const run = async () => {
      try { const d = await ref.current(); if (alive) { setData(d); setErr(null) } } catch (e) { if (alive) setErr(e) }
      if (alive) t = setTimeout(run, ms)
    }
    run()
    return () => { alive = false; clearTimeout(t) }
  }, deps) // eslint-disable-line
  return [data, err, () => ref.current().then(setData)]
}

export const pad = (n) => String(n).padStart(2, '0')
export const fmtT = (ms) => { if (!ms) return '—'; const d = new Date(ms); return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}` }
export const fmtDT = (ms) => { if (!ms) return '—'; const d = new Date(ms); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${fmtT(ms)}Z` }
export const ago = (s) => (s == null ? '—' : s < 90 ? `${Math.round(s)}s ago` : `${Math.round(s / 60)}m ago`)
export const num = (v, d = 1) => (v == null ? '—' : Number(v).toFixed(d))
