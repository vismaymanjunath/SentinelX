import React, { useEffect, useRef, useState } from 'react'
import { auth } from './api'

// Privacy-first voice input. Two local engines, never a cloud one:
//  1. 'browser': the browser's on-device SpeechRecognition (processLocally = true), only when the browser confirms it is available for en-IN.
//  2. 'whisper': audio is recorded in memory, converted to 16 kHz PCM and POSTed to THIS host (loopback dashboard), where a local Whisper
//     model transcribes it and discards it. Nothing is stored, logged or sent anywhere else.
// If neither is available the mic is disabled and typing works as normal. The text lands in the normal input for editing, and is submitted
// only through the existing Ask pipeline (server-side anonymisation included).
const LANG = 'en-IN'
const SR = typeof window !== 'undefined' ? (window.SpeechRecognition || window.webkitSpeechRecognition) : null

export function VoiceInput({ value, setValue, disabled }) {
  const [mode, setMode] = useState('checking')      // checking | browser | whisper | none
  const [state, setState] = useState('idle')        // idle | listening | recording | transcribing
  const [why, setWhy] = useState('')
  const [secs, setSecs] = useState(0)
  const rec = useRef(null), base = useRef(''), final = useRef(''), aud = useRef(null)

  useEffect(() => {
    let alive = true
    ;(async () => {
      let reason = 'This browser has no on-device speech recognition for English (India).'
      try {
        if (SR && 'processLocally' in SR.prototype && typeof SR.available === 'function' && await SR.available({ langs: [LANG], processLocally: true }) === 'available') { if (alive) setMode('browser'); return }
      } catch { /* fall through to the local Whisper engine */ }
      try {
        const r = await fetch('/api/voice/status', { headers: { Authorization: 'Bearer ' + auth.token } })
        const j = await r.json()
        if (j.available && navigator.mediaDevices?.getUserMedia) { if (alive) setMode('whisper'); return }
        reason += ' ' + (j.available ? 'This browser cannot record from the microphone.' : 'The local Whisper engine is unavailable: ' + (j.reason || ''))
      } catch { reason += ' The local Whisper engine could not be reached.' }
      if (alive) { setWhy(reason); setMode('none') }
    })()
    return () => { alive = false; try { rec.current?.abort?.() } catch { /* ignore */ } cleanupAudio() }
  }, [])

  const cleanupAudio = () => {
    const a = aud.current; aud.current = null
    if (!a) return
    try { a.node.disconnect(); a.src.disconnect() } catch { /* ignore */ }
    a.stream.getTracks().forEach(t => t.stop())
    try { a.ctx.close() } catch { /* ignore */ }
    clearInterval(a.timer)
  }

  // ---- engine 1: on-device browser recognition
  const startBrowser = () => {
    const r = new SR()
    r.lang = LANG; r.continuous = true; r.interimResults = true; r.processLocally = true
    base.current = value ? value.replace(/\s+$/, '') + ' ' : ''; final.current = ''
    r.onresult = (e) => {
      let interim = ''
      for (let i = e.resultIndex; i < e.results.length; i++) { const t = e.results[i][0].transcript; if (e.results[i].isFinal) final.current += t; else interim += t }
      setValue((base.current + final.current + interim).slice(0, 300))
    }
    r.onerror = (e) => { setState('idle'); if (e.error === 'not-allowed') setWhy('Microphone permission was denied. You can still type.'); else if (e.error !== 'aborted' && e.error !== 'no-speech') setWhy('Speech recognition stopped (' + e.error + '). You can still type.') }
    r.onend = () => setState(s => (s === 'listening' ? 'idle' : s))
    rec.current = r; setWhy('')
    try { r.start(); setState('listening') } catch { setState('idle'); setWhy('Could not start speech recognition.') }
  }

  // ---- engine 2: local Whisper on this PC
  const startWhisper = async () => {
    setWhy('')
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true } })
      const ctx = new (window.AudioContext || window.webkitAudioContext)()
      const src = ctx.createMediaStreamSource(stream)
      const node = ctx.createScriptProcessor(4096, 1, 1)
      const chunks = []
      node.onaudioprocess = (e) => { chunks.push(new Float32Array(e.inputBuffer.getChannelData(0))) }
      src.connect(node); node.connect(ctx.destination)
      const t0 = Date.now()
      const timer = setInterval(() => { const s = Math.floor((Date.now() - t0) / 1000); setSecs(s); if (s >= 55) stopWhisper() }, 250)
      aud.current = { ctx, src, node, stream, chunks, timer, rate: ctx.sampleRate }
      base.current = value ? value.replace(/\s+$/, '') + ' ' : ''
      setSecs(0); setState('recording')
    } catch (e) { setWhy(e?.name === 'NotAllowedError' ? 'Microphone permission was denied. You can still type.' : 'Could not open the microphone. You can still type.'); setState('idle') }
  }
  const stopWhisper = async () => {
    const a = aud.current
    if (!a) return
    const { chunks, rate } = a
    cleanupAudio(); setState('transcribing')
    try {
      const n = chunks.reduce((s, c) => s + c.length, 0), all = new Float32Array(n); let o = 0
      chunks.forEach(c => { all.set(c, o); o += c.length })
      const ratio = rate / 16000, m = Math.floor(n / ratio), pcm = new Int16Array(m)   // box-filter downsample to 16 kHz
      for (let i = 0; i < m; i++) { let s = 0, k = 0; for (let j = Math.floor(i * ratio); j < Math.min(n, Math.floor((i + 1) * ratio)); j++) { s += all[j]; k++ } const v = k ? s / k : 0; pcm[i] = Math.max(-1, Math.min(1, v)) * 32767 }
      const r = await fetch('/api/voice/transcribe', { method: 'POST', headers: { Authorization: 'Bearer ' + auth.token, 'Content-Type': 'application/octet-stream' }, body: pcm.buffer })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(j.detail || 'transcription failed')
      setValue((base.current + (j.text || '')).slice(0, 300))
      if (!j.text) setWhy('No speech was recognised. Try again or type.')
    } catch (e) { setWhy('Local transcription failed: ' + e.message + '. You can still type.') }
    setState('idle')
  }

  const stop = () => { if (mode === 'browser') { try { rec.current?.stop() } catch { /* ignore */ } setState('idle') } else stopWhisper() }
  const cancel = () => {
    if (mode === 'browser') { try { rec.current?.abort() } catch { /* ignore */ } setValue(base.current.trimEnd()) } else cleanupAudio()
    setState('idle')
  }

  const active = state === 'listening' || state === 'recording'
  return (
    <>
      {!active && <button type="button" className="btn" aria-label="Start voice input" disabled={disabled || mode === 'checking' || mode === 'none' || state === 'transcribing'}
        title={mode === 'none' ? why : mode === 'whisper' ? 'Speak your question — transcribed by a Whisper model on this PC' : 'Speak your question — recognised on this device only'}
        onClick={mode === 'browser' ? startBrowser : startWhisper}>{state === 'transcribing' ? 'Transcribing locally…' : '🎤'}</button>}
      {active && <>
        <span className="small" style={{ color: '#ef4444' }} aria-live="polite">● {state === 'recording' ? `Recording ${secs}s (stored nowhere)` : 'Listening on this device…'}</span>
        <button type="button" className="btn pri" onClick={stop}>Stop</button>
        <button type="button" className="btn" onClick={cancel}>Cancel</button></>}
      {mode === 'whisper' && !active && state === 'idle' && !why && <span className="small mut">local Whisper</span>}
      {(mode === 'none' || why) && !active && <div className="small mut" style={{ flexBasis: '100%' }}>🎤 {mode === 'none' ? 'Voice input unavailable: ' : ''}{why} {mode === 'none' ? 'Typing works as normal.' : ''}</div>}
      {active && <div className="small mut" style={{ flexBasis: '100%' }}>{mode === 'whisper' ? 'Audio stays in memory in this tab, goes only to this PC for transcription and is then discarded. Press Stop to transcribe; you can edit the text before asking.' : 'Audio is processed by your browser on this device only and is never uploaded or stored. Edit the text before asking.'}</div>}
    </>
  )
}
