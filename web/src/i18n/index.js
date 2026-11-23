import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './en.json'
import hi from './hi.json'
import kn from './kn.json'
import patterns from './patterns.json'

// Local dictionaries only (bundled JSON): nothing is ever sent to a translation service. Keys are the English strings, so English is the
// default and the fallback: any string without a translation simply shows in English.
export const LANGS = [['en', 'English'], ['hi', 'हिन्दी'], ['kn', 'ಕನ್ನಡ']]
let saved = 'en'
try { const s = localStorage.getItem('sx_lang'); if (LANGS.some(l => l[0] === s)) saved = s } catch { /* ignore */ }
i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, hi: { translation: hi }, kn: { translation: kn } },
  lng: saved, fallbackLng: 'en', keySeparator: false, nsSeparator: false, interpolation: { escapeValue: false }, returnEmptyString: false,
})
document.documentElement.lang = saved
export const setLang = (l) => { i18n.changeLanguage(l); document.documentElement.lang = l; try { localStorage.setItem('sx_lang', l) } catch { /* ignore */ } }
export default i18n

// ---- Static-text translator: exact-match only. A text node / placeholder / title is replaced when its whole trimmed text is a dictionary key,
// so dynamic telemetry, IDs, numbers and timestamps (which never equal a key) are untouched. English restores the original text.
// Pattern translations for sentences with live values: {0},{1}… capture the dynamic parts, which are copied through UNCHANGED
// (or translated only if the captured text is itself a known label, e.g. a status word). Longest templates are tried first.
const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const PATS = [...patterns].sort((a, b) => (a.en.startsWith('{') ? 0 : 1) - (b.en.startsWith('{') ? 0 : 1) || b.en.length - a.en.length).map(p => ({ re: new RegExp('^' + p.en.split(/\{\d\}/).map(esc).join('(.+?)') + '$', 's'), hi: p.hi, kn: p.kn }))
function tx(s, lang, depth = 0) {
  const direct = i18n.getResource(lang, 'translation', s)
  if (typeof direct === 'string' && direct) return direct
  if (depth > 3) return null
  for (const p of PATS) {
    const m = p.re.exec(s)
    if (m) return p[lang].replace(/\{(\d)\}/g, (_, i) => { const c = (m[+i + 1] || '').trim(); return tx(c, lang, depth + 1) ?? c })
  }
  return null
}
const orig = new WeakMap()            // text node -> { src: original English, out: what we wrote }
const origAttr = new WeakMap()        // element -> { attr: { src, out } }
function trNode(n) {
  const v = n.nodeValue, rec = orig.get(n)
  let src = v
  if (rec && v === rec.out) src = rec.src          // unchanged since we wrote it
  const key = src.trim()
  if (!key) return
  const lang = i18n.language
  const tr = (lang !== 'en' && tx(key, lang)) || key
  const out = src.replace(key, tr)
  if (out !== v) n.nodeValue = out
  if (out !== src || rec) orig.set(n, { src, out })
}
function trAttrs(el) {
  for (const a of ['placeholder', 'title', 'aria-label']) {
    const v = el.getAttribute?.(a); if (v == null) continue
    const m = origAttr.get(el) || {}, rec = m[a]
    const src = rec && v === rec.out ? rec.src : v
    const key = src.trim(); if (!key) continue
    const tr = (i18n.language !== 'en' && tx(key, i18n.language)) || key
    if (tr !== v) el.setAttribute(a, tr)
    if (tr !== src || rec) { m[a] = { src, out: tr }; origAttr.set(el, m) }
  }
}
const origEl = new WeakMap()          // element -> { srcs: [...English text of each node], written: [...what we wrote] }
function trTextGroup(el) {
  const nodes = [...el.childNodes]
  if (nodes.length < 2 || !nodes.every(n => n.nodeType === 3)) return false
  const rec = origEl.get(el)
  const srcs = nodes.map((n, i) => (rec && rec.written[i] === n.nodeValue && rec.srcs[i] != null ? rec.srcs[i] : n.nodeValue))
  const whole = srcs.join(''), key = whole.trim()
  if (!key) return false
  const tr = (i18n.language !== 'en' && tx(key, i18n.language)) || null
  const written = tr ? [whole.replace(key, tr), ...nodes.slice(1).map(() => '')] : srcs
  if (tr || rec) { nodes.forEach((n, i) => { if (n.nodeValue !== written[i]) n.nodeValue = written[i] }); origEl.set(el, { srcs, written }) }
  return !!tr
}
function trTree(root) {
  if (root.nodeType === 3) return trNode(root)
  if (root.nodeType !== 1 || ['SCRIPT', 'STYLE', 'PRE', 'CODE', 'TEXTAREA'].includes(root.tagName) || root.classList?.contains('mono')) return
  trAttrs(root)
  if (trTextGroup(root)) return
  for (const c of root.childNodes) trTree(c)
}
let pending = false
const schedule = () => { if (pending) return; pending = true; requestAnimationFrame(() => { pending = false; const r = document.getElementById('root'); if (r) { obs.disconnect(); trTree(r); obs.observe(r, cfg) } }) }
const cfg = { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['placeholder', 'title', 'aria-label'] }
const obs = new MutationObserver(schedule)
i18n.on('languageChanged', schedule)
window.addEventListener('DOMContentLoaded', () => { const r = document.getElementById('root'); if (r) { obs.observe(r, cfg); schedule() } })
