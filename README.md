<div align="center">

# 🛡️ SENTINEL X

### Privacy-first AIOps observability — **your data stays home, your insight goes global.**

*Watch every device, network and service from one dashboard, while raw logs, secrets and identities never leave the machine they were born on.*

![Python](https://img.shields.io/badge/Python-FastAPI-3776AB?logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black)
![Kotlin](https://img.shields.io/badge/Android-Kotlin-7F52FF?logo=kotlin&logoColor=white)
![Local AI](https://img.shields.io/badge/AI-100%25%20local%20(Ollama%20%2B%20Whisper)-0ea5e9)
![Privacy](https://img.shields.io/badge/Privacy-metadata--only-22c55e)
![Languages](https://img.shields.io/badge/UI-English%20%C2%B7%20%E0%A4%B9%E0%A4%BF%E0%A4%A8%E0%A5%8D%E0%A4%A6%E0%A5%80%20%C2%B7%20%E0%B2%95%E0%B2%A8%E0%B3%8D%E0%B2%A8%E0%B2%A1-f59e0b)

</div>

---

## ✨ The idea in 30 seconds

Traditional monitoring ships raw logs, payloads and credentials to a central platform. That widens your attack surface and breaks compliance.

**SENTINEL X flips the model.** A tiny **local collector** inside each environment collects, scans, redacts and *anonymises* telemetry on the device. Only **approved, allow-listed metadata** — numbers, severities, pseudonymous IDs — crosses the trust boundary to a **multi-tenant SaaS brain** that detects anomalies, correlates alerts into incidents, explains root causes in plain language, and even proposes safe, human-approved fixes.

> **Same visibility. A fraction of the exposure.** And you can *prove* it — on screen, byte for byte.

---

## 🚀 What makes it special

| | |
|---|---|
| 🔒 **Provable privacy** | The **Egress Proof Panel** shows the *exact* payload that left the device, hash-checked against what the cloud received. A live **Privacy Center** grades protection as *host-verified* vs *collector-reported* — no fake green lights. |
| 🧠 **AIOps that explains itself** | Baseline anomaly detection, alert **correlation** into single incidents, ranked **root-cause hypotheses** with contributing signals, and **P1–P4 triage** with a visible score breakdown. |
| 🏠 **AI that never phones home** | Incident explanations, **Ask SENTINEL X** Q&A and remediation wording run on a **local LLM (Ollama)**. Voice input runs **on-device or on local Whisper**. No cloud AI. No data leaves. |
| 🛠️ **Safe autonomous-ops path** | A remediation engine generates a plan from *real* telemetry → **you approve** → only **predefined, bounded actions** run → before/after verification → **rollback** → full **audit trail**. The AI explains; it can never invent actions. |
| 🌍 **Global-ready** | UTC + source time zones, out-of-order events placed by *event time*, **idempotent delivery** (zero duplicates), tenant region checks, and a dashboard in **English, हिन्दी and ಕನ್ನಡ**. |
| 📡 **Built for outages** | Lose the network? The collector keeps monitoring, queues anonymised data in a **durable local outbox**, retries with **exponential backoff**, and delivers everything — **zero loss, zero duplicates** — when you're back. |

---

## 🧭 Feature tour

### 🖥️ Observe
- **Overview, Devices, Analytics** — fleet health, CPU/RAM/disk/network, trends, online-vs-offline, all from real telemetry.
- **Four health states** — *Excellent · Good · Fair · Poor* with editable thresholds, stale-data handling, and the *reason* for every state change.
- **Dependency Map** — an interactive topology with upstream/downstream impact and **blast-radius** analysis, incident highlighting, and search.
- **Incident Time Machine** — replay any incident exactly as it unfolded.

### 🧩 Detect & correlate
- Median/MAD baselines + rate-of-change detection (beyond static thresholds).
- Many raw alerts → **one incident**, with the affected components and a likely cause.
- Security signals such as **repeated failed logins** summarised *without exporting raw auth records*.

### 🔐 Privacy Center
- Data inventory: what's **collected**, what **stays local**, what's **transmitted**.
- **Before / After** anonymisation, live **privacy-firewall** stats, TLS & transport status, **egress proof**, retention, a privacy **audit log**, and an admin-approved **data-deletion** workflow.
- A guided **Data Flow** walkthrough from device → TLS → host firewall → dashboard.

### 🛠️ Remediation
- Pick a problem or an active incident → click **Generate AI Fix**.
- Evidence-grounded plan with root cause, steps, risk and expected result.
- **Approve / Reject**, typed confirmation for risky steps, execution through the collector's controlled actions, verification, rollback, and audit.

### 🤖 Local AI
- **Ask SENTINEL X** — natural-language questions answered from your own data.
- **Incident explanations** — plain-language summaries with cited evidence.
- **Voice input** — browser on-device speech recognition, with a **local Whisper** fallback. Audio is never stored or uploaded.

### 🌐 Global Intelligence
Live public feeds — **11 real sources** including CISA KEV, NIST NVD, OSV, cloud-provider status pages, RIPE RIS Live (BGP), IODA and RIPE Atlas — correlated against *your* devices and labelled **possible** or **confirmed**. Every event keeps its source and timestamp.

### 🏆 Live Judge Mode
One-click scenarios — **CPU spike, memory spike, latency, failed logins, collector offline, SaaS connectivity loss, duplicate delivery, recovery** — injected into a simulated collector and pushed through the *real* pipeline. The dashboard shows the detection, the exact metadata sent, a **privacy proof**, the alert and correlated incident, and **measured** detection times against the 10 s / 15 s / 60 s targets. Nothing is hardcoded to pass.

### 📱 Everywhere
- **Remote collectors** join over an ingest-only tunnel with a join code.
- A native **Android collector app** (Kotlin) reports battery, RAM and storage.
- **Deploy-ready**: `Dockerfile` + Render blueprint for a public HTTPS deployment.

---

## 🏗️ Architecture

```
 CUSTOMER ENVIRONMENT  (collector/ — one per device or site)        │   CENTRAL SaaS  (saas/ — multi-tenant)
 real CPU · RAM · disk · network · link latency · logs              │
   → local secret/PII scan & redaction  (raw logs stay here)        │
   → local anomaly detection                                        │
   → LOCAL ANONYMISATION  (Alice-Laptop → Device-27)                │
   → PRIVACY FIREWALL  (allow-list → redact → canary guard)  ═══════╪═ HTTPS + per-device key ═► strict re-validation
   → durable SQLite outbox  (payload IDs, exponential backoff)      │    idempotent ingest · event-time ordering
   → Egress Proof log  (original ▸ redacted ▸ final + SHA-256)      │    tenant isolation on every query
                                                                    │    baselines · correlation · root cause · health
                         ───────── trust boundary ─────────────────┘    incidents · remediation · audit · local AI
```

---

## ⚡ Quick start

```powershell
# 1. Install
pip install -r requirements.txt
cd web; npm install; npm run build; cd ..

# 2. Launch the host + two demo collectors
python run_all.py
```

| Open | What you'll see |
|---|---|
| `http://127.0.0.1:8080` | The SaaS dashboard (the seed step prints the local demo logins) |
| `http://127.0.0.1:9001` | A collector console: raw-vs-redacted logs, Egress Proof, scenario simulator |
| `https://localhost:8443` | TLS-only ingest endpoint (plain HTTP is refused) |

**Want the AI features?** Install [Ollama](https://ollama.com) and run `ollama pull qwen2.5:1.5b` — everything stays on your machine.

**Remote laptops & phones:** see [`REMOTE.md`](REMOTE.md) and [`ANDROID.md`](ANDROID.md).

---

## 🎬 Two-minute demo

1. **Collector console →** show a raw log containing a secret next to its redacted twin. *It never leaves.*
2. **Egress Proof Panel →** the exact payload that was sent, with its SHA-256.
3. **SaaS Privacy Center →** the same hash, host-verified.
4. **Live Judge Mode →** hit **CPU spike**: watch detection → alert → correlated incident → recommended fix, with measured timings.
5. **SaaS connectivity loss → Recovery** — the queue fills offline, then drains with **0 lost, 0 duplicated**.
6. Flip the dashboard to **हिन्दी** or **ಕನ್ನಡ** — no reload.

---

## 🧰 Tech stack

| Layer | Built with |
|---|---|
| Backend & collector | **Python** · FastAPI · uvicorn · httpx · psutil · cryptography · numpy |
| Dashboard | **React** · Vite · i18next |
| Mobile collector | **Kotlin** (Android) |
| Storage | **SQLite** (per collector + SaaS) |
| Local AI | **Ollama** (`qwen2.5`) · **faster-whisper** |
| Transport | HTTPS / TLS 1.2+ with certificate verification |

---

## 🗂️ Project map

```
collector/   local collector: sources, anonymiser, firewall, detector, outbox, console API
saas/        multi-tenant host: ingest, AIOps, correlation, health, remediation, local AI, intel feeds
common/      shared data contract, secret scanner, anonymisation, policy
web/         React dashboard + collector console (i18n: English / Hindi / Kannada)
android/     Kotlin Android collector app
tests/       end-to-end & focused tests on isolated stacks
docs/        deep-dive technical notes
```

📚 Deep dives: [`docs/TECHNICAL.md`](docs/TECHNICAL.md) · [`REMOTE.md`](REMOTE.md) · [`ANDROID.md`](ANDROID.md)

---

## 🎯 Built for CICADA 2026

SENTINEL X was designed against the *secure, AIOps-driven observability* brief: **two-tier architecture**, **metadata-only SaaS**, **egress proof**, **four health states**, **correlated incidents with explainable recommendations**, **buffered retry with idempotent delivery**, **global-ready timestamps**, and a **safe, human-approved path to autonomous operations**.

<div align="center">

**Monitor everything. Expose nothing.** 🛡️

</div>
