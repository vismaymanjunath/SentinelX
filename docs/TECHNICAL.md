# SENTINEL X — privacy-first AIOps observability

Two genuinely separate tiers (separate processes, separate SQLite stores, TLS + API-key link between them):

```
 CUSTOMER ENVIRONMENT  (collector/, one per tenant)            │  CENTRAL SaaS  (saas/, multi-tenant)
 psutil real host metrics + simulated WAN/services + logs      │
   → local log scan & redaction (raw logs stay here)           │
   → local EWMA / rate-of-change anomaly detection             │
   → PRIVACY FIREWALL (allow-list → redact → canary guard)  ═══╪═ HTTPS (own CA) + Bearer key ═► strict re-validation
   → durable SQLite outbox (payload_id, seq) → retrying sender │   idempotent ingest (payload_id / event_id PKs)
   → Egress Proof log (original ▸ redacted ▸ final + SHA-256)  │   event-time ordering, tenant_id on every query
                                                               │   baselines · correlation · root cause · health
                       trust boundary ─────────────────────────┘   incidents · replay · remediation · audit
```

## Run

```powershell
pip install fastapi uvicorn websockets httpx psutil cryptography pytest
cd web; npm install; npm run build; cd ..
python run_all.py
```

| URL | What |
|---|---|
| http://127.0.0.1:8080 | SaaS dashboard (login below) |
| http://127.0.0.1:9001 | Collector console, tenant **acme** — Egress Proof, Scenario Simulator, raw-vs-redacted logs |
| http://127.0.0.1:9002 | Collector console, tenant **globex** |
| https://localhost:8443 | SaaS ingest endpoint (TLS only; plain HTTP ingest is refused with 426) |

Demo logins: `acme-admin / Acme#Admin2026`, `acme-viewer / Acme#View2026`, `globex-admin / Globex#Admin2026`.
Env: `COLLECTOR_HOST_MODE=simulated` uses a deterministic seeded host stream instead of real psutil values.

Remote laptops (ngrok, real host metrics): see [REMOTE.md](../REMOTE.md).

## Tests (real workflows, isolated stack on other ports)

```powershell
python -m pytest tests -q
```
Covers: TLS/auth, secrets never reach SaaS, allow-list enforcement both sides, firewall self-test + canary guard,
tenant isolation, CPU-spike detection → correlated incident → explained root cause, approval-gated remediation with
sandbox execution + rollback + audit, failed-login summary without raw records, latency incident + blast radius,
SaaS outage buffering/recovery with zero loss/duplicates, duplicate + out-of-order delivery, collector offline < 60 s,
configurable thresholds, replay ordering, measured performance.

## Where each judged requirement lives

| Requirement | Implementation |
|---|---|
| Local protection / allow-list | `common/schema.py` (contract), `collector/firewall.py`, `common/secrets.py` |
| Egress proof panel | Collector UI → *Egress Proof Panel*; `collector/engine.py` (`egress` table, TX IDs, SaaS SHA echo) |
| Metadata-only SaaS flow / server-side guard | `saas/ingest.py` (`validate_payload`, strict) · SaaS UI → *Data Inspector* |
| Auth + transport | `saas/security.py` (own CA, SAN localhost), `collector_auth` in `saas/main.py`, residency check |
| Idempotency / duplicates / out-of-order | `payloads.payload_id` PK, `events.event_id` PK, `latest` guarded by event time, baselines from event-time order |
| Buffering & retry | `collector/engine.py` outbox + backoff; *Buffer & Delivery* → Reconcile (sent vs received IDs) |
| Anomaly detection | `saas/aiops.py` (median/MAD baseline excluding anomaly intervals, z-score, rate-of-change, thresholds); `collector/detector.py` (EWMA, frozen during anomalies) |
| Correlation / root cause | `saas/correlation.py` (time + dependency graph + category; scored candidates with breakdown) |
| Four health states + stale handling | `saas/health.py`, configurable thresholds UI, UTC history |
| Replay | `/api/incidents/{id}/replay`, *Incident Time Machine* |
| Remediation | `saas/remediation.py`: policy checks → admin approval → sandbox execution in collector → audit → rollback |
| Performance (measured) | *Performance* page: ingest + browser-render latency, alert latency from injected markers, offline detection, seq-gap/dup counters |

## Honest limitations

- Baseline detection needs ~30 s of history per series after a (re)start; anomalies injected during that window are only caught by static thresholds (a shorter warm-up produced false alarms).
- SQLite for both tiers (PostgreSQL / regional clusters would be the production choice); one SaaS node simulates
  "regional ingest" (collector region must equal tenant region, otherwise 403) — no real multi-region replication.
- Collector API keys are stored hashed at the SaaS; no key rotation UI, no mTLS. The collector console is unauthenticated on 127.0.0.1.
- Service and WAN telemetry is simulated (host CPU/mem/disk/throughput are real; WAN latency includes a real, capped TCP probe).
- The secret scanner is pattern + Luhn + canary based; novel secret formats without a recognisable shape or key name can pass the scanner.
- Remediation executes only against the collector's simulated sandbox; there is no production actuator.
- Root-cause scoring is a transparent heuristic (temporal precedence, dependency coverage, upstream-alert exclusion, signal strength), not a learned model.

## Issue classification and priority (incidents)
Every incident is classified (**Infrastructure, Network, Security, Collector Health**) from its root-cause signal and given a
deterministic priority **P1-P4** (`saas/triage.py`). Score = severity (critical 40 / warning 20) + duration (60s +5, 2m +10,
5m +15, 15m +20) + affected devices (2: +10, 3+: +15) + impact (dependent services alerting up to +15, at risk up to +5)
+ corroboration (+5) + security weight (+5/+10). P1 >= 75, P2 >= 55, P3 >= 35, else P4. The exact factors are stored with each
incident and shown in Incidents -> "Classification & priority"; the monitor re-scores open incidents so priority rises as they
age and a `priority_changed` timeline event is recorded. Related alerts share one incident; several offline collectors become one.
Optional local AI analysis: see "Local AI (Ollama)" below.

## Local AI (Ollama)
Incident page -> **Local AI investigation**. An **admin** presses Analyse; viewers can read completed results. The SaaS backend
calls Ollama at `SENTINEL_OLLAMA_URL` (loopback only, default `http://127.0.0.1:11434`, model `SENTINEL_OLLAMA_MODEL`, default
`qwen2.5:1.5b`). The model receives only an allow-listed, pseudonymised context (numbers, metric names, severities, P-level and
factor points; entity names become host-1/service-1/... with the map kept server-side). No logs, alert messages, evidence, IPs,
emails or secrets are read, and the final prompt is scanned and blocked on any match. One request at a time; failures never
affect monitoring. Output is validated, redacted, shown as plain text and clearly marked as hypotheses; it never changes
category/priority and nothing it suggests is executed. A result is marked **stale** when the incident analysis/triage changes.
Never expose port 11434; ngrok only ever forwards the 5 ingest routes on the ingest listener.


## TLS and local anonymisation (laptop -> host)

### TLS
* Collectors talk **HTTPS only**. The host refuses plain HTTP on every ingest/enrolment route (426), and a collector refuses to start
  with an `http://` server URL. Certificate **and** host-name verification are always on (TLS >= 1.2); there is no insecure bypass.
* **Via ngrok** (the normal path): collector <-> ngrok is TLS with ngrok's public certificate, verified by the collector. ngrok <-> your
  host is ngrok's own encrypted tunnel to the ngrok agent, which then forwards **plain HTTP to 127.0.0.1:8090 on the same machine**.
  ngrok terminates TLS at its edge, so **this is NOT end-to-end TLS**; ngrok can see the (already anonymised) payload.
* **Direct / LAN** collectors can pin the host's private CA: the host prints the CA SHA-256 fingerprint at startup (and shows it on the
  Cloud page / `GET /api/tls/ca` for admins). Give the fingerprint and `ca.pem` to the laptop owner by a *separate* channel; the setup
  page (Advanced) accepts the CA only if its fingerprint matches, it is a CA and it is valid.
* Expired, wrong-host, self-signed and untrusted certificates are refused with a readable message and nothing is sent (the collector
  keeps buffering locally). The host renews its server certificate 30 days before expiry (and replaces a CA that is nearly expired -
  re-pin collectors then).
* The dashboard (8080) and Ollama (11434) stay on 127.0.0.1 and are never tunnelled.

### Local anonymisation (Cloud page)
* Runs **on each laptop** before the firewall, the durable outbox and the network. Removes usernames, laptop/asset IDs, IP/MAC addresses,
  user home paths and raw log samples; replaces the device name/hostname/IDs with one stable pseudonym (`Device-8243`). Metrics, timestamps,
  severities and error descriptions are kept.
* The original -> pseudonym mapping lives only in `anon-map.json` on the laptop (owner-only permissions) and is never transmitted; only
  counters are reported. New enrolments register under the pseudonym, so the host never learns the real name.
* The host re-checks every payload/heartbeat (always rejects IPs, MACs, e-mails, usernames, user paths, identifying fields; flags
  non-pseudonymous device ids and collectors that do not declare anonymisation). `SENTINEL_REQUIRE_ANON=1` rejects non-declaring collectors.
  Violation records hold codes and field names only, never the offending value.
* This is **pseudonymisation, not perfect anonymity**: the pseudonym is stable, and anyone with the laptop's local files can reverse it.
  The TCP source IP is visible to ngrok/the host at the transport layer. Laptops enrolled under their real name before this feature keep an
  identifying collector id at the host until they re-enrol. The Android app is not covered (it enrols under the name you type).
* Turn it off for a collector with `"anonymise": false` in its config or `COLLECTOR_ANONYMISE=0` (the host flags it).


## Privacy & Security (one central dashboard)
The dashboard sidebar item **Privacy & Security** (http://127.0.0.1:8080) shows, for the whole fleet and per device: anonymisation status,
records processed, identifying fields removed / pseudonymised (with a per-type breakdown), privacy-firewall activity, TLS verification and
route (direct TLS vs ngrok tunnel), privacy violations, the last successful transmission, an egress-hash proof, and the **exact payload the
host received** (the stored request body, hash-verified). The **Egress proof** tab walks the three stages: (1) original local fields -
*never* available centrally by design, (2) redacted/allow-listed (counters + the allow-list contract), (3) the exact final payload.
* Everything shown was already **received by the host**: each collector's heartbeat adds a closed-world `privacy` block (counters, enum
  labels, a sha256 and a payload id - nothing free-form, validated strictly) and the accepted payloads themselves. The raw originals,
  usernames, private IPs, MACs, original hostnames and the name<->pseudonym mapping are never sent to or requested by the host. The
  dashboard never contacts a collector console (port 9001 etc.), and nothing here is reachable through the ngrok listener.
* The local collector console is unchanged and remains the place for raw BEFORE/AFTER debugging on the laptop itself.
* The newest 25 exact payload bodies per device are kept; older ones keep their hash and stored events.
* Collectors built before this feature still work: they show counters and payloads, and "not reported" for firewall/TLS/egress-hash.
  Update a laptop's `collector/` and `common/` folders to get the full privacy block.
* Egress proof compares the hash the collector computed for its last acknowledged payload with the hash the host computed on the bytes it
  received. TLS verification status is self-reported by the collector; the route is observed by the host.


## Global Intelligence (real-world data)
Sidebar **Global Intelligence** turns SENTINEL X into a platform that compares genuine public intelligence with what your devices report.
Sources (all fetched by the SaaS server in its own threads, separate from the collector/ngrok ingest listener; the browser never calls them):
| Source | What | Frequency |
|---|---|---|
| CISA KEV (official JSON) | known-exploited CVEs | hourly (conditional GET) |
| NIST NVD REST 2.0 | CVEs, CVSS, affected CPEs | every 2 h, incremental by lastModified, paced to the 5 req/30 s key-less limit |
| OSV (GCS index + api.osv.dev) | PyPI / npm / Go advisories | every 2 h |
| AWS Health + RSS, Azure RSS, Cloudflare + GitHub Statuspage, Google Cloud incidents.json | provider incidents, services, regions, updates | every 5 min |
| RIPE RIS Live (WebSocket) | BGP announcements/withdrawals; rrc00 global rollups + targeted path/prefix subscriptions for watched ASNs | continuous stream |
| IODA v2 | country / region / ASN outage events | every 10 min |
| RIPE Atlas (public built-in msm 1001 ping, 5001 traceroute, 10001 DNS) | per-country connectivity from up to 12 probes | every 15 min |
Every event keeps its source URL and source timestamps; ids de-duplicate; changed events keep a version history. A failing source keeps its last
real data and is labelled **cached / stale / rate-limited / unavailable**; nothing is ever invented. IODA/Atlas probe addresses are never stored.
**Correlation** (`saas/intel/correlate.py`, Python only): network (RIS/IODA/Atlas vs a device's ASN/country + local latency/loss/offline alerts),
cloud (provider incident vs the device's real TCP+TLS reachability probes, with healthy controls) and vulnerabilities (installed OS/runtime/PyPI/browser
versions vs OSV/NVD ranges, re-verified by us; CISA KEV is a *possible* family match unless NVD data verifies the version). Scores are the exact sum of named
factors; **confirmed** needs a shared identifier plus time/version/local evidence; **possible** is partial; the rest stays **worldwide**. Causation is never
claimed, incident priority is never changed, no incident is created for an external event; related incidents get a timeline note and an evidence panel.
Devices report (heartbeat `environment`, closed vocabulary): public ASN + country (never the IP) and vendor/product/version of the OS, Python and a few packages/browsers;
probes run once a minute. Opt out with `COLLECTOR_INVENTORY=0` / `COLLECTOR_PROBES=0`. The local LLM (Ollama, loopback) only explains stored results; feed text is
sanitised and treated as untrusted data. `SENTINEL_INTEL=0` disables ingestion.
Limits: no geographic map (country ranking instead); RIS uses one general vantage (rrc00) plus targeted ASN subscriptions; Atlas uses root-server measurements only;
NVD exposure lookups cover the OS-independent runtime/browser CPEs we can map (Python, Chrome, Edge, Firefox), other software only via OSV (PyPI) or KEV family match.

## Security note for anyone running this from GitHub
- The logins listed above (`acme-admin`, etc.) are **local demo defaults** created by `python -m saas.seed`. Never expose a host that uses them to the internet; set your own passwords first.
- Runtime data (`data/`: databases, TLS keys, collector keys), downloaded models (`models/`), `ngrok.exe`, `.env` files and built collector bundles are git-ignored on purpose.
- The "secrets" in `tests/` and `collector/simstate.py` (for example `AKIAIOSFODNN7EXAMPLE`, `hunter2`) are fake canary values used to prove redaction.
