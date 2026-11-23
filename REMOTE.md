# Remote laptops over ngrok

Host laptop = SaaS + dashboard. Each friend laptop = a collector sending **real** CPU / RAM / disk / network metrics.

```
friend laptop ──HTTPS (public cert)──► ngrok edge ──► ngrok agent on host ──HTTP──► 127.0.0.1:8090  (ingest-only listener)
                                                                                      │ only 5 routes, Bearer-key auth
dashboard: http://127.0.0.1:8080  ← loopback only, never tunnelled ───────────────────┘ same app, different listener
```

## What is exposed
Only `127.0.0.1:8090` is given to ngrok. It serves exactly: `POST /api/ingest/v1/{payload,heartbeat,command-result,register}`
and `GET /api/ingest/v1/ledger`. Everything else (dashboard, login, `/api/*`, WebSocket, docs) returns 404 on that listener.
`ngrok http 8080` / `8443` would be **wrong** – never do that. `start_host_ngrok.ps1` hard-codes 8090.

## One-time setup (host)
1. Install ngrok (https://ngrok.com/download), create a free account, then once: `ngrok config add-authtoken <your token>`.
2. `pip install fastapi uvicorn websockets httpx psutil cryptography` and build the UI (`cd web; npm install; npm run build`) – as in README.
3. **No firewall changes needed** (ngrok only makes outbound connections). If you created the old Tailscale rule, remove it:
   `Remove-NetFirewallRule -DisplayName "SentinelX ingest (Tailscale only)"` (Admin PowerShell).

## Start the host
```powershell
cd <path-to-the-project-folder>
.\start_host_ngrok.bat          # or: .\start_host_ngrok.ps1 -JoinCode mysecret
```
It starts the host, starts `ngrok http http://127.0.0.1:8090`, and prints **Server URL** (`https://xxxx.ngrok-free.app`) and the **Join code**.
Dashboard (local only): http://127.0.0.1:8080 → `acme-admin / Acme#Admin2026`.
Manual alternative: `python run_host.py` in one window and `ngrok http http://127.0.0.1:8090` in another.

Build the friend package and send `sentinelx-collector.zip` plus the URL and join code (chat is fine for the demo):
```powershell
python make_collector_bundle.py
```

## Start each remote collector (friend laptop)
Needs Python 3.10+. Unzip, double-click `start_collector.bat` (or `python -m pip install -r requirements-collector.txt` then `python -m collector.setup`).
A page opens at http://127.0.0.1:9100 → enter **Server URL**, **Join code**, **Device name** → **Connect**.
Then the collector console opens at http://127.0.0.1:9001. TLS is verified with the normal trusted certificate store (ngrok's public certificate).
Reconnecting with the same device name reuses the same Fleet entry and rotates that device's key.
The free ngrok URL changes every time ngrok restarts – send the new URL and have friends press Connect again.

## Test: all laptops appear and send telemetry
1. Host: dashboard → **Collector Fleet** shows each device **online**, last seen < 10 s.
2. **Overview**: `<device>` (CPU/RAM/disk) and `<device> link` (latency/loss/bandwidth) update about every 2 s.
   Open a heavy app on a friend's laptop – its CPU value rises.
3. Optional: friend console → Scenario Simulator → *CPU spike* → incident appears on the dashboard.
4. Optional: ngrok inspector at http://127.0.0.1:4040 (local only) shows the requests; expect `Authorization: Bearer …` – treat it as sensitive.

## Troubleshooting (messages on the Connect page)
| Message | Meaning |
|---|---|
| ngrok says this tunnel is offline or the URL is wrong | host not running / ngrok restarted – get the current URL |
| Cannot connect to … | URL typo, no internet, or TLS certificate not trusted (corporate proxy) |
| The server rejected the join code | wrong code, or host not started with a join code |
| Too many attempts | 8 failed codes/minute lockout – wait a minute |

## Security notes (hackathon trade-offs)
- TLS verification is never disabled on the collector.
- **ngrok terminates TLS**, so ngrok can see the (metadata-only) payloads and Bearer keys. Raw logs and secrets still never leave
  the collector (privacy firewall unchanged). For end-to-end TLS you would need a TCP tunnel/own domain instead.
- The join code is the only barrier to enrolling into the demo tenant: share it privately, stop the host after the demo, and note the
  8-failures/minute lockout. It is validated server-side (constant-time), never logged and never stored; a device's own API key is stored
  only as a hash on the server. The collector's config file holds that device's key – don't share it.
- Forwarded headers (`X-Forwarded-Proto/For`) are trusted **only** from a loopback peer on the ingest-only listener.
- This has been tested locally by simulating ngrok's requests (`tests/test_remote_ngrok.py`); it has **not** been verified through a real ngrok
  tunnel from a separate laptop.


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
