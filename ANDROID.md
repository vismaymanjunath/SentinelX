# SentinelX Mobile (Android)

Native Kotlin app that registers through the existing SENTINEL X API and sends phone telemetry to the existing ingestion API.
Phones appear in **Collector Fleet** next to Windows/macOS/Linux laptops (platform badge + device details).

## What it reports (and what it cannot)
| Reported | Source |
|---|---|
| RAM used %, storage used % | `ActivityManager.MemoryInfo`, `StatFs` (system-wide) |
| Battery %, charging state | battery broadcast |
| Network traffic (Mbps, average since last sync) | `TrafficStats` device totals (can be unsupported on some devices) |
| Server latency | round trip of the app's own heartbeat |
| Device model, Android version | `Build.*` |
| **CPU: not reported** | Android 8+ blocks apps from reading system CPU usage; the app does not fake it |

Only metadata is sent (same allow-list as laptops). No files, contacts, location or app data are read.

## Build
Requires Android Studio / SDK (platform 37 installed) and JDK 17+.
```powershell
cd android
$env:ANDROID_HOME="$env:LOCALAPPDATA\Android\Sdk"
# use any Gradle 9.x (Android Studio opens the project directly: File > Open > android/)
gradle :app:assembleDebug :app:testDebugUnitTest
```
Debug APK: `android/app/build/outputs/apk/debug/app-debug.apk`

## Install on a physical phone
1. Phone: Settings → About phone → tap **Build number** 7 times → back → **Developer options** → enable **USB debugging**.
2. Plug the phone into the PC by USB and accept the "Allow USB debugging?" prompt on the phone.
3. On the PC:
```powershell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" devices        # the phone must be listed as "device"
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" install -r "android\app\build\outputs\apk\debug\app-debug.apk"
```
Alternative without USB: send `app-debug.apk` to the phone (chat/Drive), open it, and allow "Install unknown apps" for that app.
4. Open **SentinelX Mobile**.

## Connect it to the host
1. Host: `.\start_host_ngrok.bat` → note the **Server URL** (`https://xxxx.ngrok-free.app`) and **Join code**.
2. Phone (needs internet; any Wi-Fi or mobile data): enter Server URL, Join code and a **unique device name** → **Connect**.
3. The status screen shows *Connected* and *Last successful sync*.
4. Dashboard (http://127.0.0.1:8080) → **Collector Fleet** → the phone appears with an **Android** badge; click it for battery, RAM, storage and network.
5. Optional: switch on **Live demo mode** (5 s updates, shows a notification; allow notifications on Android 13+). Otherwise the phone syncs every 15 minutes in the background (WorkManager minimum) and Android may delay that under battery optimisation.

## Emulator rehearsal (lab only)
The `rehearsal` build type trusts one extra local test CA so an emulator can reach a local server (`https://10.0.2.2:8443`).
Copy `data/tls/ca.pem` to `android/app/src/rehearsal/res/raw/dev_ca.pem`, start the SaaS with `SAAS_TLS_NAMES=10.0.2.2` and a
`SENTINEL_JOIN_CODE`, then `gradle :app:assembleRehearsal`. Release/debug builds never include this trust anchor.

## Status of verification
See the test report in the project conversation. Real-phone and real-ngrok connectivity must be checked by you (steps above).
