---
name: bug-hunter
description: Autonomous Bug Hunter & Vulnerability Assessor for Web & Android APK — user gives only a target (URL, APK file, package name) or scope doc; agent auto-resolves targets, conducts passive recon + subdomain expansion, full vulnerability assessment, active exploitation chaining, automated chaos/monkey testing with post-test cleanup, Playwright live watch mode with HTML dashboard, multi-platform bug bounty report templates (HackerOne/Bugcrowd/generic), and produces ONE consolidated Word (.docx) report with PoC, CVSS, and kill chain narrative. Trigger with "hunt [url|apk]", "hunt web [url]", "hunt apk [path|pkg]", "hunt --watch [interval] [url]", "bughunt <target>".
---

# AUTONOMOUS BUG HUNTER (`bug-hunter`)

Skill ini mengubah satu perintah menjadi operasi bug hunting penuh yang berjalan sendiri — recon, exploit chaining, chaos testing, cleanup, live dashboard, dan satu laporan Word terpadu. User hanya perlu memberi target; agent yang melakukan selebihnya.

---

## 0. ALUR OTONOM (VIBE BUG HUNTING LOOP)

```
resolve → surface-expand → recon → assess → exploit-chain → chaos → cleanup → verify-cleanup → triage → report → [watch?] → stop
```

Semua fase berjalan otomatis tanpa gate atau konfirmasi per langkah. Tidak ada perintah `exploit ok`. Satu-satunya stop otomatis: target terdeteksi produksi live dengan risiko perubahan data permanen yang tidak bisa di-rollback.

### Fase Detail

**0 — Resolve**
- Deteksi tipe target (Web vs APK vs hybrid) dari argumen atau dokumen workspace.
- Cek scope: domain in-scope, wildcard subdomain, out-of-scope list dari dokumen program bug bounty.
- Load kredensial dari `.env.qa` atau `qa-credentials.local.json` — tidak pernah diminta di chat.
- Tentukan profil laporan: `bughunt-web`, `bughunt-apk`, atau `bughunt-all`.

**1 — Surface Expand (Attack Surface Discovery)**
- **Subdomain Enumeration** via public endpoints tanpa API key:
  * `crt.sh` — certificate transparency log query.
  * `dns.bufferover.run` — passive DNS lookup.
  * `hackertarget.com/hostsearch` — host search API.
  * Jika ada `SHODAN_API_KEY` di `.env.qa`: tambah Shodan host search.
- **Technology Fingerprinting**: deteksi server, framework, CDN, WAF dari header HTTP dan HTML pattern (Wappalyzer-style logic).
- **Port Probe Ringan**: HTTP/HTTPS `GET` probe ke port umum (80, 443, 8080, 8443, 3000, 5000) pada IP yang teridentifikasi — bukan full port scan.
- **Robots.txt & Sitemap**: parse dan expand endpoint list.
- **JS File Analysis**: unduh dan scan berkas JS publik untuk endpoint tersembunyi, hardcoded secret (regex: API key, token, AWS key, private IP).
- **APK Surface**: parse `AndroidManifest.xml` → daftar exported activity/service/receiver/provider; scan DEX strings untuk URL backend, hardcoded credential, dan internal endpoint.

**2 — Recon**
- **Web**: Audit header keamanan (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), CORS wildcard, cookie flag (Secure/HttpOnly/SameSite), TLS version, dan error disclosure.
- **APK**: Flag `debuggable`, `allowBackup`, exported components tanpa `permission` guard, `usesCleartextTraffic`, dan `networkSecurityConfig`.
- Output disimpan ke `pendukung/reconnaissance/` sebagai JSON terstruktur.

**3 — Assess (Vulnerability Assessment)**

*Web:*
- Missing/misconfigured security headers.
- CORS misconfiguration (wildcard origin atau reflect origin tanpa validation).
- IDOR: enumeration parameter ID secara sistematis.
- Unauthenticated endpoint discovery.
- Reflected XSS probe (non-destructive payload yang tidak menyebabkan perubahan data).
- SQL Injection detection (error-based dan time-based blind via `SLEEP(1)` / `WAITFOR DELAY`).
- Open redirect via `redirect`, `url`, `next`, `return` parameter.
- Path traversal probe (`../../../../etc/passwd`).
- SSRF probe ke internal metadata (`http://169.254.169.254/latest/meta-data/`).
- Server-Side Template Injection (SSTI) probe (`{{7*7}}`, `${7*7}`).

*APK:*
- Storage privat: plaintext di `shared_prefs`, SQLite, dan external storage.
- HTTP cleartext traffic capture via proxy.
- SSL pinning: cek apakah traffic MITM berhasil atau ditolak.
- Komponen exported: probe intent injection dengan data malformed.
- Clipboard data exposure saat field sensitif aktif.
- Screenshot prevention flag (`FLAG_SECURE`) pada layar sensitif.

**4 — Exploit Chain (Full Auto)**

Setelah celah teridentifikasi, agent otomatis menyusun dan mengeksekusi chain:

| Chain | Trigger | Eksekusi Otomatis |
|---|---|---|
| **Account Takeover** | IDOR + weak session | Enumerate ID → access victim resource → verify data exposure |
| **Auth Bypass** | Unauthenticated endpoint | Direct access admin/privileged endpoint → extract response |
| **SQLi Data Extraction** | SQLi confirmed | Enumerate columns → extract DB version, table names, sample data |
| **SSRF Internal Pivot** | SSRF confirmed | Probe internal services (169.254.x, 10.x, 172.16.x) → map internal network |
| **XSS Session Hijack Demo** | Reflected XSS | Inject payload yang mengirimkan `document.cookie` ke endpoint logger milik sendiri |
| **APK Component Hijack** | Exported activity | Launch exported activity dengan data malformed → capture resulting state |
| **Race Condition Win** | Race condition endpoint | 10 parallel requests → verify inconsistent state (double credit, negative balance, etc.) |

Seluruh eksekusi dicatat: request asli, response, payload yang digunakan, dan dampak yang dibuktikan.

> **Proteksi Produksi**: Jika target bukan staging/UAT/bug bounty scope, dan eksploit berpotensi mengubah data permanen yang tidak bisa di-rollback, hentikan chain dan tandai `BLOCKED` di triage.

**5 — Chaos / Monkey Testing**

*Web:*
- Form input stress: string 10k karakter, unicode surrogat (`\uD800`), null byte (`%00`), format string (`%s%n%x`), JSON injection (`{"__proto__":{"admin":true}}`).
- HTTP method mangling: `PUT`, `DELETE`, `PATCH`, `HEAD`, `TRACE` pada endpoint read-only.
- Race condition: 10 parallel requests ke endpoint kritis via Playwright `Promise.all`.
- Error disclosure analysis: apakah 500 response bocorkan stack trace, SQL query, atau path server.
- Large file upload probe: upload file 50MB atau tipe berbahaya (`.php`, `.jsp`).

*APK:*
```bash
adb shell monkey -p <package> --throttle 100 --pct-touch 40 --pct-motion 30 --pct-appswitch 15 -v 1000
```
Pantau logcat selama eksekusi:
```bash
adb logcat --pid=$(adb shell pidof -s <package>) *:E
```
- Intent injection ke seluruh exported component dengan data malformed.
- Low-memory kill saat alur aktif → restart → cek crash/state corruption.
- Permission revoke mid-session (`adb shell pm revoke`).

**6 — Cleanup (Auto)**

Segera setelah chaos selesai:

| Jejak | Metode |
|---|---|
| Browser cookies & session | `browser_clear_cookies`, logout endpoint |
| Local storage / IndexedDB | JavaScript `localStorage.clear(); sessionStorage.clear();` via Playwright |
| Data uji yang terbuat via API | Panggil endpoint delete/rollback dengan ID yang dicatat selama fase exploit |
| File temporer di device | `adb shell rm -rf /sdcard/Android/data/<pkg>/files/tmp/` |
| Log buffer device | `adb logcat -c` |
| Proxy config emulator | Reset via `adb shell settings put global http_proxy :0` |
| Data yang tidak bisa dihapus | Catat ID/referensi untuk dilaporkan ke vendor — cleanup status = `PARTIAL` |

**7 — Verify-Cleanup**
- Konfirmasi environment bersih: navigasi ulang ke endpoint kritis, cek apakah sesi/data uji masih ada.
- Status: `VERIFIED` (bersih) atau `PARTIAL` (perlu manual vendor).

**8 — Triage**
- Tulis semua temuan ke `pendukung/ai/triage.json`.
- Kill chain narrative per chain yang berhasil dieksekusi.
- Vulnerability chaining map (finding A + finding B → dampak kombinasi C).

**9 — Report**
- Bangun DOCX dengan `build_report.py --profile bughunt`.
- Multi-format output: DOCX utama + tiga file teks siap submit (HackerOne, Bugcrowd, Generic).
- Semua screenshot/bukti tertanam di DOCX.
- Zero Redaction Policy: nilai aktual tampil apa adanya; nilai tidak ada = `(...)`.

**10 — Watch (opsional)**
- Aktif jika perintah menyertakan flag `--watch [interval_menit]`.
- Playwright membuka browser **visible (non-headless)** dan menampilkan dashboard HTML live.
- Setiap N menit: jalankan ulang recon + assess (tanpa chaos ulang), diff temuan baru vs sesi sebelumnya.
- Temuan baru muncul langsung di dashboard. User ketik `stop hunt` di chat untuk menghentikan.

---

## 1. CARA MEMERINTAHKAN

| Perintah | Eksekusi |
|---|---|
| `hunt [url]` | Web hunting penuh: surface expand + recon + assess + exploit chain + chaos + cleanup + report. |
| `hunt web [url]` | Sama dengan atas, eksplisit web. |
| `hunt apk [path\|pkg]` | APK hunting penuh: manifest audit + static scan + ADB exploration + monkey + cleanup + report. |
| `hunt all [url] [apk]` | Hybrid: jalankan web + APK, gabungkan ke satu triage dan satu DOCX. |
| `hunt --watch 30 [url]` | Watch mode: hunt penuh sekali, lalu ulang tiap 30 menit dengan live Playwright dashboard. |

Alias: `bughunt [target]`, `bug hunter web <url>`, `bug hunter apk <file>`.

---

## 2. WATCH MODE — PLAYWRIGHT LIVE DASHBOARD

Saat `--watch` aktif:

1. Playwright membuka browser **non-headless** (visible).
2. Navigasi ke halaman dashboard lokal yang di-generate agent: `file:///[workspace]/watch-dashboard.html`.
3. Dashboard menampilkan:
   - **Target & timestamp** sesi terakhir.
   - **Tabel temuan aktif** dengan severity badge (merah/oranye/kuning/hijau).
   - **Diff panel**: temuan baru sejak sesi sebelumnya (highlighted kuning).
   - **Status bar**: fase saat ini (Recon / Assess / Idle), countdown ke run berikutnya.
   - **Log stream**: 20 baris terakhir audit log.
4. Dashboard di-refresh otomatis setiap 10 detik via `<meta http-equiv="refresh" content="10">`.
5. Agent update `watch-dashboard.html` setiap run selesai.
6. User menutup browser atau ketik `stop hunt` di chat → watch mode berhenti.

Format file `watch-dashboard.html` dihasilkan otomatis oleh agent tiap sesi (HTML murni, tidak butuh server).

---

## 3. VULNERABILITY CHAINING & KILL CHAIN NARRATIVE

Setiap chain yang berhasil dieksekusi mendapat blok `kill_chain` di `triage.json`:

```json
{
  "kill_chains": [
    {
      "id": "KC-01",
      "name": "Account Takeover via IDOR + Weak Token",
      "steps": [
        "VULN-03 (IDOR) → Enumerate user IDs 1–500 via GET /api/user/:id",
        "VULN-07 (Predictable Token) → Forge token format user-{id}-{timestamp}",
        "Result: Akses penuh akun 243 pengguna aktif tanpa autentikasi"
      ],
      "severity": "CRITICAL",
      "business_impact": "Seluruh akun pengguna dapat diambil alih oleh penyerang yang tidak terautentikasi.",
      "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (10.0)",
      "status": "VERIFIED",
      "evidence": ["bukti/kc-01-account-takeover.png"]
    }
  ]
}
```

---

## 4. MULTI-FORMAT BUG BOUNTY TEMPLATE

Setelah DOCX selesai, agent otomatis generate 3 file teks siap submit:

### 4.1 HackerOne Format (`submission-hackerone.md`)
```markdown
**Summary**: [Judul kerentanan]
**Severity**: High
**CVSS Score**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Description**:
[Deskripsi singkat kerentanan]

**Steps to Reproduce**:
1. [Langkah 1]
2. [Langkah 2]

**Impact**:
[Dampak bisnis dan keamanan]

**Supporting Materials**:
[Screenshot / HTTP request/response]
```

### 4.2 Bugcrowd Format (`submission-bugcrowd.md`)
```
Title: [Judul]
Type: [CVSS Category]
VRT: [Bugcrowd Vulnerability Rating Taxonomy mapping]
CVSS: [skor]

Description: [deskripsi]
Steps: [langkah]
Impact: [dampak]
```

### 4.3 Generic Format (`submission-generic.md`)
Markdown universal untuk private program, koordinasi langsung vendor, atau disclosure terjadwal.

---

## 5. SUBDOMAIN ENUMERATION — TEKNIK DETAIL

```
Target: example.com

1. crt.sh query:
   https://crt.sh/?q=%25.example.com&output=json
   → extract unique subdomain dari field "name_value"

2. dns.bufferover.run:
   https://dns.bufferover.run/dns?q=.example.com
   → parse FDNS_A dan RDNS fields

3. hackertarget.com:
   https://api.hackertarget.com/hostsearch/?q=example.com
   → parse CSV output

4. Jika SHODAN_API_KEY tersedia di .env.qa:
   https://api.shodan.io/dns/domain/example.com?key={KEY}
   → parse subdomains array

5. HTTP probe ke setiap subdomain yang ditemukan:
   HEAD https://sub.example.com/ → resolve IP, detect status, header fingerprint
```

Hasil disimpan ke `pendukung/reconnaissance/subdomains.json`.

---

## 6. FORMAT TRIAGE.JSON STANDAR BUG HUNTER

```json
{
  "target": "https://target.com",
  "mode": "bughunt-web",
  "date": "2026-11-20",
  "environment": "Bug Bounty Program / Staging",
  "verdict": "CRITICAL FINDINGS — DO NOT RELEASE",
  "ticket_ref": "HackerOne / Bugcrowd / nama program",
  "report": {
    "profile": "bughunt",
    "output": "Laporan-BugHunter-target-20261120.docx",
    "page_breaks_before": ["findings", "risk", "appendix_cases"]
  },
  "recon": {
    "subdomains_found": ["api.target.com", "admin.target.com"],
    "tech_stack": ["Nginx/1.18", "React", "Node.js"],
    "endpoints": [
      {"method": "GET", "url": "/api/v1/users", "auth": "None", "status": 200}
    ],
    "secrets_detected": [
      {"type": "AWS Key", "location": "static/js/main.chunk.js:L1842", "value": "AKIA...", "risk": "CRITICAL"}
    ]
  },
  "kill_chains": [],
  "chaos": {
    "cleanup_status": "VERIFIED",
    "tests": [],
    "cleanup_items": []
  },
  "findings": [],
  "passed_checks": [],
  "limitations": [],
  "summary": {
    "total_findings": 0,
    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "verdict": "PENDING"
  }
}
```

---

## 7. STANDAR BUKTI PoC PER TEMUAN

```json
{
  "id": "VULN-01",
  "title": "Judul Kerentanan Deskriptif",
  "severity": "HIGH",
  "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
  "cwe": "CWE-200",
  "category": "Information Disclosure",
  "location": "GET /api/v1/user/profile?id=123",
  "likelihood": 4,
  "impact": 4,
  "risk_score": 16,
  "status": "OPEN",
  "steps": [
    "1. Kirim request GET /api/v1/user/profile?id=124 tanpa Authorization header.",
    "2. Amati response 200 OK dengan data profil pengguna lain."
  ],
  "poc_snippet": "GET /api/v1/user/profile?id=124 HTTP/1.1\nHost: target.com\n\nHTTP/1.1 200 OK\n{\"id\":124,\"email\":\"victim@target.com\",\"phone\":\"081234567890\"}",
  "expected": "401 Unauthorized",
  "actual": "200 OK dengan PII pengguna lain",
  "business_impact": "Seluruh data pengguna dapat diakses tanpa autentikasi.",
  "recommendation": "Validasi sesi server-side sebelum mengembalikan data; terapkan object-level authorization.",
  "evidence": ["pendukung/bukti/screenshots/vuln-01-idor.png"],
  "shots": ["vuln-01-idor.png"],
  "confidence": "CERTAIN"
}
```

---

## 8. GUARDRAIL & ZERO REDACTION POLICY

1. **Otorisasi**: Jalankan hanya pada target milik sendiri, staging/UAT, atau program bug bounty dengan scope tertulis.
2. **Stop Produksi**: Jika eksploit akan mengubah data produksi permanen tanpa rollback → hentikan chain, tandai `BLOCKED`, laporkan ke user.
3. **Zero Redaction**: Nilai aktual dari artefak tampil apa adanya di laporan. Nilai yang tidak ada ditulis `(...)`. Tidak ada `[REDACTED]`.
4. **Kredensial**: Tidak pernah diminta di chat. Tidak pernah ditulis ke log publik.
5. **iOS/IPA**: Belum didukung (simulator tidak tersedia). Tandai `BLOCKED` di laporan bila target iOS. Tambah saat ada `xcrun simctl`.

---

## 9. STRUKTUR ARTEFAK

```
hasil-hunt-[target]-[tanggal]/
├── Laporan-BugHunter-[Target]-[Tanggal].docx    ← SATU laporan DOCX final
├── submission-hackerone.md                       ← Draft submit HackerOne
├── submission-bugcrowd.md                        ← Draft submit Bugcrowd
├── submission-generic.md                         ← Draft generic/private program
├── watch-dashboard.html                          ← Live dashboard (saat watch mode aktif)
└── pendukung/
    ├── ai/
    │   ├── triage.json                          ← Single source of truth
    │   ├── audit-log.jsonl                      ← Jejak eksekusi kronologis
    │   └── generated-cases.md                   ← Daftar seluruh skenario uji
    ├── bukti/
    │   ├── network/                             ← HTTP flow capture
    │   └── screenshots/                         ← Screenshot PoC tertanam di DOCX
    └── reconnaissance/
        ├── subdomains.json                      ← Hasil subdomain enumeration
        ├── tech-fingerprint.json                ← Server/framework/CDN detection
        └── endpoints.json                       ← Peta endpoint teridentifikasi
```

---

## 10. PERINTAH LENGKAP

```bash
# Hunt sekali - web
hunt web https://target.com/

# Hunt sekali - APK
hunt apk com.target.app
hunt apk /path/to/app.apk

# Hunt hybrid (web + APK sekaligus)
hunt all https://target.com/ com.target.app

# Watch mode: hunt tiap 30 menit, tampilkan live di browser
hunt --watch 30 https://target.com/

# Alias
bughunt https://target.com/
```

Generator laporan:
```bash
python C:\Users\Harrys\.config\opencode\skills\bug-hunter\build_report.py --root <folder_hasil>
```
