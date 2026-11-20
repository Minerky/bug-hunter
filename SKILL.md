---
name: bug-hunter
description: Autonomous Bug Hunter & Vulnerability Assessor for Web & Android APK — user gives only a target (URL, APK file, package name) or scope doc; agent auto-resolves targets, conducts passive/semi-passive recon, non-destructive vulnerability assessment, automated chaos/monkey testing with mandatory post-test cleanup, and produces ONE consolidated Word (.docx) vulnerability report with PoC and CVSS. Trigger with "hunt [url|apk]", "hunt web [url]", "hunt apk [path|pkg]", "bughunt <target>".
---

# AUTONOMOUS BUG HUNTER (`bug-hunter`)

Skill ini mengubah perintah bug hunting menjadi penilaian kerentanan dan resiliensi sistem yang berjalan sendiri. User cukup memberikan target (URL web, berkas APK, nama package, atau dokumen scope/program bug bounty); agent yang me-resolve target, melakukan reconnaissance pasif/semi-pasif, asesmen kerentanan non-destruktif, **monkey testing & chaos probe** untuk menguji ketahanan sistem, **membersihkan seluruh jejak pengujian (cleanup) secara otomatis**, memverifikasi status pembersihan, dan menghasilkan **SATU dokumen laporan Word (.docx)** terpadu lengkap dengan Proof of Concept (PoC) dan skor CVSS.

---

## 0. ALUR OTONOM (VIBE BUG HUNTING LOOP)

Eksekusi berjalan otonom dari awal hingga akhir tanpa menunggu instruksi per langkah:

```
resolve → recon → assess → chaos → cleanup → verify-cleanup → triage → report → stop
```

1. **Resolve**:
   - Deteksi tipe target (Web vs Android APK) dari argumen perintah atau dokumen di workspace.
   - Cek batasan scope: domain in-scope, wildcard subdomain, dan target terlarang (out-of-scope).
   - Kredensial akun uji di-resolve otomatis dari file `.env.qa` atau `qa-credentials.local.json` (jangan meminta kredensial di chat).
2. **Recon**:
   - **Web**: DNS/subdomain pasif, HTTP response headers, fingerprint server & framework, sitemap/robots, endpoint discovery, dan scan rahasia/token hardcoded pada berkas JS publik.
   - **APK**: Parsing `AndroidManifest.xml` (exported activities, exported services, broadcast receivers, content providers), audit permission overprivilege, flag `debuggable` / `allowBackup`, dan static scan string DEX untuk mendeteksi hardcoded token, API keys, dan URL backend internal.
3. **Assess (Vulnerability Assessment Non-Destruktif)**:
   - **Web**: Missing security headers (HSTS, CSP, X-Frame-Options), CORS misconfiguration, IDOR verification, endpoint unauthenticated, validasi input / non-destructive reflection probe (XSS/SQLi injection detection tanpa exploit merusak), open redirect.
   - **APK**: Komponen exported tanpa permission guard, penyimpanan data sensitif plaintext di `shared_prefs` atau SQLite privat, pengiriman traffic HTTP cleartext, pemeriksaan sertifikat / SSL pinning.
4. **Chaos (Monkey Testing & Resiliensi Sistem)**:
   - Dijalankan otomatis sebagai bagian dari `hunt` untuk menguji ketahanan aplikasi saat menerima beban atau input di luar spesifikasi.
   - **Web**: Form stress input (unicode surrogates, ultra-long string, boundary numbers, null byte injection), pengujian metode HTTP tak lazim (PUT/DELETE pada endpoint baca), probe balapan (race condition via parallel requests), dan analisis respon error (membedakan error anggun vs 500 internal server error leak).
   - **APK**: `adb shell monkey -p <package> --throttle 100 -v 1000` (1.000 event UI acak untuk mendeteksi crash/freeze), intent injection dengan data malformed pada exported components, dan uji pemulihan state saat aplikasi dihentikan paksa.
   - *Catatan Proteksi Produksi*: Jika target terdeteksi sebagai sistem produksi live dengan data nyata, hentikan aksi yang dapat mengubah data permanen dan minta konfirmasi user.
5. **Cleanup (Pembersihan Jejak Pengujian Otomatis)**:
   - Wajib dijalankan segera setelah fase chaos selesai:
     * **Web**: Hapus cookie sesi dan local storage browser (`browser_clear_cookies`), logout dari sesi aktif, dan hapus entri/transaksi uji yang sempat terbuat (via endpoint delete/rollback).
     * **APK**: Hapus file temporer yang dibuat di storage lokal/device (`adb shell rm -rf`), bersihkan log buffer (`adb logcat -c`), dan pulihkan konfigurasi jaringan/proxy emulator.
     * **Database**: Catat seluruh ID data uji yang tidak dapat dihapus otomatis untuk dilaporkan kepada pengelola sistem.
6. **Verify-Cleanup**:
   - Verifikasi apakah lingkungan dan sistem target telah kembali bersih.
   - Jika semua jejak terhapus: status cleanup = `VERIFIED`.
   - Jika ada sisa data di backend yang butuh intervensi admin/vendor: status cleanup = `PARTIAL` dan dicatat rinci pada laporan serta risk register.
7. **Triage (`ai/triage.json`)**:
   - Tulis seluruh temuan ke satu berkas `pendukung/ai/triage.json` sebagai single source of truth.
   - Tiap temuan wajib memiliki: `id`, `title`, `severity` (CRITICAL, HIGH, MEDIUM, LOW, INFO), `cvss` (skor & vektor), `cwe`, `location`, `steps` (PoC langkah demi langkah), `expected`, `actual`, `business_impact`, `recommendation`, dan tautan gambar bukti.
8. **Report**:
   - Bangun SATU berkas DOCX menggunakan `build_report.py` / `report_kit.py` dengan profil `bughunt`.
   - Seluruh screenshot dan bukti visual tertanam di dalam dokumen Word.
   - Laporan murni pencatatan hasil audit — **jangan menyisipkan catatan internal pengembangan skill atau referensi file instruksi agent**.
9. **Stop**:
   - Selesaikan laporan, lakukan verifikasi akhir (cek nol marker `[REDACTED]`), dan laporkan ringkasan temuan kepada user.

---

## 1. CARA MEMERINTAHKAN

| Perintah | Deskripsi Eksekusi |
|---|---|
| `hunt [target]` | Auto-detect URL vs APK/package, jalankan alur penuh (Recon + Assess + Chaos + Cleanup + Report). |
| `hunt web [url]` | Target web: navigasi Playwright, header audit, passive scan, form fuzzing, concurrency probe, cleanup, report. |
| `hunt apk [path\|package]` | Target Android: manifest analysis, static scan, ADB exploration, monkey stress test, cleanup, report. |
| `hunt all [url] [apk]` | Target hybrid web + mobile: jalankan kedua permukaan, gabungkan temuan ke satu triage dan satu DOCX. |

Alias yang dikenali: `bughunt [target]`, `hunt [target]`, `bug hunter web <url>`, `bug hunter apk <file>`.

---

## 2. GUARDRAIL & ATURAN NILAI (ZERO REDACTION POLICY)

1. **Etika & Otorisasi**:
   - Jalankan asesmen hanya pada target milik sendiri, lingkungan UAT/staging, atau target yang memiliki otorisasi/scope tertulis (mis. program bug bounty).
   - Dilarang keras melakukan Denial of Service (DoS), perusakan data permanen, ransomware, atau eksploitasi destruktif.
2. **Aturan Kredensial & Nilai Aktual**:
   - **Semua nilai yang tersedia di artefak ditampilkan apa adanya** di dalam laporan (URL, host, port, parameter, nama akun, token, PIN, password UAT).
   - Nilai yang tidak pernah ada atau tidak ditemukan di sumber ditulis **`(...)`**, bukan marker `[REDACTED]`.
   - Kredensial tidak pernah diminta melalui chat dan tidak dicatat ke log publik.

---

## 3. PANDUAN PENGUJIAN CHAOS & MONKEY RESILIENCE

Fase Chaos dirancang untuk menemukan kerentanan logika, penanganan error yang bocor, dan kondisi crash:

### 3.1 Web Resilience Probe
- **Input Fuzzing**: Uji form input dengan:
  * String batas panjang (5.000+ karakter) untuk mengamati buffer/database truncation.
  * Unicode khusus / karakter surrogat / null byte (`%00`) untuk mendeteksi unhandled exception.
  * Tipe data bertolak belakang (string pada field number, array pada field string).
- **HTTP Method Mangling**: Kirim `PUT`, `DELETE`, `PATCH`, `OPTIONS` ke route privat untuk mendeteksi miskonfigurasi method override atau akses kontrol lemah.
- **Race Condition / Concurrency**: Kirim 5-10 request paralel secara simultan ke endpoint kritis (klaim kupon, transfer, counter) untuk memeriksa race condition.
- **Error Leak Analysis**: Periksa apakah respon error mengembalikan stack trace lengkap, versi server/database, atau query SQL mentah (CWE-209).

### 3.2 Mobile Monkey & Intent Stress
- **UI Monkey Events**:
  ```bash
  adb shell monkey -p <package_name> --throttle 100 --pct-touch 40 --pct-motion 30 --pct-appswitch 15 -v 1000
  ```
  Pantau logcat untuk unhandled `NullPointerException` atau `ActivityNotFoundException`.
- **Intent Injection**:
  Kirim intent eksplisit dan implisit dengan action/extra tak terduga ke seluruh exported activity dan service:
  ```bash
  adb shell am start -n <package>/<exported_activity> --es extra_param "%00' OR 1=1"
  ```
- **State Restorability**: Simulasikan low-memory kill (`am kill <package>`) saat form terisi, lalu luncurkan kembali untuk memeriksa crash pada lifecycle restoration.

---

## 4. STANDAR BUKTI POC & FORMAT TRIAGE

Setiap temuan di `ai/triage.json` wajib memenuhi format standar Bug Hunter:

```json
{
  "id": "VULN-01",
  "title": "Judul Kerentanan yang Deskriptif",
  "severity": "HIGH",
  "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
  "cwe": "CWE-200 / CWE-284",
  "category": "Broken Access Control",
  "location": "GET /api/v1/user/profile?id=123",
  "likelihood": 4,
  "impact": 4,
  "risk_score": 16,
  "status": "OPEN",
  "steps": [
    "1. Akses endpoint target tanpa menyertakan header Authorization.",
    "2. Masukkan parameter id=123 milik pengguna lain.",
    "3. Amati respon server yang mengembalikan data profil lengkap pengguna lain."
  ],
  "poc_snippet": "GET /api/v1/user/profile?id=123 HTTP/1.1\nHost: target.com\n\nHTTP/1.1 200 OK\n{\"id\": 123, \"name\": \"Admin User\", \"email\": \"admin@target.com\"}",
  "expected": "Server mengembalikan respon 401 Unauthorized atau 403 Forbidden.",
  "actual": "Server mengembalikan respon 200 OK beserta seluruh data PII pengguna.",
  "business_impact": "Kebocoran data sensitif seluruh pengguna terdaftar yang dapat dimanfaatkan untuk pengambilalihan akun.",
  "recommendation": "Terapkan validasi sesi berbasis token server-side dan pastikan otorisasi objek (object-level authorization) diperiksa sebelum data dikembalikan.",
  "evidence": ["pendukung/bukti/vuln-01-poc.png"],
  "shots": ["vuln-01-poc.png"],
  "confidence": "CERTAIN"
}
```

Format blok Chaos di `ai/triage.json`:
```json
{
  "chaos": {
    "cleanup_status": "VERIFIED",
    "tests": [
      {
        "scenario": "Boundary input 10k karakter pada form input",
        "target": "POST /contact/submit",
        "response": "Graceful validation error (400 Bad Request)",
        "finding_ref": "-"
      },
      {
        "scenario": "Monkey random event 1.000 taps",
        "target": "com.target.app",
        "response": "Stabil; 0 crash, 0 freeze",
        "finding_ref": "-"
      }
    ],
    "cleanup_items": [
      {
        "item": "Session cookies browser",
        "method": "browser_clear_cookies",
        "status": "BERSIH",
        "notes": "Storage lokal dan cookies dihapus"
      },
      {
        "item": "Data input form uji",
        "method": "Endpoint delete / reset",
        "status": "BERSIH",
        "notes": "Tidak ada data dummy tertinggal"
      }
    ]
  }
}
```

---

## 5. STRUKTUR ARTEFAK & PELAPORAN

Folder hasil uji wajib mengikuti struktur rapi berikut:

```
hasil-hunt-[target]/
├── Laporan-BugHunter-[Target]-[Tanggal].docx    # SATU-SATUNYA laporan Word final
└── pendukung/
    ├── ai/
    │   ├── triage.json                         # Single source of truth seluruh temuan
    │   ├── audit-log.jsonl                     # Jejak eksekusi kronologis
    │   └── generated-cases.md                  # Rincian seluruh skenario uji
    ├── bukti/
    │   ├── network/                            # Capture traffic HTTP / flow
    │   └── screenshots/                        # Screenshot bukti visual PoC
    └── reconnaissance/                         # Output pemetaan endpoint / manifest
```

Laporan dibangun dengan perintah:
```bash
python C:\Users\Harrys\.config\opencode\skills\bug-hunter\build_report.py --root <folder_hasil>
```
Laporan diverifikasi otomatis:
- Tepat satu file `.docx` per folder target.
- Bersih dari marker `[REDACTED]`.
- Status cleanup pasca-uji tercatat jelas (`VERIFIED` atau `PARTIAL`).
