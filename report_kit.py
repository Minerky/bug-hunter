# -*- coding: utf-8 -*-
"""Kit render laporan Bug Hunter & Vulnerability Assessment generik.

Satu source of truth: pendukung/ai/triage.json.
Target menentukan isi lewat blok `report` di triage (profil, bab, tabel tambahan,
gambar bukti). Kit ini dirancang untuk laporan Bug Bounty, Vulnerability Assessment,
Reconnaissance, Chaos / Monkey Testing, dan Status Cleanup Terverifikasi.
"""
import os, re, json, hashlib, argparse
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

# Renderer sengaja TIDAK menyensor nilai. Nilai yang tersedia di artefak tampil
# apa adanya di DOCX; nilai yang tidak ada ditulis `(...)` di triage.json.
def R(text):
    """Identity renderer — pertahankan nilai apa adanya dari triage/artefak."""
    return str(text)

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

SEV_LI = {'CRITICAL': (5, 5), 'HIGH': (4, 4), 'MEDIUM': (3, 3), 'LOW': (2, 2), 'INFO': (1, 1)}
SEV_FILL = {'CRITICAL': 'B00000', 'HIGH': 'C05000', 'MEDIUM': '8A6D00', 'LOW': '336633', 'INFO': '2B5B84'}
SEV_RGB = {'CRITICAL': RGBColor(0xB0,0x00,0x00), 'HIGH': RGBColor(0xC0,0x50,0x00),
           'MEDIUM': RGBColor(0x8A,0x6D,0x00), 'LOW': RGBColor(0x33,0x66,0x33),
           'INFO': RGBColor(0x2B,0x5B,0x84)}

DEFAULT_CHAPTERS = {
    'bughunt': ['cover','executive','scope','method','environment','recon','findings',
                'chaos','risk','recommendations','limits','appendix_cases','appendix_evidence','appendix_extra'],
    'web': ['cover','executive','scope','method','environment','recon','findings',
            'chaos','risk','recommendations','limits','appendix_cases','appendix_evidence','appendix_extra'],
    'apk': ['cover','executive','scope','method','environment','recon','findings',
            'chaos','risk','recommendations','limits','appendix_cases','appendix_evidence','appendix_extra'],
    'all': ['cover','executive','scope','method','environment','recon','findings',
            'chaos','risk','recommendations','limits','appendix_cases','appendix_evidence','appendix_extra'],
}

BUILTIN_TITLES = {
    'executive': 'Ringkasan Eksekutif & Distribusi Risiko',
    'scope': 'Scope & Rules of Engagement',
    'method': 'Metodologi Pengujian',
    'environment': 'Target & Lingkungan Pengujian',
    'recon': 'Hasil Reconnaissance & Surface Mapping',
    'findings': 'Temuan Kerentanan & Bukti PoC',
    'passed': 'Pemeriksaan yang Lolos',
    'chaos': 'Pengujian Chaos / Monkey & Status Cleanup',
    'risk': 'Risk Register & Matriks Risiko',
    'recommendations': 'Rekomendasi Remediasi Prioritas',
    'limits': 'Batasan Pengujian & Status',
    'appendix_cases': 'Lampiran — Daftar Skenario Uji',
    'appendix_evidence': 'Lampiran — Inventaris Bukti & Traffic',
    'appendix_extra': 'Lampiran — Bukti Visual / Screenshot',
}

SECTION_HINTS = {
    'scope': ['Scope & Rules'], 'method': ['Metodologi'], 'environment': ['Target & Lingkungan'],
    'recon': ['Reconnaissance'], 'findings': ['Temuan Kerentanan'], 'chaos': ['Pengujian Chaos'],
    'risk': ['Risk Register'], 'recommendations': ['Rekomendasi Remediasi'],
    'limits': ['Batasan Pengujian'], 'appendix_cases': ['Daftar Skenario Uji'],
    'appendix_evidence': ['Inventaris Bukti'], 'appendix_extra': ['Bukti Visual'],
}


def norm_findings(triage):
    out = []
    for f in triage.get('findings', []):
        sev = str(f.get('severity') or f.get('sev') or 'LOW').upper()
        likelihood = f.get('likelihood')
        imp = f.get('impact')
        impact_score = imp if isinstance(imp, (int, float)) else None
        business = f.get('business_impact') or (imp if isinstance(imp, str) else '')
        if likelihood is None or impact_score is None:
            likelihood, impact_score = SEV_LI.get(sev, (2, 2))
        try:
            score = int(f.get('risk_score') or round(likelihood * impact_score))
        except Exception:
            score = likelihood * impact_score
        ev = f.get('evidence', [])
        if isinstance(ev, str):
            ev = [x.strip() for x in re.split(r';|\n', ev) if x.strip()]
        shots = list(f.get('shots') or [])
        for e in ev:
            if isinstance(e, str) and e.lower().endswith('.png'):
                shots.append(os.path.basename(e))
        out.append({
            'id': f.get('id', '-'), 'title': f.get('title', '-'), 'severity': sev,
            'category': f.get('category') or f.get('cat') or '-',
            'status': f.get('status', '-'), 'location': f.get('location', ''),
            'cvss': f.get('cvss', '-'), 'cwe': f.get('cwe', '-'),
            'likelihood': likelihood, 'impact_score': impact_score, 'score': score,
            'expected': f.get('expected', '-'), 'actual': f.get('actual', '-'),
            'business': business, 'recommendation': f.get('recommendation') or f.get('rec') or '-',
            'steps': f.get('steps') or f.get('poc_steps') or [],
            'poc_snippet': f.get('poc_snippet', ''),
            'chain': f.get('chain') or [], 'evidence': ev, 'confidence': f.get('confidence', '-'),
            'shots': list(dict.fromkeys(shots)),
        })
    return out


class Report:
    def __init__(self, root, triage, cfg, profile):
        self.root = os.path.abspath(root)
        self.base = os.path.join(self.root, 'pendukung')
        self.triage = triage
        self.cfg = cfg
        self.profile = profile
        self._findings = norm_findings(triage)
        self.doc = Document()
        self._setup()

    def _setup(self):
        sec = self.doc.sections[0]
        sec.top_margin = Inches(0.75)
        sec.bottom_margin = Inches(0.75)
        sec.left_margin = Inches(0.8)
        sec.right_margin = Inches(0.8)
        sec.page_width = Inches(8.27)
        sec.page_height = Inches(11.69)
        self._footer(sec)

        norm = self.doc.styles['Normal']
        norm.font.name = 'Calibri'
        norm.font.size = Pt(10)
        norm.font.color.rgb = RGBColor(0x22, 0x22, 0x22)
        norm.paragraph_format.line_spacing = 1.15
        norm.paragraph_format.space_after = Pt(4)

        for lvl, sz, col in [(1,16,RGBColor(0x0E,0x2A,0x47)),(2,13,RGBColor(0x1B,0x36,0x5D)),(3,11,RGBColor(0x2C,0x4D,0x75))]:
            try:
                st = self.doc.styles[f'Heading {lvl}']
                st.font.name = 'Calibri'
                st.font.size = Pt(sz)
                st.font.bold = True
                st.font.color.rgb = col
                st.paragraph_format.space_before = Pt(10)
                st.paragraph_format.space_after = Pt(3)
            except Exception:
                pass

    def _footer(self, sec):
        ft = sec.footer; p = ft.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p.text = f"{self.triage.get('target', 'Target')} — Bug Hunter & Vulnerability Assessment | Hal. "
        self._page_field(p)

    @staticmethod
    def _shade(cell, fill):
        tcPr = cell._tc.get_or_add_tcPr()
        for e in list(tcPr):
            if e.tag.endswith('shd'): tcPr.remove(e)
        tcPr.append(OxmlElement('w:shd', {qn('w:val'):'clear', qn('w:color'):'auto', qn('w:fill'):fill}))

    @staticmethod
    def _margins(cell, top=70, start=100, bottom=70, end=100):
        tcPr = cell._tc.get_or_add_tcPr()
        for e in list(tcPr):
            if e.tag.endswith('tcMar'): tcPr.remove(e)
        tcMar = OxmlElement('w:tcMar')
        for k, v in [('top',top),('left',start),('bottom',bottom),('right',end)]:
            m = OxmlElement(f'w:{k}', {qn('w:w'):str(v), qn('w:type'):'dxa'})
            tcMar.append(m)
        tcPr.append(tcMar)

    @staticmethod
    def _repeat(row):
        trPr = row._tr.get_or_add_trPr()
        trPr.append(OxmlElement('w:tblHeader'))
        trPr.append(OxmlElement('w:cantSplit'))

    @staticmethod
    def _borders(t):
        tblPr = t._tbl.tblPr
        for e in list(tblPr):
            if e.tag.endswith('tblBorders'): tblPr.remove(e)
        b = OxmlElement('w:tblBorders')
        for side in ['top','left','bottom','right','insideH','insideV']:
            b.append(OxmlElement(f'w:{side}', {qn('w:val'):'single', qn('w:sz'):'4', qn('w:space'):'0', qn('w:color'):'D6DCE5'}))
        tblPr.append(b)

    @staticmethod
    def _page_field(p):
        r = p.add_run()
        fldChar1 = OxmlElement('w:fldChar'); fldChar1.set(qn('w:fldCharType'), 'begin')
        instrText = OxmlElement('w:instrText'); instrText.set(qn('xml:space'), 'preserve'); instrText.text = "PAGE"
        fldChar2 = OxmlElement('w:fldChar'); fldChar2.set(qn('w:fldCharType'), 'separate')
        fldChar3 = OxmlElement('w:fldChar'); fldChar3.set(qn('w:fldCharType'), 'end')
        r._r.append(fldChar1); r._r.append(instrText); r._r.append(fldChar2); r._r.append(fldChar3)

    @staticmethod
    def _rule(p, color='C9D3DF', size='6'):
        pBdr = OxmlElement('w:pBdr')
        bot = OxmlElement('w:bottom', {qn('w:val'):'single', qn('w:sz'):size, qn('w:space'):'4', qn('w:color'):color})
        pBdr.append(bot)
        p._p.get_or_add_pPr().append(pBdr)

    def P(self, text='', bold=False, italic=False, size=None):
        p = self.doc.add_paragraph()
        r = p.add_run(R(text))
        r.bold = bold; r.italic = italic
        if size: r.font.size = Pt(size)
        return p

    def H(self, text, level=1):
        p = self.doc.add_heading(level=level)
        r = p.add_run(R(text))
        r.bold = True
        return p

    def spacer(self, pt=4):
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(pt)
        p.paragraph_format.space_after = Pt(0)
        return p

    def table(self, headers, rows, widths=None, score_col=None, severity_col=None):
        t = self.doc.add_table(rows=len(rows)+1, cols=len(headers))
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        self._borders(t)
        self._repeat(t.rows[0])
        hdr = t.rows[0]
        for i, h in enumerate(headers):
            c = hdr.cells[i]
            c.text = R(str(h))
            self._shade(c, '1B365D')
            self._margins(c, 80, 100, 80, 100)
            c.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p = c.paragraphs[0]; p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            for r in p.runs:
                r.font.bold = True; r.font.color.rgb = RGBColor(0xFF,0xFF,0xFF); r.font.size = Pt(9.5)
        for r_idx, row in enumerate(rows):
            tr = t.rows[r_idx+1]
            bg = 'F4F7FA' if (r_idx % 2 == 1) else 'FFFFFF'
            for c_idx, val in enumerate(row):
                c = tr.cells[c_idx]
                c.text = R(str(val))
                self._shade(c, bg)
                self._margins(c, 55, 90, 55, 90)
                c.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
                p = c.paragraphs[0]
                for r in p.runs: r.font.size = Pt(9)
                if severity_col is not None and c_idx == severity_col:
                    s = str(val).upper()
                    if s in SEV_FILL:
                        self._shade(c, SEV_FILL[s])
                        for r in p.runs:
                            r.font.bold = True
                            r.font.color.rgb = RGBColor(0xFF,0xFF,0xFF)
                if score_col is not None and c_idx == score_col:
                    try:
                        sc = int(val)
                        if sc >= 20: fill = SEV_FILL['CRITICAL']
                        elif sc >= 12: fill = SEV_FILL['HIGH']
                        elif sc >= 6: fill = SEV_FILL['MEDIUM']
                        else: fill = SEV_FILL['LOW']
                        self._shade(c, fill)
                        for r in p.runs:
                            r.font.bold = True
                            r.font.color.rgb = RGBColor(0xFF,0xFF,0xFF)
                    except Exception:
                        pass
        if widths:
            for row in t.rows:
                for idx, w in enumerate(widths):
                    if idx < len(row.cells): row.cells[idx].width = Inches(w)
        self.doc.add_paragraph()
        return t

    def bullet(self, text):
        p = self.doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(2)
        p.add_run(R(text))
        return p

    def banner(self, text, fill='8A6D00', size=11):
        t = self.doc.add_table(rows=1, cols=1)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        c = t.rows[0].cells[0]
        c.width = Inches(6.67)
        self._shade(c, fill)
        self._margins(c, 100, 140, 100, 140)
        p = c.paragraphs[0]; p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(R(text))
        r.font.bold = True; r.font.size = Pt(size); r.font.color.rgb = RGBColor(0xFF,0xFF,0xFF)
        self.doc.add_paragraph()

    def resolve_image(self, ref):
        candidates = [
            ref,
            os.path.join(self.base, 'bukti', ref),
            os.path.join(self.base, 'screenshots', ref),
            os.path.join(self.base, ref),
            os.path.join(self.root, ref),
        ]
        for c in candidates:
            if c and os.path.isfile(c): return c
        bn = os.path.basename(ref)
        for sub in ['bukti', 'screenshots', '.']:
            d = os.path.join(self.base, sub)
            if os.path.isdir(d):
                p = os.path.join(d, bn)
                if os.path.isfile(p): return p
        return None

    def image(self, ref, caption, width=5.6):
        fp = self.resolve_image(ref)
        if not fp:
            self.P('Gambar tidak tersedia: ' + str(ref), italic=True); return False
        self.doc.add_picture(fp, width=Inches(width))
        cap = self.doc.add_paragraph(style='Caption'); cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap.add_run(R(caption)).italic = True
        return True

    # ---------- built-in chapters ----------
    def cover(self):
        cfg = self.cfg; tr = self.triage
        self.spacer(26)
        p = self.doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(R(cfg.get('title') or f"LAPORAN BUG HUNTER & VULNERABILITY ASSESSMENT\n{tr.get('target','-')}"))
        r.font.size = Pt(20); r.font.bold = True; r.font.color.rgb = RGBColor(0x0E,0x2A,0x47)

        sub = cfg.get('subtitle') or f"Penilaian Keamanan Otomatis, PoC Kerentanan, dan Chaos Testing"
        p2 = self.doc.add_paragraph(); p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r2 = p2.add_run(R(sub))
        r2.font.size = Pt(12); r2.font.italic = True; r2.font.color.rgb = RGBColor(0x55,0x55,0x55)
        self._rule(p2, color='0E2A47', size='12')
        self.spacer(14)

        rows = self._cover_fields()
        self.table(['Parameter', 'Nilai'], rows, widths=[2.2, 4.4])
        self.spacer(10)

        notes = cfg.get('cover_notes') or [
            "Laporan ini menyajikan hasil reconnaissance, temuan kerentanan dengan pembuktian konsep (PoC), hasil pengujian chaos / monkey testing, serta status verifikasi pembersihan (cleanup) pasca-uji.",
            "Semua nilai aktual yang ditemukan di artefak ditampilkan apa adanya. Nilai yang tidak tersedia ditulis `(...)`."
        ]
        for note in notes:
            self.P(note, italic=True, size=9)
        self.doc.add_page_break()

    def _cover_fields(self):
        tr = self.triage
        v = tr.get('verdict') or tr.get('summary', {}).get('verdict', '-')
        rows = [
            ['Target', tr.get('target', '-')],
            ['Tanggal Pengujian', tr.get('date') or tr.get('generated_at', '-')],
            ['Profil Pengujian', self.profile.upper()],
            ['Status / Rekomendasi Rilis', str(v)],
            ['Klasifikasi Dokumen', 'Confidential — Vulnerability Assessment'],
            ['Referensi Tiket / Program', str(tr.get('ticket_ref', 'Bug Bounty Assessment'))]
        ]
        if 'application' in tr:
            app = tr['application']
            rows.insert(1, ['Aplikasi Target', f"{app.get('name','-')} v{app.get('version','-')} ({app.get('package','-')})"])
        return rows

    def executive(self):
        s = self.triage.get('summary', {})
        tot = s.get('total_findings', len(self._findings))
        by_sev = s.get('by_severity', {})
        v = self.triage.get('verdict') or s.get('verdict', '-')

        fill = 'B00000' if ('REJECT' in str(v) or 'DO_NOT' in str(v) or by_sev.get('CRITICAL',0)>0) else ('C05000' if by_sev.get('HIGH',0)>0 else '336633')
        self.banner(f"HASIL AKHIR: {v}", fill=fill, size=13)

        self.H('Distribusi Kerentanan Berdasarkan Tingkat Keparahan', 2)
        rows = [
            ['CRITICAL', str(by_sev.get('CRITICAL', 0)), 'Remediasi mendesak (P1)', 'Eksploitasi langsung dengan dampak masif'],
            ['HIGH',     str(by_sev.get('HIGH', 0)),     'Remediasi prioritas tinggi (P1)', 'Dampak signifikan terhadap integritas atau kerahasiaan'],
            ['MEDIUM',   str(by_sev.get('MEDIUM', 0)),   'Perbaikan pada sprint aktif (P2)', 'Kelemahan konfigurasi / akses terkontrol'],
            ['LOW',      str(by_sev.get('LOW', 0)),      'Perbaikan terjadwal (P3)', 'Penyimpangan best-practice / risiko minimal'],
            ['INFO',     str(by_sev.get('INFO', 0)),     'Informasional', 'Temuan observasi konfigurasi atau arsitektur'],
            ['TOTAL',    str(tot),                       '-', 'Seluruh temuan teridentifikasi']
        ]
        self.table(['Tingkat Keparahan', 'Jumlah', 'Tindakan', 'Definisi'], rows,
                   widths=[1.5, 0.8, 2.0, 2.3], severity_col=0)

        self.blocks(self.cfg.get('executive_blocks', []))

    def scope(self):
        tr = self.triage
        sc = tr.get('scope', {})
        in_scope = sc.get('in_scope', [tr.get('target', '-')])
        out_scope = sc.get('out_of_scope', ['Host di luar daftar yang ditentukan', 'Serangan Denial of Service (DoS/DDoS)', 'Perusakan data permanen tanpa rollback'])

        rows = [
            ['Target Terotorisasi', '\n'.join(in_scope) if isinstance(in_scope, list) else str(in_scope)],
            ['Batasan / Out-of-Scope', '\n'.join(out_scope) if isinstance(out_scope, list) else str(out_scope)],
            ['Rules of Engagement', 'Non-destruktif default; probe verifikasi celah; pengujian resiliensi dengan pembersihan otomatis.'],
            ['Stop Condition', 'Hentikan eksplorasi bila terjadi instabilitas sistem target yang tidak terduga.'],
        ]
        self.table(['Aspek Scope', 'Ketentuan'], rows, widths=[1.8, 4.8])
        self.blocks(self.cfg.get('scope_blocks', []))

    def method(self):
        rows = self.cfg.get('method_rows') or [
            ['Fase', 'Alat & Teknik', 'Bukti / Output'],
            ['Reconnaissance', 'DNS, header inspection, JS/manifest parse, secret hunting', 'Daftar endpoint & secret scan'],
            ['Vulnerability Assessment', 'Playwright browser, ADB, static analysis, passive flow capture', 'Log interaksi & request capture'],
            ['Chaos / Monkey Testing', 'Input fuzzing, unexpected method/type, monkey random UI stress', 'Resilience log & error responses'],
            ['Cleanup & Verification', 'Automated reset cookies/session, adb shell cleanup, DB record teardown', 'Audit log pembersihan terverifikasi'],
            ['Reporting', 'Satu source of truth triage.json -> satu DOCX mandiri', 'Dokumen laporan ini'],
        ]
        if rows and len(rows[0]) == 2:
            self.table(rows[0], rows[1:], widths=[1.8, 4.8])
        else:
            self.table(rows[0], rows[1:], widths=[1.5, 2.5, 2.6])
        self.blocks(self.cfg.get('method_blocks', []))

    def environment(self):
        tr = self.triage; acc = tr.get('test_account', {})
        rows = [['Komponen', 'Keterangan'],
                ['Target Pengujian', tr.get('target', '-')],
                ['Environment', tr.get('environment', '-')],
                ['Otorisasi', tr.get('authorization', '-')],
                ['Akun Uji', acc.get('identity', '(...)')],
                ['Role Akun', acc.get('role', '(...)')],
                ['Sumber Akun', acc.get('source', '(...)')],
                ['Kredensial / Token', ' / '.join(filter(None, [str(acc.get('password','')), str(acc.get('token',''))])) or '(...)']]
        if 'application' in tr:
            app = tr['application']
            rows.insert(1, ['Nama Aplikasi', app.get('name', '-')])
            rows.insert(2, ['Versi & Build', app.get('version', '-')])
            rows.insert(3, ['Package ID', app.get('package', '-')])
        self.table(rows[0], rows[1:], widths=[1.8, 4.8])
        self.blocks(self.cfg.get('environment_blocks', []))

    def recon(self):
        r = self.triage.get('recon', {})
        self.P('Hasil pemetaan permukaan serangan (attack surface), endpoint publik, dan parameter target.', italic=True)
        if 'endpoints' in r:
            self.H('Endpoint Terpetakan', 2)
            rows = [[ep.get('method','GET'), ep.get('url','-'), ep.get('auth','Public'), str(ep.get('status','-'))]
                    for ep in r.get('endpoints', [])]
            if rows:
                self.table(['Method', 'URL / Path', 'Auth Required', 'Status Code'], rows, widths=[0.9, 3.8, 1.1, 0.8])
        if 'secrets_detected' in r:
            self.H('Potensi Kredensial / Token Teridentifikasi di Artefak', 2)
            rows = [[s.get('type','Secret'), s.get('location','-'), s.get('value','(...)'), s.get('risk','Medium')]
                    for s in r.get('secrets_detected', [])]
            if rows:
                self.table(['Jenis Secret', 'Lokasi / File', 'Nilai Terdeteksi', 'Risiko'], rows, widths=[1.3, 2.4, 2.1, 0.8])
        self.blocks(self.cfg.get('recon_blocks', []))

    def findings(self):
        self.P('Temuan kerentanan diurutkan berdasarkan tingkat keparahan. Setiap temuan dilengkapi langkah pembuktian konsep (Proof of Concept) yang dapat direproduksi.', italic=True)
        used = set()
        for f in self._findings:
            h = self.H(f"{f['id']} — {f['title']}", 2)
            for r in h.runs:
                if f['severity'] in SEV_RGB: r.font.color.rgb = SEV_RGB[f['severity']]
            
            meta_rows = [
                ['Severity', f['severity']],
                ['Kategori / CWE', f"{f['category']} ({f['cwe']})"],
                ['Status', f['status']],
                ['Skor Risiko (L × I)', f"{f['score']} (Likelihood: {f['likelihood']}, Impact: {f['impact_score']})"],
            ]
            if f['cvss'] != '-': meta_rows.append(['CVSS v3.1', str(f['cvss'])])
            if f['location']: meta_rows.append(['Lokasi / Endpoint', str(f['location'])])
            self.table(['Parameter', 'Nilai'], meta_rows, widths=[1.8, 4.8])

            if f['steps']:
                self.P('Langkah Reproduksi (Proof of Concept):', bold=True)
                for s in f['steps']: self.bullet(s)

            if f.get('poc_snippet'):
                self.P('Snippet Request / Response / Payload:', bold=True)
                self.P(str(f['poc_snippet']), italic=True)

            self.P('Ekspektasi: ' + str(f['expected']))
            self.P('Aktual: ' + str(f['actual']))
            if f['business']: self.P('Dampak Bisnis & Keamanan: ' + str(f['business']))
            self.P('Rekomendasi Remediasi: ' + str(f['recommendation']))
            if f['evidence']:
                self.P('Bukti: ' + '; '.join(map(str, f['evidence'])) +
                       (f" (keyakinan: {f['confidence']})" if f['confidence'] != '-' else ''), italic=True)
            for shot in f['shots']:
                fp = self.resolve_image(shot)
                if fp and fp not in used:
                    self.image(shot, f"Bukti Visual: {f['id']} — {os.path.basename(fp)}")
                    used.add(fp)
                    break

    def chaos(self):
        ch = self.triage.get('chaos', {})
        self.P('Hasil pengujian chaos / monkey testing untuk memverifikasi resiliensi aplikasi terhadap input ekstrem, kondisi balapan (race condition), serta verifikasi bahwa seluruh jejak pengujian telah dibersihkan.', italic=True)
        
        # Cleanup status banner
        cl_status = str(ch.get('cleanup_status', 'VERIFIED')).upper()
        if 'PARTIAL' in cl_status or 'FAILED' in cl_status:
            self.banner(f"STATUS CLEANUP: {cl_status} — PERLU PEMBERSIHAN MANUAL OLEH VENDOR", fill='B00000', size=11)
        else:
            self.banner(f"STATUS CLEANUP PASCA-UJI: TERVERIFIKASI BERSIH (VERIFIED)", fill='336633', size=11)

        tests = ch.get('tests', [])
        if tests:
            self.H('Skenario Chaos & Monkey Testing', 2)
            rows = [[t.get('scenario','Chaos'), t.get('target','-'), t.get('response','Graceful'), t.get('finding_ref','-')]
                    for t in tests]
            self.table(['Skenario Pengujian', 'Komponen / Endpoint Target', 'Respon Sistem', 'Temuan Terkait'], rows,
                       widths=[2.0, 2.2, 1.6, 0.8])

        cleanup_items = ch.get('cleanup_items', [])
        if cleanup_items:
            self.H('Inventaris Pembersihan Jejak (Teardown)', 2)
            rows = [[ci.get('item','Artefak'), ci.get('method','-'), ci.get('status','BERSIH'), ci.get('notes','-')]
                    for ci in cleanup_items]
            self.table(['Jejak / Artefak', 'Metode Pembersihan', 'Status', 'Catatan'], rows,
                       widths=[1.8, 1.8, 1.1, 1.9])
        self.blocks(self.cfg.get('chaos_blocks', []))

    def passed(self):
        self.P('Pemeriksaan keamanan dan fungsional yang dinyatakan lolos tanpa kerentanan.', italic=True)
        for c in self.triage.get('passed_checks', []): self.bullet(c)

    def risk(self):
        self.P('Skor Risiko = Likelihood × Impact (1–5). Band: 20–25 Critical, 12–19 High, 6–11 Medium, 1–5 Low.', italic=True)
        rows = [[f['id'], f['title'][:50], str(f['likelihood']), str(f['impact_score']),
                 str(f['score']), f.get('owner','tidak ditetapkan'), str(f['recommendation'])[:88], f['status']]
                for f in self._findings]
        self.table(['ID', 'Kerentanan', 'L', 'I', 'Skor', 'Owner', 'Rencana Mitigasi', 'Status'], rows,
                   widths=[0.65, 1.75, 0.3, 0.3, 0.45, 0.65, 2.0, 0.8], score_col=4)

    def recommendations(self):
        groups = [('P1 — Tindakan Segera (CRITICAL & HIGH)', ('CRITICAL','HIGH')),
                  ('P2 — Tindakan Terjadwal (MEDIUM)', ('MEDIUM',)),
                  ('P3 — Peningkatan Keamanan Lanjutan (LOW & INFO)', ('LOW','INFO'))]
        for title, sevs in groups:
            items = [f"{f['id']}: {f['recommendation']}" for f in self._findings if f['severity'] in sevs]
            if not items: continue
            self.H(title, 2)
            for it in items: self.bullet(it)

    def limits(self):
        self.P('Batasan pengujian, scope yang tidak diuji, dan dependensi lingkungan.', italic=True)
        for x in self.triage.get('limitations', []): self.bullet(x)
        if self.cfg.get('limit_note'): self.P(self.cfg['limit_note'], bold=True)
        self.blocks(self.cfg.get('limits_blocks', []))

    def appendix_cases(self):
        path = os.path.join(self.base, 'ai', 'generated-cases.md')
        if not os.path.isfile(path):
            self.P('[Berkas generated-cases.md tidak tersedia]', italic=True); return
        lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1; continue
            if line.startswith('#'):
                lvl = min(len(line) - len(line.lstrip('#')), 3)
                self.H(line.lstrip('#').strip(), max(lvl, 2))
                i += 1; continue
            if line.startswith('|') and i + 1 < len(lines) and '|---' in lines[i+1]:
                headers = [c.strip() for c in line.split('|')[1:-1]]
                i += 2; rows = []
                while i < len(lines) and lines[i].strip().startswith('|'):
                    rows.append([c.strip() for c in lines[i].strip().split('|')[1:-1]])
                    i += 1
                widths = [0.8, 1.4, 2.4, 0.9, 1.1] if len(headers) == 5 else None
                status_col = 3 if len(headers) == 5 else None
                self.table(headers, rows, widths=widths, severity_col=status_col)
                continue
            if line.startswith(('-', '*')):
                self.bullet(line.lstrip('-*').strip())
            else:
                self.P(line)
            i += 1

    def appendix_evidence(self):
        self.P('Daftar berkas artefak, capture traffic, dan screenshot yang tersimpan di direktori pendukung/bukti.', italic=True)
        bukti_dir = os.path.join(self.base, 'bukti')
        shots_dir = os.path.join(self.base, 'screenshots')
        rows = []
        for d, label in [(bukti_dir, 'Bukti / Capture'), (shots_dir, 'Screenshot')]:
            if not os.path.isdir(d): continue
            for root, _, files in os.walk(d):
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    rel = os.path.relpath(fp, self.base)
                    sz = os.path.getsize(fp)
                    rows.append([rel.replace('\\','/'), label, f"{sz:,} B", sha256(fp)[:16] + '...'])
        if rows:
            self.table(['Path Berkas', 'Kategori', 'Ukuran', 'SHA-256 (Prefix)'], rows[:60],
                       widths=[2.8, 1.3, 1.0, 1.5])
        else:
            self.P('Tidak ada berkas bukti di pendukung/bukti/.', italic=True)

    def appendix_extra(self):
        shots = self.cfg.get('extra_shots', [])
        if not shots:
            self.P('Tidak ada gambar bukti visual tambahan yang didefinisikan di profil laporan.', italic=True); return
        self.P('Berikut bukti visual dari sesi pengujian. Semua gambar tertanam di dokumen ini.')
        for item in shots:
            ref, cap = item if isinstance(item, (list, tuple)) else (item, str(item))
            self.image(ref, cap)

    # ---------- data-driven extra blocks ----------
    def blocks(self, blocks):
        for b in blocks:
            typ = b.get('type', 'paragraph')
            if typ == 'table':
                self.table(b.get('headers',[]), b.get('rows',[]), b.get('widths'),
                           score_col=b.get('score_col'), severity_col=b.get('severity_col'))
            elif typ == 'heading':
                self.H(b.get('text',''), b.get('level', 2))
            elif typ == 'bullets':
                for it in b.get('items', []): self.bullet(it)
            elif typ == 'flow_table':
                self._flow_table(b)
            else:
                self.P(b.get('text',''), bold=b.get('bold',False), italic=b.get('italic',False))

    def _flow_table(self, b):
        flows_path = os.path.join(self.base, 'bukti', 'network', 'flows.jsonl')
        if not os.path.isfile(flows_path):
            self.P('[Traffic capture flows.jsonl tidak tersedia]', italic=True); return
        rows = []
        param_subs = self.cfg.get('flow_param_values', {})
        for line in open(flows_path, encoding='utf-8', errors='replace'):
            if not line.strip(): continue
            try:
                fl = json.loads(line)
            except Exception:
                continue
            u = fl.get('url','-')
            for placeholder, actual_val in param_subs.items():
                if placeholder in u:
                    u = u.replace(placeholder, str(actual_val))
            rows.append([fl.get('method','-'), u[:120], str(fl.get('status','-')),
                         f"{fl.get('duration_ms',0):.1f}" if isinstance(fl.get('duration_ms'), (int,float)) else '-',
                         str(fl.get('response_size',0))])
        if rows:
            self.table(['Method','URL','Status','Lat (ms)','Size (B)'], rows, widths=[0.7, 4.0, 0.6, 0.7, 0.7])


def infer_profile(triage):
    p = triage.get('report', {}).get('profile')
    if p: return p
    mode = str(triage.get('mode', '')).lower()
    if 'apk' in mode or 'mobile' in mode: return 'apk'
    if 'web' in mode: return 'web'
    return 'bughunt'


def build(root, profile_override=None, output_override=None):
    root = os.path.abspath(root)
    triage = json.load(open(os.path.join(root,'pendukung','ai','triage.json'), encoding='utf-8'))
    cfg = triage.get('report', {})
    profile = profile_override or cfg.get('profile') or infer_profile(triage)
    chapters = cfg.get('chapters') or DEFAULT_CHAPTERS.get(profile, DEFAULT_CHAPTERS['bughunt'])
    rep = Report(root, triage, cfg, profile)
    n = 0
    pre = set(cfg.get('page_breaks_before', []))
    for ch in chapters:
        key = ch if isinstance(ch, str) else ch.get('builtin')
        if key == 'cover':
            rep.cover(); continue
        if key in pre: rep.doc.add_page_break()
        n += 1
        if isinstance(ch, str):
            title = BUILTIN_TITLES.get(ch, ch.replace('_',' ').title())
            rep.H(f"{n}. {title}", 1)
            getattr(rep, ch)()
        else:
            rep.H(f"{n}. {ch.get('title','Bagian')}", 1)
            rep.blocks(ch.get('blocks', []))
    out = output_override or os.path.join(root, cfg.get('output', f'Laporan-BugHunter-{profile}-{triage.get("date", "assessment")}.docx'))
    rep.doc.save(out)
    print('SAVED', out)
    print('PROFILE', profile, 'CHAPTERS', len([c for c in chapters if c != 'cover']),
          'FINDINGS', len(rep._findings), 'TABLES', len(rep.doc.tables),
          'IMAGES', len(rep.doc.inline_shapes))
    return out


def verify(root, docx=None):
    root = os.path.abspath(root)
    if not docx:
        docs = [f for f in os.listdir(root) if f.endswith('.docx') and not f.startswith('~$')]
        if len(docs) != 1:
            print(f"VERIFY WARNING: expected 1 docx, found {len(docs)}: {docs}")
        docx = os.path.join(root, docs[0]) if docs else None
    if not docx or not os.path.isfile(docx):
        print("VERIFY ERROR: docx file not found")
        return False
    doc = Document(docx)
    text_chunks = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        for r in t.rows:
            for c in r.cells:
                text_chunks.append(c.text)
    full_text = '\n'.join(text_chunks)
    
    bad_patterns = [
        (re.compile(r'\[REDACTED\]'), 'redaction-marker'),
    ]
    hits = 0
    for pat, label in bad_patterns:
        m = pat.findall(full_text)
        if m:
            print(f"VERIFY FAIL in DOCX: {len(m)} occurrences of {label}")
            hits += len(m)
    if hits == 0:
        print("SCAN DOCX : CLEAN")
    print(f"TOTAL HITS: {hits}")
    return hits == 0
