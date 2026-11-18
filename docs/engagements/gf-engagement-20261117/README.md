# Engagement logging — gurufintek.com (produksi, milik operator)

Pipeline engagement Go (five logs + MITRE/WSTG attack mapping + env CVSS + report/deck)
dijalankan end-to-end pada aset produksi milik Hugo Massie, 2026-11-17.

## Run
- Task: `852 PENTEST-Gurufintek-20261117` (status done)
- Run: 91 — dikumpulkan dari 1487 baris aktivitas, tanpa scanner baru
  (mengumpulkan log yang sudah ada; tidak mengirim trafik baru ke produksi)
- Deliverable: `engagement-reports/task-852/` (PDF 962KB, DOCX, PPTX, HTML, 5 log + manifest)

## Gate & environmental CVSS
Gate **menahan** laporan pertama (HTTP 409) karena belum ada profil konteks — bukti gate
aktif pada aset nyata. Profil di-set jujur:

- business_context: situs publik fintech edukasi/pengaduan (produksi, milik sendiri)
- scope: internet-facing; hanya permukaan publik + header/TLS/DNS.
  Permukaan terautentikasi **belum diuji** — diblokir Cloudflare Turnstile.
- compensating_controls: Cloudflare WAF/CDN, Turnstile, lockout 5x, CSP ketat, GraphQL introspection off
- CR=L (konten edukasi publik, tanpa data kartu/PII sensitif) · IR=M · AR=M

## Temuan (4, semua kelas DNS/TLS/header)
| Temuan | Severity | CVSS base | Env |
|---|---|---|---|
| Missing DMARC + CAA (gurufintek.com) | medium | 5.0 | not applied |
| TLS 1.0/1.1 + CBC cipher (443, 8443) | low | 3.0 | not applied |
| CSP permits unsafe-inline | low | 3.0 | not applied |
| Missing COEP/CORP headers | low | 3.0 | not applied |

Semua env **not applied** — benar: kelas DNS/TLS/header tak punya komponen C/I/A yang
diubah profil; laporan melabel eksplisit alih-alih memaksa skor. Laporan menyatakan
coverage (permukaan terautentikasi belum tercakup) alih-alih membaca bersih.

## Catatan jujur coverage
- Permukaan publik + header/TLS/DNS: tercakup.
- Permukaan terautentikasi (login-protected, write API /api/berita, IDOR, stored XSS):
  **belum diuji** — Cloudflare Turnstile tak ter-solve headless. Butuh test account.
- callbackUrl open-redirect (FINDING 2 dari 2026-10-09): masih UNVERIFIED (butuh sesi).

## Bukti
- Live DB: eng_run run=91 task=852; eng_attack_mapping; 5 log + manifest (sha256, hash-chained).
- Service: `0.9.4-engagement21`, dibangun dari source HEAD utama (commit engagement-port).
