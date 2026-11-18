# Re-verifikasi temuan gurufintek — 2026-11-18

Re-check semua 4 temuan dari run 91 dengan bukti nyata (bukan mewarisi status lama).
Hasil: 3 masih valid, 1 sudah diperbaiki oleh gurufintek.

| Finding | Klaim awal | Re-verifikasi | Status |
|---|---|---|---|
| #3529 DMARC/CAA missing | medium | DMARC TIDAK ADA, CAA TIDAK ADA (dig) | **MASIH VALID** |
| #3832 TLS 1.0/1.1 + CBC | low | TLS 1.0 & 1.1 **DITOLAK** (Cipher NONE); hanya TLS 1.2/1.3 aktif | **SUDAH DIPERBAIKI** — false positive |
| #3833 CSP unsafe-inline di script-src | low | CSP masih memuat `script-src 'self' 'unsafe-inline'` | **MASIH VALID** |
| #3834 COEP/CORP missing | low | Cross-Origin-Embedder-Policy & Resource-Policy TIDAK ADA | **MASIH VALID** |

## Kenapa ini penting
Melaporkan #3832 sebagai temuan aktif = **false positive**. gurufintek sudah menutup
TLS lemah (kemungkinan lewat Cloudflare edge). Laporan harus mencatatnya sebagai
REMEDIATED, bukan open — sesuai aturan "detected ≠ confirmed" dan "jangan klaim
inflated / tandai false positive jujur".

## Bukti per temuan (file)
- `finding-3529-dns-dmarc-caa.txt` — dig TXT/_dmarc/CAA output
- `finding-3832-tls-versions.txt` — openssl s_client per protocol version
- `finding-3833-3834-security-headers.txt` — curl -sI + analisis header

## Perintah reproduksi
```bash
dig +short TXT _dmarc.gurufintek.com      # kosong = no DMARC
dig +short CAA gurufintek.com             # kosong = no CAA
echo | openssl s_client -connect gurufintek.com:443 -servername gurufintek.com -tls1_1
curl -sI https://gurufintek.com | grep -iE "content-security|cross-origin"
```

## Tambah: FINDING 2 (callbackUrl open-redirect) — CLOSED
Uji mendalam (tanpa login) membuktikan NextAuth memvalidasi callbackUrl: semua URL
eksternal dipaksa dinormalisasi ke `/`. Open-redirect TIDAK bisa dieksploitasi.
Status FINDING 2 dari 2026-10-09: **FALSE POSITIVE / CLOSED** (bukan butuh session).
Bukti: `finding-callbackurl-open-redirect.txt`.
