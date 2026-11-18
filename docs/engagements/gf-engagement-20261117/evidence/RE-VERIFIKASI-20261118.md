# Re-verifikasi temuan gurufintek — 2026-11-18

Re-check semua 4 temuan dari run 91 dengan bukti nyata (bukan mewarisi status lama).
Hasil: 3 masih valid, 1 sudah diperbaiki oleh gurufintek.

| Finding | Klaim awal | Re-verifikasi | Status |
|---|---|---|---|
| #3529 DMARC/CAA missing | medium | DMARC TIDAK ADA, CAA TIDAK ADA (dig) | **MASIH VALID** |
| #3832 TLS 1.0/1.1 + CBC | low | **MASIH DITERIMA** (native retest verdict=reproduced) | **MASIH VALID** |
| #3833 CSP unsafe-inline di script-src | low | CSP masih memuat `script-src 'self' 'unsafe-inline'` | **MASIH VALID** |
| #3834 COEP/CORP missing | low | Cross-Origin-Embedder-Policy & Resource-Policy TIDAK ADA | **MASIH VALID** |

## Koreksi penting pada tes TLS saya sendiri (jangan ulangi kesalahan ini)
Tes openssl manual saya pertama-tama melaporkan "TLS 1.0/1.1 DITOLAK" — itu **FALSE
NEGATIVE**. OpenSSL 3.0 di host ini mematikan dukungan TLS 1.0/1.1 di sisi KLIENT,
jadi `-tls1` mengembalikan "Cipher is (NONE)" bukan karena server menolak, melainkan
karena klien saya tak pernah bisa menawarkan protokol itu. Native retest (verdict
`reproduced`) memakai metode lain dan membuktikan cipher lemah CBC **masih diterima**
di :443, www:443, :8443. Kesimpulan akhir mengikuti verdict native engine.

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
