# Rencana test case authenticated — gurufintek.com

Status: **BELUM DIEKSEKUSI** — menunggu test account (Cloudflare Turnstile memblokir
pembuatan akun headless). Dokumen ini daftar persis yang akan dijalankan begitu
satu akun uji tersedia, supaya operator bisa review cakupan sebelum eksekusi.

## Yang dibutuhkan dari operator

Satu akun uji di gurufintek.com (role paling rendah / user biasa):
- email + password
- (opsional) satu akun kedua role berbeda — untuk uji vertical privilege escalation

Tanpa akun, tidak ada satu pun test di bawah yang bisa dijalankan: semua butuh sesi
sah. Ini bukan keterbatasan alat, tapi kontrol Turnstile di sisi target.

## Permukaan yang terkonfirmasi (dari GET tanpa login, 2026-11-18)

| Endpoint | Anon | Catatan |
|---|---|---|
| `GET /api/berita` | 200 | publik; `q`, `source` = filter nyata |
| `POST /api/berita` | 401 | butuh login |
| `PATCH /api/berita` | 401 | butuh login |
| `DELETE /api/berita` | 401 | butuh login |
| `PUT /api/berita` | 404 | method tak didukung |
| `POST /api/auth/login` | 400 | Zod schema disclosure (FINDING 1, sudah tercatat) |
| `GET /dashboard`,`/profile`,`/akun` | 302 | redirect ke login = butuh sesi |
| `/register` | 200 | Turnstile aktif |

Form register punya field: `name`, `email`, `password`, `confirmPassword`,
`description`, `consent`, + Turnstile.

## Test case (diekskusi setelah akun ada)

### A. Broken access control / BOLA (prioritas 1)
1. **IDOR read** — ambil `id` resource milik user lain dari `/api/berita` (publik),
   coba akses detail/edit via sesi sendiri. Ekspektasi aman: 403/404, bukan 200.
2. **IDOR write** — `PATCH /api/berita` dengan `id` milik user lain. Ekspektasi: ditolak.
3. **DELETE cross-owner** — `DELETE /api/berita` resource milik user lain.
4. **Vertical** — endpoint admin/panel (`/dashboard` sub-rute) diakses dengan role user
   biasa. Ekspektasi: 403, bukan konten admin.

### B. Mass assignment (prioritas 1)
5. `PATCH` profil dengan field ekstra (`role`, `isAdmin`, `verified`, `email`).
   Ekspektasi: field tak dikenal diabaikan/ditolak, bukan diterapkan.
6. `POST /api/berita` dengan field `authorId`/`ownerId`/`status` yang bukan miliknya.

### C. Stored XSS (prioritas 2)
7. Kirim payload XSS (`<img src=x onerror=...>`, `<svg onload=...>`) via:
   - field `description` profil (register/profile update)
   - `POST /api/berita` body
   - aspirasi/pengaduan (jika terautentikasi)
   Lalu buka halaman yang merender konten itu; assertion DOM (banner terlihat) =
   PoC-of-impact, bukan sekadar refleksi.
8. Perhatikan CSP: `script-src 'self' 'unsafe-inline'` — `unsafe-inline` berarti
   inline handler seperti `onerror` bisa jalan. Ini yang membuat stored XSS berdampak
   nyata; tanpa `unsafe-inline` dampaknya turun ke HTML injection.

### D. callbackUrl post-login (prioritas 2)
9. Login dengan `callbackUrl=//evil.com` dan `https://evil.com`; periksa `Location`
   SETELAH login berhasil. Tanpa login, NextAuth sudah menolak (dinormalisasi ke `/`);
   langkah ini mengonfirmasi perilaku post-auth.

### E. Session & token (prioritas 3)
10. Cookie flags sesi setelah login: `HttpOnly`, `Secure`, `SameSite`.
11. Fixation: apakah session id berubah setelah login (bukan dipakai ulang).
12. Logout: apakah sesi benar-benar invalid (replay cookie lama → 401).

### F. Rate limit authenticated (prioritas 3)
13. `POST /api/berita` berulang → apakah ada limit? (anon sudah 401; perlu ukur
    per-sesi untuk tahu apakah limit ada di jalur terautentikasi).

### G. File upload (jika ada)
14. Cari endpoint upload (avatar/profil). Uji: ekstensi ganda, content-type mismatch,
    path traversal di nama file, polyglot. Verifikasi eksekusi, bukan cuma upload OK.

## Aturan eksekusi (tidak dinegosiasikan)

- **Non-GET = aksi tulis.** Setiap test write memakai resource milik AKUN UJI SENDIRI,
  bukan milik user lain — kecuali step IDOR yang memang menguji akses lintas-user, dan
  itu hanya baca/satu percobaan, lalu dihentikan begitu terbukti ditolak/diterima.
- **Jangan merusak data user lain.** IDOR write diuji dengan target id milik sendiri
  dulu (baseline), baru satu percobaan ke id lain.
- **Bukti:** setiap temuan = request+response mentah + screenshot/DOM assertion bila
  kelas browser. Status `confirmed` hanya bila dampak terbukti, bukan dugaan.
- **Blocked dilaporkan blocked**: endpoint yang menolak sesuai ekspektasi = catatan
  coverage, bukan temuan.
- **Gate tetap berlaku**: laporan authenticated hanya dirender bila semua temuan
  punya CVSS + remediasi + bukti (kelas browser), sama seperti run publik.

## Estimasi

Dengan satu akun: ~45–90 menit untuk A–D (yang paling berdampak), lalu E–G bila ada.
Output: temuan terverifikasi + laporan HTML/PDF/DOCX + deck, format sama seperti
run publik task 852.
