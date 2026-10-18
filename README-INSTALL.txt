CLUB GRATIS — MULTI-USER BACKEND V1

ISI PAKET
- index.html: antarmuka login/daftar, dashboard koneksi Cloudflare, panduan permission, admin panel.
- worker.js: API pendaftaran/login berbasis D1, session, rate limit, koneksi Cloudflare per pengguna, enkripsi token, audit log, dan handler fitur Cloudflare lama.
- assets/club-gratis-logo.jpg: logo yang sudah digunakan di web.
- sql/schema-reference.sql: referensi schema, bukan perlu dijalankan ulang bila tabel yang sama sudah dibuat.

PENTING
Jangan langsung mengganti Worker produksi sebelum menguji versi ini. Buat salinan/versi staging Worker terlebih dahulu. Jangan kirim atau tempel API Token Cloudflare ke chat, file HTML, GitHub, atau log.

1. FRONTEND
- Upload index.html dan folder assets/ beserta isinya ke repo GitHub Pages yang sama.
- Frontend masih memakai endpoint API: https://cf-domain-adder.xtracombo425.workers.dev

2. WORKER
- Deploy worker.js ke Worker backend (disarankan staging terlebih dahulu).
- Pastikan binding D1 bernama DB mengarah ke club-gratis-db di Production.
- Pertahankan SESSION_SECRET yang kuat.
- Tambahkan Worker Secret TOKEN_ENCRYPTION_KEY dengan nilai acak rahasia minimal 32 karakter. Gunakan password manager atau generator kriptografi; jangan memakai nilai contoh dan jangan commit secret ke GitHub.
- APP_USERNAME, APP_PASSWORD, CF_API_TOKEN, dan CF_ACCOUNT_ID tidak lagi dipakai untuk menjalankan fitur pengguna biasa oleh versi backend ini. Jangan buru-buru menghapus secret lama sampai pengujian staging selesai.
- ALLOWED_ORIGIN tetap https://xtracombo.github.io. Jika URL Pages berubah, sesuaikan ALLOWED_ORIGIN dan CORS.

3. ADMIN PERTAMA
- Buka web, daftar akun pertama dengan username dan email milik sendiri, lalu login.
- Di D1 Console jalankan SQL berikut dengan email akun sendiri menggantikan alamat contoh:
  UPDATE users SET role = 'admin' WHERE email = 'email-akun-admin@example.com';
- Logout lalu login kembali agar role admin dimuat ulang. Admin Panel hanya bisa dibuka oleh role admin yang diverifikasi backend.
- Jangan membuat endpoint publik untuk menaikkan role sendiri.

4. MENGHUBUNGKAN CLOUDFLARE
- Di Dashboard, buka Koneksi Cloudflare.
- Isi Account ID 32 karakter dan API Token dari akun Cloudflare milik pengguna.
- Token diverifikasi terhadap Cloudflare API dan dienkripsi dengan AES-GCM sebelum disimpan ke D1.
- Token asli tidak dikirim ke frontend lagi setelah disimpan.
- OAuth resmi Cloudflare belum diimplementasikan pada paket ini; koneksi saat ini memakai Account ID + API Token manual.

5. TOKEN PERMISSIONS (sesuai panduan di web)
- Account → Cloudflare Pages → Read dan Edit.
- Account → Workers Scripts → Read dan Edit.
- Zone → Zone → Read dan Edit.
- Zone → DNS → Edit.
- Pilih Account Resources dan Zone Resources sesuai kebutuhan. All accounts / All zones memberi cakupan luas; pengguna sebaiknya membatasi resource jika tidak membutuhkan akses penuh.
- Sebagian fitur dapat memerlukan permission tambahan berdasarkan endpoint Cloudflare yang dipanggil dan konfigurasi akun.

6. UJI WAJIB DI STAGING
- Daftar 2 akun berbeda dan login keduanya.
- Pastikan akun A tidak bisa membaca/menjalankan koneksi Cloudflare akun B.
- Sambungkan token yang benar dan token yang salah.
- Uji Domain, DNS, Workers, Routes, dan Pages dengan token uji.
- Uji logout, sesi kedaluwarsa, akun disabled, rate limit, dan endpoint Admin memakai akun user biasa (harus 403).
- Pastikan token tidak muncul pada HTML, response API, console browser, atau audit log.
- Baru setelah seluruh pengujian berhasil, deploy ke Worker produksi.

BATASAN V1
- Koneksi OAuth belum ada; hanya metode manual Account ID + API Token.
- Role Admin awal harus dipromosikan secara manual di D1.
- Paket ini sudah lolos pemeriksaan sintaks JavaScript dengan node --check, tetapi belum diuji langsung di Cloudflare staging atau diuji end-to-end terhadap akun Cloudflare nyata.
