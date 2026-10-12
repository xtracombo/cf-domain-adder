# Cloudflare Domain Adder

Website sederhana untuk mengirim permintaan penambahan domain melalui Cloudflare API resmi. Ini **tidak** melewati blokir billing; jika akun memiliki saldo tertunggak dan Cloudflare menolak permintaan, hasil penolakan akan ditampilkan.

## File
- `index.html` — UI untuk GitHub Pages / Cloudflare Pages.
- `worker.js` — backend Worker. API token tidak boleh ditaruh di HTML atau JavaScript browser.

## Konfigurasi Worker
1. Buat Worker baru atau gunakan Worker yang memang boleh Anda ubah.
2. Tempel isi `worker.js`.
3. Pada **Settings → Variables and Secrets**:
   - Tambahkan secret `CF_API_TOKEN` berisi API Token.
   - Tambahkan variable `CF_ACCOUNT_ID` berisi Account ID Cloudflare.
4. Token perlu izin yang mencukupi untuk membuat zone (mulai dengan `Zone:Edit` dan scope akun yang benar). Gunakan token terbatas; jangan gunakan Global API Key.
5. Deploy Worker.

## Hosting dan routing
`index.html` memanggil URL relatif `/api/add-domain`. Hosting harus mengarahkan path `/api/*` ke Worker yang sama-origin, misalnya dengan route Worker pada hostname website. Jika hosting frontend dan Worker memakai hostname berbeda, ubah URL `fetch('/api/add-domain', ...)` ke URL Worker dan tambahkan CORS yang dibatasi ke origin website Anda.

## Penting
- Jangan pernah membagikan API Token, Global API Key, atau password Cloudflare.
- Uji hanya pada domain yang Anda miliki atau berwenang kelola.
- Penambahan zone mungkin memerlukan verifikasi domain/nameserver dan tetap tunduk pada aturan akun, batas API, dan status billing Cloudflare.
- Bila API mengembalikan error billing/permission, alat ini tidak dapat menghilangkan pembatasan tersebut.
