# Batik Nusantara di EdgeOne Pages (Blob + Cloud Functions)

Website galeri motif batik Nusantara yang dibuat untuk deployment di EdgeOne Pages menggunakan kombinasi Cloud Functions dan Blob Storage.

## 🌍 Live Demo

Situs langsung terdeploy di: **https://batik-nusantara.edgeone.cool/**
Semua foto dan logo batik disajikan melalui EdgeOne Pages Blob Storage dengan CDN otomatis.

## 📖 Cara Kerja

1. Pengunjung browser mengakses link gambar `/img/xxx.jpg`
2. Request dialihkan ke Cloud Function di `cloud-functions/img/[[path]].js`
3. Cloud Function menghasilkan presigned URL untuk upload ke Blob Storage
4. Gambar disimpan langsung ke Blob, lalu dinyatakan melalui CDN

## 🛠️ Setup & Deploy

1. **Deploy ke EdgeOne Pages** – taruh folder ini ke repositori EdgeOne Pages. Tidak perlu build command, dependencies terpakai dari `package.json`.
2. **Tambahkan UPLOAD_TOKEN** – di Settings → Environment Variables, tambahkan variabel `UPLOAD_TOKEN` dengan string acak. Lalu **redeploy**.
3. **Konfigurasi ASSET_BASE** – opsional. Edit `config.js` untuk mengatur base URL jika perlu (default: `/img/`).

## 📤 Unggah Gambar (Upload)

Untuk menambahkan gambar baru ke galeri:

1. Dapatkan `UPLOAD_TOKEN` dari Environment Variables di halaman EdgeOne Pages (telah ditambahkan di step setup).
2. Jalankan perintah dari folder `batik-nusantara-seed/`:

```bash
SITE=https://batik-nusantara.edgeone.cool TOKEN=<UPLOAD_TOKEN> node upload.mjs
```

3. Perintah ini akan:
   - Memvalidasi nama file (hanya `.jpg`, `.jpeg`, `.png`, `.webp`)
   - Membuat presigned URL dengan masa berlaku 600 detik
   - Mengunggah file langsung ke Blob Storage lewat API `/api/upload-url`
   - Gambar akan langsung muncul di situs setelah selesai

4. Buka situs `https://batik-nusantara.edgeone.cool/` – foto dan logo batik sudah terload dari Blob Storage.

## 📦 Seed Files

- `batik-nusantara-seed/` berisi 276 file gambar motif batik awal
- Setiap motif mencakup berbagai ukuran dan warna
- File-file ini bisa ditambah atau diganti sesuai kebutuhan

## 🔧 Troubleshooting

- Jika muncul "UPLOAD_TOKEN belum terbaca": cek lagi di Environment Variables EdgeOne Pages dan pastikan sudah **redeploy**.
- Jika "Token tidak cocok": pastikan header `Authorization: Bearer <TOKEN>` sesuai saat test manual.
- Pastikan nama file gambar sesuai regex: `^[a-z0-9._-]+\.(jpg|jpeg|png|webp)$`
