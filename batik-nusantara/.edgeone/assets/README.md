# Batik Nusantara di EdgeOne Pages (Blob + Cloud Functions)

Alur: browser → `/img/xxx.jpg` → cloud function `cloud-functions/img/[[path]].js` → Pages Blob (store `batik`).
Di HTML tetap berupa link biasa (`/img/...`), awalannya diatur di `config.js` (`ASSET_BASE`).

1. Deploy folder ini ke EdgeOne Pages (tanpa build command; dependensi dari package.json).
2. Di Settings → Environment Variables tambahkan `UPLOAD_TOKEN` (string acak), lalu redeploy.
3. Dari folder `batik-nusantara-seed/`: `SITE=https://situs-kamu TOKEN=<UPLOAD_TOKEN> node upload.mjs`
   (mengunggah file gambar (276 file pada seed awal; seed tambahan berisi 27 file untuk 9 motif baru) ke Blob lewat `/api/upload-url`).
4. Buka situs; foto dan logo kini dilayani dari Blob.
