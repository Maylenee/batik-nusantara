// Pemakaian (Node 18+), setelah situs ter-deploy dan UPLOAD_TOKEN diisi di EdgeOne Pages:
//   SITE=https://nama-situs.edgeone.app TOKEN=rahasia node upload.mjs
import { readdir, readFile } from "node:fs/promises";
const { SITE, TOKEN } = process.env;
if (!SITE || !TOKEN) throw new Error("Isi SITE dan TOKEN");
const types = { jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp" };
const files = await readdir(new URL("./img/", import.meta.url));
let ok = 0, fail = [];
for (const name of files) {
  const contentType = types[name.split(".").pop().toLowerCase()];
  try {
    const r = await fetch(`${SITE}/api/upload-url`, {
      method: "POST",
      headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name, contentType }),
    });
    if (!r.ok) throw new Error("upload-url " + r.status + " " + (await r.text()).slice(0, 120));
    const { url } = await r.json();
    const put = await fetch(url, { method: "PUT", headers: { "Content-Type": contentType }, body: await readFile(new URL(`./img/${name}`, import.meta.url)) });
    if (!put.ok) throw new Error("PUT " + put.status);
    ok++;
  } catch (e) { fail.push(name + ": " + e.message); }
}
console.log(`${ok}/${files.length} terunggah`); if (fail.length) console.log(fail.join("\n"));
