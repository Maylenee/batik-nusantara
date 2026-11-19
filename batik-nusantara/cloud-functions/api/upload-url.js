// POST /api/upload-url  {name:"parang-1.jpg", contentType:"image/jpeg"}
// Header: Authorization: Bearer <UPLOAD_TOKEN>   (set UPLOAD_TOKEN di Environment Variables EdgeOne Pages)
// Mengembalikan pre-signed PUT URL, file dikirim langsung ke Blob tanpa lewat fungsi.
import { getStore } from "@edgeone/pages-blob";

export async function onRequest(context) {
  const { request } = context;
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  const token =
    (context.env && context.env.UPLOAD_TOKEN) ||
    (typeof process !== "undefined" && process.env && process.env.UPLOAD_TOKEN) ||
    "";
  if (!token) return new Response("UPLOAD_TOKEN belum terbaca di server (cek Environment Variables lalu redeploy)", { status: 500 });
  if (request.headers.get("authorization") !== `Bearer ${token}`) {
    return new Response("Token tidak cocok", { status: 401 });
  }
  const { name, contentType } = await request.json();
  if (!/^[a-z0-9._-]+\.(jpg|jpeg|png|webp)$/i.test(name || "")) {
    return new Response("Nama file tidak valid", { status: 400 });
  }
  const out = await getStore("batik").createUploadUrl("img/" + name, {
    expireSeconds: 600,
    contentType: contentType || "application/octet-stream",
  });
  return new Response(JSON.stringify(out), { headers: { "Content-Type": "application/json" } });
}
