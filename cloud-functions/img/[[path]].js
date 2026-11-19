// GET /img/<nama>.jpg|png  → dibaca dari EdgeOne Pages Blob (store "batik", key "img/<nama>")
import { getStore } from "@edgeone/pages-blob";

const TYPES = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  webp: "image/webp",
};

export async function onRequest({ request }) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const name = decodeURIComponent(
    new URL(request.url).pathname.replace(/^\/img\//, ""),
  );
  const ext = name.split(".").pop().toLowerCase();
  if (!/^[a-z0-9._-]+$/i.test(name) || !TYPES[ext]) {
    return new Response("Not Found", { status: 404 });
  }
  const body = await getStore("batik").get("img/" + name, { type: "stream" });
  if (!body) return new Response("Not Found", { status: 404 });
  return new Response(body, {
    headers: {
      "Content-Type": TYPES[ext],
      // dicache di browser & CDN supaya fungsi jarang terpanggil
      "Cache-Control": "public, max-age=604800, s-maxage=2592000",
    },
  });
}
