const ALLOWED_ORIGIN = "https://xtracombo.github.io";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": ALLOWED_ORIGIN,
      "vary": "Origin",
    },
  });
}

function normalizeDomain(input) {
  if (typeof input !== "string") return null;
  let value = input.trim().toLowerCase();
  if (!value) return null;

  if (/^https?:\/\//i.test(value)) {
    try {
      const parsed = new URL(value);
      if (parsed.username || parsed.password || parsed.port) return null;
      value = parsed.hostname.toLowerCase();
    } catch {
      return null;
    }
  }

  value = value.replace(/\.$/, "");
  if (!value || value.length > 253 || /[\/@:\s?#]/.test(value)) return null;
  const labels = value.split(".");
  if (labels.length < 2) return null;

  for (const label of labels) {
    if (!label || label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }
  return value;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = origin === ALLOWED_ORIGIN;

    if (request.method === "OPTIONS") {
      if (!allowed) return new Response(null, { status: 403 });
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": ALLOWED_ORIGIN,
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers": "content-type, x-app-password",
          "access-control-max-age": "86400",
          "vary": "Origin",
        },
      });
    }
    if (!allowed) return json({ success: false, message: "Origin tidak diizinkan." }, 403);

    const url = new URL(request.url);
    if (url.pathname !== "/api/add-domain") return json({ success: false, message: "Not found." }, 404);
    if (request.method !== "POST") return json({ success: false, message: "Method not allowed." }, 405);

    if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID || !env.APP_PASSWORD) {
      return json({ success: false, message: "Konfigurasi Worker belum lengkap. Periksa APP_PASSWORD, CF_API_TOKEN, dan CF_ACCOUNT_ID." }, 500);
    }
    if ((request.headers.get("X-App-Password") || "") !== env.APP_PASSWORD) {
      return json({ success: false, message: "Password aplikasi salah." }, 401);
    }

    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, message: "Body JSON tidak valid." }, 400); }

    const domain = normalizeDomain(body.domain);
    if (!domain) {
      return json({ success: false, message: "Format nama domain tidak valid. Masukkan hostname seperti contoh.com tanpa path atau port." }, 400);
    }

    try {
      const cfResponse = await fetch("https://api.cloudflare.com/client/v4/zones", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.CF_API_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name: domain, account: { id: env.CF_ACCOUNT_ID }, type: "full" }),
      });
      const payload = await cfResponse.json().catch(() => ({}));
      return json({
        success: payload.success === true,
        result: payload.result || null,
        errors: payload.errors || [],
        messages: payload.messages || [],
      }, cfResponse.status);
    } catch {
      return json({ success: false, message: "Tidak berhasil menghubungi Cloudflare API." }, 502);
    }
  },
};
