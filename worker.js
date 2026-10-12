/**
 * Cloudflare Worker backend for Domain Adder.
 *
 * Required Worker secrets/variables:
 *   CF_API_TOKEN  Secret: API token with Zone:Edit permission, scoped as narrowly as Cloudflare allows.
 *   CF_ACCOUNT_ID Variable: Cloudflare account ID where the zone should be added.
 *
 * Deploy this Worker and serve the static index.html from a Pages project, routing
 * /api/* to this Worker. If using a Worker-only deployment, adapt the static hosting
 * setup accordingly.
 */
const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function isValidDomain(domain) {
  if (typeof domain !== "string" || domain.length > 253) return false;
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!d || d.includes("://") || d.includes("/") || d.includes("@") || d.includes(":")) return false;
  const labels = d.split(".");
  if (labels.length < 2) return false;
  return labels.every(label =>
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": url.origin,
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers": "content-type",
          "access-control-max-age": "86400",
        },
      });
    }

    if (url.pathname !== "/api/add-domain") return json({ success: false, message: "Not found" }, 404);
    if (request.method !== "POST") return json({ success: false, message: "Method not allowed" }, 405);
    if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) {
      return json({ success: false, message: "Backend belum dikonfigurasi: CF_API_TOKEN atau CF_ACCOUNT_ID belum diatur." }, 500);
    }

    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "JSON tidak valid." }, 400); }

    const domain = String(body.domain || "").trim().toLowerCase().replace(/\.$/, "");
    if (!isValidDomain(domain)) {
      return json({ success: false, message: "Nama domain tidak valid. Masukkan contoh.com tanpa https:// atau path." }, 400);
    }

    // Calls the official Cloudflare API. This does not bypass account billing restrictions.
    const cfResponse = await fetch("https://api.cloudflare.com/client/v4/zones", {
      method: "POST",
      headers: {
        "authorization": `Bearer ${env.CF_API_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: domain,
        account: { id: env.CF_ACCOUNT_ID },
        type: "full",
      }),
    });

    const payload = await cfResponse.json().catch(() => ({
      success: false,
      errors: [{ message: "Respons Cloudflare bukan JSON yang valid." }],
    }));

    // Return Cloudflare's actual API result/errors so the user can diagnose the issue.
    return json(payload, cfResponse.status);
  },
};
