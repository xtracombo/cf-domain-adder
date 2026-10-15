const ALLOWED_ORIGIN = "https://xtracombo.github.io";
const SESSION_TTL_SECONDS = 60 * 60 * 8;

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

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function encodeText(value) { return base64url(new TextEncoder().encode(value)); }
function decodeText(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return new TextDecoder().decode(Uint8Array.from(atob(padded), c => c.charCodeAt(0)));
}
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))));
}
async function createSession(username, secret) {
  const now = Math.floor(Date.now() / 1000);
  const header = encodeText(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = encodeText(JSON.stringify({ sub: username, iat: now, exp: now + SESSION_TTL_SECONDS }));
  const input = `${header}.${payload}`;
  return `${input}.${await sign(input, secret)}`;
}
async function verifySession(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const input = `${parts[0]}.${parts[1]}`;
  const expected = await sign(input, secret);
  if (expected.length !== parts[2].length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ parts[2].charCodeAt(i);
  if (diff !== 0) return false;
  try {
    const payload = JSON.parse(decodeText(parts[1]));
    return typeof payload.sub === "string" && payload.exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
function normalizeDomain(input) {
  if (typeof input !== "string") return null;
  let value = input.trim().toLowerCase();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) {
    try {
      const parsed = new URL(value);
      if (parsed.username || parsed.password || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash) return null;
      value = parsed.hostname.toLowerCase();
    } catch { return null; }
  }
  value = value.replace(/\.$/, "");
  if (!value || value.length > 253 || /[\/@:\s?#]/.test(value)) return null;
  const labels = value.split(".");
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (!label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }
  return value;
}
function errorsText(payload) {
  return Array.isArray(payload?.errors) ? payload.errors.map(e => `${e.code ?? ""} ${e.message ?? ""}`.trim()).join("; ") : "";
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = origin === ALLOWED_ORIGIN;
    if (request.method === "OPTIONS") {
      if (!allowed) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: {
        "access-control-allow-origin": ALLOWED_ORIGIN,
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type, x-session-token",
        "access-control-max-age": "86400", "vary": "Origin"
      }});
    }
    if (!allowed) return json({ success: false, message: "Origin tidak diizinkan." }, 403);
    const route = new URL(request.url).pathname;
    const knownRoutes = [
  "/api/login",
  "/api/add-domain",
  "/api/check-domain",
  "/api/delete-domain",
  "/api/dns-list",
  "/api/dns-create",
  "/api/dns-update",
  "/api/dns-delete",
  "/api/workers-list",
  "/api/worker-domains-list",
  "/api/worker-domain-create",
  "/api/worker-domain-delete",
  "/api/pages-domains-list",
  "/api/pages-domain-create",
  "/api/pages-domain-delete",
  "/api/worker-routes-list",
  "/api/worker-route-create",
  "/api/worker-route-delete",
  "/api/pages-list",
  "/api/zones-list"
];
    if (!knownRoutes.includes(route)) return json({ success: false, message: "Not found." }, 404);
    if (request.method !== "POST") return json({ success: false, message: "Method not allowed." }, 405);

    if (route === "/api/login") {
      if (!env.APP_USERNAME || !env.APP_PASSWORD || !env.SESSION_SECRET) {
        return json({ success: false, message: "Konfigurasi login belum lengkap. Atur APP_USERNAME, APP_PASSWORD, dan SESSION_SECRET sebagai Secrets." }, 500);
      }
      let credentials;
      try { credentials = await request.json(); } catch { return json({ success: false, message: "Body JSON tidak valid." }, 400); }
      if (typeof credentials.username !== "string" || typeof credentials.password !== "string" || credentials.username !== env.APP_USERNAME || credentials.password !== env.APP_PASSWORD) {
        return json({ success: false, message: "Username atau password salah." }, 401);
      }
      return json({ success: true, token: await createSession(env.APP_USERNAME, env.SESSION_SECRET), expiresIn: SESSION_TTL_SECONDS, message: "Login berhasil." });
    }

    if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID || !env.SESSION_SECRET) {
      return json({ success: false, message: "Konfigurasi Worker belum lengkap. Periksa CF_API_TOKEN, CF_ACCOUNT_ID, dan SESSION_SECRET." }, 500);
    }
    const sessionToken = request.headers.get("X-Session-Token") || "";
    if (!(await verifySession(sessionToken, env.SESSION_SECRET))) {
      return json({ success: false, message: "Sesi login tidak valid atau sudah berakhir. Silakan login kembali." }, 401);
    }
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "Body JSON tidak valid." }, 400); }
  // Cloudflare Pages management endpoints.
if (route === "/api/zones-list") {
  try {
    const all = [];
    let page = 1, totalPages = 1;
    while (page <= totalPages && page <= 100) {
      const u = new URL("https://api.cloudflare.com/client/v4/zones");
      u.searchParams.set("account.id", env.CF_ACCOUNT_ID);
      u.searchParams.set("per_page", "100");
      u.searchParams.set("page", String(page));
      const r = await fetch(u.toString(), { headers: { "Authorization": `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" } });
      const d = await r.json().catch(() => ({}));
      if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal memuat daftar domain Cloudflare.", errors: d.errors || [] }, r.status || 502);
      all.push(...(Array.isArray(d.result) ? d.result : []));
      const tp = Number(d.result_info?.total_pages);
      if (Number.isFinite(tp) && tp > 0) totalPages = tp;
      else if ((d.result || []).length < 100) totalPages = page;
      page++;
    }
    return json({ success: true, result: all.map(z => ({ id: z.id, name: z.name, status: z.status })), result_info: { returned_count: all.length, pages_fetched: Math.min(page - 1, 100) } });
  } catch {
    return json({ success: false, message: "Tidak berhasil memuat daftar domain Cloudflare." }, 502);
  }
}
if (route === "/api/pages-list") {
  try {
    const all = [];
    let page = 1;
    let totalPages = 1;
    while (page <= totalPages && page <= 100) {
      const pagesUrl = new URL(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CF_ACCOUNT_ID)}/pages/projects`);
      pagesUrl.searchParams.set("per_page", "100");
      pagesUrl.searchParams.set("page", String(page));
      const response = await fetch(pagesUrl.toString(), { headers: { "Authorization": `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" } });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.success !== true) return json({ success: false, message: errorsText(data) || "Gagal mengambil daftar Cloudflare Pages.", errors: data.errors || [] }, response.status || 502);
      all.push(...(Array.isArray(data.result) ? data.result : []));
      const tp = Number(data.result_info?.total_pages);
      if (Number.isFinite(tp) && tp > 0) totalPages = tp;
      else if ((data.result || []).length < 100) totalPages = page;
      page++;
    }
    return json({ success: true, result: all, result_info: { pages_fetched: Math.min(page - 1, 100), returned_count: all.length }, message: "Daftar Cloudflare Pages berhasil dimuat." });
  } catch {
    return json({ success: false, message: "Tidak berhasil menghubungi Cloudflare Pages API." }, 502);
  }
}
if (["/api/pages-domains-list", "/api/pages-domain-create", "/api/pages-domain-delete"].includes(route)) {
  const projectName = typeof body.projectName === "string" ? body.projectName.trim() : "";
  if (!projectName || projectName.length > 58 || !/^[a-z0-9][a-z0-9-]*$/.test(projectName)) return json({ success: false, message: "Nama proyek Pages tidak valid." }, 400);
  const projectBase = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CF_ACCOUNT_ID)}/pages/projects/${encodeURIComponent(projectName)}/domains`;
  const auth = { "Authorization": `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" };
  try {
    if (route === "/api/pages-domains-list") {
      const r = await fetch(projectBase, { headers: auth }); const d = await r.json().catch(() => ({}));
      if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal membaca Custom Domains Pages.", errors: d.errors || [] }, r.status || 502);
      return json({ success: true, result: d.result || [], result_info: d.result_info || null, projectName });
    }
    const domain = normalizeDomain(body.domain);
    if (!domain) return json({ success: false, message: "Hostname/domain tidak valid." }, 400);
    if (route === "/api/pages-domain-create") {
      const r = await fetch(projectBase, { method: "POST", headers: auth, body: JSON.stringify({ name: domain }) }); const d = await r.json().catch(() => ({}));
      if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menambahkan domain ke Pages.", errors: d.errors || [] }, r.status || 502);
      return json({ success: true, result: d.result || null, message: "Custom Domain Pages berhasil ditambahkan." });
    }
    const r = await fetch(`${projectBase}/${encodeURIComponent(domain)}`, { method: "DELETE", headers: auth }); const d = await r.json().catch(() => ({}));
    if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menghapus domain dari Pages.", errors: d.errors || [] }, r.status || 502);
    return json({ success: true, deleted: true, message: "Domain berhasil dihapus dari Pages." });
  } catch {
    return json({ success: false, message: "Tidak berhasil menghubungi Cloudflare Pages API." }, 502);
  }
}
    // Cloudflare Workers management endpoints.
    const workerRoutes = ["/api/workers-list", "/api/worker-domains-list", "/api/worker-domain-create", "/api/worker-domain-delete", "/api/worker-routes-list", "/api/worker-route-create", "/api/worker-route-delete"];
    if (workerRoutes.includes(route)) {
      const auth = { "Authorization": `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" };
      const accountBase = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CF_ACCOUNT_ID)}`;
      try {
        if (route === "/api/workers-list") {
          const u = new URL(`${accountBase}/workers/scripts`);
          u.searchParams.set("per_page", "100");
          const r = await fetch(u.toString(), { headers: auth }); const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal membaca daftar Workers.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, result: d.result || [], result_info: d.result_info || null });
        }
        if (route === "/api/worker-domains-list") {
          const perPage = 100;
          const maxPages = 1000;
          const allDomains = [];
          const seenIds = new Set();
          const seenPages = new Set();
          let page = 1;
          let totalPages = null;
          let totalCount = null;
          let paginationComplete = false;

          while (page <= maxPages) {
            const u = new URL(`${accountBase}/workers/domains`);
            u.searchParams.set("per_page", String(perPage));
            u.searchParams.set("page", String(page));
            const r = await fetch(u.toString(), { headers: auth });
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.success !== true) {
              return json({ success: false, message: errorsText(d) || `Gagal mengambil Custom Domains pada halaman ${page}.`, errors: d.errors || [], pages_fetched: page - 1, partial_count: allDomains.length }, r.status || 502);
            }
            const items = Array.isArray(d.result) ? d.result : [];
            const info = d.result_info || {};
            if (Number.isFinite(Number(info.total_pages)) && Number(info.total_pages) > 0) totalPages = Number(info.total_pages);
            if (Number.isFinite(Number(info.total_count)) && Number(info.total_count) >= 0) totalCount = Number(info.total_count);
            if (items.length === 0) { paginationComplete = true; break; }
            const signature = items.map(item => item.id || `${item.hostname || ''}|${item.service || ''}|${item.environment || ''}`).join('|');
            if (seenPages.has(signature)) return json({ success: false, message: `API mengembalikan halaman duplikat pada halaman ${page}. Pengambilan dihentikan agar tidak mengulang data.`, pages_fetched: page - 1, partial_count: allDomains.length, api_total_count: totalCount }, 502);
            seenPages.add(signature);
            for (const item of items) {
              const key = item.id || `${item.hostname || ''}|${item.service || ''}|${item.environment || ''}`;
              if (!seenIds.has(key)) { seenIds.add(key); allDomains.push(item); }
            }
            if (totalPages !== null) {
              if (page >= totalPages) { paginationComplete = true; break; }
            } else if (items.length < perPage) {
              paginationComplete = true; break;
            }
            page++;
          }
          if (!paginationComplete && page > maxPages) return json({ success: false, message: `Pengambilan dihentikan setelah ${maxPages} halaman. Data mungkin belum lengkap.`, partial_count: allDomains.length, pages_fetched: maxPages, api_total_count: totalCount }, 502);
          return json({ success: true, result: allDomains, result_info: { per_page: perPage, pages_fetched: Math.min(page, maxPages), total_pages: totalPages, total_count: totalCount, returned_count: allDomains.length, pagination_complete: paginationComplete, count_matches_api: totalCount === null ? null : allDomains.length === totalCount }, message: paginationComplete ? "Pengambilan Custom Domains selesai." : "Pengambilan Custom Domains belum terkonfirmasi lengkap." });
        }
        if (route === "/api/worker-domain-create") {
          const hostname = normalizeDomain(body.hostname);
          const service = typeof body.service === "string" ? body.service.trim() : "";
          const environment = typeof body.environment === "string" ? body.environment.trim() : "";
          if (!hostname || !service || service.length > 128 || /[^a-zA-Z0-9_-]/.test(service)) return json({ success: false, message: "Hostname atau nama Worker tidak valid." }, 400);
          const payload = { hostname, service };
          if (environment) payload.environment = environment;
          const r = await fetch(`${accountBase}/workers/domains`, { method: "PUT", headers: auth, body: JSON.stringify(payload) });
          const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal membuat Worker Custom Domain.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, result: d.result || null, message: "Permintaan Custom Domain berhasil." });
        }
        if (route === "/api/worker-domain-delete") {
          const hostname = normalizeDomain(body.hostname);
          if (!hostname) return json({ success: false, message: "Hostname tidak valid." }, 400);
          const r = await fetch(`${accountBase}/workers/domains/${encodeURIComponent(hostname)}`, { method: "DELETE", headers: auth });
          const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menghapus Worker Custom Domain.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, deleted: true, message: "Worker Custom Domain berhasil dihapus." });
        }
        const zoneName = normalizeDomain(body.domain);
        if (!zoneName) return json({ success: false, message: "Masukkan nama zona yang valid." }, 400);
        const zonesUrl = new URL("https://api.cloudflare.com/client/v4/zones");
        zonesUrl.searchParams.set("name", zoneName); zonesUrl.searchParams.set("account.id", env.CF_ACCOUNT_ID); zonesUrl.searchParams.set("per_page", "50");
        const zr = await fetch(zonesUrl.toString(), { headers: auth }); const zp = await zr.json().catch(() => ({}));
        if (!zr.ok || zp.success !== true) return json({ success: false, message: errorsText(zp) || "Gagal mencari zona Cloudflare.", errors: zp.errors || [] }, zr.status || 502);
        const zone = (zp.result || []).find(z => String(z.name || "").toLowerCase() === zoneName);
        if (!zone) return json({ success: false, message: `Zona ${zoneName} tidak ditemukan di akun ini.` }, 404);
        const routesBase = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zone.id)}/workers/routes`;
        if (route === "/api/worker-routes-list") {
          const r = await fetch(routesBase, { headers: auth }); const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal membaca Workers Routes.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, zone: zone.name, zoneId: zone.id, result: d.result || [] });
        }
        if (route === "/api/worker-route-create") {
          const pattern = typeof body.pattern === "string" ? body.pattern.trim().toLowerCase() : "";
          const script = typeof body.script === "string" ? body.script.trim() : "";
          const suffix = `.${zone.name}`;
          const hostPart = pattern.split("/")[0];
          const bareHost = hostPart.startsWith("*.") ? hostPart.slice(2) : hostPart;
          if (!script || script.length > 128 || /[^a-zA-Z0-9_-]/.test(script)) return json({ success: false, message: "Pilih nama Worker yang valid." }, 400);
          if (!pattern || !pattern.includes("/") || !pattern.endsWith("/*") || !(bareHost === zone.name || bareHost.endsWith(suffix)) || /[?#\s]/.test(pattern)) {
            return json({ success: false, message: `Pattern harus berupa hostname dalam zona ${zone.name}, misalnya app.${zone.name}/* atau *.${zone.name}/*.` }, 400);
          }
          const r = await fetch(routesBase, { method: "POST", headers: auth, body: JSON.stringify({ pattern, script }) }); const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal membuat Workers Route.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, zone: zone.name, result: d.result || null, message: "Workers Route berhasil dibuat." });
        }
        if (route === "/api/worker-route-delete") {
          const routeId = typeof body.routeId === "string" ? body.routeId.trim() : "";
          if (!/^[a-f0-9-]{16,64}$/i.test(routeId)) return json({ success: false, message: "ID route tidak valid." }, 400);
          const r = await fetch(`${routesBase}/${encodeURIComponent(routeId)}`, { method: "DELETE", headers: auth }); const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menghapus Workers Route.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, deleted: true, message: "Workers Route berhasil dihapus." });
        }
      } catch { return json({ success: false, message: "Tidak berhasil menghubungi Cloudflare Workers API." }, 502); }
    }

    // DNS endpoints operate on a zone that already exists in this Cloudflare account.
    const dnsRoute = ["/api/dns-list", "/api/dns-create", "/api/dns-update", "/api/dns-delete"].includes(route);
    if (dnsRoute) {
      const zoneName = normalizeDomain(body.domain);
      if (!zoneName) return json({ success: false, message: "Nama zona tidak valid." }, 400);
      if (["/api/dns-update", "/api/dns-delete"].includes(route) && (typeof body.recordId !== "string" || !/^[a-f0-9]{32}$/i.test(body.recordId))) {
        return json({ success: false, message: "Record ID tidak valid." }, 400);
      }
      try {
        const zonesUrl = new URL("https://api.cloudflare.com/client/v4/zones");
        zonesUrl.searchParams.set("name", zoneName);
        zonesUrl.searchParams.set("account.id", env.CF_ACCOUNT_ID);
        zonesUrl.searchParams.set("per_page", "50");
        const zr = await fetch(zonesUrl.toString(), { headers: { "Authorization": `Bearer ${env.CF_API_TOKEN}` } });
        const zp = await zr.json().catch(() => ({}));
        if (!zr.ok || zp.success !== true) return json({ success: false, message: errorsText(zp) || "Gagal mencari zona Cloudflare.", errors: zp.errors || [] }, zr.status || 502);
        const zone = (zp.result || []).find(z => String(z.name || "").toLowerCase() === zoneName);
        if (!zone) return json({ success: false, message: `Zona ${zoneName} tidak ditemukan di akun ini.` }, 404);
        const base = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zone.id)}/dns_records`;
        const auth = { "Authorization": `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" };
        if (route === "/api/dns-list") {
          const u = new URL(base); u.searchParams.set("per_page", "100"); u.searchParams.set("page", String(Math.max(1, Math.min(10000, Number(body.page) || 1))));
          if (body.search) u.searchParams.set("name", String(body.search).trim());
          const r = await fetch(u.toString(), { headers: auth }); const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal membaca DNS records.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, zone: zone.name, zoneId: zone.id, result: d.result || [], result_info: d.result_info || null });
        }
        if (route === "/api/dns-delete") {
          const r = await fetch(`${base}/${encodeURIComponent(body.recordId)}`, { method: "DELETE", headers: auth }); const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menghapus DNS record.", errors: d.errors || [] }, r.status || 502);
          return json({ success: true, deleted: true, zone: zone.name, recordId: body.recordId, message: "DNS record berhasil dihapus." });
        }
        const allowedTypes = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS"];
        const type = String(body.type || "").toUpperCase();
        const content = typeof body.content === "string" ? body.content.trim() : "";
        let name = typeof body.name === "string" ? body.name.trim().toLowerCase() : "";
        if (!name || name === "@") name = zone.name;
        else if (name !== zone.name && !name.endsWith(`.${zone.name}`)) name = `${name}.${zone.name}`;
        if (!allowedTypes.includes(type)) return json({ success: false, message: `Tipe record tidak didukung. Pilih: ${allowedTypes.join(", ")}.` }, 400);
        if (!content) return json({ success: false, message: "Konten/target DNS wajib diisi." }, 400);
        if (name.length > 253 || name.split(".").some(label => !label || label.length > 63 || !/^[a-z0-9_*](?:[a-z0-9_-]*[a-z0-9_*])?$/.test(label))) return json({ success: false, message: "Nama DNS tidak valid." }, 400);
        const record = { type, name, content, ttl: Number(body.ttl) === 1 ? 1 : Math.max(60, Math.min(86400, Number(body.ttl) || 1)), proxied: ["A", "AAAA", "CNAME"].includes(type) && body.proxied === true };
        if (type === "MX") { record.priority = Number.isInteger(Number(body.priority)) ? Math.max(0, Math.min(65535, Number(body.priority))) : 10; }
        if (type === "SRV") { record.data = body.data && typeof body.data === "object" ? body.data : undefined; }
        const isUpdate = route === "/api/dns-update";
        const r = await fetch(isUpdate ? `${base}/${encodeURIComponent(body.recordId)}` : base, { method: isUpdate ? "PUT" : "POST", headers: auth, body: JSON.stringify(record) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || (isUpdate ? "Gagal memperbarui DNS record." : "Gagal membuat DNS record."), errors: d.errors || [] }, r.status || 502);
        return json({ success: true, zone: zone.name, result: d.result || null, message: isUpdate ? "DNS record berhasil diperbarui." : "DNS record berhasil dibuat." });
      } catch { return json({ success: false, message: "Tidak berhasil menghubungi Cloudflare API." }, 502); }
    }
    const domain = normalizeDomain(body.domain);
    if (!domain) return json({ success: false, message: "Format nama domain tidak valid. Masukkan hostname seperti contoh.com tanpa path atau port." }, 400);

    try {
      if (route === "/api/check-domain" || route === "/api/delete-domain") {
        const endpoint = new URL("https://api.cloudflare.com/client/v4/zones");
        endpoint.searchParams.set("name", domain);
        endpoint.searchParams.set("account.id", env.CF_ACCOUNT_ID);
        endpoint.searchParams.set("per_page", "50");
        const lookupResponse = await fetch(endpoint.toString(), { headers: { "Authorization": `Bearer ${env.CF_API_TOKEN}` } });
        const lookup = await lookupResponse.json().catch(() => ({}));
        if (!lookupResponse.ok || lookup.success !== true) {
          return json({ success: false, message: errorsText(lookup) || "Cloudflare gagal mencari domain.", errors: lookup.errors || [], messages: lookup.messages || [] }, lookupResponse.status || 502);
        }
        const zone = (lookup.result || []).find(item => String(item.name || "").toLowerCase() === domain) || null;
        if (!zone) return json({ success: route === "/api/check-domain", found: false, domain, message: "Domain tidak ditemukan pada akun Cloudflare ini." }, route === "/api/delete-domain" ? 404 : 200);
        if (route === "/api/delete-domain") {
          if (typeof body.confirmDomain !== "string" || body.confirmDomain.trim().toLowerCase() !== domain) {
            return json({ success: false, message: `Konfirmasi tidak cocok. Ketik nama domain tepat: ${domain}` }, 400);
          }
          const deleteResponse = await fetch(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zone.id)}`, {
            method: "DELETE", headers: { "Authorization": `Bearer ${env.CF_API_TOKEN}` }
          });
          const deletion = await deleteResponse.json().catch(() => ({}));
          if (!deleteResponse.ok || deletion.success !== true) {
            return json({ success: false, message: errorsText(deletion) || "Cloudflare gagal menghapus zona.", errors: deletion.errors || [], messages: deletion.messages || [] }, deleteResponse.status || 502);
          }
          return json({ success: true, deleted: true, domain: zone.name, id: zone.id, message: "Zona berhasil dihapus dari akun Cloudflare." });
        }
        return json({ success: true, found: true, domain: zone.name, result: {
          id: zone.id, name: zone.name, status: zone.status, paused: zone.paused,
          type: zone.type, name_servers: zone.name_servers || [], original_name_servers: zone.original_name_servers || [],
          created_on: zone.created_on || null, modified_on: zone.modified_on || null
        }});
      }
      const cfResponse = await fetch("https://api.cloudflare.com/client/v4/zones", {
        method: "POST", headers: { "Authorization": `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: domain, account: { id: env.CF_ACCOUNT_ID }, type: "full" })
      });
      const payload = await cfResponse.json().catch(() => ({}));
      return json({ success: payload.success === true, result: payload.result || null, errors: payload.errors || [], messages: payload.messages || [] }, cfResponse.status);
    } catch {
      return json({ success: false, message: "Tidak berhasil menghubungi Cloudflare API." }, 502);
    }
  }
};
