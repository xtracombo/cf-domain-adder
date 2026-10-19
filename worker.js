const ALLOWED_ORIGIN = "https://xtracombo.github.io";
const SESSION_TTL_SECONDS = 60 * 60 * 8;
const PBKDF2_ITERATIONS = 210000;

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
async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return [...digest].map(b => b.toString(16).padStart(2, "0")).join("");
}
function randomId(bytes = 24) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return [...data].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hashPassword(password, salt = randomId(16)) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, material, 256);
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${salt}$${base64url(new Uint8Array(bits))}`;
}
async function verifyPassword(password, stored) {
  try {
    const [scheme, rounds, salt, expected] = stored.split("$");
    if (scheme !== "pbkdf2-sha256" || Number(rounds) < 100000 || Number(rounds) > 1000000) return false;
    const actual = await hashPassword(password, salt);
    const parts = actual.split("$");
    return parts[3].length === expected.length && parts[3] === expected;
  } catch { return false; }
}
async function encryptToken(token, secret) {
  const keyBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(token)));
  return `v1.${base64url(iv)}.${base64url(ciphertext)}`;
}
async function decryptToken(value, secret) {
  const [version, ivText, dataText] = String(value || "").split(".");
  if (version !== "v1" || !ivText || !dataText) throw new Error("Format token terenkripsi tidak valid.");
  const keyBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const decode = text => Uint8Array.from(atob(text.replace(/-/g,"+").replace(/_/g,"/") + "=".repeat((4-text.length%4)%4)), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(ivText) }, key, decode(dataText));
  return new TextDecoder().decode(plain);
}
async function consumeRateLimit(env, key, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000), expires = now + windowSeconds;
  const row = await env.DB.prepare(`INSERT INTO rate_limits (rate_key, attempts, window_started_at, expires_at) VALUES (?, 1, ?, ?) ON CONFLICT(rate_key) DO UPDATE SET attempts = CASE WHEN rate_limits.expires_at <= ? THEN 1 ELSE rate_limits.attempts + 1 END, window_started_at = CASE WHEN rate_limits.expires_at <= ? THEN excluded.window_started_at ELSE rate_limits.window_started_at END, expires_at = CASE WHEN rate_limits.expires_at <= ? THEN excluded.expires_at ELSE rate_limits.expires_at END RETURNING attempts, expires_at`).bind(key, now, expires, now, now, now).first();
  return { allowed: Number(row?.attempts || 0) <= limit, attempts: Number(row?.attempts || 0), expiresAt: Number(row?.expires_at || expires) };
}
async function audit(env, actorId, action, targetType = null, targetId = null, result = "success", details = null) {
  try { await env.DB.prepare("INSERT INTO audit_logs (id, actor_user_id, action, target_type, target_id, result, details_json) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(randomId(16), actorId || null, action, targetType, targetId, result, details ? JSON.stringify(details) : null).run(); } catch {}
}
function validEmail(email) { return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function validUsername(username) { return typeof username === "string" && /^[a-zA-Z0-9_.-]{3,32}$/.test(username); }

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
      "/api/register", "/api/login", "/api/logout", "/api/me", "/api/connect-cloudflare", "/api/disconnect-cloudflare",
      "/api/admin/users", "/api/admin/audit",
      "/api/add-domain", "/api/check-domain", "/api/delete-domain", "/api/dns-list", "/api/dns-create", "/api/dns-update", "/api/dns-delete",
      "/api/workers-list", "/api/worker-domains-list", "/api/worker-domain-create", "/api/worker-domain-delete",
      "/api/pages-domains-list", "/api/pages-domain-create", "/api/pages-domain-delete", "/api/worker-routes-list", "/api/worker-route-create", "/api/worker-route-delete", "/api/pages-list", "/api/zones-list"
    ];
    if (!knownRoutes.includes(route)) return json({ success: false, message: "Not found." }, 404);
    if (request.method !== "POST") return json({ success: false, message: "Method not allowed." }, 405);
    if (!env.DB || !env.SESSION_SECRET) return json({ success: false, message: "Konfigurasi backend belum lengkap. Pastikan binding D1 bernama DB dan Secret SESSION_SECRET tersedia." }, 500);
    let body;
    try { body = await request.json(); } catch { return json({ success: false, message: "Body JSON tidak valid." }, 400); }

    if (route === "/api/register") {
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const rate = await consumeRateLimit(env, `register:${await sha256Hex(ip)}`, 5, 3600);
      if (!rate.allowed) return json({ success: false, message: "Terlalu banyak percobaan pendaftaran. Coba lagi sekitar satu jam lagi." }, 429);
      const username = typeof body.username === "string" ? body.username.trim() : "";
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!validUsername(username)) return json({ success: false, message: "Username harus 3–32 karakter: huruf, angka, titik, garis bawah, atau tanda hubung." }, 400);
      if (!validEmail(email)) return json({ success: false, message: "Alamat email tidak valid." }, 400);
      if (password.length < 12 || password.length > 256) return json({ success: false, message: "Password harus minimal 12 karakter." }, 400);
      const exists = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1").bind(username, email).first();
      if (exists) return json({ success: false, message: "Username atau email sudah terdaftar." }, 409);
      const id = randomId(16), passwordHash = await hashPassword(password);
      try {
        await env.DB.prepare("INSERT INTO users (id, username, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'user', 'active')").bind(id, username, email, passwordHash).run();
        await audit(env, id, "user.register", "user", id);
        return json({ success: true, message: "Pendaftaran berhasil. Silakan login." }, 201);
      } catch { return json({ success: false, message: "Pendaftaran gagal. Username atau email mungkin sudah digunakan." }, 409); }
    }

    if (route === "/api/login") {
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const rate = await consumeRateLimit(env, `login:${await sha256Hex(ip)}`, 10, 900);
      if (!rate.allowed) return json({ success: false, message: "Terlalu banyak percobaan login. Coba lagi dalam beberapa menit." }, 429);
      const login = typeof body.login === "string" ? body.login.trim() : (typeof body.username === "string" ? body.username.trim() : "");
      const password = typeof body.password === "string" ? body.password : "";
      if (!login || !password) return json({ success: false, message: "Masukkan username/email dan password." }, 400);
      const user = await env.DB.prepare("SELECT id, username, email, password_hash, role, status FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1").bind(login, login).first();
      if (!user || user.status !== "active" || !(await verifyPassword(password, user.password_hash))) {
        await audit(env, user?.id || null, "user.login", "user", user?.id || null, "failure", { reason: "invalid_credentials" });
        return json({ success: false, message: "Username/email atau password salah, atau akun dinonaktifkan." }, 401);
      }
      const token = randomId(32), tokenHash = await sha256Hex(token), sessionId = randomId(16);
      const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
      await env.DB.prepare("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)").bind(sessionId, user.id, tokenHash, expiresAt).run();
      await env.DB.prepare("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?").bind(user.id).run();
      await audit(env, user.id, "user.login", "user", user.id);
      return json({ success: true, token, expiresIn: SESSION_TTL_SECONDS, user: { id: user.id, username: user.username, email: user.email, role: user.role }, message: "Login berhasil." });
    }

    const sessionToken = request.headers.get("X-Session-Token") || "";
    if (!sessionToken) return json({ success: false, message: "Silakan login terlebih dahulu." }, 401);
    const tokenHash = await sha256Hex(sessionToken);
    const session = await env.DB.prepare("SELECT s.id AS session_id, s.user_id, s.expires_at, u.username, u.email, u.role, u.status FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? LIMIT 1").bind(tokenHash).first();
    if (!session || session.status !== "active" || Date.parse(session.expires_at) <= Date.now()) {
      if (session) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(session.session_id).run();
      return json({ success: false, message: "Sesi tidak valid atau sudah berakhir. Silakan login kembali." }, 401);
    }
    const userId = session.user_id;
    if (route === "/api/logout") {
      await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(session.session_id).run();
      await audit(env, userId, "user.logout", "user", userId);
      return json({ success: true, message: "Logout berhasil." });
    }
    if (route === "/api/me") {
      const connection = await env.DB.prepare("SELECT id, account_id, status, created_at, updated_at FROM cloudflare_connections WHERE user_id = ? ORDER BY created_at DESC LIMIT 1").bind(userId).first();
      return json({ success: true, user: { id: userId, username: session.username, email: session.email, role: session.role }, connection: connection ? { connected: true, accountId: connection.account_id, status: connection.status } : { connected: false } });
    }
    if (route === "/api/connect-cloudflare") {
      const accountId = typeof body.accountId === "string" ? body.accountId.trim() : "";
      const apiToken = typeof body.apiToken === "string" ? body.apiToken.trim() : "";
      if (!/^[a-f0-9]{32}$/i.test(accountId)) return json({ success: false, message: "Account ID harus berupa 32 karakter heksadesimal." }, 400);
      if (apiToken.length < 20 || apiToken.length > 512 || /\s/.test(apiToken)) return json({ success: false, message: "API Token tidak valid. Tempel token Cloudflare tanpa spasi." }, 400);
      if (!env.TOKEN_ENCRYPTION_KEY || env.TOKEN_ENCRYPTION_KEY.length < 32) return json({ success: false, message: "Admin perlu mengatur Secret TOKEN_ENCRYPTION_KEY (minimal 32 karakter) sebelum koneksi dapat disimpan." }, 500);
      const auth = { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" };
      const verifyResponse = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", { headers: auth });
      const verifyData = await verifyResponse.json().catch(() => ({}));
      const accountResponse = verifyData.success === true && verifyData.result?.status === "active"
        ? await fetch(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/workers/scripts?per_page=1`, { headers: auth })
        : null;
      const accountData = accountResponse ? await accountResponse.json().catch(() => ({})) : {};
      if (!verifyResponse.ok || verifyData.success !== true || verifyData.result?.status !== "active" || !accountResponse?.ok || accountData.success !== true) {
        await audit(env, userId, "cloudflare.connect", "cloudflare_account", accountId, "failure", { httpStatus: verifyResponse.status });
        return json({ success: false, message: "Cloudflare menolak koneksi. Periksa Account ID, API Token, dan permission token." }, 400);
      }
      const encrypted = await encryptToken(apiToken, env.TOKEN_ENCRYPTION_KEY);
      const existing = await env.DB.prepare("SELECT id FROM cloudflare_connections WHERE user_id = ? AND account_id = ? LIMIT 1").bind(userId, accountId).first();
      if (existing) {
        await env.DB.prepare("UPDATE cloudflare_connections SET encrypted_token = ?, token_key_version = 'v1', status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(encrypted, existing.id).run();
      } else {
        await env.DB.prepare("INSERT INTO cloudflare_connections (id, user_id, account_id, encrypted_token, token_key_version, status) VALUES (?, ?, ?, ?, 'v1', 'active')").bind(randomId(16), userId, accountId, encrypted).run();
      }
      await audit(env, userId, "cloudflare.connect", "cloudflare_account", accountId);
      return json({ success: true, message: "Akun Cloudflare berhasil diverifikasi dan dihubungkan.", accountId });
    }
    if (route === "/api/disconnect-cloudflare") {
      const accountId = typeof body.accountId === "string" ? body.accountId.trim() : "";
      if (accountId) await env.DB.prepare("DELETE FROM cloudflare_connections WHERE user_id = ? AND account_id = ?").bind(userId, accountId).run();
      else await env.DB.prepare("DELETE FROM cloudflare_connections WHERE user_id = ?").bind(userId).run();
      await audit(env, userId, "cloudflare.disconnect", "cloudflare_account", accountId || null);
      return json({ success: true, message: "Koneksi Cloudflare dihapus dari Club Gratis." });
    }
    if (route === "/api/admin/users" || route === "/api/admin/audit") {
      if (session.role !== "admin") return json({ success: false, message: "Akses khusus Admin." }, 403);
      if (route === "/api/admin/users") {
        const rows = await env.DB.prepare("SELECT u.id, u.username, u.email, u.role, u.status, u.created_at, u.last_login_at, c.account_id AS cloudflare_account_id, c.status AS connection_status FROM users u LEFT JOIN cloudflare_connections c ON c.user_id = u.id ORDER BY u.created_at DESC LIMIT 200").all();
        return json({ success: true, result: rows.results || [] });
      }
      const rows = await env.DB.prepare("SELECT a.id, a.actor_user_id, u.username AS actor_username, a.action, a.target_type, a.target_id, a.result, a.details_json, a.created_at FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id ORDER BY a.created_at DESC LIMIT 200").all();
      return json({ success: true, result: rows.results || [] });
    }

    const connection = await env.DB.prepare("SELECT account_id, encrypted_token, status FROM cloudflare_connections WHERE user_id = ? AND status = 'active' ORDER BY updated_at DESC LIMIT 1").bind(userId).first();
    if (!connection) return json({ success: false, message: "Hubungkan akun Cloudflare terlebih dahulu melalui panel Koneksi Cloudflare." }, 409);
    if (!env.TOKEN_ENCRYPTION_KEY) return json({ success: false, message: "Secret TOKEN_ENCRYPTION_KEY belum dikonfigurasi." }, 500);
    let userApiToken;
    try { userApiToken = await decryptToken(connection.encrypted_token, env.TOKEN_ENCRYPTION_KEY); }
    catch { return json({ success: false, message: "Token tersimpan tidak dapat dibuka. Hubungkan ulang akun Cloudflare." }, 500); }
    // Reuse existing feature handlers, but inject only this authenticated user's credentials.
    env = Object.assign(Object.create(Object.getPrototypeOf(env)), env, { CF_ACCOUNT_ID: connection.account_id, CF_API_TOKEN: userApiToken });

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
    // Cloudflare Pages projects endpoint does not accept the standard
    // page/per_page query options in this account/API response. Request the
    // collection without pagination parameters to avoid error 8000024.
    const pagesUrl = new URL(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CF_ACCOUNT_ID)}/pages/projects`);
    const response = await fetch(pagesUrl.toString(), { headers: { "Authorization": `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.success !== true) {
      return json({ success: false, message: errorsText(data) || "Gagal mengambil daftar Cloudflare Pages.", errors: data.errors || [] }, response.status || 502);
    }
    const projects = Array.isArray(data.result) ? data.result : [];
    return json({ success: true, result: projects, result_info: { returned_count: projects.length }, message: "Daftar Cloudflare Pages berhasil dimuat." });
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
      const r = await fetch(projectBase, { method: "POST", headers: auth, body: JSON.stringify({ name: domain }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menambahkan domain ke Pages.", errors: d.errors || [] }, r.status || 502);

      // Automatically create the DNS CNAME needed by Pages, when this hostname
      // belongs to a zone managed in the same Cloudflare account. Never overwrite
      // an existing record that points somewhere else.
      const dnsSetup = { attempted: false, created: false, status: "skipped", message: "DNS tidak dibuat otomatis." };
      try {
        const zonesUrl = new URL("https://api.cloudflare.com/client/v4/zones");
        zonesUrl.searchParams.set("account.id", env.CF_ACCOUNT_ID);
        zonesUrl.searchParams.set("per_page", "100");
        zonesUrl.searchParams.set("page", "1");
        const zonesResponse = await fetch(zonesUrl.toString(), { headers: auth });
        const zonesData = await zonesResponse.json().catch(() => ({}));
        if (zonesResponse.ok && zonesData.success === true) {
          const zones = Array.isArray(zonesData.result) ? zonesData.result : [];
          const zone = zones.filter(z => domain === z.name || domain.endsWith("." + z.name))
            .sort((a, b) => String(b.name || "").length - String(a.name || "").length)[0];
          if (zone) {
            dnsSetup.attempted = true;
            const recordName = domain;
            const target = `${projectName}.pages.dev`;
            const dnsBase = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zone.id)}/dns_records`;
            const searchUrl = new URL(dnsBase);
            searchUrl.searchParams.set("name", recordName);
            searchUrl.searchParams.set("per_page", "100");
            const existingResponse = await fetch(searchUrl.toString(), { headers: auth });
            const existingData = await existingResponse.json().catch(() => ({}));
            if (!existingResponse.ok || existingData.success !== true) {
              dnsSetup.status = "error";
              dnsSetup.message = errorsText(existingData) || "Domain Pages ditambahkan, tetapi DNS record gagal diperiksa.";
            } else {
              const records = Array.isArray(existingData.result) ? existingData.result : [];
              const same = records.find(rec => String(rec.type).toUpperCase() === "CNAME" && String(rec.content || "").replace(/\.$/, "").toLowerCase() === target.toLowerCase());
              const conflict = records.find(rec => !same && (String(rec.type).toUpperCase() !== "TXT"));
              if (same) {
                dnsSetup.status = "existing";
                dnsSetup.created = false;
                dnsSetup.message = `DNS CNAME sudah ada dan mengarah ke ${target}.`;
                dnsSetup.record = same;
              } else if (conflict) {
                dnsSetup.status = "conflict";
                dnsSetup.message = `Domain Pages ditambahkan, tetapi DNS tidak diubah karena sudah ada record ${conflict.type} untuk ${recordName}. Periksa record itu sebelum menggantinya ke ${target}.`;
              } else {
                const createResponse = await fetch(dnsBase, { method: "POST", headers: auth, body: JSON.stringify({ type: "CNAME", name: recordName, content: target, ttl: 1, proxied: false }) });
                const createData = await createResponse.json().catch(() => ({}));
                if (createResponse.ok && createData.success === true) {
                  dnsSetup.status = "created";
                  dnsSetup.created = true;
                  dnsSetup.message = `DNS CNAME otomatis dibuat: ${recordName} → ${target} (DNS only).`;
                  dnsSetup.record = createData.result || null;
                } else {
                  dnsSetup.status = "error";
                  dnsSetup.message = errorsText(createData) || "Domain Pages ditambahkan, tetapi pembuatan DNS CNAME gagal.";
                }
              }
            }
          } else {
            dnsSetup.status = "zone-not-found";
            dnsSetup.message = "Domain Pages ditambahkan, tetapi zona DNS yang cocok tidak ditemukan pada akun Cloudflare ini. DNS perlu dibuat manual.";
          }
        } else {
          dnsSetup.status = "error";
          dnsSetup.message = errorsText(zonesData) || "Domain Pages ditambahkan, tetapi daftar zona gagal dimuat untuk membuat DNS.";
        }
      } catch {
        dnsSetup.status = "error";
        dnsSetup.message = "Domain Pages berhasil ditambahkan, tetapi terjadi kesalahan saat menyiapkan DNS otomatis.";
      }
      return json({ success: true, result: d.result || null, dns: dnsSetup, message: "Custom Domain Pages berhasil ditambahkan." });
    }
    const r = await fetch(`${projectBase}/${encodeURIComponent(domain)}`, { method: "DELETE", headers: auth }); const d = await r.json().catch(() => ({}));
    if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menghapus domain dari Pages.", errors: d.errors || [] }, r.status || 502);
    await audit(env, userId, "pages.domain.delete", "pages_domain", domain, "success", { projectName, domain });
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
          await audit(env, userId, "worker.domain.create", "worker_domain", hostname, "success", { hostname, service });
          return json({ success: true, result: d.result || null, message: "Permintaan Custom Domain berhasil." });
        }
        if (route === "/api/worker-domain-delete") {
          const hostname = normalizeDomain(body.hostname);
          if (!hostname) return json({ success: false, message: "Hostname tidak valid." }, 400);

          // Cloudflare's DELETE endpoint expects the Custom Domain ID, not its hostname.
          // Resolve the ID from the account's Custom Domains list before deleting.
          let domainId = typeof body.domainId === "string" ? body.domainId.trim() : "";
          if (!domainId) {
            // Some Cloudflare responses omit result_info.total_pages. In that case,
            // keep paging while the page is full; do not assume page 1 is the only page.
            const perPage = 100;
            const maxPages = 1000;
            let page = 1;
            let pagesFetched = 0;
            let apiTotalPages = null;
            let apiTotalCount = null;
            let foundDomain = null;
            while (page <= maxPages) {
              const listUrl = new URL(`${accountBase}/workers/domains`);
              listUrl.searchParams.set("per_page", String(perPage));
              listUrl.searchParams.set("page", String(page));
              const listResponse = await fetch(listUrl.toString(), { headers: auth });
              const listData = await listResponse.json().catch(() => ({}));
              if (!listResponse.ok || listData.success !== true) {
                return json({ success: false, message: errorsText(listData) || `Gagal mencari Custom Domain pada halaman ${page} sebelum penghapusan.`, errors: listData.errors || [], pages_fetched: pagesFetched }, listResponse.status || 502);
              }
              pagesFetched++;
              const items = Array.isArray(listData.result) ? listData.result : [];
              const info = listData.result_info || {};
              const totalPagesValue = Number(info.total_pages);
              const totalCountValue = Number(info.total_count);
              if (Number.isFinite(totalPagesValue) && totalPagesValue > 0) apiTotalPages = totalPagesValue;
              if (Number.isFinite(totalCountValue) && totalCountValue >= 0) apiTotalCount = totalCountValue;
              foundDomain = items.find(item => String(item.hostname || "").trim().toLowerCase() === hostname) || null;
              if (foundDomain) {
                domainId = String(foundDomain.id || "").trim();
                break;
              }
              if (items.length === 0) break;
              if (apiTotalPages !== null && page >= apiTotalPages) break;
              if (apiTotalPages === null && items.length < perPage) break;
              page++;
            }
            if (!domainId && page > maxPages) {
              return json({ success: false, message: `Pencarian Custom Domain dihentikan setelah ${maxPages} halaman. Domain tidak dihapus karena hasil pencarian belum dipastikan lengkap.`, pages_fetched: pagesFetched, api_total_pages: apiTotalPages, api_total_count: apiTotalCount }, 502);
            }
            if (foundDomain && !domainId) {
              return json({ success: false, message: `Custom Domain ${hostname} ditemukan pada daftar Cloudflare tetapi responsnya tidak memiliki ID penghapusan. Kunci yang tersedia: ${Object.keys(foundDomain).join(", ")}. Tidak ada domain yang dihapus.`, pages_fetched: pagesFetched, api_total_pages: apiTotalPages, api_total_count: apiTotalCount }, 502);
            }
          }
          if (!domainId) return json({ success: false, message: `Custom Domain ${hostname} ditemukan tanpa ID penghapusan, atau tidak ditemukan dalam daftar Cloudflare. Tidak ada domain yang dihapus.` }, 404);

          const r = await fetch(`${accountBase}/workers/domains/${encodeURIComponent(domainId)}`, { method: "DELETE", headers: auth });
          const raw = await r.text();
          let d = {};
          try { d = raw ? JSON.parse(raw) : {}; } catch { d = {}; }

          // Cloudflare can remove the domain but return an empty/unexpected body.
          // If the DELETE response is ambiguous, verify by querying the domain list.
          if (r.ok && d.success === true) {
            await audit(env, userId, "worker.domain.delete", "worker_domain", hostname, "success", { hostname, domainId });
            return json({ success: true, deleted: true, hostname, domainId, message: `Worker Custom Domain ${hostname} berhasil dihapus.` });
          }

          let verifiedDeleted = false;
          try {
            const verifyUrl = new URL(`${accountBase}/workers/domains`);
            verifyUrl.searchParams.set("per_page", "100");
            verifyUrl.searchParams.set("page", "1");
            const verifyResponse = await fetch(verifyUrl.toString(), { headers: auth });
            const verifyData = await verifyResponse.json().catch(() => ({}));
            if (verifyResponse.ok && verifyData.success === true) {
              const remaining = (Array.isArray(verifyData.result) ? verifyData.result : []).some(item =>
                String(item.hostname || "").trim().toLowerCase() === hostname
              );
              verifiedDeleted = !remaining;
            }
          } catch { /* verification failed; report the original API response below */ }

          if (verifiedDeleted) {
            return json({
              success: true,
              deleted: true,
              verified: true,
              hostname,
              domainId,
              message: `Worker Custom Domain ${hostname} sudah terhapus di Cloudflare. Respons DELETE API tidak standar, tetapi penghapusan telah diverifikasi.`
            });
          }

          const apiErrors = Array.isArray(d.errors) ? d.errors : [];
          const apiMessage = errorsText(d) || (raw ? raw.slice(0, 500) : "Cloudflare mengembalikan respons kosong.");
          return json({
            success: false,
            message: `Cloudflare DELETE belum dapat diverifikasi (HTTP ${r.status || 502}): ${apiMessage}`,
            cloudflare_status: r.status || 502,
            errors: apiErrors,
            error_codes: apiErrors.map(e => e && e.code).filter(v => v !== undefined),
            error_messages: apiErrors.map(e => e && e.message).filter(Boolean),
            hostname,
            domainId,
            endpoint: `/accounts/{account_id}/workers/domains/{domainId}`
          }, r.ok ? 502 : r.status || 502);
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
          await audit(env, userId, "worker.route.create", "worker_route", pattern, "success", { zone: zone.name, pattern, script });
          return json({ success: true, zone: zone.name, result: d.result || null, message: "Workers Route berhasil dibuat." });
        }
        if (route === "/api/worker-route-delete") {
          const routeId = typeof body.routeId === "string" ? body.routeId.trim() : "";
          if (!/^[a-f0-9-]{16,64}$/i.test(routeId)) return json({ success: false, message: "ID route tidak valid." }, 400);
          const r = await fetch(`${routesBase}/${encodeURIComponent(routeId)}`, { method: "DELETE", headers: auth }); const d = await r.json().catch(() => ({}));
          if (!r.ok || d.success !== true) return json({ success: false, message: errorsText(d) || "Gagal menghapus Workers Route.", errors: d.errors || [] }, r.status || 502);
          await audit(env, userId, "worker.route.delete", "worker_route", routeId, "success", { routeId });
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
          await audit(env, userId, "dns.record.delete", "dns_record", body.recordId, "success", { zone: zone.name, recordId: body.recordId });
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
        await audit(env, userId, isUpdate ? "dns.record.update" : "dns.record.create", "dns_record", d.result?.id || body.recordId || null, "success", { zone: zone.name, type, name, content, proxied: record.proxied });
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
          await audit(env, userId, "domain.delete", "zone", zone.id, "success", { domain: zone.name });
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
