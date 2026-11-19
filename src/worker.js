// Cloudflare Worker: statik menü + güvenli yönetici paneli (KV'de saklanan menü verisi)
const enc = new TextEncoder();
const SESSION_TTL = 60 * 60 * 8; // 8 saat
const MAX_FAILS = 8; // 10 dk içinde izin verilen hatalı giriş

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
// Uzunluktan bağımsız, sabit zamanlı karşılaştırma
async function strEq(a, b) {
  return safeEq(await hmac("cmp", String(a)), await hmac("cmp", String(b)));
}
async function pbkdf2(password, saltB64) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unb64u(saltB64), iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return b64u(bits);
}

const sessionSecret = (env) => env.SESSION_SECRET || env.ADMIN_PASSWORD || "";

async function getCred(env) {
  // Panelden değiştirilmiş giriş bilgisi varsa onu, yoksa Cloudflare secret'larını kullan
  const stored = await env.MENU_KV.get("cred", "json");
  return stored || null;
}

async function checkLogin(env, user, pass) {
  const stored = await getCred(env);
  if (stored) {
    const okUser = await strEq(user, stored.user);
    const okPass = safeEq(await pbkdf2(pass, stored.salt), stored.hash);
    return { ok: okUser && okPass, ver: String(stored.ver || 1), user: stored.user };
  }
  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) return { ok: false, ver: "0", user: "" };
  const okUser = await strEq(user, env.ADMIN_USERNAME);
  const okPass = await strEq(pass, env.ADMIN_PASSWORD);
  return { ok: okUser && okPass, ver: "0", user: env.ADMIN_USERNAME };
}

async function makeToken(env, user, ver) {
  const payload = b64u(enc.encode(JSON.stringify({ u: user, v: ver, exp: Math.floor(Date.now() / 1000) + SESSION_TTL })));
  return payload + "." + (await hmac(sessionSecret(env), payload));
}

function readCookie(request, name) {
  const m = (request.headers.get("Cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? m[1] : null;
}

async function getSession(request, env) {
  const tok = readCookie(request, "session");
  if (!tok || !sessionSecret(env)) return null;
  const [payload, sig] = tok.split(".");
  if (!payload || !sig) return null;
  if (!safeEq(await hmac(sessionSecret(env), payload), sig)) return null;
  let data;
  try {
    data = JSON.parse(new TextDecoder().decode(unb64u(payload)));
  } catch {
    return null;
  }
  if (!data.exp || data.exp < Date.now() / 1000) return null;
  // Şifre değiştirildiyse eski oturumlar geçersiz olsun
  const stored = await getCred(env);
  const curVer = stored ? String(stored.ver || 1) : "0";
  if (String(data.v) !== curVer) return null;
  return data;
}

const cookie = (request, value, maxAge) =>
  `session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}` +
  (new URL(request.url).protocol === "https:" ? "; Secure" : "");

function validateMenu(m) {
  const str = (v, max) => typeof v === "string" && v.length <= max;
  const num = (v) => typeof v === "number" && isFinite(v) && v >= 0 && v < 1e7;
  if (!Array.isArray(m) || m.length < 1 || m.length > 40) return "Geçersiz menü yapısı.";
  const out = [];
  for (const c of m) {
    if (!Array.isArray(c) || c.length !== 4) return "Geçersiz kategori.";
    const [id, title, sub, items] = c;
    if (!str(id, 40) || !/^[a-z0-9_-]+$/i.test(id) || !str(title, 80) || !str(sub, 160) || !Array.isArray(items) || items.length > 200)
      return "Geçersiz kategori verisi.";
    const its = [];
    for (const r of items) {
      if (!Array.isArray(r) || r.length < 6) return "Geçersiz ürün.";
      const [n, d, p, k, t, key] = r;
      if (!str(n, 120) || !str(d, 600) || !num(p) || !num(k) || !str(t, 40) || !str(key, 40) || !/^[a-z0-9_-]*$/i.test(key))
        return "Geçersiz ürün verisi.";
      if (!n.trim()) return "Ürün adı boş olamaz.";
      its.push([n, d, p, k, t, key]);
    }
    out.push([id, title, sub, its]);
  }
  return out;
}

async function api(request, env, path) {
  if (!env.MENU_KV) return json({ error: "KV (MENU_KV) tanımlı değil. README'ye bakın." }, 500);
  if (!sessionSecret(env)) return json({ error: "ADMIN_PASSWORD secret'ı tanımlı değil." }, 500);

  if (request.method !== "POST" && request.method !== "PUT" && request.method !== "GET")
    return json({ error: "Yöntem desteklenmiyor" }, 405);

  if (request.method !== "GET") {
    // Basit CSRF savunması: yalnızca kendi sitemizden gelen JSON istekleri
    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) return json({ error: "Yasak" }, 403);
    if (!(request.headers.get("Content-Type") || "").includes("application/json")) return json({ error: "JSON bekleniyor" }, 415);
  }

  if (path === "/api/login" && request.method === "POST") {
    const ip = request.headers.get("CF-Connecting-IP") || "x";
    const rlKey = "rl:" + ip;
    const fails = parseInt((await env.MENU_KV.get(rlKey)) || "0", 10);
    if (fails >= MAX_FAILS) return json({ error: "Çok fazla deneme. 10 dakika sonra tekrar deneyin." }, 429);
    let b;
    try {
      b = await request.json();
    } catch {
      return json({ error: "Geçersiz istek" }, 400);
    }
    const r = await checkLogin(env, String(b.user || ""), String(b.pass || ""));
    if (!r.ok) {
      await env.MENU_KV.put(rlKey, String(fails + 1), { expirationTtl: 600 });
      await new Promise((res) => setTimeout(res, 400));
      return json({ error: "Kullanıcı adı veya şifre hatalı." }, 401);
    }
    await env.MENU_KV.delete(rlKey);
    const tok = await makeToken(env, r.user, r.ver);
    return json({ ok: true, user: r.user }, 200, { "Set-Cookie": cookie(request, tok, SESSION_TTL) });
  }

  if (path === "/api/logout" && request.method === "POST")
    return json({ ok: true }, 200, { "Set-Cookie": cookie(request, "", 0) });

  const sess = await getSession(request, env);
  if (!sess) return json({ error: "Oturum gerekli" }, 401);

  if (path === "/api/me" && request.method === "GET") return json({ ok: true, user: sess.u });

  if (path === "/api/menu" && request.method === "PUT") {
    if (parseInt(request.headers.get("Content-Length") || "0", 10) > 400000) return json({ error: "Veri çok büyük" }, 413);
    let b;
    try {
      b = await request.json();
    } catch {
      return json({ error: "Geçersiz istek" }, 400);
    }
    const res = validateMenu(b.menu);
    if (typeof res === "string") return json({ error: res }, 400);
    const prev = await env.MENU_KV.get("menu");
    if (prev) await env.MENU_KV.put("menu:prev", prev);
    await env.MENU_KV.put("menu", JSON.stringify(res));
    return json({ ok: true });
  }

  if (path === "/api/menu/reset" && request.method === "POST") {
    await env.MENU_KV.delete("menu");
    return json({ ok: true });
  }

  if (path === "/api/credentials" && request.method === "POST") {
    let b;
    try {
      b = await request.json();
    } catch {
      return json({ error: "Geçersiz istek" }, 400);
    }
    const cur = await checkLogin(env, sess.u, String(b.current || ""));
    if (!cur.ok) return json({ error: "Mevcut şifre hatalı." }, 403);
    const nu = String(b.newUser || "").trim() || sess.u;
    const np = String(b.newPassword || "");
    if (nu.length < 3 || nu.length > 40) return json({ error: "Kullanıcı adı 3-40 karakter olmalı." }, 400);
    if (np.length < 8 || np.length > 100) return json({ error: "Şifre en az 8 karakter olmalı." }, 400);
    const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
    const stored = await getCred(env);
    const ver = (stored ? stored.ver || 1 : 0) + 1;
    await env.MENU_KV.put("cred", JSON.stringify({ user: nu, salt, hash: await pbkdf2(np, salt), ver }));
    const tok = await makeToken(env, nu, String(ver));
    return json({ ok: true, user: nu }, 200, { "Set-Cookie": cookie(request, tok, SESSION_TTL) });
  }

  return json({ error: "Bulunamadı" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith("/api/")) return api(request, env, path);

    if (request.method !== "GET" && request.method !== "HEAD")
      return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD" } });

    // /menu.js: varsayılan menü + (varsa) panelden kaydedilmiş menü
    if (path === "/menu.js") {
      const base = await env.ASSETS.fetch(request);
      let text = await base.text();
      if (env.MENU_KV) {
        try {
          const saved = await env.MENU_KV.get("menu");
          if (saved) text += "\nwindow.MENU = " + saved + ";\n";
        } catch (_) {}
      }
      return new Response(text, {
        status: 200,
        headers: {
          "Content-Type": "application/javascript; charset=utf-8",
          "Cache-Control": "no-cache",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }

    const res = await env.ASSETS.fetch(request);
    const headers = new Headers(res.headers);
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set("X-Frame-Options", "SAMEORIGIN");

    if (path.startsWith("/img/")) headers.set("Cache-Control", "public, max-age=2592000");
    else if (path === "/" || path.endsWith(".html") || path === "/admin") headers.set("Cache-Control", "public, max-age=0, must-revalidate");
    if (path.startsWith("/admin")) headers.set("X-Robots-Tag", "noindex, nofollow");

    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  },
};
