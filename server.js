"use strict";

const http = require("http");
const https = require("https");
const fs = require("fs");
const url = require("url");
const crypto = require("crypto");
const querystring = require("querystring");

// --------------------
// Config (Render-safe)
// --------------------
const PORT = process.env.PORT || 3005;

// Read Google OAuth credentials from file (local) or env (prod)
let google = {};
try {
  google = JSON.parse(fs.readFileSync("./auth/credentials.json", "utf8"));
} catch (_) {
  google = {};
}

const client_id = process.env.GOOGLE_CLIENT_ID || google.client_id;
const client_secret = process.env.GOOGLE_CLIENT_SECRET || google.client_secret;
const redirect_uri = process.env.GOOGLE_REDIRECT_URI || google.redirect_uri;

// Read USAJobs secrets from file (local) or env (prod)
let usajobs = {};
try {
  usajobs = JSON.parse(fs.readFileSync("./auth/usajobs.json", "utf8"));
} catch (_) {
  usajobs = {};
}

const USAJOBS_AUTH_KEY = process.env.USAJOBS_AUTH_KEY || usajobs.usajobs_auth_key;
const USAJOBS_USER_AGENT = process.env.USAJOBS_USER_AGENT || usajobs.usajobs_user_agent;

// OAuth scopes: identity only
const SCOPE = "openid email profile";

// Google OAuth endpoints
const AUTH_HOST = "accounts.google.com";
const AUTH_PATH = "/o/oauth2/v2/auth";

const TOKEN_HOST = "oauth2.googleapis.com";
const TOKEN_PATH = "/token";

const USERINFO_HOST = "openidconnect.googleapis.com";
const USERINFO_PATH = "/v1/userinfo";

// USAJobs endpoints
const USAJOBS_HOST = "data.usajobs.gov";
const USAJOBS_SEARCH_PATH = "/api/search";

// --------------------
// In-memory stores
// --------------------
const oauth_state = new Map(); // state -> { createdAt }
const sessions = new Map(); // sid -> { token, cache: Map() }

// --------------------
// Helpers
// --------------------
function base64url_random(bytes = 24) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function now_ms() {
  return Date.now();
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const p = part.trim();
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const k = p.slice(0, eq);
    const v = p.slice(eq + 1);
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const pieces = [`${name}=${encodeURIComponent(value)}`];
  if (opts.httpOnly !== false) pieces.push("HttpOnly");
  pieces.push("Path=/");
  pieces.push("SameSite=Lax");
  if (opts.maxAgeSec !== undefined) pieces.push(`Max-Age=${opts.maxAgeSec}`);
  res.setHeader("Set-Cookie", pieces.join("; "));
}

function sendText(res, status, text) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(text);
}

function sendHTML(res, status, html) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function sendJSON(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj, null, 2));
}

function send404(req, res) {
  sendText(res, 404, `404 Not Found: ${req.url}`);
}

function readFileSafe(path) {
  try {
    return fs.readFileSync(path);
  } catch {
    return null;
  }
}

function escapeHtml(s) {
  if (typeof s !== "string") return "";
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function httpsRequestJSON({ host, path, method, headers, body }) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host, path, method, headers }, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        const status = resp.statusCode || 0;
        const ct = (resp.headers["content-type"] || "").toLowerCase();

        if (ct.includes("application/json") || data.trim().startsWith("{")) {
          try {
            resolve({ status, headers: resp.headers, json: JSON.parse(data), raw: data });
          } catch {
            resolve({ status, headers: resp.headers, json: null, raw: data });
          }
        } else {
          resolve({ status, headers: resp.headers, json: null, raw: data });
        }
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// TTL cache (stored per session)
function cacheGet(session, key) {
  const entry = session.cache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= now_ms()) {
    session.cache.delete(key);
    return null;
  }
  return entry.value;
}

function cacheSet(session, key, value, ttlMs) {
  session.cache.set(key, { value, expiresAt: now_ms() + ttlMs });
}

// Build USAJobs search path
function buildUSAJobsSearchPath(keyword, location) {
  const params = new url.URLSearchParams();
  params.set("Keyword", keyword);
  if (location) params.set("LocationName", location);
  params.set("ResultsPerPage", "10");
  return `${USAJOBS_SEARCH_PATH}?${params.toString()}`;
}

// --------------------
// Server
// --------------------
const server = http.createServer(request_handler);

server.listen(PORT, () => {
  console.log(`Now listening on http://localhost:${PORT}`);
  console.log("Redirect URI in use:", redirect_uri);
});

async function request_handler(req, res) {
  console.log(`${req.method} ${req.url}`);

  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // Only GET routes (simple and CS355-friendly)
  if (req.method !== "GET") {
    return sendText(res, 405, "Method Not Allowed");
  }

  // --------------------
  // Landing page (served from file)
  // IMPORTANT FIX: Your big landing HTML must live in ./html/index.html
  // Do NOT paste raw HTML after server.js ends.
  // --------------------
  if (pathname === "/") {
    const file = readFileSafe("./html/index.html");
    if (!file) return sendText(res, 500, "Missing ./html/index.html");
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(file);
  }

  // --------------------
  // About page (employer-facing)
  // --------------------
  if (pathname === "/about") {
    const html = `
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>About · Hiring Market Intelligence Radar</title>
      <style>
        :root{
          --bg0:#0b1220;--bg1:#0a1a2f;--card:rgba(255,255,255,.06);
          --border:rgba(255,255,255,.12);--text:#eaf2ff;--muted:rgba(234,242,255,.72);
          --accent:#6ea8fe;--shadow:0 18px 45px rgba(0,0,0,.35);--radius:18px;
        }
        *{box-sizing:border-box}
        body{
          margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;color:var(--text);
          min-height:100vh;
          background:
            radial-gradient(1200px 800px at 18% 18%, rgba(110,168,254,.22), transparent 55%),
            radial-gradient(900px 600px at 82% 28%, rgba(124,219,255,.14), transparent 60%),
            linear-gradient(180deg,var(--bg1),var(--bg0));
        }
        .wrap{max-width:980px;margin:0 auto;padding:26px 16px 44px}
        a{color:var(--accent);text-decoration:none}
        a:hover{text-decoration:underline}
        .card{
          border:1px solid var(--border);
          background:linear-gradient(180deg,var(--card),rgba(255,255,255,.03));
          border-radius:var(--radius);
          box-shadow:var(--shadow);
          padding:18px;
        }
        h1{margin:0 0 6px;font-size:26px}
        .muted{color:var(--muted)}
        code{background:rgba(255,255,255,.07);padding:2px 6px;border-radius:8px;border:1px solid rgba(255,255,255,.12)}
        ul{margin:10px 0 0 18px;color:var(--muted);line-height:1.5}
        .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
        .pill{font-size:12px;color:var(--muted);border:1px solid rgba(255,255,255,.12);padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.05)}
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
        @media(max-width:900px){.grid{grid-template-columns:1fr}}
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="top">
          <div class="pill">Employer Overview</div>
          <div>
            <a href="/">Home</a> · <a href="/connect">Connect</a> · <a href="/dashboard">Dashboard</a>
          </div>
        </div>

        <div class="card">
          <h1>Hiring Market Intelligence Radar</h1>
          <p class="muted">
            A portfolio-grade B2B analytics prototype that authenticates an admin via OAuth, queries public job data,
            and produces a simple demand/competition benchmark with caching and resilient HTTP handling.
          </p>

          <div class="grid">
            <div class="card" style="box-shadow:none">
              <h2 style="margin:0 0 6px;font-size:16px">OAuth flow (3-legged)</h2>
              <ul>
                <li><code>GET /connect</code> → redirect to OAuth provider</li>
                <li><code>GET /oauth/callback</code> → exchange code for access token</li>
                <li>Session stored server-side (cookie <code>sid</code>)</li>
              </ul>
            </div>

            <div class="card" style="box-shadow:none">
              <h2 style="margin:0 0 6px;font-size:16px">Data sources + endpoints</h2>
              <ul>
                <li><code>/api/market-trends</code> → normalized listings</li>
                <li><code>/api/benchmarks</code> → derived score + label</li>
                <li>Upstream source: USAJobs (server-to-server)</li>
              </ul>
            </div>

            <div class="card" style="box-shadow:none">
              <h2 style="margin:0 0 6px;font-size:16px">Caching</h2>
              <ul>
                <li>Market trends cached <b>15 minutes</b> (per session)</li>
                <li>Benchmarks cached <b>10 minutes</b> (per session)</li>
                <li>Reduces upstream calls and improves latency</li>
              </ul>
            </div>

            <div class="card" style="box-shadow:none">
              <h2 style="margin:0 0 6px;font-size:16px">Stale cache scenario</h2>
              <ul>
                <li>Job postings can change between cache refresh windows</li>
                <li>Mitigation: short TTLs + user-triggered refresh</li>
                <li>Extendable to conditional requests / ETags</li>
              </ul>
            </div>
          </div>

          <p class="muted" style="margin-top:12px">
            Security note: API keys and OAuth secrets are kept out of source control; production deploys use environment variables.
          </p>
        </div>
      </div>
    </body>
    </html>
    `;
    return sendHTML(res, 200, html);
  }

  // --------------------
  // OAuth: Connect (redirect to Google)
  // --------------------
  if (pathname === "/connect") {
    if (!client_id || !client_secret || !redirect_uri) {
      return sendText(res, 500, "Missing Google OAuth config (client_id/client_secret/redirect_uri)");
    }

    const state = base64url_random(24);
    oauth_state.set(state, { createdAt: now_ms() });

    const params = new url.URLSearchParams({
      client_id,
      redirect_uri,
      response_type: "code",
      scope: SCOPE,
      state,
      access_type: "online",
      prompt: "consent"
    });

    const location = `https://${AUTH_HOST}${AUTH_PATH}?${params.toString()}`;
    res.writeHead(302, { Location: location });
    return res.end();
  }

  // --------------------
  // OAuth callback: exchange code -> token
  // --------------------
  if (pathname === "/oauth/callback") {
    const code = parsed.query.code;
    const state = parsed.query.state;
    const error = parsed.query.error;

    if (error) return sendText(res, 401, `OAuth error: ${error}`);
    if (!code || !state) return sendText(res, 400, "Missing OAuth code or state");

    const entry = oauth_state.get(state);
    oauth_state.delete(state);
    if (!entry) return sendText(res, 403, "Invalid or expired state");
    if (now_ms() - entry.createdAt > 10 * 60 * 1000) return sendText(res, 403, "Expired state");

    const postBody = querystring.stringify({
      code,
      client_id,
      client_secret,
      redirect_uri,
      grant_type: "authorization_code"
    });

    const tokenResp = await httpsRequestJSON({
      host: TOKEN_HOST,
      path: TOKEN_PATH,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(postBody)
      },
      body: postBody
    });

    if (tokenResp.status !== 200 || !tokenResp.json || !tokenResp.json.access_token) {
      console.log("Token exchange failed:", tokenResp.status, tokenResp.raw);
      return sendText(res, 502, "Token exchange failed (see server logs)");
    }

    const sid = base64url_random(24);
    sessions.set(sid, {
      token: tokenResp.json,
      cache: new Map()
    });

    setCookie(res, "sid", sid, { maxAgeSec: 60 * 60 }); // 1 hour
    res.writeHead(302, { Location: "/dashboard" });
    return res.end();
  }

  // --------------------
  // Dashboard: dark themed employer-friendly UI (UNCHANGED)
  // --------------------
    // --------------------
  // Dashboard: upgraded animated UI (same functionality)
  // --------------------
  if (pathname === "/dashboard") {
    const cookies = parseCookies(req);
    const sid = cookies.sid;

    if (!sid || !sessions.has(sid)) {
      return sendHTML(
        res,
        401,
        `<h1>Not Connected</h1><p>You must <a href="/connect">connect your organization</a> first.</p>`
      );
    }

    const session = sessions.get(sid);

    // Fetch userinfo (cached 5 minutes)
    const uKey = "google:userinfo";
    let userinfo = cacheGet(session, uKey);

    if (!userinfo) {
      const userResp = await httpsRequestJSON({
        host: USERINFO_HOST,
        path: USERINFO_PATH,
        method: "GET",
        headers: {
          Authorization: `Bearer ${session.token.access_token}`,
          Accept: "application/json"
        }
      });

      if (userResp.status !== 200 || !userResp.json) {
        console.log("Userinfo failed:", userResp.status, userResp.raw);
        sessions.delete(sid);
        setCookie(res, "sid", "", { maxAgeSec: 0 });
        return sendHTML(
          res,
          401,
          `<h1>Authorization expired</h1><p>Please <a href="/connect">connect again</a>.</p>`
        );
      }

      userinfo = userResp.json;
      cacheSet(session, uKey, userinfo, 5 * 60 * 1000);
    }

    const email = userinfo.email || "(no email)";
    const domain =
      typeof email === "string" && email.includes("@") ? email.split("@")[1] : "(unknown)";
    const userName =
      userinfo.name ||
      (typeof email === "string" && email.includes("@") ? email.split("@")[0] : "User");

    const avatarLetter = escapeHtml((userName || "U").charAt(0).toUpperCase());

    const html = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Dashboard · Hiring Radar</title>

  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    :root{
      --bg0:#070A14;
      --bg1:#0B1023;
      --card:rgba(255,255,255,.06);
      --card2:rgba(255,255,255,.04);
      --stroke:rgba(255,255,255,.12);
      --stroke2:rgba(255,255,255,.08);
      --text:#F5F7FF;
      --muted:rgba(245,247,255,.68);

      --a:#7C5CFF;     /* purple */
      --b:#22D3EE;     /* cyan */
      --c:#34D399;     /* green */
      --d:#FB7185;     /* pink */
      --e:#FBBF24;     /* amber */

      --shadow:0 22px 60px rgba(0,0,0,.55);
      --shadow2:0 12px 30px rgba(0,0,0,.45);
      --r:18px;
      --r2:14px;
    }

    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0;
      font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      color:var(--text);
      background: radial-gradient(1200px 800px at 18% 18%, rgba(124,92,255,.18), transparent 55%),
                  radial-gradient(1000px 700px at 85% 30%, rgba(34,211,238,.14), transparent 55%),
                  radial-gradient(900px 650px at 70% 90%, rgba(52,211,153,.10), transparent 55%),
                  linear-gradient(180deg, var(--bg1), var(--bg0));
      overflow-x:hidden;
    }

    /* animated blobs */
    .blob{
      position:fixed; inset:auto;
      width:520px; height:520px;
      filter: blur(34px);
      opacity:.30;
      z-index:0;
      animation: drift 18s ease-in-out infinite;
      border-radius: 999px;
      pointer-events:none;
    }
    .blob.one{left:-140px; top:-160px; background:radial-gradient(circle at 30% 30%, rgba(124,92,255,.95), transparent 60%);}
    .blob.two{right:-160px; top:40px; background:radial-gradient(circle at 30% 30%, rgba(34,211,238,.95), transparent 60%); animation-delay:-6s;}
    .blob.three{left:40%; bottom:-220px; background:radial-gradient(circle at 30% 30%, rgba(52,211,153,.95), transparent 60%); animation-delay:-10s;}
    @keyframes drift{
      0%,100%{transform:translate(0,0) scale(1) rotate(0deg)}
      33%{transform:translate(26px,-18px) scale(1.05) rotate(6deg)}
      66%{transform:translate(-22px,16px) scale(.98) rotate(-6deg)}
    }

    /* subtle noise overlay */
    .noise{
      position:fixed; inset:0;
      background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 400 400' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.05'/%3E%3C/svg%3E");
      pointer-events:none;
      z-index:1;
    }

    a{color:inherit}
    .app{
      position:relative;
      z-index:2;
      min-height:100%;
      display:flex;
    }

    /* Sidebar (Dribbble-ish) */
    .sidebar{
      width:300px;
      padding:22px 18px;
      border-right:1px solid var(--stroke2);
      background:linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      backdrop-filter: blur(14px);
    }
    .brand{
      display:flex; align-items:center; gap:12px;
      padding:10px 10px 18px;
      border-bottom:1px solid var(--stroke2);
      margin-bottom:16px;
    }
    .mark{
      width:38px; height:38px; border-radius:12px;
      background: linear-gradient(135deg, var(--a), var(--b));
      box-shadow: 0 10px 30px rgba(124,92,255,.25);
      position:relative;
      overflow:hidden;
    }
    .mark:before{
      content:"";
      position:absolute; inset:-30%;
      background: linear-gradient(45deg, transparent, rgba(255,255,255,.35), transparent);
      transform: translateX(-60%);
      animation: sheen 3.4s ease-in-out infinite;
    }
    @keyframes sheen{
      0%{transform:translateX(-60%) rotate(15deg)}
      55%{transform:translateX(60%) rotate(15deg)}
      100%{transform:translateX(60%) rotate(15deg)}
    }
    .brand h1{
      margin:0;
      font-size:15px;
      letter-spacing:.2px;
    }
    .brand p{
      margin:2px 0 0;
      font-size:12px;
      color:var(--muted);
    }

    .nav{
      display:flex;
      flex-direction:column;
      gap:10px;
      margin-top:14px;
    }
    .nav a{
      text-decoration:none;
      padding:11px 12px;
      border-radius:12px;
      border:1px solid transparent;
      color:var(--muted);
      display:flex; align-items:center; gap:10px;
      transition: transform .18s ease, background .18s ease, border-color .18s ease, color .18s ease;
    }
    .nav a:hover{
      background: rgba(255,255,255,.06);
      border-color: var(--stroke2);
      color: var(--text);
      transform: translateY(-1px);
    }
    .nav a.active{
      background: linear-gradient(135deg, rgba(124,92,255,.18), rgba(34,211,238,.10));
      border-color: rgba(124,92,255,.28);
      color: var(--text);
    }
    .nav svg{width:16px;height:16px;opacity:.9}

    .sidebarCard{
      margin-top:16px;
      padding:14px;
      border-radius:16px;
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
      border:1px solid var(--stroke2);
      box-shadow: var(--shadow2);
    }
    .sidebarCard .row{
      display:flex; align-items:center; justify-content:space-between;
      margin-bottom:10px;
    }
    .pill{
      font-size:11px;
      letter-spacing:.4px;
      text-transform:uppercase;
      padding:5px 10px;
      border-radius:999px;
      border:1px solid rgba(52,211,153,.25);
      background: rgba(52,211,153,.10);
      color: rgba(52,211,153,.95);
    }
    .userBox{
      display:flex; gap:10px; align-items:center;
      padding-top:10px;
      border-top:1px solid var(--stroke2);
      margin-top:12px;
    }
    .avatar{
      width:40px; height:40px; border-radius:14px;
      background: linear-gradient(135deg, rgba(251,113,133,.95), rgba(124,92,255,.75));
      display:flex; align-items:center; justify-content:center;
      font-weight:800;
      box-shadow: 0 16px 36px rgba(251,113,133,.18);
    }
    .uName{font-size:13px;font-weight:700;margin:0}
    .uMeta{font-size:12px;color:var(--muted);margin:2px 0 0; word-break:break-all}

    /* Main */
    .main{
      flex:1;
      padding:22px 26px 36px;
    }

    .topbar{
      display:flex; align-items:center; justify-content:space-between;
      gap:14px;
      padding:12px 12px 16px;
      border-bottom: 1px solid var(--stroke2);
      backdrop-filter: blur(10px);
    }
    .title h2{
      margin:0;
      font-size:22px;
      letter-spacing:-.2px;
    }
    .title p{margin:6px 0 0; color:var(--muted); font-size:13px}

    .actions{
      display:flex; gap:10px; align-items:center;
    }
    .chip{
      padding:10px 12px;
      border-radius:14px;
      border:1px solid var(--stroke2);
      background: rgba(255,255,255,.04);
      color: var(--muted);
      font-size:12px;
      display:flex; align-items:center; gap:8px;
    }
    .chip b{color:var(--text); font-weight:700}
    .btnLink{
      text-decoration:none;
      padding:10px 12px;
      border-radius:14px;
      border:1px solid rgba(124,92,255,.28);
      background: linear-gradient(135deg, rgba(124,92,255,.18), rgba(34,211,238,.08));
      box-shadow: 0 14px 40px rgba(124,92,255,.16);
      transition: transform .18s ease, filter .18s ease;
      font-size:12px;
      font-weight:700;
    }
    .btnLink:hover{transform: translateY(-1px); filter: brightness(1.05);}

    /* Cards grid */
    .grid{
      margin-top:18px;
      display:grid;
      grid-template-columns: 1.15fr .85fr;
      gap:16px;
    }
    @media(max-width:1100px){
      .sidebar{display:none}
      .grid{grid-template-columns:1fr}
      .main{padding:18px}
    }

    .card{
      border-radius: var(--r);
      border:1px solid var(--stroke2);
      background: linear-gradient(180deg, var(--card), var(--card2));
      box-shadow: var(--shadow2);
      overflow:hidden;
      position:relative;
      transform: translateY(0);
      transition: transform .18s ease, border-color .18s ease, box-shadow .18s ease;
      animation: rise .55s ease both;
    }
    @keyframes rise{from{opacity:0; transform: translateY(10px)} to{opacity:1; transform: translateY(0)}}
    .card:hover{
      transform: translateY(-2px);
      border-color: rgba(124,92,255,.25);
      box-shadow: var(--shadow);
    }

    .cardHead{
      padding:16px 16px 12px;
      display:flex; align-items:center; justify-content:space-between;
      gap:10px;
      border-bottom:1px solid var(--stroke2);
    }
    .cardHead h3{margin:0; font-size:14px; letter-spacing:.1px}
    .hint{font-size:12px;color:var(--muted)}

    .cardBody{padding:16px}

    /* Form */
    .fieldRow{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:12px;
      margin-bottom:12px;
    }
    @media(max-width:720px){.fieldRow{grid-template-columns:1fr}}

    .field label{
      display:block;
      font-size:12px;
      color:var(--muted);
      margin:0 0 8px 2px;
      font-weight:600;
    }
    .input{
      width:100%;
      padding:12px 12px;
      border-radius:14px;
      border:1px solid var(--stroke2);
      background: rgba(0,0,0,.22);
      color: var(--text);
      outline:none;
      transition: border-color .18s ease, box-shadow .18s ease, transform .18s ease;
    }
    .input:focus{
      border-color: rgba(34,211,238,.40);
      box-shadow: 0 0 0 4px rgba(34,211,238,.12);
    }

    .btnRow{
      display:grid;
      grid-template-columns:1fr 1fr 1fr;
      gap:10px;
      margin-top:12px;
    }
    @media(max-width:720px){.btnRow{grid-template-columns:1fr}}

    .btn{
      padding:12px 12px;
      border-radius:14px;
      border:1px solid var(--stroke2);
      background: rgba(255,255,255,.04);
      color: var(--text);
      cursor:pointer;
      font-weight:800;
      font-size:13px;
      letter-spacing:.15px;
      display:flex; align-items:center; justify-content:center; gap:10px;
      transition: transform .18s ease, filter .18s ease, border-color .18s ease, background .18s ease;
      position:relative;
      overflow:hidden;
    }
    .btn:hover{transform: translateY(-1px); border-color: rgba(255,255,255,.18)}
    .btn:active{transform: translateY(0px) scale(.99)}
    .btn svg{width:16px;height:16px;opacity:.95}

    .btnPrimary{
      border-color: rgba(124,92,255,.35);
      background: linear-gradient(135deg, rgba(124,92,255,.30), rgba(34,211,238,.14));
      box-shadow: 0 18px 50px rgba(124,92,255,.18);
    }
    .btnPrimary:before{
      content:"";
      position:absolute; inset:-60%;
      background: linear-gradient(45deg, transparent, rgba(255,255,255,.22), transparent);
      transform: translateX(-40%);
      transition: transform .25s ease;
    }
    .btnPrimary:hover:before{transform: translateX(40%);}

    .btnGhost{
      color: var(--muted);
    }

    /* Output panels */
    .two{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:12px;
      margin-top:14px;
    }
    @media(max-width:900px){.two{grid-template-columns:1fr}}

    .panel{
      border-radius: 16px;
      border:1px solid var(--stroke2);
      background: rgba(0,0,0,.22);
      overflow:hidden;
    }
    .panelTop{
      display:flex; align-items:center; justify-content:space-between;
      padding:10px 12px;
      border-bottom:1px solid var(--stroke2);
      color: var(--muted);
      font-size:12px;
      font-weight:700;
      letter-spacing:.2px;
    }
    .panelTop .tag{
      font-size:11px;
      padding:4px 10px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.04);
      color: var(--muted);
    }

    pre{
      margin:0;
      padding:12px;
      max-height:420px;
      overflow:auto;
      color: rgba(245,247,255,.78);
      font-size:12px;
      line-height:1.55;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }
    pre::-webkit-scrollbar{width:10px}
    pre::-webkit-scrollbar-track{background:rgba(0,0,0,.25)}
    pre::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12); border-radius:999px; border:2px solid rgba(0,0,0,.2)}

    /* Skeleton loading */
    .skeleton{
      position:relative;
      color: transparent !important;
      background: rgba(255,255,255,.06);
      border-radius: 12px;
      overflow:hidden;
    }
    .skeleton:after{
      content:"";
      position:absolute; inset:-40% -60%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,.18), transparent);
      animation: shimmer 1.2s linear infinite;
      transform: skewX(-12deg);
    }
    @keyframes shimmer{to{transform: translateX(60%) skewX(-12deg)}}

    /* Toast */
    .toast{
      position:fixed;
      right:18px; bottom:18px;
      z-index:999;
      display:flex; align-items:center; gap:10px;
      padding:12px 14px;
      border-radius:16px;
      border:1px solid var(--stroke2);
      background: rgba(10,14,26,.70);
      backdrop-filter: blur(12px);
      box-shadow: var(--shadow2);
      opacity:0;
      transform: translateY(12px);
      transition: opacity .22s ease, transform .22s ease;
    }
    .toast.show{opacity:1; transform: translateY(0)}
    .dot{
      width:10px; height:10px; border-radius:999px;
      background: radial-gradient(circle at 30% 30%, rgba(34,211,238,1), rgba(124,92,255,1));
      box-shadow: 0 0 0 6px rgba(34,211,238,.08);
      animation: pulse 1.4s ease-in-out infinite;
    }
    @keyframes pulse{0%,100%{transform:scale(1); opacity:1} 50%{transform:scale(1.2); opacity:.7}}
    .toast span{font-size:12px;color:rgba(245,247,255,.85); font-weight:700}

  </style>
</head>

<body>
  <div class="blob one"></div>
  <div class="blob two"></div>
  <div class="blob three"></div>
  <div class="noise"></div>

  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <div class="mark"></div>
        <div>
          <h1>Hiring Radar</h1>
          <p>Market Intelligence Suite</p>
        </div>
      </div>

      <nav class="nav">
        <a class="active" href="/dashboard">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>
          Dashboard
        </a>
        <a href="/about">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M11 17h2v-6h-2v6zm0-8h2V7h-2v2zm1-7C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/></svg>
          About
        </a>
        <a href="/">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>
          Home
        </a>
        <a href="/logout">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 13v-2H7V8l-5 4 5 4v-3h9zm3-10H11c-1.1 0-2 .9-2 2v4h2V5h8v14h-8v-4H9v4c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
          Sign Out
        </a>
      </nav>

      <div class="sidebarCard">
        <div class="row">
          <div style="font-weight:800">Organization</div>
          <div class="pill">Connected</div>
        </div>
        <div style="color:var(--muted);font-size:12px;line-height:1.5">
          Admin session secured via OAuth 2.0 with TTL caching for market calls.
        </div>

        <div class="userBox">
          <div class="avatar">${avatarLetter}</div>
          <div>
            <p class="uName">${escapeHtml(userName)}</p>
            <p class="uMeta">${escapeHtml(email)}</p>
            <p class="uMeta" style="margin-top:6px"><b style="color:var(--text)">Org:</b> ${escapeHtml(domain)}</p>
          </div>
        </div>
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <div class="title">
          <h2>Market Intelligence Dashboard</h2>
          <p>Query USAJOBS and compute lightweight benchmarks with resilient server-side caching.</p>
        </div>
        <div class="actions">
          <div class="chip">
            Cache <b>15m</b> Trends · <b>10m</b> Bench
          </div>
          <a class="btnLink" href="/about">Docs</a>
        </div>
      </div>

      <section class="grid">
        <div class="card" style="animation-delay:.02s">
          <div class="cardHead">
            <h3>Market Query</h3>
            <div class="hint">Live upstream • cached per session</div>
          </div>

          <div class="cardBody">
            <div class="fieldRow">
              <div class="field">
                <label>Keyword</label>
                <input class="input" id="kw" value="software engineer" placeholder="e.g., data analyst, network engineer" />
              </div>
              <div class="field">
                <label>Location</label>
                <input class="input" id="loc" value="New York" placeholder="e.g., New York, Remote, San Francisco" />
              </div>
            </div>

            <div class="btnRow">
              <button class="btn btnPrimary" id="run">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/></svg>
                Market Trends
              </button>

              <button class="btn btnPrimary" id="bench">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
                Benchmarks
              </button>

              <button class="btn btnGhost" id="clear">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 9v10H8V9h8m-1.5-6h-5l-1 1H5v2h14V4h-4.5l-1-1z"/></svg>
                Clear
              </button>
            </div>

            <div class="two">
              <div class="panel">
                <div class="panelTop">
                  <div>Market Trends</div>
                  <div class="tag" id="tag1">idle</div>
                </div>
                <pre id="out">(results will appear here)</pre>
              </div>

              <div class="panel">
                <div class="panelTop">
                  <div>Benchmarks</div>
                  <div class="tag" id="tag2">idle</div>
                </div>
                <pre id="bout">(benchmarks will appear here)</pre>
              </div>
            </div>
          </div>
        </div>

        <div class="card" style="animation-delay:.08s">
          <div class="cardHead">
            <h3>Session Summary</h3>
            <div class="hint">Identity + quick status</div>
          </div>
          <div class="cardBody" style="color:var(--muted); font-size:13px; line-height:1.6">
            <div style="display:grid; gap:10px">
              <div style="padding:12px;border-radius:16px;border:1px solid var(--stroke2);background:rgba(0,0,0,.22)">
                <div style="font-weight:800;color:var(--text);margin-bottom:4px">Admin</div>
                <div>${escapeHtml(userName)} · ${escapeHtml(domain)}</div>
              </div>

              <div style="padding:12px;border-radius:16px;border:1px solid var(--stroke2);background:rgba(0,0,0,.22)">
                <div style="font-weight:800;color:var(--text);margin-bottom:4px">Resilience</div>
                <div>Non-existent routes return explicit 404 responses. Upstream failures return 502 with logs.</div>
              </div>

              <div style="padding:12px;border-radius:16px;border:1px solid var(--stroke2);background:rgba(0,0,0,.22)">
                <div style="font-weight:800;color:var(--text);margin-bottom:4px">Caching</div>
                <div>Trends TTL: 15 minutes · Benchmarks TTL: 10 minutes · Userinfo TTL: 5 minutes</div>
              </div>

              <div style="padding:12px;border-radius:16px;border:1px solid var(--stroke2);background:rgba(0,0,0,.22)">
                <div style="font-weight:800;color:var(--text);margin-bottom:4px">Tip</div>
                <div>Try keywords like “cybersecurity”, “data scientist”, “network engineer”, and locations like “Remote”.</div>
              </div>
            </div>
          </div>
        </div>

      </section>
    </main>
  </div>

  <div class="toast" id="toast"><div class="dot"></div><span id="toastText">Loading…</span></div>

  <script>
    const out = document.getElementById("out");
    const bout = document.getElementById("bout");
    const toast = document.getElementById("toast");
    const toastText = document.getElementById("toastText");
    const tag1 = document.getElementById("tag1");
    const tag2 = document.getElementById("tag2");

    function showToast(msg){
      toastText.textContent = msg;
      toast.classList.add("show");
      window.clearTimeout(showToast._t);
      showToast._t = window.setTimeout(() => toast.classList.remove("show"), 2000);
    }

    function readInputs(){
      const kw = encodeURIComponent(document.getElementById("kw").value.trim());
      const loc = encodeURIComponent(document.getElementById("loc").value.trim());
      return { kw, loc };
    }

    function setLoading(preEl, whichTag){
      preEl.classList.add("skeleton");
      preEl.textContent = "Loading…";
      whichTag.textContent = "loading";
    }

    function setDone(preEl, whichTag, ok){
      preEl.classList.remove("skeleton");
      whichTag.textContent = ok ? "done" : "error";
    }

    async function runEndpoint(endpoint, targetPre, whichTag){
      showToast("Fetching data…");
      setLoading(targetPre, whichTag);
      try{
        const resp = await fetch(endpoint);
        const text = await resp.text();
        targetPre.textContent = text;
        setDone(targetPre, whichTag, resp.ok);
        showToast(resp.ok ? "Complete" : ("Error: " + resp.status));
      }catch(e){
        targetPre.textContent = String(e);
        setDone(targetPre, whichTag, false);
        showToast("Network error");
      }
    }

    document.getElementById("run").addEventListener("click", async () => {
      const { kw, loc } = readInputs();
      const endpoint = \`/api/market-trends?keyword=\${kw}&location=\${loc}\`;
      await runEndpoint(endpoint, out, tag1);
    });

    document.getElementById("bench").addEventListener("click", async () => {
      const { kw, loc } = readInputs();
      const endpoint = \`/api/benchmarks?keyword=\${kw}&location=\${loc}\`;
      await runEndpoint(endpoint, bout, tag2);
    });

    document.getElementById("clear").addEventListener("click", () => {
      out.classList.remove("skeleton");
      bout.classList.remove("skeleton");
      out.textContent = "(cleared)";
      bout.textContent = "(cleared)";
      tag1.textContent = "idle";
      tag2.textContent = "idle";
      showToast("Cleared");
    });
  </script>
</body>
</html>
    `;
    return sendHTML(res, 200, html);
  }


  // --------------------
  // Logout (FIX: this route existed in UI but not in server before)
  // --------------------
  if (pathname === "/logout") {
    const cookies = parseCookies(req);
    const sid = cookies.sid;
    if (sid) sessions.delete(sid);
    setCookie(res, "sid", "", { maxAgeSec: 0 });
    res.writeHead(302, { Location: "/" });
    return res.end();
  }

  // --------------------
  // API: Market Trends (FIX: missing endpoint caused 404)
  // --------------------
  if (pathname === "/api/market-trends") {
    const cookies = parseCookies(req);
    const sid = cookies.sid;

    if (!sid || !sessions.has(sid)) {
      return sendJSON(res, 401, { error: "Not connected. Visit /connect first." });
    }

    if (!USAJOBS_AUTH_KEY || !USAJOBS_USER_AGENT) {
      return sendJSON(res, 500, { error: "Missing USAJOBS config (AUTH_KEY / USER_AGENT)." });
    }

    const session = sessions.get(sid);

    const keywordRaw = (parsed.query.keyword || "").toString().trim();
    const locationRaw = (parsed.query.location || "").toString().trim();

    if (!keywordRaw) {
      return sendJSON(res, 400, { error: "Missing required query param: keyword" });
    }

    const cacheKey = `usajobs:market:${keywordRaw.toLowerCase()}|${locationRaw.toLowerCase()}`;
    const cached = cacheGet(session, cacheKey);
    if (cached) {
      return sendJSON(res, 200, { ...cached, cache: "HIT" });
    }

    const upstreamPath = buildUSAJobsSearchPath(keywordRaw, locationRaw);

    const upstream = await httpsRequestJSON({
      host: USAJOBS_HOST,
      path: upstreamPath,
      method: "GET",
      headers: {
        Host: USAJOBS_HOST,
        "User-Agent": USAJOBS_USER_AGENT,
        "Authorization-Key": USAJOBS_AUTH_KEY,
        Accept: "application/json"
      }
    });

    if (upstream.status !== 200 || !upstream.json) {
      console.log("USAJOBS error:", upstream.status, upstream.raw);
      return sendJSON(res, 502, { error: "Upstream USAJOBS request failed", status: upstream.status });
    }

    const sr = upstream.json.SearchResult || {};
    const items = Array.isArray(sr.SearchResultItems) ? sr.SearchResultItems : [];
    const total = Number(sr.SearchResultCountAll || 0);

    const normalized = items.map((it) => {
      const d = it && it.MatchedObjectDescriptor ? it.MatchedObjectDescriptor : {};
      const pos = d.PositionLocation && Array.isArray(d.PositionLocation) ? d.PositionLocation : [];
      const locs = pos.map((p) => (p && p.LocationName ? p.LocationName : null)).filter(Boolean);

      return {
        positionTitle: d.PositionTitle || "",
        organizationName: d.OrganizationName || "",
        departmentName: d.DepartmentName || "",
        applyURI: Array.isArray(d.ApplyURI) ? d.ApplyURI[0] : d.ApplyURI || "",
        url: d.PositionURI || "",
        locations: locs,
        publicationStartDate: d.PublicationStartDate || "",
        applicationCloseDate: d.ApplicationCloseDate || ""
      };
    });

    const payload = {
      keyword: keywordRaw,
      location: locationRaw,
      totalResults: total,
      returned: normalized.length,
      results: normalized,
      ttlSeconds: 15 * 60
    };

    cacheSet(session, cacheKey, payload, 15 * 60 * 1000);
    return sendJSON(res, 200, { ...payload, cache: "MISS" });
  }

  // --------------------
  // API: Benchmarks (FIX: missing endpoint caused 404)
  // --------------------
  if (pathname === "/api/benchmarks") {
    const cookies = parseCookies(req);
    const sid = cookies.sid;

    if (!sid || !sessions.has(sid)) {
      return sendJSON(res, 401, { error: "Not connected. Visit /connect first." });
    }

    if (!USAJOBS_AUTH_KEY || !USAJOBS_USER_AGENT) {
      return sendJSON(res, 500, { error: "Missing USAJOBS config (AUTH_KEY / USER_AGENT)." });
    }

    const session = sessions.get(sid);

    const keywordRaw = (parsed.query.keyword || "").toString().trim();
    const locationRaw = (parsed.query.location || "").toString().trim();

    if (!keywordRaw) {
      return sendJSON(res, 400, { error: "Missing required query param: keyword" });
    }

    const cacheKey = `bench:${keywordRaw.toLowerCase()}|${locationRaw.toLowerCase()}`;
    const cached = cacheGet(session, cacheKey);
    if (cached) {
      return sendJSON(res, 200, { ...cached, cache: "HIT" });
    }

    const upstreamPath = buildUSAJobsSearchPath(keywordRaw, locationRaw);

    const upstream = await httpsRequestJSON({
      host: USAJOBS_HOST,
      path: upstreamPath,
      method: "GET",
      headers: {
        Host: USAJOBS_HOST,
        "User-Agent": USAJOBS_USER_AGENT,
        "Authorization-Key": USAJOBS_AUTH_KEY,
        Accept: "application/json"
      }
    });

    if (upstream.status !== 200 || !upstream.json) {
      console.log("USAJOBS error:", upstream.status, upstream.raw);
      return sendJSON(res, 502, { error: "Upstream USAJOBS request failed", status: upstream.status });
    }

    const sr = upstream.json.SearchResult || {};
    const items = Array.isArray(sr.SearchResultItems) ? sr.SearchResultItems : [];
    const total = Number(sr.SearchResultCountAll || 0);

    const orgs = new Set();
    const locations = new Set();

    for (const it of items) {
      const d = it && it.MatchedObjectDescriptor ? it.MatchedObjectDescriptor : {};
      if (d.OrganizationName) orgs.add(d.OrganizationName);

      const pos = d.PositionLocation && Array.isArray(d.PositionLocation) ? d.PositionLocation : [];
      for (const p of pos) {
        if (p && p.LocationName) locations.add(p.LocationName);
      }
    }

    const demandScore = Math.min(100, Math.round((total / 200) * 100));
    let competitionLabel = "Low";
    if (total >= 100) competitionLabel = "High";
    else if (total >= 30) competitionLabel = "Medium";

    const payload = {
      keyword: keywordRaw,
      location: locationRaw,
      totalResults: total,
      uniqueOrganizationsInTop10: orgs.size,
      uniqueLocationsInTop10: locations.size,
      demandScore,
      competitionLabel,
      ttlSeconds: 10 * 60
    };

    cacheSet(session, cacheKey, payload, 10 * 60 * 1000);
    return sendJSON(res, 200, { ...payload, cache: "MISS" });
  }

  // --------------------
  // Default: resilient 404
  // --------------------
  return send404(req, res);
}
