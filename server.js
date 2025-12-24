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
  // REPLACE the entire /dashboard route handler (starting from line ~280)
// Find: if (pathname === "/dashboard") {
// Replace the entire HTML string with this enhanced version:

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
  const domain = typeof email === "string" && email.includes("@") ? email.split("@")[1] : "(unknown)";
  const userName = userinfo.name || (typeof email === "string" && email.includes("@") ? email.split("@")[0] : "User");
  const avatarLetter = escapeHtml((userName || "U").charAt(0).toUpperCase());

  const html = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Intelligence Dashboard · Hiring Radar</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  
  <style>
    :root{
      --bg:#000000;
      --bg-secondary:#0a0a0a;
      --card:rgba(255,255,255,0.03);
      --stroke:rgba(255,255,255,0.1);
      --text:#ffffff;
      --text-secondary:#a1a1aa;
      --purple:#a855f7;
      --purple-light:#c084fc;
      --blue:#3b82f6;
      --cyan:#06b6d4;
      --green:#10b981;
      --pink:#ec4899;
      --orange:#f97316;
    }
    
    *{box-sizing:border-box;margin:0;padding:0}
    
    body{
      font-family:'Inter',system-ui,sans-serif;
      background:var(--bg);
      color:var(--text);
      overflow-x:hidden;
      line-height:1.6;
    }
    
    /* Animated Grid */
    .grid-bg{
      position:fixed;
      inset:0;
      background-image:
        linear-gradient(to right, rgba(168,85,247,0.08) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(168,85,247,0.08) 1px, transparent 1px);
      background-size:60px 60px;
      animation:grid-move 25s linear infinite;
      z-index:0;
    }
    
    @keyframes grid-move{
      0%{background-position:0 0}
      100%{background-position:60px 60px}
    }
    
    /* Gradient Orbs */
    .orb{
      position:fixed;
      border-radius:50%;
      filter:blur(120px);
      opacity:0.4;
      animation:float-orb 25s ease-in-out infinite;
      z-index:0;
      pointer-events:none;
    }
    
    .orb-1{
      width:500px;height:500px;
      background:radial-gradient(circle, var(--purple), transparent 70%);
      top:-200px;left:-150px;
    }
    
    .orb-2{
      width:450px;height:450px;
      background:radial-gradient(circle, var(--blue), transparent 70%);
      top:30%;right:-100px;
      animation-delay:8s;
    }
    
    .orb-3{
      width:400px;height:400px;
      background:radial-gradient(circle, var(--cyan), transparent 70%);
      bottom:-150px;left:25%;
      animation-delay:15s;
    }
    
    @keyframes float-orb{
      0%,100%{transform:translate(0,0) scale(1)}
      33%{transform:translate(40px,-30px) scale(1.08)}
      66%{transform:translate(-30px,25px) scale(0.95)}
    }
    
    /* Layout */
    .app{
      position:relative;
      z-index:1;
      display:flex;
      min-height:100vh;
    }
    
    .sidebar{
      width:300px;
      border-right:1px solid var(--stroke);
      background:rgba(0,0,0,0.4);
      backdrop-filter:blur(20px);
      padding:24px;
      position:sticky;
      top:0;
      height:100vh;
      overflow-y:auto;
    }
    
    .brand{
      display:flex;
      align-items:center;
      gap:12px;
      padding-bottom:24px;
      border-bottom:1px solid var(--stroke);
      margin-bottom:24px;
    }
    
    .logo-icon{
      width:42px;height:42px;
      background:linear-gradient(135deg, var(--purple), var(--blue));
      border-radius:12px;
      display:flex;
      align-items:center;
      justify-content:center;
      box-shadow:0 0 40px rgba(168,85,247,0.6);
      animation:pulse-glow 3s ease-in-out infinite;
      position:relative;
      overflow:hidden;
    }
    
    @keyframes pulse-glow{
      0%,100%{box-shadow:0 0 40px rgba(168,85,247,0.6)}
      50%{box-shadow:0 0 60px rgba(168,85,247,0.9), 0 0 90px rgba(59,130,246,0.5)}
    }
    
    .logo-icon::before{
      content:'';
      position:absolute;
      inset:-40%;
      background:linear-gradient(45deg, transparent, rgba(255,255,255,0.4), transparent);
      transform:translateX(-60%);
      animation:sheen 3.5s ease-in-out infinite;
    }
    
    @keyframes sheen{
      0%{transform:translateX(-60%) rotate(15deg)}
      60%{transform:translateX(60%) rotate(15deg)}
      100%{transform:translateX(60%) rotate(15deg)}
    }
    
    .brand-text h1{
      font-size:16px;
      font-weight:800;
      background:linear-gradient(135deg, var(--purple-light), var(--blue));
      -webkit-background-clip:text;
      -webkit-text-fill-color:transparent;
      background-clip:text;
    }
    
    .brand-text p{
      font-size:12px;
      color:var(--text-secondary);
      margin-top:2px;
    }
    
    /* Navigation */
    .nav{
      display:flex;
      flex-direction:column;
      gap:8px;
    }
    
    .nav a{
      display:flex;
      align-items:center;
      gap:12px;
      padding:12px 14px;
      border-radius:12px;
      color:var(--text-secondary);
      text-decoration:none;
      font-size:14px;
      font-weight:600;
      transition:all .3s;
      position:relative;
      overflow:hidden;
    }
    
    .nav a::before{
      content:'';
      position:absolute;
      inset:0;
      background:linear-gradient(135deg, rgba(168,85,247,0.15), rgba(59,130,246,0.1));
      opacity:0;
      transition:opacity .3s;
    }
    
    .nav a:hover::before,
    .nav a.active::before{
      opacity:1;
    }
    
    .nav a:hover,
    .nav a.active{
      color:var(--text);
      border-color:rgba(168,85,247,0.3);
      transform:translateX(4px);
    }
    
    .nav svg{
      width:18px;
      height:18px;
      position:relative;
      z-index:1;
    }
    
    .nav span{
      position:relative;
      z-index:1;
    }
    
    /* User Card */
    .user-card{
      margin-top:24px;
      padding:16px;
      border-radius:16px;
      background:rgba(255,255,255,0.03);
      border:1px solid var(--stroke);
      transition:all .3s;
    }
    
    .user-card:hover{
      border-color:rgba(168,85,247,0.4);
      box-shadow:0 10px 40px rgba(168,85,247,0.2);
    }
    
    .status-badge{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:6px 12px;
      border-radius:20px;
      background:rgba(16,185,129,0.15);
      border:1px solid rgba(16,185,129,0.3);
      font-size:11px;
      font-weight:700;
      color:var(--green);
      margin-bottom:12px;
    }
    
    .status-dot{
      width:6px;
      height:6px;
      background:var(--green);
      border-radius:50%;
      animation:pulse-dot 2s ease-in-out infinite;
    }
    
    @keyframes pulse-dot{
      0%,100%{opacity:1;transform:scale(1)}
      50%{opacity:0.6;transform:scale(1.4)}
    }
    
    .user-info{
      display:flex;
      align-items:center;
      gap:12px;
      padding-top:12px;
      border-top:1px solid var(--stroke);
    }
    
    .avatar{
      width:44px;
      height:44px;
      border-radius:12px;
      background:linear-gradient(135deg, var(--pink), var(--purple));
      display:flex;
      align-items:center;
      justify-content:center;
      font-size:18px;
      font-weight:900;
      box-shadow:0 10px 30px rgba(236,72,153,0.4);
    }
    
    .user-details{
      flex:1;
      min-width:0;
    }
    
    .user-name{
      font-size:13px;
      font-weight:700;
      margin-bottom:2px;
    }
    
    .user-email{
      font-size:11px;
      color:var(--text-secondary);
      overflow:hidden;
      text-overflow:ellipsis;
      white-space:nowrap;
    }
    
    .user-org{
      font-size:11px;
      color:var(--text-secondary);
      margin-top:4px;
    }
    
    .user-org strong{
      color:var(--purple-light);
      font-weight:700;
    }
    
    /* Main Content */
    .main{
      flex:1;
      padding:32px;
      max-width:1400px;
    }
    
    .header{
      margin-bottom:32px;
    }
    
    .header-top{
      display:flex;
      align-items:center;
      justify-content:space-between;
      margin-bottom:12px;
    }
    
    h2{
      font-size:32px;
      font-weight:900;
      background:linear-gradient(135deg, var(--purple-light), var(--blue), var(--cyan));
      -webkit-background-clip:text;
      -webkit-text-fill-color:transparent;
      background-clip:text;
      background-size:200%;
      animation:gradient-shift 5s ease infinite;
    }
    
    @keyframes gradient-shift{
      0%,100%{background-position:0% 50%}
      50%{background-position:100% 50%}
    }
    
    .header-actions{
      display:flex;
      gap:12px;
      align-items:center;
    }
    
    .chip{
      padding:10px 16px;
      border-radius:12px;
      background:rgba(255,255,255,0.05);
      border:1px solid var(--stroke);
      font-size:12px;
      font-weight:600;
      color:var(--text-secondary);
      display:flex;
      align-items:center;
      gap:8px;
    }
    
    .chip strong{
      color:var(--purple-light);
    }
    
    .btn-link{
      padding:10px 20px;
      border-radius:12px;
      background:linear-gradient(135deg, rgba(168,85,247,0.2), rgba(59,130,246,0.15));
      border:1px solid rgba(168,85,247,0.4);
      color:var(--text);
      text-decoration:none;
      font-size:13px;
      font-weight:700;
      transition:all .3s;
    }
    
    .btn-link:hover{
      transform:translateY(-2px);
      box-shadow:0 10px 30px rgba(168,85,247,0.4);
      border-color:rgba(168,85,247,0.6);
    }
    
    .subtitle{
      font-size:15px;
      color:var(--text-secondary);
      line-height:1.6;
    }
    
    /* Cards Grid */
    .grid{
      display:grid;
      grid-template-columns:1.2fr 0.8fr;
      gap:24px;
      margin-bottom:24px;
    }
    
    .card{
      background:rgba(255,255,255,0.03);
      border:1px solid var(--stroke);
      border-radius:24px;
      overflow:hidden;
      transition:all .4s;
      position:relative;
    }
    
    .card::before{
      content:'';
      position:absolute;
      inset:0;
      background:radial-gradient(800px circle at var(--mouse-x) var(--mouse-y), rgba(168,85,247,0.08), transparent 40%);
      opacity:0;
      transition:opacity .4s;
      pointer-events:none;
    }
    
    .card:hover::before{
      opacity:1;
    }
    
    .card:hover{
      border-color:rgba(168,85,247,0.4);
      transform:translateY(-4px);
      box-shadow:0 20px 60px rgba(168,85,247,0.25);
    }
    
    .card-header{
      padding:20px 24px;
      border-bottom:1px solid var(--stroke);
      display:flex;
      align-items:center;
      justify-content:space-between;
      background:rgba(0,0,0,0.2);
    }
    
    .card-title{
      font-size:16px;
      font-weight:800;
      display:flex;
      align-items:center;
      gap:10px;
    }
    
    .card-icon{
      width:32px;
      height:32px;
      border-radius:8px;
      background:linear-gradient(135deg, var(--purple), var(--pink));
      display:flex;
      align-items:center;
      justify-content:center;
      box-shadow:0 8px 20px rgba(168,85,247,0.4);
    }
    
    .card-icon svg{
      width:16px;
      height:16px;
    }
    
    .hint{
      font-size:12px;
      color:var(--text-secondary);
      font-weight:500;
    }
    
    .card-body{
      padding:24px;
    }
    
    /* Form */
    .form-row{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:16px;
      margin-bottom:16px;
    }
    
    .form-group label{
      display:block;
      font-size:13px;
      font-weight:700;
      color:var(--text-secondary);
      margin-bottom:8px;
      text-transform:uppercase;
      letter-spacing:0.5px;
    }
    
    .input{
      width:100%;
      padding:14px 16px;
      border-radius:12px;
      background:rgba(0,0,0,0.3);
      border:1px solid var(--stroke);
      color:var(--text);
      font-size:14px;
      font-weight:500;
      transition:all .3s;
      outline:none;
    }
    
    .input:focus{
      border-color:var(--purple);
      box-shadow:0 0 0 4px rgba(168,85,247,0.15);
      background:rgba(0,0,0,0.4);
    }
    
    /* Buttons */
    .btn-row{
      display:grid;
      grid-template-columns:1fr 1fr 1fr;
      gap:12px;
      margin-top:20px;
    }
    
    .btn{
      padding:14px 20px;
      border-radius:12px;
      border:none;
      font-size:14px;
      font-weight:800;
      cursor:pointer;
      transition:all .3s;
      display:flex;
      align-items:center;
      justify-content:center;
      gap:10px;
      position:relative;
      overflow:hidden;
    }
    
    .btn svg{
      width:18px;
      height:18px;
    }
    
    .btn-primary{
      background:linear-gradient(135deg, var(--purple), var(--blue));
      color:white;
      box-shadow:0 10px 30px rgba(168,85,247,0.4);
    }
    
    .btn-primary::before{
      content:'';
      position:absolute;
      inset:0;
      background:linear-gradient(135deg, var(--purple-light), var(--blue));
      opacity:0;
      transition:opacity .3s;
    }
    
    .btn-primary:hover::before{
      opacity:1;
    }
    
    .btn-primary:hover{
      transform:translateY(-2px);
      box-shadow:0 15px 40px rgba(168,85,247,0.6);
    }
    
    .btn-primary span{
      position:relative;
      z-index:1;
    }
    
    .btn-secondary{
      background:rgba(255,255,255,0.05);
      border:1px solid var(--stroke);
      color:var(--text-secondary);
    }
    
    .btn-secondary:hover{
      background:rgba(255,255,255,0.08);
      border-color:rgba(168,85,247,0.4);
      color:var(--text);
      transform:translateY(-2px);
    }
    
    /* Results Panels */
    .results-grid{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:16px;
      margin-top:20px;
    }
    
    .panel{
      border-radius:16px;
      background:rgba(0,0,0,0.3);
      border:1px solid var(--stroke);
      overflow:hidden;
    }
    
    .panel-header{
      padding:12px 16px;
      background:rgba(0,0,0,0.3);
      border-bottom:1px solid var(--stroke);
      display:flex;
      align-items:center;
      justify-content:space-between;
    }
    
    .panel-title{
      font-size:12px;
      font-weight:700;
      color:var(--text-secondary);
      text-transform:uppercase;
      letter-spacing:0.5px;
    }
    
    .status-tag{
      padding:4px 10px;
      border-radius:12px;
      font-size:11px;
      font-weight:700;
      background:rgba(255,255,255,0.05);
      border:1px solid var(--stroke);
      color:var(--text-secondary);
    }
    
    .status-tag.loading{
      background:rgba(59,130,246,0.15);
      border-color:rgba(59,130,246,0.3);
      color:var(--blue);
    }
    
    .status-tag.done{
      background:rgba(16,185,129,0.15);
      border-color:rgba(16,185,129,0.3);
      color:var(--green);
    }
    
    .status-tag.error{
      background:rgba(236,72,153,0.15);
      border-color:rgba(236,72,153,0.3);
      color:var(--pink);
    }
    
    pre{
      margin:0;
      padding:16px;
      max-height:380px;
      overflow:auto;
      font-size:12px;
      line-height:1.6;
      color:rgba(255,255,255,0.8);
      font-family:ui-monospace,Menlo,Monaco,monospace;
    }
    
    pre::-webkit-scrollbar{width:8px}
    pre::-webkit-scrollbar-track{background:rgba(0,0,0,0.2)}
    pre::-webkit-scrollbar-thumb{background:rgba(168,85,247,0.3);border-radius:4px}
    pre::-webkit-scrollbar-thumb:hover{background:rgba(168,85,247,0.5)}
    
    /* Skeleton Loading */
    .skeleton{
      color:transparent!important;
      background:linear-gradient(90deg, rgba(255,255,255,0.05) 25%, rgba(255,255,255,0.1) 50%, rgba(255,255,255,0.05) 75%);
      background-size:200% 100%;
      animation:shimmer 1.5s ease-in-out infinite;
      border-radius:8px;
    }
    
    @keyframes shimmer{
      0%{background-position:200% 0}
      100%{background-position:-200% 0}
    }
    
    /* Info Cards */
    .info-grid{
      display:grid;
      gap:12px;
    }
    
    .info-card{
      padding:16px;
      border-radius:16px;
      background:rgba(0,0,0,0.3);
      border:1px solid var(--stroke);
      transition:all .3s;
    }
    
    .info-card:hover{
      border-color:rgba(168,85,247,0.4);
      transform:translateX(4px);
    }
    
    .info-card-title{
      font-size:13px;
      font-weight:800;
      margin-bottom:6px;
      color:var(--purple-light);
    }
    
    .info-card-text{
      font-size:13px;
      line-height:1.5;
      color:var(--text-secondary);
    }
    
    /* Toast Notification */
    .toast{
      position:fixed;
      bottom:24px;
      right:24px;
      padding:16px 24px;
      border-radius:16px;
      background:rgba(10,10,10,0.95);
      backdrop-filter:blur(20px);
      border:1px solid var(--stroke);
      box-shadow:0 20px 60px rgba(0,0,0,0.8);
      display:flex;
      align-items:center;
      gap:12px;
      opacity:0;
      transform:translateY(20px);
      transition:all .3s;
      z-index:1000;
    }
    
    .toast.show{
      opacity:1;
      transform:translateY(0);
    }
    
    .toast-icon{
      width:32px;
      height:32px;
      border-radius:8px;
      background:linear-gradient(135deg, var(--purple), var(--blue));
      display:flex;
      align-items:center;
      justify-content:center;
      animation:pulse-icon 1.5s ease-in-out infinite;
    }
    
    @keyframes pulse-icon{
      0%,100%{transform:scale(1)}
      50%{transform:scale(1.1)}
    }
    
    .toast-text{
      font-size:14px;
      font-weight:700;
      color:var(--text);
    }
    
    /* Responsive */
    @media(max-width:1200px){
      .grid{grid-template-columns:1fr}
      .sidebar{display:none}
    }
    
    @media(max-width:768px){
      .main{padding:20px}
      .form-row{grid-template-columns:1fr}
      .btn-row{grid-template-columns:1fr}
      .results-grid{grid-template-columns:1fr}
    }
  </style>
</head>

<body>
  <div class="grid-bg"></div>
  <div class="orb orb-1"></div>
  <div class="orb orb-2"></div>
  <div class="orb orb-3"></div>
  
  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <div class="logo-icon">
          <svg fill="white" viewBox="0 0 24 24"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <div class="brand-text">
          <h1>Hiring Radar</h1>
          <p>Intelligence Suite</p>
        </div>
      </div>
      
      <nav class="nav">
        <a href="/dashboard" class="active">
          <svg fill="currentColor" viewBox="0 0 24 24"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>
          <span>Dashboard</span>
        </a>
        <a href="/about">
          <svg fill="currentColor" viewBox="0 0 24 24"><path d="M11 17h2v-6h-2v6zm1-8c.55 0 1-.45 1-1s-.45-1-1-1-1 .45-1 1 .45 1 1 1zm0-7C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/></svg>
          <span>About</span>
        </a>
        <a href="/">
          <svg fill="currentColor" viewBox="0 0 24 24"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>
          <span>Home</span>
        </a>
        <a href="/logout">
          <svg fill="currentColor" viewBox="0 0 24 24"><path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5-5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/></svg>
          <span>Sign Out</span>
        </a>
      </nav>
      
      <div class="user-card">
        <div class="status-badge">
          <span class="status-dot"></span>
          CONNECTED
        </div>
        <p style="font-size:12px;color:var(--text-secondary);line-height:1.5">
          Secured via OAuth 2.0 with intelligent TTL caching
        </p>
        <div class="user-info">
          <div class="avatar">${avatarLetter}</div>
          <div class="user-details">
            <div class="user-name">${escapeHtml(userName)}</div>
            <div class="user-email">${escapeHtml(email)}</div>
            <div class="user-org"><strong>ORG:</strong> ${escapeHtml(domain)}</div>
          </div>
        </div>
      </div>
    </aside>
    
    <main class="main">
      <div class="header">
        <div class="header-top">
          <h2>Intelligence Dashboard</h2>
          <div class="header-actions">
            <div class="chip">
              Cache <strong>15m</strong> Trends · <strong>10m</strong> Bench
            </div>
            <a href="/about" class="btn-link">Documentation</a>
          </div>
        </div>
        <p class="subtitle">
          Query live USAJOBS data and compute intelligent benchmarks with resilient server-side caching.
        </p>
      </div>
      
      <div class="grid">
        <div class="card">
          <div class="card-header">
            <div class="card-title">
              <div class="card-icon">
                <svg fill="white" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
              </div>
              Market Query
            </div>
            <span class="hint">Live upstream • cached per session</span>
          </div>
          
          <div class="card-body">
            <div class="form-row">
              <div class="form-group">
                <label>Keyword</label>
                <input class="input" id="kw" value="software engineer" placeholder="e.g., data analyst, network engineer" />
              </div>
              <div class="form-group">
                <label>Location</label>
                <input class="input" id="loc" value="New York" placeholder="e.g., New York, Remote, San Francisco" />
              </div>
            </div>
            
            <div class="btn-row">
              <button class="btn btn-primary" id="run">
                <svg fill="white" viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/></svg>
                <span>Market Trends</span>
              </button>
              
              <button class="btn btn-primary" id="bench">
                <svg fill="white" viewBox="0 0 24 24"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
                <span>Benchmarks</span>
              </button>
              
              <button class="btn btn-secondary" id="clear">
                <svg fill="currentColor" viewBox="0 0 24 24"><path d="M16 9v10H8V9h8m-1.5-6h-5l-1 1H5v2h14V4h-4.5l-1-1z"/></svg>
                <span>Clear</span>
              </button>
            </div>
            
            <div class="results-grid">
              <div class="panel">
                <div class="panel-header">
                  <span class="panel-title">Market Trends</span>
                  <span class="status-tag" id="tag1">idle</span>
                </div>
                <pre id="out">(results will appear here)</pre>
              </div>
              
              <div class="panel">
                <div class="panel-header">
                  <span class="panel-title">Benchmarks</span>
                  <span class="status-tag" id="tag2">idle</span>
                </div>
                <pre id="bout">(benchmarks will appear here)</pre>
              </div>
            </div>
          </div>
        </div>
        
        <div class="card">
          <div class="card-header">
            <div class="card-title">
              <div class="card-icon" style="background:linear-gradient(135deg, var(--cyan), var(--green))">
                <svg fill="white" viewBox="0 0 24 24"><path d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z"/></svg>
              </div>
              Session Summary
            </div>
          </div>
          
          <div class="card-body">
            <div class="info-grid">
              <div class="info-card">
                <div class="info-card-title">Admin Identity</div>
                <div class="info-card-text">${escapeHtml(userName)} · ${escapeHtml(domain)}</div>
              </div>
              
              <div class="info-card">
                <div class="info-card-title">Resilience</div>
                <div class="info-card-text">Non-existent routes return 404. Upstream failures return 502 with logs.</div>
              </div>
              
              <div class="info-card">
                <div class="info-card-title">Caching Strategy</div>
                <div class="info-card-text">Trends: 15min · Benchmarks: 10min · Userinfo: 5min</div>
              </div>
              
              <div class="info-card">
                <div class="info-card-title">Pro Tip</div>
                <div class="info-card-text">Try "cybersecurity", "data scientist", "network engineer" + "Remote"</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>
  
  <div class="toast" id="toast">
    <div class="toast-icon">
      <svg width="16" height="16" fill="white" viewBox="0 0 24 24"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
    </div>
    <span class="toast-text" id="toastText">Loading…</span>
  </div>
  
  <script>
    const out = document.getElementById('out');
    const bout = document.getElementById('bout');
    const toast = document.getElementById('toast');
    const toastText = document.getElementById('toastText');
    const tag1 = document.getElementById('tag1');
    const tag2 = document.getElementById('tag2');
    
    // Toast notification
    function showToast(msg){
      toastText.textContent = msg;
      toast.classList.add('show');
      clearTimeout(showToast._t);
      showToast._t = setTimeout(() => toast.classList.remove('show'), 2200);
    }
    
    // Read form inputs
    function readInputs(){
      const kw = encodeURIComponent(document.getElementById('kw').value.trim());
      const loc = encodeURIComponent(document.getElementById('loc').value.trim());
      return { kw, loc };
    }
    
    // Loading state
    function setLoading(preEl, tagEl){
      preEl.classList.add('skeleton');
      preEl.textContent = 'Loading data…';
      tagEl.textContent = 'loading';
      tagEl.className = 'status-tag loading';
    }
    
    // Done state
    function setDone(preEl, tagEl, success){
      preEl.classList.remove('skeleton');
      if(success){
        tagEl.textContent = 'done';
        tagEl.className = 'status-tag done';
      }else{
        tagEl.textContent = 'error';
        tagEl.className = 'status-tag error';
      }
    }
    
    // Fetch endpoint
    async function runEndpoint(endpoint, targetPre, targetTag){
      showToast('Fetching data…');
      setLoading(targetPre, targetTag);
      
      try{
        const resp = await fetch(endpoint);
        const text = await resp.text();
        targetPre.textContent = text;
        setDone(targetPre, targetTag, resp.ok);
        showToast(resp.ok ? '✓ Complete' : \`✗ Error: \${resp.status}\`);
      }catch(err){
        targetPre.textContent = String(err);
        setDone(targetPre, targetTag, false);
        showToast('✗ Network error');
      }
    }
    
    // Event listeners
    document.getElementById('run').addEventListener('click', async () => {
      const { kw, loc } = readInputs();
      await runEndpoint(\`/api/market-trends?keyword=\${kw}&location=\${loc}\`, out, tag1);
    });
    
    document.getElementById('bench').addEventListener('click', async () => {
      const { kw, loc } = readInputs();
      await runEndpoint(\`/api/benchmarks?keyword=\${kw}&location=\${loc}\`, bout, tag2);
    });
    
    document.getElementById('clear').addEventListener('click', () => {
      out.classList.remove('skeleton');
      bout.classList.remove('skeleton');
      out.textContent = '(cleared)';
      bout.textContent = '(cleared)';
      tag1.textContent = 'idle';
      tag1.className = 'status-tag';
      tag2.textContent = 'idle';
      tag2.className = 'status-tag';
      showToast('✓ Cleared');
    });
    
    // Mouse tracking for card glow effect
    document.querySelectorAll('.card').forEach(card => {
      card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.setProperty('--mouse-x', x + 'px');
        card.style.setProperty('--mouse-y', y + 'px');
      });
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
