'use strict';
// Digit Radar server. No dependencies.
// - Serves the page, behind a 6-digit PAGE_PIN when one is set.
// - Proxies analyst questions to the Anthropic API (the API key never reaches the browser).
// - Hands the browser a one-time Deriv trading WebSocket URL. The Deriv token never leaves this server.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(function (line) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (e) { /* no .env file, use real environment */ }

const env = process.env;
const PORT = Number(env.PORT) || 3000;
const KEY = env.ANTHROPIC_API_KEY || '';
const MODEL = env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
const PASS = env.APP_PASSWORD || '';
const PAGE_PIN = env.PAGE_PIN || '';
const PUBLIC = path.join(__dirname, 'public');

const D = {
  token: env.DERIV_API_TOKEN || '',
  appId: env.DERIV_APP_ID || '',
  demo: env.DERIV_ACCOUNT_DEMO || '',
  real: env.DERIV_ACCOUNT_REAL || '',
  allowReal: env.DERIV_ALLOW_REAL === '1',
  maxStake: Number(env.MAX_STAKE) > 0 ? Number(env.MAX_STAKE) : 10,
  base: (env.DERIV_API_BASE || 'https://api.derivws.com').replace(/\/+$/, '')
};
const WS_PREFIX = 'wss://api.derivws.com/';
const ID_RE = /^[A-Za-z0-9_-]{3,40}$/;

function tradingStatus() {
  const s = { configured: false, demo: false, real: false, maxStake: D.maxStake, reason: '' };
  if (!PASS) s.reason = 'Set APP_PASSWORD on the server before turning trading on.';
  else if (!D.token || !D.appId) s.reason = 'Add DERIV_API_TOKEN and DERIV_APP_ID to the server settings.';
  else {
    s.demo = ID_RE.test(D.demo);
    s.real = D.allowReal && ID_RE.test(D.real);
    s.configured = s.demo || s.real;
    if (!s.configured) s.reason = 'Add DERIV_ACCOUNT_DEMO (and DERIV_ACCOUNT_REAL with DERIV_ALLOW_REAL=1 for real money).';
  }
  return s;
}

const SYSTEM = 'You are the analyst inside Digit Radar, a tool for traders of Deriv digit contracts (Matches, Differs, Over, Under, Even and Odd) on synthetic volatility indices. ' +
  'Facts you must respect: these indices come from a random number generator, last digits are independent and uniform, and no past pattern predicts the next digit. ' +
  'Never claim to predict a digit, never promise profit, never say a digit is due. ' +
  'Help the trader decide using only the numbers in the snapshot: say whether the sample shows any skew beyond chance (chi-square against the 5 percent critical value), compare the sample win rate with the break-even win rate, read the paper test only as far as its trade count supports, treat volatility as context only, and when realTrades has logged trades, compare the real net result of the trader with the fair-odds expectation and say plainly when it sits inside the range of luck. If scanResults are present, discuss them, and remind the trader that the most frequent digit, the least frequent digit and the best barrier are all picked from the same data, so some apparent strength appears by chance. ' +
  'If the data source is simulated ticks, say the stats come from simulated ticks. ' +
  'Open with a one-line verdict, for example: No edge shown. Skip this trade. Then give 2 to 4 short points and one concrete risk suggestion such as stake as a small share of balance, a loss limit, a trade cap, or stopping after a losing streak. ' +
  'Plain text only, no markdown, under 200 words.';

// ---- small helpers ----
function send(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function readBody(req, max) {
  return new Promise(function (resolve, reject) {
    let size = 0; const chunks = [];
    req.on('data', function (c) {
      size += c.length;
      if (size > max) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', function () { resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}
// Behind one proxy (Render, Railway, Fly) the last X-Forwarded-For entry is the real client.
function clientIp(req) {
  const parts = String(req.headers['x-forwarded-for'] || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : (req.socket.remoteAddress || '');
}
const buckets = new Map();
function limited(name, ip, max, windowMs) {
  const key = name + '|' + ip, now = Date.now();
  const list = (buckets.get(key) || []).filter(function (t) { return now - t < windowMs; });
  list.push(now); buckets.set(key, list);
  return list.length > max;
}
const fails = new Map();
const pinFails = new Map();
const sessions = new Map(); // session token -> expiry time
const SESSION_MS = 12 * 60 * 60 * 1000;
setInterval(function () {
  buckets.clear(); fails.clear(); pinFails.clear();
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
}, 15 * 60 * 1000).unref();

function passOk(req) {
  const a = crypto.createHash('sha256').update(String(req.headers['x-app-password'] || '')).digest();
  const b = crypto.createHash('sha256').update(PASS).digest();
  return crypto.timingSafeEqual(a, b);
}
// Returns true when the caller may continue. When no APP_PASSWORD is set, only the analyst is open.
function checkAuth(req, res) {
  if (!PASS) return true;
  const ip = clientIp(req), now = Date.now();
  const list = (fails.get(ip) || []).filter(function (t) { return now - t < 600000; });
  if (list.length >= 10) { send(res, 429, { error: 'Too many wrong passwords. Wait ten minutes.' }); return false; }
  if (passOk(req)) return true;
  list.push(now); fails.set(ip, list);
  send(res, 401, { error: 'Wrong or missing access password.' });
  return false;
}

// ---- page PIN ----
function validSession(req) {
  const m = /(?:^|;\s*)dr_session=([0-9a-f]{64})/.exec(req.headers.cookie || '');
  if (!m) return false;
  const exp = sessions.get(m[1]);
  if (!exp || exp < Date.now()) { sessions.delete(m[1]); return false; }
  return true;
}
function pinMatches(input) {
  const a = crypto.createHash('sha256').update(String(input)).digest();
  const b = crypto.createHash('sha256').update(PAGE_PIN).digest();
  return crypto.timingSafeEqual(a, b);
}
async function pinLogin(req, res) {
  const ip = clientIp(req), now = Date.now();
  const list = (pinFails.get(ip) || []).filter(function (t) { return now - t < 600000; });
  if (list.length >= 5) return send(res, 429, { error: 'Too many wrong PINs. Wait ten minutes.' });
  let data;
  try { data = JSON.parse(await readBody(req, 200)); } catch (e) { return send(res, 400, { error: 'Bad request.' }); }
  const pin = data && typeof data.pin === 'string' ? data.pin : '';
  if (!/^\d{6}$/.test(pin) || !pinMatches(pin)) {
    list.push(now); pinFails.set(ip, list);
    return send(res, 401, { error: 'Wrong PIN.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_MS);
  res.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'set-cookie': 'dr_session=' + token + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + Math.floor(SESSION_MS / 1000)
  });
  res.end(JSON.stringify({ ok: true }));
}
const LOGIN_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<title>Digit Radar</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1420;color:#e7ecf5;font:16px system-ui,sans-serif}' +
  'form{display:flex;flex-direction:column;gap:12px;width:min(92vw,300px);text-align:center}h1{font-size:22px;margin:0 0 6px}' +
  'input{font:28px monospace;letter-spacing:.4em;text-align:center;padding:12px;border-radius:10px;border:1px solid #2a3548;background:#171f2e;color:#e7ecf5}' +
  'button{padding:12px;border:0;border-radius:10px;background:#3b82f6;color:#fff;font-size:16px;font-weight:600}' +
  'p{margin:0;min-height:20px;color:#ef6461;font-size:14px}</style></head><body>' +
  '<form id="f"><h1>Digit Radar</h1><input id="pin" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="------" required>' +
  '<button type="submit">Unlock</button><p id="msg"></p></form>' +
  '<script>document.getElementById("f").addEventListener("submit",function(e){e.preventDefault();var v=document.getElementById("pin").value;' +
  'fetch("/api/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({pin:v})}).then(function(r){return r.json().then(function(b){return{ok:r.ok,b:b};});})' +
  '.then(function(x){if(x.ok){location.href="/";}else{document.getElementById("msg").textContent=(x.b&&x.b.error)||"Could not unlock.";}})' +
  '.catch(function(){document.getElementById("msg").textContent="Could not reach the server.";});});</script></body></html>';

// ---- analyst ----
async function analyze(req, res) {
  if (!checkAuth(req, res)) return;
  if (!KEY) return send(res, 503, { error: 'The analyst is not set up. Add ANTHROPIC_API_KEY to the server settings and restart.' });
  if (limited('analyze', clientIp(req), 8, 60000)) return send(res, 429, { error: 'Too many questions in a short time. Wait a minute and try again.' });

  let data;
  try { data = JSON.parse(await readBody(req, 20000)); } catch (e) { return send(res, 400, { error: 'Bad request.' }); }
  const q = typeof data.question === 'string' ? data.question.slice(0, 400) : '';
  if (!q || !data.snapshot || typeof data.snapshot !== 'object') return send(res, 400, { error: 'Missing question or snapshot.' });
  const snap = JSON.stringify(data.snapshot);
  if (snap.length > 9000) return send(res, 400, { error: 'Snapshot too large.' });

  const ctl = new AbortController();
  const timer = setTimeout(function () { ctl.abort(); }, 40000);
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: ctl.signal,
      headers: { 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: MODEL, max_tokens: 600, system: SYSTEM,
        messages: [{ role: 'user', content: 'Trader question: ' + q + '\n\nSnapshot JSON:\n' + snap }]
      })
    });
    const out = await r.json().catch(function () { return {}; });
    if (!r.ok) {
      console.error('Anthropic API error', r.status, out && out.error && out.error.message);
      const msg = r.status === 401 ? 'The server API key was rejected. Check ANTHROPIC_API_KEY.'
        : r.status === 429 ? 'The analyst is busy. Try again in a moment.'
        : 'The analyst is unavailable right now. Try again shortly.';
      return send(res, 502, { error: msg });
    }
    const text = (out.content || []).filter(function (b) { return b.type === 'text'; }).map(function (b) { return b.text; }).join('\n').trim();
    return send(res, 200, { text: text || 'The analyst returned an empty answer. Ask again.' });
  } catch (e) {
    console.error('Analyst request failed', e && e.message);
    return send(res, 502, { error: 'The analyst is unavailable right now. Try again shortly.' });
  } finally { clearTimeout(timer); }
}

// ---- Deriv ----
async function derivCall(method, p) {
  const ctl = new AbortController();
  const timer = setTimeout(function () { ctl.abort(); }, 15000);
  try {
    const r = await fetch(D.base + p, {
      method: method, signal: ctl.signal,
      headers: { Authorization: 'Bearer ' + D.token, 'Deriv-App-ID': D.appId }
    });
    let body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    return { status: r.status, body: body };
  } finally { clearTimeout(timer); }
}
function derivError(body, status) {
  let m = '';
  if (body && typeof body === 'object') {
    m = (body.error && (body.error.message || body.error.code)) || body.message || (body.errors && body.errors[0] && (body.errors[0].message || body.errors[0].detail)) || '';
  }
  return 'Deriv refused the request (' + status + ').' + (m ? ' ' + String(m).slice(0, 200) : '');
}
function tradingGate(req, res) {
  if (!checkAuth(req, res)) return false;
  const s = tradingStatus();
  if (!PASS) { send(res, 403, { error: s.reason }); return false; }
  if (!D.token || !D.appId) { send(res, 503, { error: s.reason }); return false; }
  return true;
}
async function derivAccounts(req, res) {
  if (!tradingGate(req, res)) return;
  if (limited('accounts', clientIp(req), 10, 60000)) return send(res, 429, { error: 'Too many requests. Wait a minute.' });
  try {
    const r = await derivCall('GET', '/trading/v1/options/accounts');
    return send(res, 200, { status: r.status, body: r.body });
  } catch (e) { return send(res, 502, { error: 'Could not reach Deriv.' }); }
}
async function derivOtp(req, res) {
  if (!tradingGate(req, res)) return;
  const s = tradingStatus();
  if (!s.configured) return send(res, 503, { error: s.reason });
  if (limited('otp', clientIp(req), 8, 60000)) return send(res, 429, { error: 'Too many connection attempts. Wait a minute.' });
  let data;
  try { data = JSON.parse(await readBody(req, 2000)); } catch (e) { return send(res, 400, { error: 'Bad request.' }); }
  const mode = data && data.mode === 'real' ? 'real' : 'demo';
  if (mode === 'real' && !s.real) return send(res, 403, { error: 'Real-money trading is switched off on this server. Set DERIV_ALLOW_REAL=1 and DERIV_ACCOUNT_REAL to enable it.' });
  if (mode === 'demo' && !s.demo) return send(res, 403, { error: 'No demo account is set. Add DERIV_ACCOUNT_DEMO.' });
  const id = mode === 'real' ? D.real : D.demo;
  try {
    const r = await derivCall('POST', '/trading/v1/options/accounts/' + encodeURIComponent(id) + '/otp');
    const url = r.body && r.body.data && r.body.data.url;
    if (r.status < 200 || r.status >= 300 || typeof url !== 'string') return send(res, 502, { error: derivError(r.body, r.status) });
    if (url.indexOf(WS_PREFIX) !== 0 || url.indexOf(mode === 'real' ? '/ws/real' : '/ws/demo') < 0) return send(res, 502, { error: 'Deriv returned an unexpected connection URL.' });
    return send(res, 200, { url: url, mode: mode });
  } catch (e) {
    console.error('OTP request failed', e && e.message);
    return send(res, 502, { error: 'Could not reach Deriv.' });
  }
}

// ---- static files ----
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
  "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' wss://api.derivws.com wss://ws.derivws.com; " +
  "frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

function handler(req, res) {
  const url = (req.url || '/').split('?')[0];
  if (url === '/api/health') return send(res, 200, { ok: true });
  if (url === '/api/login') return req.method === 'POST' ? pinLogin(req, res) : send(res, 405, { error: 'Use POST.' });
  if (url === '/login') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': CSP, 'x-frame-options': 'DENY' });
    return res.end(LOGIN_PAGE);
  }
  // With a page PIN set, every other page and API call needs a valid session first.
  if (PAGE_PIN && !validSession(req)) {
    if (url.indexOf('/api/') === 0) return send(res, 401, { error: 'Enter the dashboard PIN first.' });
    res.writeHead(302, { location: '/login', 'cache-control': 'no-store' });
    return res.end();
  }
  if (url === '/api/analyze') return req.method === 'POST' ? analyze(req, res) : send(res, 405, { error: 'Use POST.' });
  if (url === '/api/deriv/otp') return req.method === 'POST' ? derivOtp(req, res) : send(res, 405, { error: 'Use POST.' });
  if (url === '/api/deriv/accounts') return req.method === 'GET' ? derivAccounts(req, res) : send(res, 405, { error: 'Use GET.' });
  if (url === '/api/config') return send(res, 200, { analyst: !!KEY, passwordRequired: !!PASS, trading: tradingStatus() });
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  const rel = url === '/' ? 'index.html' : url.replace(/^\/+/, '');
  const file = path.normalize(path.join(PUBLIC, rel));
  if (file.indexOf(PUBLIC + path.sep) !== 0) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, function (err, buf) {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, {
      'content-type': TYPES[path.extname(file)] || 'application/octet-stream',
      'cache-control': 'no-cache',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'content-security-policy': CSP
    });
    res.end(req.method === 'HEAD' ? undefined : buf);
  });
}


module.exports = handler;

if (require.main === module) http.createServer(handler).listen(PORT, function () {
  const t = tradingStatus();
  console.log('Digit Radar running at http://localhost:' + PORT);
  console.log(KEY ? 'Analyst: on (' + MODEL + ')' : 'Analyst: off, add ANTHROPIC_API_KEY');
  console.log(t.configured ? 'Trading: demo ' + (t.demo ? 'on' : 'off') + ', real ' + (t.real ? 'ON' : 'off') + ', max stake ' + t.maxStake : 'Trading: off. ' + t.reason);
  console.log(PAGE_PIN ? 'Page PIN: on' : 'Page PIN: off, set PAGE_PIN (6 digits) to lock the dashboard');
  if (!PASS) console.log('Warning: no APP_PASSWORD set. Set one before putting this site online.');
});
