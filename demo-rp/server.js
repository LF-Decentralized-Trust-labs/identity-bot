const http = require('http');
const https = require('https');
const urlMod = require('url');
const fs = require('fs');
const path = require('path');

const ORG_IA_URL = process.env.ORG_IA_URL || 'http://127.0.0.1:5050';
const ASSET_ID = process.env.ASSET_ID;
const PORT = parseInt(process.env.PORT || '8080', 10);

const loginStatus = new Map();

const parsed = urlMod.parse(ORG_IA_URL);
const orgHost = parsed.hostname;
const orgPort = parseInt(parsed.port || (parsed.protocol === 'https:' ? '443' : '80'), 10);
const orgMod = parsed.protocol === 'https:' ? https : http;

function orgRequest(options, body, cb) {
  const req = orgMod.request(
    Object.assign({ host: orgHost, port: orgPort }, options),
    (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; });
      res.on('end', () => cb(null, res, buf));
    }
  );
  req.on('error', cb);
  if (body) req.write(body);
  req.end();
}

function readBody(req, cb) {
  let buf = '';
  req.on('data', (c) => { buf += c; });
  req.on('end', () => cb(buf));
}

function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  const pathname = req.url.split('?')[0];
  const parts = pathname.split('/').filter(Boolean);

  // GET / — serve index.html
  if (req.method === 'GET' && pathname === '/') {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(html);
  }

  // GET /login-start — issue a challenge via org IA
  if (req.method === 'GET' && pathname === '/login-start') {
    if (!ASSET_ID) return json(res, 500, { error: 'ASSET_ID env var required' });
    const body = JSON.stringify({
      asset_id: ASSET_ID,
      audience: 'Demo RP',
      requested_disclosures: ['display_name'],
      callback_url: `http://127.0.0.1:${PORT}/login-complete`,
    });
    orgRequest(
      { method: 'POST', path: '/api/login/challenge',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      body,
      (err, orgRes, data) => {
        if (err) return json(res, 502, { error: err.message });
        try {
          const j = JSON.parse(data);
          const token = j.session_token;
          // qr_url comes from org IA; construct as fallback if absent
          const qr_url = j.qr_url || (token ? `http://127.0.0.1:${PORT}/i/${token}` : undefined);
          if (token) loginStatus.set(token, { status: 'pending' });
          json(res, 200, { qr_url, session_token: token });
        } catch (e) {
          json(res, 502, { error: 'bad response from org IA', raw: data });
        }
      }
    );
    return;
  }

  // GET /i/:token — proxy to org IA
  if (req.method === 'GET' && parts[0] === 'i' && parts[1]) {
    orgRequest({ method: 'GET', path: `/i/${parts[1]}` }, null, (err, orgRes, data) => {
      if (err) { res.writeHead(502); return res.end(err.message); }
      res.writeHead(orgRes.statusCode, { 'Content-Type': 'application/json' });
      res.end(data);
    });
    return;
  }

  // POST /login-complete — store assertion result
  // org IA posts assertion here; session token may come as ?session= query param
  if (req.method === 'POST' && pathname === '/login-complete') {
    const qs = new urlMod.URLSearchParams(req.url.includes('?') ? req.url.split('?')[1] : '');
    readBody(req, (data) => {
      try {
        const body = JSON.parse(data);
        const token = body.session_token || body.session || qs.get('session');
        const pairwiseAID = body.pairwise_aid || body.pairwiseAID || 'unknown';
        if (token) loginStatus.set(token, { status: 'complete', pairwiseAID });
        json(res, 200, { ok: true });
      } catch (e) {
        json(res, 400, { error: 'invalid JSON' });
      }
    });
    return;
  }

  // GET /login-status/:token — poll for login result
  if (req.method === 'GET' && parts[0] === 'login-status' && parts[1]) {
    json(res, 200, loginStatus.get(parts[1]) || { status: 'pending' });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Demo RP listening on http://127.0.0.1:${PORT}`);
  if (!ASSET_ID) console.warn('Warning: ASSET_ID env var is not set — /login-start will fail');
});
