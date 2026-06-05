import express from 'express';
import httpProxy from 'http-proxy';
import { spawn } from 'child_process';
import crypto from 'crypto';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT         = process.env.PORT || 3000;
const INTERNAL_PORT = 3001;                          // supergateway runs here
const BASE_URL     = process.env.BASE_URL || `http://localhost:${PORT}`;
const BEARER_TOKEN = process.env.BEARER_TOKEN || crypto.randomBytes(32).toString('hex');

console.log(`Yahoo Mail MCP Server starting`);
console.log(`BASE_URL:      ${BASE_URL}`);
console.log(`BEARER_TOKEN:  ${BEARER_TOKEN}`);   // visible in Railway logs

// ── In-memory auth code store ──────────────────────────────────────────────
const authCodes = new Map();

// ── OAuth2 Metadata Discovery ──────────────────────────────────────────────
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth/authorize`,
    token_endpoint:         `${BASE_URL}/oauth/token`,
    scopes_supported:                   ['mcp'],
    response_types_supported:           ['code'],
    grant_types_supported:              ['authorization_code'],
    code_challenge_methods_supported:   ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  });
});

// ── Authorization endpoint (auto-approves — personal use only) ─────────────
app.get('/oauth/authorize', (req, res) => {
  const { redirect_uri, state, code_challenge, code_challenge_method } = req.query;
  if (!redirect_uri) return res.status(400).send('Missing redirect_uri');

  const code = crypto.randomBytes(16).toString('hex');
  authCodes.set(code, { ts: Date.now(), code_challenge, code_challenge_method });
  setTimeout(() => authCodes.delete(code), 10 * 60 * 1000); // expire in 10 min

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  res.redirect(url.toString());
});

// ── Token endpoint ─────────────────────────────────────────────────────────
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, code_verifier } = req.body;

  if (grant_type !== 'authorization_code')
    return res.status(400).json({ error: 'unsupported_grant_type' });

  const stored = authCodes.get(code);
  if (!stored) return res.status(400).json({ error: 'invalid_grant' });

  // Verify PKCE S256 if provided
  if (stored.code_challenge && code_verifier) {
    const expected = crypto.createHash('sha256')
      .update(Buffer.from(code_verifier))
      .digest('base64url');
    if (expected !== stored.code_challenge)
      return res.status(400).json({ error: 'invalid_grant' });
  }

  authCodes.delete(code);
  res.json({ access_token: BEARER_TOKEN, token_type: 'Bearer', expires_in: 31536000 });
});

// ── Bearer token middleware ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ') && auth.slice(7) === BEARER_TOKEN) return next();
  res.status(401)
     .set('WWW-Authenticate', `Bearer realm="${BASE_URL}"`)
     .json({ error: 'Unauthorized' });
}

// ── Proxy /sse and /message to internal supergateway ──────────────────────
const proxy = httpProxy.createProxy({ target: `http://localhost:${INTERNAL_PORT}` });
proxy.on('error', (err, req, res) => {
  console.error('Proxy error:', err.message);
  if (!res.headersSent) res.status(502).json({ error: 'MCP backend not ready yet, retry in a few seconds' });
});

app.use('/sse',     requireAuth, (req, res) => proxy.web(req, res));
app.use('/message', requireAuth, (req, res) => proxy.web(req, res));

// ── Health check ──────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', server: 'Yahoo Mail MCP Server' }));

// ── Start Express ─────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));

// ── Start supergateway on internal port ───────────────────────────────────
// Small delay to let Railway assign PORT before supergateway starts
setTimeout(() => {
  console.log(`Starting supergateway on internal port ${INTERNAL_PORT}...`);
  const sg = spawn(
    'npx',
    ['-y', 'supergateway', '--port', String(INTERNAL_PORT), '--stdio', 'npx -y imap-email-mcp'],
    { env: { ...process.env }, shell: true }
  );
  sg.stdout.on('data', d => console.log('[sg]', d.toString().trim()));
  sg.stderr.on('data', d => console.error('[sg]', d.toString().trim()));
  sg.on('exit', code => console.log(`supergateway exited (${code})`));
}, 2000);
