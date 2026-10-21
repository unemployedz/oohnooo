// language: JavaScript (Node.js), file: server.js, target: Render web service
// Forges/stores ROBLOSECURITY cookies, validates them against Roblox API.

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const forgedPasskeys = new Map();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/forge', (req, res) => {
    const { cookie } = req.body;
    if (!cookie || typeof cookie !== 'string') {
        return res.status(400).json({ error: 'Missing .ROBLOSECURITY cookie' });
    }

    // Strip newlines/spaces that occur during copy-paste
    const cleanCookie = cookie.replace(/[\r\n\s]/g, '');

    // Roblox cookies are long and include the warning prefix. Check minimum length.
    if (cleanCookie.length < 50) {
        return res.status(400).json({ error: 'Invalid cookie format (too short)' });
    }

    const passkeyId = 'pk_' + Date.now() + '_' + Math.random().toString(36).slice(2, 11);
    forgedPasskeys.set(passkeyId, { cookie: cleanCookie, json: null, createdAt: new Date().toISOString() });

    res.json({ success: true, passkeyId, message: 'Passkey forged. Use Login to validate.' });
});

app.post('/api/login', async (req, res) => {
    const { passkeyId } = req.body;
    const entry = forgedPasskeys.get(passkeyId);
    if (!entry) {
        return res.status(404).json({ error: 'Passkey not found' });
    }

    try {
        // First hit to auth endpoint returns 403 carrying the CSRF token in headers.
        const authResp = await axios.post('https://auth.roblox.com/v2/login', {}, {
            headers: {
                'Cookie': `.ROBLOSECURITY=${entry.cookie}`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            validateStatus: () => true
        });

        const csrfToken = authResp.headers['x-csrf-token'];
        if (!csrfToken) {
            return res.status(401).json({ error: 'Failed to obtain CSRF token. Cookie may be invalid or expired.' });
        }

        const userResp = await axios.get('https://users.roblox.com/v1/users/authenticated', {
            headers: {
                'Cookie': `.ROBLOSECURITY=${entry.cookie}`,
                'X-CSRF-TOKEN': csrfToken,
                'User-Agent': 'Mozilla/5.0'
            }
        });

        const userId = userResp.data.id;
        const detailsResp = await axios.get(`https://users.roblox.com/v1/users/${userId}`, {
            headers: {
                'Cookie': `.ROBLOSECURITY=${entry.cookie}`,
                'X-CSRF-TOKEN': csrfToken
            }
        });

        const json = {
            authenticated: userResp.data,
            details: detailsResp.data,
            csrfToken
        };

        entry.json = json;
        res.json({ success: true, json });
    } catch (err) {
        res.status(500).json({ error: 'Login failed', details: err.message });
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
