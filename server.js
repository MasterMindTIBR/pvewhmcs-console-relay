'use strict';

/*
    pvewhmcs-console-relay
    Console Relay for Proxmox VE for WHMCS
    https://github.com/MasterMindTIBR/pvewhmcs-console-relay
    File: server.js

    Copyright (C) junglivre

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
 * Bridges a browser's noVNC WebSocket to Proxmox's own
 * /api2/json/nodes/.../vncwebsocket endpoint, so that:
 *   - Proxmox never needs a public IP; only this relay needs network
 *     reachability to it (the same reachability pvewhmcs.php already
 *     needs for provisioning).
 *   - PVEAuthCookie never reaches the browser: this process presents it
 *     to Proxmox itself, on the outbound connection, and v2 tokens carry
 *     it encrypted (AES-256-GCM), so the browser cannot read it either.
 *   - The browser only ever talks to the WHMCS domain, so there is no
 *     PTR, same-registrable-domain, or cross-domain cookie requirement.
 *
 * pvewhmcs.php mints a short-lived, single-use token (see
 * pvewhmcs_build_console_token() in proxmox.php) describing the upstream
 * Proxmox target. This relay verifies that token, connects upstream, and
 * pipes frames both ways until either side closes. The token's "exp" only
 * bounds the browser attach window; an attached session lives up to
 * maxSessionSeconds.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const WebSocket = require('ws');

function loadConfig() {
    const configPath = process.env.PVEWHMCS_RELAY_CONFIG
        || path.join(__dirname, 'config.json');
    const raw = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(raw);

    if (!config.secret || String(config.secret).length < 32) {
        throw new Error('config.json: "secret" must be set and at least 32 characters, matching the WHMCS Module Config "Console Relay Secret".');
    }
    config.listenPort = Number(config.listenPort) || 8765;
    config.pathPrefix = String(config.pathPrefix || '/pve-console-ws').replace(/\/+$/, '');
    config.maxSessionSeconds = Number(config.maxSessionSeconds) || 7200;

    return config;
}

function base64UrlDecode(input) {
    let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    while (normalized.length % 4 !== 0) {
        normalized += '=';
    }

    return Buffer.from(normalized, 'base64');
}

// IPv6 literals must be bracketed inside a URL authority.
function urlHost(host) {
    const value = String(host);

    return value.includes(':') && !value.startsWith('[') ? `[${value}]` : value;
}

const TOKEN_V2_PREFIX = 'v2.';
const TOKEN_V2_CONTEXT = 'pvewhmcs-console-token-v2';
const TOKEN_V2_IV_BYTES = 12;
const TOKEN_V2_TAG_BYTES = 16;

/**
 * v2: "v2." + base64url(iv | AES-256-GCM ciphertext | tag), key =
 * SHA-256(TOKEN_V2_CONTEXT + "|" + secret), AAD = TOKEN_V2_CONTEXT.
 * Must stay byte-compatible with pvewhmcs_build_console_token().
 */
function decodeTokenV2(token, secret) {
    const raw = base64UrlDecode(token.slice(TOKEN_V2_PREFIX.length));
    if (raw.length <= TOKEN_V2_IV_BYTES + TOKEN_V2_TAG_BYTES) {
        throw new Error('malformed token');
    }
    const iv = raw.subarray(0, TOKEN_V2_IV_BYTES);
    const tag = raw.subarray(raw.length - TOKEN_V2_TAG_BYTES);
    const ciphertext = raw.subarray(TOKEN_V2_IV_BYTES, raw.length - TOKEN_V2_TAG_BYTES);
    const key = crypto.createHash('sha256').update(TOKEN_V2_CONTEXT + '|' + secret).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from(TOKEN_V2_CONTEXT, 'utf8'));
    decipher.setAuthTag(tag);
    let plaintext;
    try {
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (err) {
        throw new Error('signature mismatch');
    }

    return JSON.parse(plaintext.toString('utf8'));
}

/**
 * v1 (legacy, readable by the browser): base64url(json) + "." + hex HMAC-SHA256.
 * Still accepted so a relay upgrade never breaks consoles minted by an
 * older WHMCS module.
 */
function decodeTokenV1(token, secret) {
    if (token.indexOf('.') === -1) {
        throw new Error('malformed token');
    }

    const separatorIndex = token.lastIndexOf('.');
    const encoded = token.slice(0, separatorIndex);
    const signature = token.slice(separatorIndex + 1);

    const expected = crypto.createHmac('sha256', secret).update(encoded).digest('hex');
    const expectedBuffer = Buffer.from(expected, 'hex');
    const providedBuffer = Buffer.from(String(signature), 'hex');
    if (expectedBuffer.length !== providedBuffer.length || !crypto.timingSafeEqual(expectedBuffer, providedBuffer)) {
        throw new Error('signature mismatch');
    }

    return JSON.parse(base64UrlDecode(encoded).toString('utf8'));
}

/**
 * Verifies token structure/authenticity/expiry only. Single-use replay
 * protection happens in the caller, which tracks the "sid" once the
 * token is confirmed authentic.
 */
function verifyToken(token, secret) {
    if (typeof token !== 'string' || token === '') {
        throw new Error('malformed token');
    }

    const payload = token.startsWith(TOKEN_V2_PREFIX)
        ? decodeTokenV2(token, secret)
        : decodeTokenV1(token, secret);
    if (!payload || typeof payload !== 'object') {
        throw new Error('malformed token');
    }
    if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('token expired');
    }
    if (!payload.host || !payload.path || !payload.cookie || !payload.sid) {
        throw new Error('token missing required fields');
    }

    return payload;
}

function createSessionRegistry() {
    const sessions = new Map();

    setInterval(() => {
        const now = Math.floor(Date.now() / 1000);
        for (const [sid, session] of sessions) {
            // A closed session is kept until its token expires so the same
            // sid cannot be replayed; after that it is safe to forget.
            if (session.expiresAt < now || (session.closed && session.payload.exp < now)) {
                sessions.delete(sid);
            }
        }
    }, 60000).unref();

    return {
        get(sid) {
            return sessions.get(sid);
        },
        set(sid, session) {
            sessions.set(sid, session);
        },
        delete(sid) {
            sessions.delete(sid);
        },
    };
}

function createRelay(config) {
    const httpServer = http.createServer((req, res) => {
        const requestPath = (req.url || '').split('?')[0];
        const preparePrefix = config.pathPrefix + '/';
        const prepareSuffix = '/prepare';
        const isPrepareRequest = requestPath.indexOf(preparePrefix) === 0
            && requestPath.endsWith(prepareSuffix);

        if (requestPath === '/healthz' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('ok');

            return;
        }

        // Only pvewhmcs.php calls /prepare, server-side, so no CORS headers:
        // a browser on another origin must not be able to read the reply.
        if (isPrepareRequest && req.method === 'POST') {
            const token = requestPath.slice(preparePrefix.length, -prepareSuffix.length);
            const prepareHeaders = {
                'Cache-Control': 'no-store',
            };

            let payload;
            try {
                payload = verifyToken(token, config.secret);
            } catch (err) {
                log('reject', { reason: err.message });
                res.writeHead(401, Object.assign({}, prepareHeaders, { 'Content-Type': 'application/json' }));
                res.end(JSON.stringify({ ready: false, error: 'unauthorized' }));

                return;
            }

            req.resume();
            const session = getOrCreateSession(payload);
            if (session.closed) {
                res.writeHead(409, Object.assign({}, prepareHeaders, {
                    'Content-Type': 'application/json',
                }));
                res.end(JSON.stringify({ ready: false, error: 'session already used' }));

                return;
            }

            // Respond as soon as the upstream connection attempt has been
            // kicked off, not once it fully completes. Proxmox's vncproxy
            // attach window starts counting from the vncproxy API call, so
            // what matters here is starting the WebSocket handshake to
            // Proxmox promptly; waiting for it to finish before replying
            // would tie this response's latency to Proxmox reachability
            // and defeat the purpose of preconnecting early.
            log('prewarm', { sid: payload.sid, host: payload.host });
            res.writeHead(200, Object.assign({}, prepareHeaders, {
                'Content-Type': 'application/json',
            }));
            res.end(JSON.stringify({ ready: true }));

            return;
        }

        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
    });

    const wss = new WebSocket.Server({ noServer: true });
    const sessions = createSessionRegistry();
    const maxBufferedBytes = 1024 * 1024;

    const closeSession = (session, clientCode, reason) => {
        if (session.closed) {
            return;
        }
        session.closed = true;
        clearTimeout(session.sessionTimer);
        clearTimeout(session.attachTimer);
        try { if (session.clientWs) session.clientWs.close(clientCode, reason); } catch (e) { /* already closed */ }
        try { if (session.upstream) session.upstream.close(); } catch (e) { /* already closed */ }
    };

    const createUpstream = (session) => new Promise((resolve, reject) => {
        const payload = session.payload;
        const upstreamUrl = `wss://${urlHost(payload.host)}:${payload.port || 8006}/${payload.path}`;
        const upstreamOrigin = `https://${urlHost(payload.host)}:${payload.port || 8006}`;
        const upstream = new WebSocket(upstreamUrl, {
            headers: {
                Cookie: 'PVEAuthCookie=' + payload.cookie,
                Origin: upstreamOrigin,
            },
            rejectUnauthorized: payload.verify !== false,
            handshakeTimeout: 10000,
        });
        session.upstream = upstream;

        upstream.on('open', () => {
            session.upstreamOpen = true;
            for (const buffered of session.toUpstream.splice(0)) {
                upstream.send(buffered);
            }
            log('connected', {
                sid: payload.sid,
                host: payload.host,
                prewarmed: !session.clientWs,
            });
        });

        upstream.on('message', (data) => {
            if (session.clientWs && session.clientWs.readyState === WebSocket.OPEN) {
                session.clientWs.send(data);

                return;
            }

            const buffered = Buffer.from(data);
            if (session.fromUpstreamBytes + buffered.length > maxBufferedBytes) {
                log('handoff-buffer-overflow', { sid: payload.sid });
                closeSession(session, 1011, 'handoff buffer overflow');

                return;
            }
            session.fromUpstream.push(buffered);
            session.fromUpstreamBytes += buffered.length;
        });

        upstream.on('close', (code, reason) => {
            if (!session.upstreamOpen) {
                reject(new Error('upstream closed before handshake'));
            }
            log('upstream-close', {
                sid: payload.sid,
                host: payload.host,
                port: payload.port || 8006,
                code,
                reason: reason.toString(),
            });
            closeSession(session, 1000, 'upstream closed');
        });

        upstream.on('unexpected-response', (_request, response) => {
            log('upstream-http-error', {
                sid: payload.sid,
                host: payload.host,
                port: payload.port || 8006,
                statusCode: response.statusCode,
                statusMessage: response.statusMessage,
            });
        });

        upstream.on('error', (err) => {
            reject(err);
            log('upstream-error', {
                sid: payload.sid,
                host: payload.host,
                port: payload.port || 8006,
                message: err.message,
            });
            closeSession(session, 1011, 'upstream error');
        });
    });

    const getOrCreateSession = (payload) => {
        let session = sessions.get(payload.sid);
        if (session) {
            return session;
        }

        const now = Math.floor(Date.now() / 1000);
        session = {
            payload,
            clientWs: null,
            closed: false,
            upstream: null,
            upstreamOpen: false,
            readyPromise: null,
            toUpstream: [],
            fromUpstream: [],
            fromUpstreamBytes: 0,
            // Session lifetime, independent of the token's short attach
            // window; never shorter than the token so the sid stays
            // registered (single-use) for as long as the token is valid.
            expiresAt: Math.max(now + config.maxSessionSeconds, payload.exp),
            sessionTimer: null,
            attachTimer: null,
        };
        session.sessionTimer = setTimeout(() => {
            log('session-timeout', { sid: payload.sid });
            closeSession(session, 4408, 'session timeout');
        }, Math.max(1000, config.maxSessionSeconds * 1000));
        session.sessionTimer.unref();
        // A prewarmed upstream whose browser never attaches is released
        // when the token expires.
        session.attachTimer = setTimeout(() => {
            if (!session.clientWs) {
                log('attach-timeout', { sid: payload.sid });
                closeSession(session, 4408, 'attach timeout');
            }
        }, Math.max(1000, (payload.exp - now) * 1000));
        session.attachTimer.unref();
        sessions.set(payload.sid, session);
        session.readyPromise = createUpstream(session);
        session.readyPromise.catch(() => {});

        return session;
    };

    httpServer.on('upgrade', (req, socket, head) => {
        const requestPath = (req.url || '').split('?')[0];
        const prefix = config.pathPrefix + '/';
        if (requestPath.endsWith('/prepare') || requestPath.indexOf(prefix) !== 0) {
            socket.destroy();

            return;
        }
        wss.handleUpgrade(req, socket, head, (ws) => {
            wss.emit('connection', ws, req);
        });
    });

    wss.on('connection', (clientWs, req) => {
        const token = req.url.split('?')[0].slice(config.pathPrefix.length + 1);
        let payload;
        try {
            payload = verifyToken(token, config.secret);
        } catch (err) {
            log('reject', { reason: err.message });
            clientWs.close(4401, 'unauthorized');

            return;
        }

        const session = getOrCreateSession(payload);
        if (session.closed) {
            clientWs.close(4401, 'token already used');

            return;
        }
        if (session.clientWs) {
            clientWs.close(4409, 'console already attached');

            return;
        }
        session.clientWs = clientWs;
        clearTimeout(session.attachTimer);
        for (const buffered of session.fromUpstream.splice(0)) {
            clientWs.send(buffered);
        }
        session.fromUpstreamBytes = 0;
        log('viewer-connected', { sid: payload.sid, host: payload.host });

        clientWs.on('message', (data) => {
            if (session.upstreamOpen) {
                session.upstream.send(data);
            } else {
                session.toUpstream.push(data);
            }
        });
        clientWs.on('close', () => closeSession(session, 1000, 'viewer closed'));
        clientWs.on('error', () => closeSession(session, 1011, 'viewer error'));
    });

    return httpServer;
}

function log(event, fields) {
    console.log(JSON.stringify(Object.assign({ ts: new Date().toISOString(), event }, fields)));
}

if (require.main === module) {
    let config;
    try {
        config = loadConfig();
    } catch (err) {
        console.error('pvewhmcs-console-relay: failed to load config.json (' + err.message + ').');
        console.error('Copy config.example.json to config.json in this same directory and set "secret" to the same value as the WHMCS Module Config "Console Relay Secret".');
        process.exit(1);
    }

    const server = createRelay(config);
    // PORT is honored so any standard process manager (systemd
    // Environment=, Docker, etc.) can override it; falls back to
    // config.json's listenPort otherwise.
    const listenPort = process.env.PORT || config.listenPort;
    server.listen(listenPort, '127.0.0.1', () => {
        log('listening', { port: listenPort, pathPrefix: config.pathPrefix });
    });
}

module.exports = { loadConfig, verifyToken, decodeTokenV1, decodeTokenV2, base64UrlDecode, createRelay, createSessionRegistry };
