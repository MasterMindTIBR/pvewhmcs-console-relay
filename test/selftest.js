'use strict';
// Self-test of the relay hardening against a fake TLS upstream. Needs the
// openssl CLI (throwaway self-signed CA/cert in a temp dir). Run: npm test
const assert = require('assert');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');
const path = require('path');
const WebSocket = require('ws');
const { createRelay, verifyToken } = require('../server');

const SECRET = crypto.randomBytes(32).toString('hex');
const CTX = 'pvewhmcs-console-token-v2';

function b64url(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Same format as pvewhmcs_build_console_token() (v2) and the legacy v1.
function tokenV2(payload) {
    const key = crypto.createHash('sha256').update(CTX + '|' + SECRET).digest();
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from(CTX));
    const ct = Buffer.concat([c.update(JSON.stringify(payload)), c.final()]);

    return 'v2.' + b64url(Buffer.concat([iv, ct, c.getAuthTag()]));
}
function tokenV1(payload) {
    const enc = b64url(Buffer.from(JSON.stringify(payload)));

    return enc + '.' + crypto.createHmac('sha256', SECRET).update(enc).digest('hex');
}

function certs(dir) {
    const o = (...a) => execFileSync('openssl', a, { cwd: dir, stdio: 'ignore' });
    o('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=test-ca');
    o('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'srv.key', '-out', 'srv.csr', '-subj', '/CN=127.0.0.1');
    fs.writeFileSync(path.join(dir, 'ext.cnf'), 'subjectAltName=IP:127.0.0.1\n');
    o('x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'srv.pem', '-days', '1', '-extfile', 'ext.cnf');
}

function listen(server) {
    return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
}

// Resolves with the close code, or the HTTP status when the upgrade is refused.
function viewer(relayPort, token, send, opts) {
    return new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/pve-console-ws/${token}`, opts);
        let got = '';
        ws.on('open', () => { if (send) ws.send(send); });
        ws.on('message', (d) => { got += d.toString(); if (got === 'hello') ws.close(1000); });
        ws.on('close', (code) => resolve({ code, got }));
        ws.on('unexpected-response', (_req, res) => resolve({ http: res.statusCode, got }));
        ws.on('error', () => {});
    });
}

function prepare(relayPort, token) {
    return new Promise((resolve) => {
        const req = http.request({ host: '127.0.0.1', port: relayPort, method: 'POST', path: `/pve-console-ws/${token}/prepare` }, (res) => { res.resume(); resolve(res.statusCode); });
        req.end();
    });
}

(async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-selftest-'));
    certs(dir);
    let upstreamDelay = 0;
    const up = https.createServer({ key: fs.readFileSync(path.join(dir, 'srv.key')), cert: fs.readFileSync(path.join(dir, 'srv.pem')) });
    const upWss = new WebSocket.Server({ noServer: true });
    up.on('upgrade', (req, sock, head) => {
        if (req.url.startsWith('/deny')) {
            sock.end('HTTP/1.1 401 No ticket\r\nContent-Length: 0\r\n\r\n');

            return;
        }
        setTimeout(() => upWss.handleUpgrade(req, sock, head, (ws) => ws.send('hello')), upstreamDelay);
    });
    const upPort = await listen(up);

    const base = { secret: SECRET, pathPrefix: '/pve-console-ws', maxSessionSeconds: 60, pingIntervalSeconds: 1, maxPayloadBytes: 65536, acceptLegacyV1: false, allowInsecureUpstream: false };
    const withCa = createRelay(Object.assign({}, base, { upstreamCa: fs.readFileSync(path.join(dir, 'ca.pem')) }));
    const noCa = createRelay(base);
    const pCa = await listen(withCa);
    const pNo = await listen(noCa);
    const payload = () => ({ host: '127.0.0.1', port: upPort, path: 'x', cookie: 'c', sid: crypto.randomBytes(16).toString('hex'), exp: Math.floor(Date.now() / 1000) + 60 });
    const log = console.log; console.log = (m) => { if (process.env.DBG) process.stderr.write(m + '\n'); };

    // 1. v1 refused by default, accepted only when opted in.
    assert.throws(() => verifyToken(tokenV1(payload()), SECRET), /legacy v1/);
    assert.ok(verifyToken(tokenV1(payload()), SECRET, true).sid);
    assert.strictEqual((await viewer(pCa, tokenV1(payload()))).http, 401);

    // 2. v2 + trusted CA: data flows.
    assert.strictEqual((await viewer(pCa, tokenV2(payload()))).got, 'hello');

    // 3. Untrusted upstream cert is refused even when the token says verify:false.
    const r3 = await viewer(pNo, tokenV2(Object.assign(payload(), { verify: false })));
    assert.notStrictEqual(r3.got, 'hello');
    assert.strictEqual(r3.code, 1011);

    // 4. A viewer message above maxPayloadBytes closes the socket (1009).
    upstreamDelay = 500;
    assert.strictEqual((await viewer(pCa, tokenV2(payload()), Buffer.alloc(65537))).code, 1009);

    // 5. Viewer data buffered before the upstream opens is capped.
    const r5 = await new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${pCa}/pve-console-ws/${tokenV2(payload())}`);
        ws.on('open', () => { for (let i = 0; i < 3; i++) ws.send(Buffer.alloc(40000)); });
        ws.on('close', (code) => resolve(code));
        setTimeout(() => resolve('no close'), 3000);
        ws.on('error', () => {});
    });
    assert.strictEqual(r5, 1011);

    // 6. Zero-length frames count against the queue too (entry cap).
    const r6 = await new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${pCa}/pve-console-ws/${tokenV2(payload())}`);
        ws.on('open', () => { for (let i = 0; i < 2000; i++) ws.send(Buffer.alloc(0)); });
        ws.on('close', (code) => resolve(code));
        setTimeout(() => resolve('no close'), 3000);
        ws.on('error', () => {});
    });
    assert.strictEqual(r6, 1011);

    // 7. An attached viewer gets WebSocket pings (idle consoles survive proxy read timeouts).
    upstreamDelay = 0;
    const r7 = await new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${pCa}/pve-console-ws/${tokenV2(payload())}`);
        ws.on('ping', () => { ws.close(1000); resolve('ping'); });
        setTimeout(() => resolve('no ping'), 3000);
        ws.on('error', () => {});
    });
    assert.strictEqual(r7, 'ping');

    // 8. Garbage frames after a refused upgrade do not crash the process; another session keeps working.
    const held = new WebSocket(`ws://127.0.0.1:${pCa}/pve-console-ws/${tokenV2(payload())}`);
    held.on('error', () => {});
    await new Promise((r) => held.on('message', r));
    const refused = await new Promise((resolve) => {
        const s = net.connect(pCa, '127.0.0.1', () => {
            s.write('GET /pve-console-ws/v2.bogus HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');
            s.write(Buffer.from([0x81, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]));
        });
        let reply = '';
        s.on('data', (d) => { reply += d; });
        s.on('close', () => resolve(reply.split('\r\n')[0]));
        s.on('error', () => resolve(reply.split('\r\n')[0]));
    });
    assert.strictEqual(refused, 'HTTP/1.1 401 Unauthorized');
    assert.strictEqual(held.readyState, WebSocket.OPEN);
    assert.strictEqual((await viewer(pCa, tokenV2(payload()))).got, 'hello');
    held.close();

    // 9. Session caps: 429 globally and per host/VM.
    const capped = createRelay(Object.assign({}, base, { upstreamCa: fs.readFileSync(path.join(dir, 'ca.pem')), maxSessions: 3, maxSessionsPerTarget: 2 }));
    const pCap = await listen(capped);
    assert.strictEqual(await prepare(pCap, tokenV2(payload())), 200);
    assert.strictEqual(await prepare(pCap, tokenV2(payload())), 200);
    assert.strictEqual(await prepare(pCap, tokenV2(payload())), 429);
    assert.strictEqual(await prepare(pCap, tokenV2(Object.assign(payload(), { path: 'other' }))), 200);
    assert.strictEqual((await viewer(pCap, tokenV2(Object.assign(payload(), { path: 'third' })))).http, 429);

    // 10. A PVE HTTP error (401) closes the attached viewer instead of leaving it waiting.
    upstreamDelay = 0;
    const t10 = Date.now();
    const r10 = await viewer(pCa, tokenV2(Object.assign(payload(), { path: 'deny' })));
    assert.strictEqual(r10.code, 1011);
    assert.ok(Date.now() - t10 < 3000);

    // 11. A viewer that stops answering pings is terminated within two ping cycles.
    const r11 = await new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${pCa}/pve-console-ws/${tokenV2(payload())}`, { autoPong: false });
        ws.on('close', (code) => resolve(code));
        ws.on('error', () => {});
        setTimeout(() => resolve('still open'), 4000);
    });
    assert.strictEqual(r11, 1006);

    // 12. A used token is refused with 409 (tombstone without the PVE cookie).
    const used = tokenV2(payload());
    await viewer(pCa, used);
    assert.strictEqual((await viewer(pCa, used)).http, 409);

    // 13. The session limit closes the console with 4408.
    const short = createRelay(Object.assign({}, base, { upstreamCa: fs.readFileSync(path.join(dir, 'ca.pem')), maxSessionSeconds: 1 }));
    const pShort = await listen(short);
    const r13 = await new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${pShort}/pve-console-ws/${tokenV2(payload())}`);
        ws.on('close', (code) => resolve(code));
        ws.on('error', () => {});
    });
    assert.strictEqual(r13, 4408);

    console.log = log;
    console.log('SELFTEST OK');
    process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
