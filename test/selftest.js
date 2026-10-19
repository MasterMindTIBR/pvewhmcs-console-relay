'use strict';
// Self-test of the relay hardening against a fake TLS upstream. Needs the
// openssl CLI (throwaway self-signed CA/cert in a temp dir). Run: npm test
const assert = require('assert');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const fs = require('fs');
const https = require('https');
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

// Connects a viewer and resolves with how the session ended.
function viewer(relayPort, token, send) {
    return new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${relayPort}/pve-console-ws/${token}`);
        let got = '';
        ws.on('open', () => { if (send) ws.send(send); });
        ws.on('message', (d) => { got += d.toString(); if (got === 'hello') ws.close(1000); });
        ws.on('close', (code) => resolve({ code, got }));
        ws.on('error', () => {});
    });
}

(async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-selftest-'));
    certs(dir);
    let upstreamDelay = 0;
    const up = https.createServer({ key: fs.readFileSync(path.join(dir, 'srv.key')), cert: fs.readFileSync(path.join(dir, 'srv.pem')) });
    const upWss = new WebSocket.Server({ noServer: true });
    up.on('upgrade', (req, sock, head) => setTimeout(() => upWss.handleUpgrade(req, sock, head, (ws) => ws.send('hello')), upstreamDelay));
    const upPort = await listen(up);

    const base = { secret: SECRET, pathPrefix: '/pve-console-ws', maxSessionSeconds: 60, maxPayloadBytes: 65536, acceptLegacyV1: false, allowInsecureUpstream: false };
    const withCa = createRelay(Object.assign({}, base, { upstreamCa: fs.readFileSync(path.join(dir, 'ca.pem')) }));
    const noCa = createRelay(base);
    const pCa = await listen(withCa);
    const pNo = await listen(noCa);
    const payload = () => ({ host: '127.0.0.1', port: upPort, path: 'x', cookie: 'c', sid: crypto.randomBytes(16).toString('hex'), exp: Math.floor(Date.now() / 1000) + 60 });
    const log = console.log; console.log = (m) => { if (process.env.DBG) process.stderr.write(m + '\n'); };

    // 1. v1 refused by default, accepted only when opted in.
    assert.throws(() => verifyToken(tokenV1(payload()), SECRET), /legacy v1/);
    assert.ok(verifyToken(tokenV1(payload()), SECRET, true).sid);
    assert.strictEqual((await viewer(pCa, tokenV1(payload()))).code, 4401);

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

    console.log = log;
    console.log('SELFTEST OK');
    process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
