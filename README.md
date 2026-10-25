# pvewhmcs-console-relay

Console Relay for [Proxmox VE for WHMCS](https://github.com/MasterMindTIBR/Proxmox-VE-for-WHMCS).

Bridges a browser's noVNC WebSocket to Proxmox's `vncwebsocket` API endpoint,
so Proxmox never needs a public IP, a PTR record, or to share a registrable
domain with WHMCS for cookie purposes. Only this relay needs network
reachability to Proxmox on port 8006 — the same reachability the WHMCS
module already needs for provisioning.

This relay is deployed alongside the WHMCS module; see that project's
[README "noVNC" section](https://github.com/MasterMindTIBR/Proxmox-VE-for-WHMCS#-2-novnc-console-tunnel-client-area)
for the WHMCS-side setup (restricted `vnc@pve` user, Module Config fields).

## Run this standalone — it's a long-lived WebSocket server

Don't deploy this behind a generic app-server/PaaS-style process manager.
Those are built around short request/response cycles and often reverse-bind
or proxy the port your app listens on, which breaks a raw `http.Server` +
`ws` process holding many long-lived duplex WebSocket connections open for
the duration of each console session. Run it
as its own process (systemd below) and reverse-proxy to it directly with a
web server that has first-class WebSocket support (nginx, or Apache with
`mod_proxy_wstunnel`).

## How it fits together

Two supported layouts, both fronting a single standalone `node server.js`
process:

```text
Same domain:  Browser --wss--> WHMCS domain (443) --reverse proxy /pve-console-ws/--> relay (127.0.0.1:8765) --wss--> Proxmox:8006 (private)
Subdomain:    Browser --wss--> vnc.example.com (443) -----------reverse proxy /---------> relay (127.0.0.1:8765) --wss--> Proxmox:8006 (private)
```

`pvewhmcs_noVNC()` first asks the relay to open the Proxmox WebSocket and wait
for the browser (`POST <pathPrefix>/<token>/prepare`, sent server-to-server
by WHMCS; the relay sends no CORS headers, so a browser on another origin
cannot use it). It then hands the already-connected session to noVNC. This
prewarm/handoff is intentional: the Proxmox VNC proxy has a short attachment
timeout, while a browser may still be loading a slow tab or noVNC assets.
The relay verifies the same short-lived, single-use token for both requests.

Current WHMCS modules mint **v2** tokens: the payload (Proxmox host, port,
path and the `vnc@pve` ticket) is encrypted with AES-256-GCM under a key
derived from the shared `secret`, so the browser holding the URL cannot read
it. The relay still accepts legacy **v1** tokens (HMAC-signed, readable) from
older module versions.

If you deploy the relay on its own subdomain, set that subdomain in WHMCS
under **Addons > Proxmox VE for WHMCS > Config > Console Relay Host** (and
**Console Relay Port** only if it isn't the default `443`). Leave both blank
to keep sharing the WHMCS domain instead.

## 1. Deploy the relay

Needs a supported Node.js LTS (22 or later).

```bash
useradd --system --home /nonexistent --shell /usr/sbin/nologin pverelay
git clone https://github.com/MasterMindTIBR/pvewhmcs-console-relay.git /opt/pvewhmcs-console-relay
cd /opt/pvewhmcs-console-relay
npm ci --omit=dev
cp config.example.json config.json
# edit config.json: set "secret" to the same value as WHMCS's Module Config
# "Console Relay Secret" (generate one with: openssl rand -hex 32)
chown root:pverelay config.json && chmod 640 config.json   # the secret must not be world-readable
```

`config.json` options besides `secret`, `listenPort`, `pathPrefix`:

| Key | Default | Meaning |
| --- | --- | --- |
| `maxSessionSeconds` | 14400 | hard limit of a console session, counted from the prepare; closed with code 4408 |
| `pingIntervalSeconds` | 30 | WebSocket ping to the browser and to Proxmox, so idle consoles survive reverse-proxy read timeouts. A side that has not answered by the next ping is dropped and the session closed |
| `maxPayloadBytes` | 1048576 | largest WebSocket message; also the byte cap of each queue held before the viewer/upstream connects (plus at most 1024 messages per queue) |
| `maxBufferedBytes` | 524288 | once both sides are connected, a side with more unsent data than this is too slow and the session is closed (backpressure) |
| `maxSessions` | 50 | open sessions (prewarmed, attached, or closed with a socket still closing) in this process; over it, `/prepare` and the WebSocket upgrade answer HTTP 429. Size it with `MemoryMax`: each session can hold about 2 × (`maxBufferedBytes` + `maxPayloadBytes`) |
| `maxSessionsPerTarget` | 3 | open sessions for the same Proxmox host and console path (one VM); HTTP 429 over it |
| `closeGraceSeconds` | 5 | how long a closing socket may wait for the peer's close frame before the relay drops it. Until then the session still counts against both caps |
| `upstreamCaFile` | — | PEM of the CA that signed the Proxmox certificates (e.g. the cluster's `/etc/pve/pve-root-ca.pem`); without it the system CAs are used |
| `allowInsecureUpstream` | `false` | TLS to Proxmox is **always verified**; only `true` lets a token minted with TLS verification off (WHMCS server "Secure" unticked) skip it |
| `acceptLegacyV1` | `false` | accept the legacy v1 tokens of WHMCS modules older than v1.3.6 (readable by the browser) |

Create `/etc/systemd/system/pvewhmcs-console-relay.service`:

```ini
[Unit]
Description=Proxmox VE for WHMCS - Console Relay
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/pvewhmcs-console-relay
ExecStart=/usr/bin/node server.js
Restart=on-failure
User=pverelay
Group=pverelay
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=256M

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now pvewhmcs-console-relay
```

Confirm it's alive locally before wiring up the reverse proxy:

```bash
curl http://127.0.0.1:8765/healthz
# ok
```

## 2. Reverse-proxy it

The relay only listens on `127.0.0.1`; it is never exposed directly.
Whatever serves the public domain/subdomain must reverse-proxy to it,
passing the WebSocket `Upgrade` header through untouched.

**Dedicated subdomain** (proxy the whole thing):

Nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
}
```

Apache (needs `mod_proxy_wstunnel` and `mod_rewrite` enabled):

```apache
RewriteEngine On
RewriteCond %{HTTP:Upgrade} =websocket [NC]
RewriteRule ^/(.*)   ws://127.0.0.1:8765/$1   [P,L]
ProxyPass        / http://127.0.0.1:8765/
ProxyPassReverse / http://127.0.0.1:8765/
```

**Sharing the WHMCS domain instead** (proxy only the one path prefix):

```nginx
location /pve-console-ws/ {
    proxy_pass http://127.0.0.1:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
}
```

Adjust the port in any of the above to match `listenPort` in `config.json`.

## 3. Verify

1. In WHMCS Client Area, request a console for an active VM/CT.
2. The WHMCS launcher must wait for the relay's prewarm response before
   opening noVNC. The browser should then connect to
   `wss://<console-relay-host>/pve-console-ws/<token>` — where
   `<console-relay-host>` is either your dedicated subdomain (Console Relay
   Host in Module Config) or the WHMCS domain if you left that blank. Check
   DevTools' Network tab; it must **not** be a direct connection to the
   Proxmox host, and the upgrade response should be `101 Switching
   Protocols`, not a stall.
3. If the upgrade fails immediately with HTTP 401, the token was invalid/expired —
   check the relay's log (`journalctl -u pvewhmcs-console-relay`) and
   confirm both secrets match exactly.
4. If noVNC reports `1011` with reason `upstream error`, the relay reached
   the browser but could not open Proxmox's WebSocket. Inspect the same log
   for `upstream-error`, `upstream-http-error`, or `upstream-close`:
   - `ENOTFOUND`, `EAI_AGAIN`, `ECONNREFUSED`, or `ETIMEDOUT` means the relay
     cannot resolve or reach the configured Proxmox hostname/port.
   - Certificate errors mean the relay cannot validate the Proxmox certificate;
     fix the certificate/hostname or deliberately disable Secure for that
     WHMCS server.
   - An HTTP status in `upstream-http-error` means Proxmox rejected the
     WebSocket request; verify the `vnc@pve` user has only the documented
     `VM.Console` permission and that the VM still exists.
5. If the WebSocket never reaches `open`, the reverse proxy likely isn't
   passing the `Upgrade` header through — re-check Section 2.

## Security notes

- Rotate `secret` by updating it in both places (WHMCS Module Config and
  `config.json`) — old, in-flight tokens simply stop validating.
- The relay never touches the WHMCS database or PVE credentials beyond what
  each token carries. A token only authorizes attaching to its session
  during its short lifetime (120 s, set by the WHMCS module); a prewarmed
  session that no browser attaches to in that window is closed. Once a viewer
  is attached, the session lasts until either side closes or
  `maxSessionSeconds` (default 14400) elapses. Each token's `sid` works once.
- The token is checked before the WebSocket upgrade: an invalid or expired
  token gets HTTP 401, a used token or a second viewer HTTP 409, and a
  session cap HTTP 429. No WebSocket is opened for a refused request.
- The token travels in the URL path. Keep it out of every proxy log: no
  `access_log` for the console location, and an `error_log` level that does
  not record request lines (`crit`), including on the front reverse proxy.
- **Upgrading from earlier versions:** TLS to Proxmox is now always verified
  and v1 tokens are refused. Point `upstreamCaFile` at the Proxmox CA (or
  install valid certificates) before upgrading, or set
  `allowInsecureUpstream: true` as a temporary, explicit opt-out.
- A suspended WHMCS service keeps an already open console until it closes or
  `maxSessionSeconds` elapses (the example uses 4 h).
- Keep `listenPort` bound to `127.0.0.1` (already the default) so it is only
  reachable through the reverse proxy, never directly from the Internet.

## License

Copyright (C) junglivre. Licensed under the GNU General Public License v3.0
or later — see [LICENSE](LICENSE).
