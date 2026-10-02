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
for the browser. It then hands the already-connected session to noVNC. This
prewarm/handoff is intentional: the Proxmox VNC proxy has a short attachment
timeout, while a browser may still be loading a slow tab or noVNC assets.
The relay verifies the same short-lived, HMAC-signed token for both requests.

If you deploy the relay on its own subdomain, set that subdomain in WHMCS
under **Addons > Proxmox VE for WHMCS > Config > Console Relay Host** (and
**Console Relay Port** only if it isn't the default `443`). Leave both blank
to keep sharing the WHMCS domain instead.

## 1. Deploy the relay

```bash
git clone https://github.com/MasterMindTIBR/pvewhmcs-console-relay.git /opt/pvewhmcs-console-relay
cd /opt/pvewhmcs-console-relay
cp config.example.json config.json
# edit config.json: set "secret" to the same value as WHMCS's Module Config
# "Console Relay Secret" (generate one with: openssl rand -hex 32)
npm install --omit=dev
```

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
User=<a dedicated non-root system user>

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
3. If it fails immediately with code `4401`, the token was invalid/expired —
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
  each token carries. The signed token is held only until the browser handoff
  completes and expires after five minutes.
- Keep `listenPort` bound to `127.0.0.1` (already the default) so it is only
  reachable through the reverse proxy, never directly from the Internet.

## License

Copyright (C) junglivre. Licensed under the GNU General Public License v3.0
or later — see [LICENSE](LICENSE).
