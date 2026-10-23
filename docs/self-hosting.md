# Self-hosting

The agentio server is one Go binary, run as a Docker container you build from its source. Accounts, pairing and the sealed relay between your computers and your browsers all work on your own server, with an SQLite database, without a hosted agentio account or subscription.

## What you run, and what you don't

The server and the wire protocol are published as source ([zazencodes/agentio-server](https://github.com/zazencodes/agentio-server)); there are no prebuilt server binaries or images. The `agentio` CLI and the web app are proprietary, distributed as builds only:

- **The official CLI works with your server.** On each computer, `agentio login --server https://agentio.example.com`. Pairing, sealing, signatures and the pinned keys are the same as with the hosted service: whoever runs the server, including you, can neither read what your agents and your browser say to each other nor get text or decisions into your agents (docs/api.md §5, §6, §9).
- **The official web app works with your server, hosted by you.** Every release has the built app, `agentio-web-<version>.tar.gz`: a static site you put on any web host with a file naming your server ([The web app](#the-web-app)). The app at app.agentio.sh talks only to api.agentio.sh. Your server itself is an API and relay only; it serves no web pages. Manage accounts with `agentio-server user …` and the API; people log in to the web app with their username and password.
- **Your own clients** can implement [docs/api.md](api.md), which documents everything the server sends and receives, including pairing, sealed frames and the signed envelopes (with shared test vectors in `protocol/testdata/`).

## What the server keeps

Accounts, tokens, the public keys of each paired computer and browser, which computer may relay to which browser, and each browser's Web Push subscription. Nothing an agent or a person writes, no names and no paths: every project, session, notification, request, reply and setting passes through the server's memory, encrypted, on its way to a live connection, and is never written to disk, a log or the database. History lives on the computer (the CLI's bridge) and in the browser. Pairings in flight live in memory for 10 minutes; a restart loses them.

## Running it

Clone [zazencodes/agentio-server](https://github.com/zazencodes/agentio-server) (each release is a tag), then build and
start the container; the Compose file builds the image from the tree:

```sh
cd deploy/compose
# edit AGENTIO_PUBLIC_URL in docker-compose.yml
docker compose up -d
docker compose exec agentio agentio-server user add --role admin you
```

`docker compose exec agentio agentio-server version` prints the release and the source revision it was built from.
Put a reverse proxy that terminates TLS in front of it ([below](#reverse-proxy-and-tls)).

## Configuration

All settings are documented in [`deploy/examples/server.yml`](../deploy/examples/server.yml). Every key can also be an environment variable: `public-url` → `AGENTIO_PUBLIC_URL`. Unknown keys are an error. `public-url` must be the public URL users reach. Pairing codes carry the URL the CLI was given with `agentio login --server`.

Storage: one SQLite database, `agentio.db` in `data-dir`. Migrations run automatically at startup. The server runs as a single instance (relay sockets, presence and pairings in flight live in memory), and its database holds only accounts, tokens and public keys, so it needs no database server. Put it behind one reverse proxy.

## Reverse proxy and TLS

The relay uses WebSockets and pairing uses long polls (up to 60 seconds), so turn buffering off and allow long timeouts. Caddy:

```
agentio.example.com {
	reverse_proxy localhost:2586
}
```

nginx:

```nginx
location / {
  proxy_pass http://127.0.0.1:2586;
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_buffering off;
  proxy_read_timeout 3h;
  client_max_body_size 2m;   # relay messages are at most 1 MiB
}
```

Set `trust-proxy: true` so rate limits use the client IP from `X-Forwarded-For`. The server speaks plain HTTP: the proxy terminates TLS. Configure your proxy's access log the way you want it: the server's own request log never records paths, query strings or IP addresses, but a proxy's default log does (`?token=` carries a browser's token on the relay socket).

## The web app

The web app is a static site: HTML, JavaScript, a service worker and icons, with no server side. It isn't served by your agentio server; host it on its own origin, such as `https://app.example.com`, with any web server or static host. Take `agentio-web-<version>.tar.gz` from the [release](https://github.com/zazencodes/agentio-releases/releases) with the same version as your server, check it against the release's `checksums.txt`, and add `agentio.json`:

```sh
tar -xzf agentio-web-v1.2.3.tar.gz
echo '{"server": "https://agentio.example.com"}' > agentio-web-v1.2.3/agentio.json
sudo mkdir -p /srv && sudo cp -R agentio-web-v1.2.3 /srv/agentio-web
```

**`agentio.json`** is the only setting, read by the app and its service worker when they start. It must be exactly `{"server": "<your server>"}`: https, scheme, host and an optional port only (no path, no trailing slash), the same URL you give `agentio login --server`, since the app pairs only with codes naming exactly that server. `http` works only for a server on `localhost` or `127.0.0.1`, for local testing. Without a valid file the app shows what's wrong and does nothing else; it never falls back to another server. Whoever hosts the app decides which server it trusts, as they already decide its code; your agentio server has no say in it. The release bundle has no `agentio.json`, so updating means replacing every other file and keeping yours.

The web host must:

- **Use HTTPS on a domain name** (not an IP address). Passkeys (WebAuthn), WebCrypto, IndexedDB and service workers require a secure context; `localhost` counts as one for local checks.
- **Serve the app at the root of its own origin.** Its service worker is `/sw.js` with scope `/`. Keep the origin stable: pairings and the passkeys for sensitive answers are bound to it, and moving the app means pairing every browser again.
- **Serve `index.html` for every path that isn't a file** (`/pair`, `/sessions/…`): the app routes in the browser.
- **Send the security headers below** on every response. The Content Security Policy must let the app connect to your server over `https` and `wss` (the relay is a WebSocket); the rest keeps script to the app's own files. `index.html`, `sw.js` and `agentio.json` must not be cached without revalidation (`Cache-Control: no-cache`); `/static/*` is content-hashed and may be cached forever.

Caddy, with the bundle in `/srv/agentio-web`:

```
app.example.com {
	root * /srv/agentio-web
	header {
		Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://agentio.example.com wss://agentio.example.com; img-src 'self' https: data: blob:; media-src 'self' https: blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'self'; manifest-src 'self'"
		X-Frame-Options DENY
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		Strict-Transport-Security "max-age=31536000"
		Permissions-Policy "camera=(), microphone=(), geolocation=()"
	}
	@static path /static/*
	header @static Cache-Control "public, max-age=31536000, immutable"
	@other not path /static/*
	header @other Cache-Control no-cache
	try_files {path} /index.html
	file_server
}
```

The bundle's `_headers` file holds the same headers for hosts that read that format (Cloudflare, Netlify), with a policy that lets the app connect to any server (`https:`, `wss:`, and `http:`/`ws:` for local testing), so it needs no editing; other hosts ignore it.

## Users and access

```sh
agentio-server user add --role admin alex       # password from a prompt or AGENTIO_PASSWORD
agentio-server user list                        # also: user del, user change-pass, user change-role (the only admin tools)
```

People sign in to the web app with their username and password (`POST /api/v1/auth/password`), which gives that
browser a 30-day token. The Account page lists every signed-in browser and computer and signs any of them out; a
token's secret is shown only once, to the browser or computer it was issued to.

Users delete their own account in the web app's Account page (`DELETE /api/v1/account`, confirmed with their password); `user del` does the same for an operator. Either removes the account, its tokens, paired computers and browsers and Web Push subscriptions.

Agent features always require an account, and nothing reaches an agent unless a browser the computer pinned at pairing signed it. Pairing needs a signed-in browser: the computer joins that browser's account.

## Web Push

Browsers get notifications through Web Push while no tab is open. Generate keys with `agentio-server webpush keys`, then set `webpush-public-key`, `webpush-private-key` and `webpush-contact`. Keep the private key secret and keep it across updates: changing keys makes every browser subscribe again.

When a computer sends a notification to a browser with no live connection, the server hands the computer's sealed push frame, unread, to the browser's push service (TTL 12 hours) and forgets it. The push service (Google, Mozilla, Microsoft or Apple) sees a sealed payload and its timing. Subscriptions must point at one of those services; a server whose `public-url` is on `localhost` also accepts `http` subscriptions on a loopback host, for development.

## Limits

Rate limits protect the server from abuse, and are fixed: each caller (each paired computer has its own bucket, as does each account and each anonymous IP) may make 60 requests, then one more every 5 seconds; each IP may fail 10 sign-ins or tokens, then one more every 30 seconds. Addresses in `rate-limit-exempt-ips` and admins are exempt from the request limit.

## Backups

Back up the database with SQLite's online backup command while the server runs:

```sh
sqlite3 /var/lib/agentio/agentio.db ".backup '/backups/agentio-$(date +%F).db'"
```

To restore, stop the server, put the file back as `agentio.db`, start it. A backup holds accounts, tokens and public keys, never content.

## Upgrading

Check out the new release tag and run `docker compose up -d --build`. Database migrations run automatically and are forward-only, so back up first. Bridges and browsers reconnect on their own; pairings in flight are lost and must be started again.

## Health and monitoring

- `GET /api/v1/health` → `{"healthy": true}` (checks the database).
- Logs go to stderr (`log-format: json` for structured logs). At `log-level: debug` each request is logged with its method, route template, status and duration only.
