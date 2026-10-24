# agentio API

This is the wire contract shared by the server, the `agentio` CLI and its local bridge, and the web app. The Go types in `protocol/` are the canonical encoding of everything below. (The iOS and Android apps are paused and don't speak this version yet.)

All JSON uses `snake_case`. Times are Unix seconds (integers) unless noted. IDs are opaque strings.

The server is a **sealed relay**. It keeps accounts, public keys and who may talk to whom, and passes encrypted frames between a computer's bridge and the user's paired browsers while both are connected. Every project, session, notification, request, reply, decision and setting is signed and encrypted on the computer or in the browser and only decrypted on the other side. The server stores none of it and holds no key that can decrypt or sign it. History lives on the computer and in the browser.

---

## 1. Authentication

Requests carry a token in one form only (a malformed or unknown credential is a `401`, never silently ignored):

| Where | Form |
|---|---|
| Every endpoint | `Authorization: Bearer aio_4u4Moo52igfaCTJIvJkMiMb2bxxyJTSR` |
| Relay sockets only (browsers can't set headers on WebSockets, section 7) | `?token=aio_4u4Moo52igfaCTJIvJkMiMb2bxxyJTSR` |

A request with both, or with the `token` parameter on any other endpoint, is a `401`. Passwords are accepted by
`POST /api/v1/auth/password` alone (section 3), which exchanges them for a token.

A token has a public ID (`tok_` + 20 characters), which names it in listings and revocation, and a secret (`aio_` + 32
characters), which is shown once: when a sign-in or a pairing issues it. Token kinds:

| Kind | Issued to | Can |
|---|---|---|
| `user` | a signed-in browser | everything the user can do |
| `host` | a paired machine (`agentio login`) | open the host relay socket, start `agentio devices add` pairings, unpair its own devices and revoke itself; **cannot** manage the account |

Tokens authenticate *transport*, not *authority*: nothing reaches an agent unless it is signed by a device the machine pinned at pairing, and nothing is shown in the browser unless it is signed by a machine the browser pinned (section 9). There is no anonymous access to anything but the public endpoints marked "no auth".

Errors are always:

```json
{"code": "forbidden", "error": "You don't have access to this"}
```

The HTTP status says what kind of failure it is; `code` is a stable snake_case name for the specific one (`bad_request`, `slow_down`, …), and `error` is a sentence to show people. Clients switch on the status (and `code` where they need more) and display `error`.

---

## 2. Server metadata

| Method & path | Auth | Notes |
|---|---|---|
| `GET /api/v1/health` | no auth | `{"healthy": true}` |
| `GET /api/v1/config` | no auth | `{"version","enable_password_login","enable_signup","web_push_public_key"}`, plus any extension's fields (section 8) |

`enable_password_login` says whether `POST /api/v1/auth/password` signs in, `enable_signup` whether `POST /api/v1/account` creates accounts. `web_push_public_key` is the VAPID key browsers subscribe with, empty when Web Push isn't set up (section 7.3).

---

## 3. Accounts

| Method & path | Body | Notes |
|---|---|---|
| `POST /api/v1/account` | `{"username","password"}` | Sign up (if enabled), no auth |
| `POST /api/v1/auth/password` | `{"username","password"}` | Sign in, no auth: a `user` token that expires after 30 days → `IssuedToken`. Failures count against the IP's login budget (`429` once it is spent) |
| `GET /api/v1/account` | | `{"username","role","tokens":[Token]}`, plus any extension's fields (section 8). A host token sees no tokens |
| `DELETE /api/v1/account` | `{"password"}` | Deletes the account, its machines, devices and tokens. Confirmed with the account's password. Admins can't delete their own account |
| `POST /api/v1/account/password` | `{"password","new_password"}` | |
| `DELETE /api/v1/account/tokens/{id}` | | Revokes a token of the account (user token): signs that browser or computer out, or this one, and closes its relay sockets |

`Token` is `{"id","kind","label","last_access","expires","current"}`, never the secret; `current` marks the token
that made the request. `IssuedToken` is `{"id","token","kind","label","expires"}`, the only response with a secret.

---

## 4. Keys and IDs

* Every key is **P-256**. Signing keys are ECDSA with SHA-256; encryption keys are ECDH.
* A public key is encoded as base64url (no padding) of its 65-byte uncompressed X9.63 form (`04 || X || Y`).
* Signer IDs come from the signing key: `hst_` (hosts) or `dev_` (devices) + the first 20 characters of lowercase base32 (no padding) of sha256(the 65 raw bytes). A host's ID is therefore fixed by its key.
* A **host** (a computer's bridge) has a signing key and an encryption key, kept in the CLI's config directory (`0600`).
* A **device** (a paired browser profile) has a signing key (a non-extractable WebCrypto ECDSA key in IndexedDB), a **sensitive key** (an ES256 WebAuthn credential that needs user verification for every use, section 9.6) and an encryption key (a non-extractable WebCrypto ECDH key in IndexedDB). Its ID comes from its signing key.
* Both sides pin each other's keys at pairing (section 5). A key the server hands out is never trusted; only pinned keys are.

---

## 5. Pairing (`agentio login`, `agentio devices add`)

Pairing exchanges public keys over the terminal's code, which the server never sees.

1. The CLI creates (once) its host keys, a pairing ID `pair_…` (`NewRandomID`) and a 32-byte pairing secret `K`, and registers the pairing:

   ```
   POST /api/v1/pair   (no auth; the host token for `agentio devices add`)
     {"id":"pair_…","host_key":"<host signing key>","host_enc_key":"<host encryption key>"}
     → {"id":"pair_…","secret":"<host poll secret>","expires":1760659800}
   ```

   `host_key` must be new to the server unless the request carries that host's own token, and then `host_enc_key` must be the one the server already holds for it (`409` otherwise). Every pairing is claimed by a signed-in browser (step 3). Pairings live only in the server's memory and expire after 10 minutes; a restart loses them (start again). Each client IP (each /64 for IPv6) may hold a few unclaimed pairings at once; starting another replaces its oldest.

2. It shows `agentio://pair?s=<url-encoded server base URL>&p=<pair id>&h=<host signing key>&k=<K>`. `K` is never sent to the server. The user pastes it into the browser's `/pair` form; it is never placed in a browser URL.

3. The browser creates (once per profile and server) its three device keys and claims:

   ```
   POST /api/v1/pair/{id}/claim   (user token)
     {"device_key","device_sensitive_key","device_sensitive_origin","device_enc_key","sealed_name","mac"}
     → {"secret":"<device poll secret>","expires":1760659800}
   ```

   * `sealed_name` = `seal(HKDF(K, "agentio/v1/pair-name"), device_name, aad = "agentio/v1/pair-name\n" + pair_id)` (section 6.1). `device_name` is 1–64 characters with no control characters; the host rejects (never truncates) anything else. The server only checks that `sealed_name` is at most 512 characters.
   * `mac = base64url(HMAC-SHA256(K, "agentio/v1/pair\n" + pair_id + "\n" + host_key + "\n" + device_key + "\n" + device_sensitive_key + "\n" + device_enc_key + "\n" + device_name + "\n" + device_sensitive_origin))`.
   * `device_sensitive_origin` is the exact app origin (scheme, host and port; HTTPS, or `http://localhost:<port>` for development), bound for WebAuthn (section 9.6).

   A pairing can be claimed once (`409` after that), and only with a user token (`401` without one, `403` for a host token): a new machine joins that account. Claiming an existing host (`devices add`) needs a user token of that host's account (`409` for another account), so a host token can never be turned into a user token. No pairing creates an account or issues a user token.

4. Both sides long-poll the pairing with their own secret:

   ```
   GET /api/v1/pair/{id}?secret=<host or device poll secret>&wait=50   (no auth)
   ```

   | `status` | Meaning |
   |---|---|
   | `pending` | Waiting for a browser |
   | `claimed` | A browser claimed it; waiting for the terminal |
   | `confirmed` | The terminal confirmed |
   | `rejected` | The terminal declined |
   | `expired` | Not confirmed within 10 minutes |

   The host's view includes `"claim": {"device","device_key","device_sensitive_key","device_sensitive_origin","device_enc_key","sealed_name","mac"}` once claimed. The device's view includes, once confirmed, `"confirm": "<sealed confirmation>"`, `"host": {"id","key","enc_key"}` and `"username"`.

5. The CLI opens `sealed_name`, checks the name and the MAC, asks `Pair with "Alex's browser"? [y/N]` in the terminal, pins the device, and confirms with its signed transcript, sealed so the server can't read the host name:

   ```
   POST /api/v1/pair/{id}/confirm   {"secret":"<host poll secret>","confirm":"<sealed confirmation>"}
     → {"host_id":"hst_…","username":"alex","token":"aio_…"}     (token only for a new machine)
   POST /api/v1/pair/{id}/reject    {"secret":"<host poll secret>"}
   ```

   `confirm` = `seal(HKDF(K, "agentio/v1/pair-confirm"), JSON of the pair Envelope, aad = "agentio/v1/pair-confirm\n" + pair_id)`. The pair envelope (kind `pair`, section 9.3) is signed by the host key. On confirm the server records the host (new machines), the device (if new to the account) and the link between them (`host_devices`), and the pairing is done.

6. The browser opens the confirmation, checks the pair envelope against `host_key` from the code, that every device field is its own (keys, encryption key, origin and name), then pins the host: `{host_id, host_key, host_enc_key, host_name, server}`. The host's encryption key comes only from the signed confirmation.

Nothing about names, operating systems or versions reaches the server in plaintext.

---

## 6. Sealing

### 6.1 Sealing with the pairing secret

`HKDF(K, info)` is HKDF-SHA256 with input key `K` (32 bytes), an empty salt and `info`, giving 32 bytes. `seal(key, plaintext, aad)` is AES-256-GCM with a random 96-bit nonce, encoded as base64url(`nonce || ciphertext || tag`).

### 6.2 Sealed frames

Every frame between a host and a device is **sign-then-encrypt**:

1. The sender builds a signed Envelope (section 9.2), including WebAuthn assertions.
2. It derives the pair key for this host and device:
   `HKDF-SHA256(ikm = ECDH(own encryption key, peer encryption key) (the 32-byte X coordinate), salt = "", info = "agentio/v1/seal\n" + host_id + "\n" + device_id)` → 32 bytes, an AES-256-GCM key. The ECDH is static-static; the pair key is cached per pin. Both directions use the same key; the AAD carries the direction.
3. It encrypts the Envelope's JSON with a random 96-bit nonce and AAD
   `"agentio/v1/seal\n" + from + "\n" + to + "\n" + id + "\n" + time` (`time` in decimal).

```json
{"id": "frm_…", "from": "hst_…", "to": "dev_…", "time": 1760659200, "nonce": "<b64url, 12 bytes>", "ct": "<b64url, ciphertext || tag>"}
```

`id` is `NewRandomID("frm_")`, new for every frame, including every resend. `time` is when the frame was sealed. A host addressing several devices sends one sealed frame per device.

A recipient accepts a frame only if:

* `to` is itself and `from` is a peer it pinned (and whose encryption key it pinned);
* `time` is within 10 minutes of its own clock (in either direction), and it hasn't accepted a frame with this `id` in the last 20 minutes;
* it decrypts with the pair key and AAD;
* the inner Envelope's `signer` equals `from`, and the inner Envelope then passes the verification gates (sections 9.4, 9.5).

Anything else is rejected exactly like a bad signature: logged (rate-limited), counted, never acted on. Web Push payloads (section 7.3) are the one exception to the frame time window, since push services may hold them for hours; the service worker instead requires the signed push `time` within 12 hours (the push TTL) plus 2 minutes of skew, shows each push ID at most once (remembered in IndexedDB), and only shows them.

The browser's guard spans its tabs: every tab receives every frame for its device, so frame IDs are remembered in IndexedDB, and a tab accepts an update with a `reply` only for an RPC it sent itself and is still waiting on (each reply once). Live updates merge by `seq`, so a replayed one changes nothing.

`protocol/testdata/sealing-vectors.json` holds fixed keys, nonces and the sealed outputs of section 6.1 and 6.2; the Go and web tests check every one.

---

## 7. Relay

Two WebSockets, one per side, both authenticated by token (the `Authorization` header, or `?token=` from browsers):

* `GET /api/v1/relay/host` (host token): the bridge.
* `GET /api/v1/relay/device?device=dev_…` (user token): a paired browser tab. The device must belong to the token's user (`403` otherwise). Every open tab has its own connection.

Messages are JSON text messages of at most 1 MiB.

### 7.1 Client → server

```json
{"type":"frame","frame":SealedFrame}
{"type":"frame","frame":SealedFrame,"push":SealedFrame}
{"type":"pong"}
```

The server checks only that `frame.from` is the connection's own host or device, that `host_devices` links `from` and `to`, and that `push` (hosts only) has the same `from` and `to` as `frame`; an extension may also refuse it (section 8). It then writes `{"type":"frame","frame":…}` to every live connection of `to` and answers the sender:

```json
{"type":"relayed","id":"frm_…","to":"dev_…","result":"delivered"}
```

| `result` | Meaning |
|---|---|
| `delivered` | Written to at least one live socket of `to`. Nothing more: not read, not processed |
| `offline` | `to` has no live connection. The frame is dropped (its `push`, if any, is sent as Web Push, 7.3) |
| `refused` | Not relayed; `code` and `error` say why (`not_paired`: `from` and `to` aren't linked; an extension's own code when it refuses the frame) |

The server keeps no queue. Each side's own outbox decides what to send again (sections 10.4, 11.4). Nothing about a relayed frame is stored.

### 7.2 Server → client

```json
{"type":"hello","host":"hst_…"}                                            (host socket)
{"type":"hello","device":"dev_…","hosts":[{"host":"hst_…","online":true}]}  (device socket: every host linked to it)
{"type":"frame","frame":SealedFrame}
{"type":"relayed","id":"frm_…","to":"…","result":"delivered"|"offline"|"refused","code"?,"error"?}
{"type":"presence","host":"hst_…","online":true|false}                    (device sockets, when a linked host connects or drops)
{"type":"ping"}                                                             (every 30 s; answer with pong)
```

A host is online while it has a live relay connection. The server closes a socket whose token is revoked, whose host is deleted, or whose device is unpaired, and closes with code 1008 (policy violation) a socket that sends a malformed message, an unknown type, a frame whose `from` isn't its own, or a `push` from a device or with another `from`/`to` than its frame. Relay sockets need a token (section 1), so they can be closed when it is revoked.

### 7.3 Web Push

A host frame may carry `push`: a second, short sealed frame (kind `push`, section 9.3) for the same device. If the device has no live connection and has a Web Push subscription, the server sends the `push` frame's JSON as the Web Push payload (RFC 8291 encrypts it again for the push service, TTL 12 hours, urgency high) and then forgets it. The service worker opens it with the browser's keys from IndexedDB, verifies it against the pinned host and shows the notification. The bridge sends a push only for new requests and for events other than `progress`, and shortens the push text until the sealed `push` frame's JSON is at most 3000 bytes.

```
PUT    /api/v1/devices/{id}/webpush   {"endpoint","auth","p256dh"}   (user token)
DELETE /api/v1/devices/{id}/webpush
```

One subscription per device; `PUT` replaces it. `endpoint` must be an `https` URL of a known push service (Google FCM, Mozilla, Microsoft WNS, Apple), so the server can't be made to post to arbitrary hosts; a server whose own `public-url` is on a loopback host (development) also accepts `http` endpoints on a loopback host. A push service answering `404` or `410` deletes the subscription.

---

## 8. Server extensions

This document describes the server as published. A server built with an extension (another program around the same
server) may add endpoints next to these, fields to `GET /api/v1/config` and `GET /api/v1/account`, and a refusal of
relayed frames (a `refused` result with its own `code`, section 7.1). It may also give accounts no passwords, for a
server whose people sign in through its own endpoints: then `POST /api/v1/auth/password`, `POST /api/v1/account`,
`POST /api/v1/account/password` and `DELETE /api/v1/account` answer `403 no_passwords` (sign-up `403 signup_off`), and
`GET /api/v1/config` says `enable_password_login: false` and `enable_signup: false`. Otherwise an extension never
changes an endpoint, field or check described here. Clients ignore fields they don't know, and use an extension's endpoints only when its fields in
`GET /api/v1/config` say they are on.

---

## 9. Machines, devices and signatures

### 9.1 Machines and devices on the server

```
GET    /api/v1/hosts                         → {"hosts":[{"id","key","enc_key","online","created"}]}
DELETE /api/v1/hosts/{id}                    user token, or the host's own token (`agentio logout`)
GET    /api/v1/devices                       → {"devices":[{"id","key","sensitive_key","enc_key","sensitive_origin","hosts":["hst_…"],"created"}]}
DELETE /api/v1/devices/{id}                  user token: unpairs this device from every machine
DELETE /api/v1/hosts/{id}/devices/{device}   the host's own token (`agentio devices remove`) or a user token
```

Deleting a host revokes its token and closes its relay socket; deleting a device or a link closes the device's sockets for the affected hosts and stops the relay between them. The server knows no names: the browser shows each machine's name from its pin (and the machine's own signed updates), the bridge shows each device's name from its pins. Keys listed here are for display only; nobody trusts them (section 4).

### 9.2 Envelope

```json
{"v": 1, "kind": "command", "signer": "dev_…", "payload": "<base64url of the payload JSON bytes>", "sig": "<base64url of the DER signature>"}
```

The signature is ECDSA P-256/SHA-256 (ASN.1 DER, as Go's `ecdsa.SignASN1` produces) over the bytes `"agentio/v1/" + kind + "\n" + payload bytes`, so a signature for one kind is never valid for another. Verifiers check the signature over the exact payload bytes first and parse them only afterwards; nobody re-encodes a payload, so there is no canonical form. Unknown payload fields are ignored.

`protocol/testdata/signing-vectors.json` and `settings-vectors.json` hold test keys and envelopes produced by each implementation; the Go and web tests verify all of them.

### 9.3 Kinds

| Kind | Signed by | Payload |
|---|---|---|
| `pair` | host | `{"pair","host","host_key","host_enc_key","host_name","device","device_key","device_sensitive_key","device_sensitive_origin","device_enc_key","device_name","time"}` |
| `update` | host | section 10.2 |
| `push` | host | `{"id","host","session","request"?,"title","body","time"}` |
| `request` | host | `{"id","host","session","type","title","body","prefill"?,"options","sensitive","created","expires"}`; travels inside `update` items |
| `settings` | host | section 10.6; travels inside `update` |
| `sync` | device | `{"id","host","since","epoch","time"}` |
| `timeline` | device | `{"id","host","session","before","limit","time"}` |
| `command` | device | `{"id","host","session","text","created","expires"}` |
| `response` | device; the sensitive key when the request is `sensitive` | `{"request","request_hash","decision","text","time"}` |
| `cancel` | device | `{"host","command","time"}` |
| `delete` | device | `{"host","project"?,"session"?,"time"}` |
| `away` | device | `{"host","mode":"auto"\|"on"\|"off","time"}` |
| `settings_change` | device (normal key) | `{"id","host","revision","defaults","projects":[{"id","values"}],"created","expires"}` |

RPC IDs (`sync`, `timeline`) are `NewRandomID("rpc_")`. Command IDs are `NewRandomID("cmd_")`; `text` is trimmed by the browser before signing, 1–8000 characters; `expires` is at most 24 h after `created`. Request IDs (`req_…`) and event IDs (`evt_…`) are chosen by the bridge. A response's `request_hash` is the hex sha256 of the request envelope's payload bytes. Approvals take `approve` or `reject` (`text` optional, a reason); questions take `answer` with non-empty `text`.

Optional `prefill` is an exact editable draft for questions only: valid UTF-8, at most 8000 Unicode code points, without NUL. Empty drafts are allowed. Approvals reject any supplied prefill. The bridge rejects invalid drafts without truncating them. Clients render only the verified value and keep edits by request ID through refreshes. The response hash binds the exact draft too.

### 9.4 What the bridge accepts

Every device frame first passes section 6.2 (pinned device, fresh, unseen, decrypts, inner signer = `from`). Then, before anything reaches a session, an MCP tool or a file:

* **command**: signed by the frame's device (a pinned device); `host` is this host; `created` is at most 2 minutes in the future and `expires` hasn't passed; `id` not seen before (seen IDs are kept until they expire). A replayed ID is not handled again, but the bridge still answers with the command's current item. Any other failure is recorded as a `failed` command item with `"Rejected: …"` and logged, and never reaches the agent.
* **response**: signed with the right key for the request's sensitivity (the WebAuthn scheme for browsers, 9.6); `request` is a request this bridge is still waiting on and `request_hash` matches the payload it signed; the decision fits the request type. A response to a request that is no longer pending is answered with that request's item.
* **cancel**, **delete**: `host` is this host. A cancel stops a command that hasn't been delivered. A delete removes the session (or the project and all its sessions) and its history from the computer; it is refused when its signed `time` is more than 2 minutes in the future, more than 24 hours old, or earlier than the target's creation (so a delayed delete can't erase history recreated since).
* **away**: `host` is this host; newer than the last applied setting (device or local `agentio away`); at most 2 minutes in the future.
* **settings_change**: signed by the device's normal key (no WebAuthn assertion); `host` is this host; `created` at most 2 minutes in the future and `expires` not passed; `id` not seen before (kept until `expires`); the settings file is valid and its revision equals `revision`; every project ID names a project this bridge registered or one already in the file; only known keys with valid values. Anything else is rejected, logged, counted in `agentio doctor` and reported in the next snapshot's `change` with the reason (for example "its settings changed since you looked"). A replayed ID is ignored. Writers of the settings file (`agentio config`, `init`, `uninstall`, the bridge) hold an OS lock across read, check and atomic write.
* **sync**, **timeline**: `host` is this host. Answered with an `update` to that device only.

`agentio doctor` shows the pinned devices and how many frames were rejected.

### 9.5 What the browser accepts

Every host frame first passes section 6.2 (pinned host, fresh, unseen, decrypts, inner signer = `from` = the pinned host ID). Then:

* An `update` counts only if its signed `host` is the frame's host. Everything in it (machine info, projects, sessions, items, deletions, away state) is shown as coming from that computer; the "Unverified" display path no longer exists because the server supplies no content.
* A request item's nested `request` envelope must verify against the same pinned host, with signed `host` = that host, signed `id` = the item's ID and signed `session` = the item's session. Answer controls appear only for such requests.
* A nested `settings` snapshot must verify against the pinned host with signed `host` = that host. Settings controls appear only for a verified snapshot without `error`.
* Reply boxes, Approve/Reject/Answer and push notification actions are offered only for items from a pinned host; a push notification click opens the app, which syncs before showing any control.

The browser's normal key is a non-extractable WebCrypto P-256 CryptoKey in IndexedDB; normal signing has no device-unlock gate. The independent app origin and its JavaScript delivery are trust roots, separate from the untrusted API relay.

### 9.6 Sensitive browser answers (WebAuthn)

The claim and the pair envelope include `device_sensitive_origin`, appended to the pairing MAC transcript (section 5). The CLI pins the origin beside the keys and includes it in its signed confirmation; the browser compares it with its own origin. The browser registers a WebAuthn credential with ES256 (`alg: -7`), RP ID equal to the app's hostname, and user verification required. Its public key uses section 4's encoding.

Sensitive browser response envelopes add:

```json
{"webauthn":{"client_data_json":"<base64url>","authenticator_data":"<base64url>"}}
```

`payload` is the usual exact response JSON. The assertion challenge is SHA-256 of
`"agentio/v1/response\n" + payload bytes`. `sig` is the authenticator's DER ES256 signature
of `authenticatorData || SHA256(clientDataJSON)`, as defined by WebAuthn. The bridge checks the pinned sensitive public key,
`type: webauthn.get`, exact challenge, exact pinned origin, RP hash = SHA-256(origin hostname),
UP and UV flags, and no cross-origin/top-origin context. No signature counter is used for
anti-replay: responses are already bound to a unique pending request and its exact hash.
Plain envelopes are refused for sensitive input; WebAuthn assertions are refused on all other paths.
A canceled or unsupported user-verification ceremony sends no response. The authenticator
provider (including credential sync, if enabled) is part of the browser's trust roots.

---

## 10. The bridge: store of record

The bridge keeps all history on the computer, in `AGENTIO_HOME`: `history/<session>.jsonl` (append-only; the latest record of an item wins), `projects.json`, `sessions.json` and `history.json` (the epoch, the sequence counter and deletion tombstones). History stays until the user deletes the session or project (from the browser with a signed `delete`, or `agentio sessions delete`).

### 10.1 Records

Every project, session and item has a `seq`: the value of the bridge's counter when it last changed. The counter only grows. `epoch` is a random ID created with the history; if the history is ever recreated, the epoch changes and browsers start again from scratch.

Project:

```json
{"id":"prj_…","name":"my-app","path":"~/projects/my-app","agents":["claude-code","codex"],"created":1760650000,"last_activity":1760659200,"seq":41}
```

Session:

```json
{"id":"ses_…","project":"prj_…","provider":"claude-code","native_id":"5b1c…","title":"Fix auth bug","status":"active",
 "input":"queue","input_reason":"Available at the next agentio tool call","remote":false,"created":1760650000,"last_activity":1760659200,"seq":57}
```

Item (one entry of a session's timeline; exactly one of `event`, `request`, `command`):

```json
{"id":"evt_…","session":"ses_…","type":"event","time":1760659100,"pos":118,"seq":118,
 "event":{"category":"completed","title":"Tests pass","message":"All 212 tests pass"}}

{"id":"req_…","session":"ses_…","type":"request","time":1760659160,"pos":119,"seq":124,
 "request":{"envelope":Envelope,"status":"approved",
            "response":{"decision":"approve","text":"","time":1760659200,"signer":"dev_…","device":"Alex's browser"}}}

{"id":"cmd_…","session":"ses_…","type":"command","time":1760659150,"pos":120,"seq":126,
 "command":{"text":"Use SQLite.","created":1760659150,"expires":1760745550,"signer":"dev_…","device":"Alex's browser",
            "state":"delivered","state_detail":"Written to the agentio MCP tool result; client receipt is not confirmed","delivery":"queue","updated":1760659152}}
```

`pos` is fixed when the item is created and orders the timeline (oldest first); `seq` changes with the item's state. A request item carries the host-signed request envelope (kind `request`); the browser shows its signed title, body, prefill, options and sensitivity and binds its answer to that envelope's payload hash. Event categories: `info`, `progress`, `completed`, `failed`, `attention`, `approval`, `question`, `warning`. Session `status`: `active` (an MCP connection owns it), `idle`, `ended`.

The bridge truncates titles (200 characters; session titles 120), event messages and request bodies (4000 bytes), and `input_reason` (200) before signing.

Request `status`: `pending`, `approved`, `rejected`, `answered`, `expired`, `canceled`. The first valid response wins.

Command `state` moves strictly forward:

| State | Meaning (what the browser says) |
|---|---|
| `received` | The bridge has it ("On alex-mbp") |
| `pending` | Held for the agent; `state_detail` says when it will see it ("Available at the next agentio tool call") |
| `delivered` | Written to the agentio MCP result transport; client/model receipt is unconfirmed |
| `failed` | Could not be delivered; `state_detail` says why |
| `expired` | Not delivered before `expires` (24 h) |
| `canceled` | Canceled by the user before delivery |

Before the bridge has it, the browser shows "Sending" for a command in its own outbox. Nothing is reported `delivered` before a complete successful MCP stdout write. MCP has no result-receipt protocol; a crash after writing but before acknowledgment may duplicate a message. A session that ends with commands not yet delivered moves them to `failed` (`"The session ended before this could be delivered"`); the user can retry (the browser signs a new command with the same text) or discard (a local dismissal).

`input` says what a reply will do right now: `queue` (it waits for the agent's next agentio MCP tool result) or `unavailable` (with `input_reason`). Replies never start or interrupt a turn.

`remote` is true while the session is in remote control (section 10.7). `input_reason` then reads "Remote control is on: the agent picks it up at its next step", or "The agent is waiting for your message" while an `agentio_wait` call waits.

Session IDs are derived: `ses_` + first 20 chars of lowercase base32(sha256(`host_id|provider|native_id`)). Project IDs: `prj_` + the same over `host_id|path_hash`, where `path_hash` is the hex sha256 of the project's absolute path with symlinks resolved (the key of its entry in the settings file).

### 10.2 Updates

Everything the bridge tells a browser is an `update` envelope:

```json
{"host":"hst_…","time":1760659200,"epoch":"epo_…","reply":"rpc_…",
 "machine":{"name":"alex-mbp","os":"darwin","arch":"arm64","version":"0.4.0"},
 "projects":[Project],"sessions":[Session],"items":[Item],
 "deleted":[{"project":"prj_…","seq":130},{"session":"ses_…","seq":131}],
 "settings":Envelope,"away":{"mode":"auto","time":1760650000,"away":false},
 "full":false,"cursor":131,"more":false,"has_more":false}
```

Every field but `host`, `time` and `epoch` is optional. `reply` is the RPC ID it answers; live updates have none. `full`, `cursor` and `more` are set only on `sync` replies, `has_more` only on `timeline` replies. `settings` is the newest notification settings snapshot (section 10.6). `away` is the newest away setting and the effective away state.

Live: whenever a project, session or item changes, or the settings snapshot or away state change, the bridge sends an update with the changed records to every pinned device, with a `push` for new requests and non-progress events. It never sends a live update again: a device that missed one gets it from its next `sync`. While the bridge's own relay connection is down, it keeps the frames it would have sent (sealed again when they go out, `push` included) and sends them once it is connected.

### 10.3 RPC

| Device sends | Bridge answers (to that device only) |
|---|---|
| `sync` `{id, since, epoch}` | `update` with `reply` = `id` |
| `timeline` `{id, session, before, limit}` | `update` with `reply` = `id`, `items` and `has_more` |
| `command` | `update` with the command item (sent to every device) |
| `response` | `update` with the request item (every device) |
| `cancel` | `update` with the command item (every device) |
| `delete` | `update` with `deleted` (every device) |
| `away` | `update` with `away` (every device) |
| `settings_change` | `update` with the new `settings` snapshot, whose `change` reports the outcome (every device) |

**sync**: if `epoch` isn't the bridge's, `since` is 0, or `since` is older than the oldest remembered deletion, the reply is a **full snapshot** (`full: true`), which replaces the device's whole mirror of this host: `machine`, every project and session, every pending request, the newest items of each session (at most 50 each, oldest dropped first so the reply stays within about 256 KB; older ones come from `timeline`), `settings`, `away`, and `cursor` = the current counter. Otherwise it carries `machine`, `settings`, `away`, and every project, session, item and deletion with `seq` > `since`, in `seq` order, at most 256 KB of payload per reply; `cursor` is the highest `seq` included and `more` is true when there is more, which the device fetches with another `sync` from that cursor. Deletions are remembered for 30 days.

**timeline**: the `limit` (at most 200) newest items of `session` with `pos` < `before` (0 means the newest), oldest first, and `has_more` when older ones exist.

### 10.4 The bridge's outbox

The bridge's outbox holds only frames waiting for its own relay connection. It never resends a frame a browser didn't receive (`offline`): browsers always `sync` when they connect and when a host comes online. Nothing depends on the server holding anything.

### 10.5 Away

`auto` = away when the machine has had no keyboard/mouse input for 5 minutes (where the bridge can measure that: macOS and Linux desktops; elsewhere `auto` behaves as `off`). The bridge applies the newest valid device setting, and `agentio away` on the computer overrides any setting made before it. Away state informs explicit MCP status calls; agentio does not intercept native permission prompts.

### 10.6 Notification settings

The settings file on the computer (`settings.toml`) is the source of truth; only the bridge verifies and applies a change. The bridge includes its signed snapshot in sync replies and sends a live update whenever the file's revision changes (it checks every 5 seconds, so `agentio config`, `init`, `uninstall` and hand edits all reach the browser) and after handling a change.

| Kind | Payload |
|---|---|
| `settings` | `{"host","revision","time","idle_time","builtin","defaults","projects":[{"id","path","values"}],"change"?,"error"?}` |
| `settings_change` | `{"id","host","revision","defaults","projects":[{"id","values"}],"created","expires"}` |

Notification settings (`notify`, `progress`, `requests`; values `always`, `never` or a whole-second duration from 1 s to 24 h, as `agentio config` takes them):

* `revision`: hex SHA-256 of the settings file's exact bytes (of no bytes when it doesn't exist). Any byte change, including a hand edit or a comment, makes a new revision.
* `builtin`, `defaults` and `values` map keys to stored values; `builtin` carries the built-in defaults so the browser doesn't hard-code them. A snapshot's `projects` lists only projects with overrides, with their display path (`~/pro/x`); raw paths never travel.
* `idle_time`: whether the computer can measure keyboard/mouse idle time (the browser shows the same caveat as `agentio config` when it can't).
* `error`: the file doesn't parse or validate. The snapshot then carries no values, the browser shows the error with no controls, and the bridge rejects changes until it is fixed.
* `change`: the outcome of the newest device change the bridge handled, `{"id","result":"applied"|"rejected","reason"}`.
* `settings_change` is the complete desired file: `defaults` replaces `[defaults]`, `projects` replaces every project table, and a project left out has no override. `id` is `chg_` + `NewRandomID`; `expires` = `created` + 7 days. The browser builds it only from a verified snapshot, its own pending change and the user's input, against the snapshot's `revision`.

### 10.7 Remote control

Remote control is off for every session until its agent turns it on with `agentio_remote`, which the MCP instructions allow only when the user asks to continue from their phone. Turning it on sets the session's `remote`, adds an `info` event "Remote control on" and sends it with a push notification that opens the session; turning it off adds "Remote control off" without one. It goes off when the session ends. While it is on, the session's notifications, questions and approvals are sent at once whatever the project's `notify` and `requests` settings say (the user asked for the session on their phone); `progress` keeps its setting. Nothing about the wire changes: the user's messages are ordinary commands, delivered at the next agentio tool call. The agent also waits for them with the `agentio_wait` MCP tool instead of ending its turn.

---

## 11. The browser

### 11.1 Mirror

IndexedDB holds, per pinned host, the decrypted mirror of what it has synced: machine info, projects, sessions, items, the settings snapshot, the away state, the `epoch`, the `cursor` and when it last synced. Records merge by `seq` (a higher `seq` replaces a lower one; deletions remove and leave a tombstone until a sync reply's cursor passes them); a full snapshot replaces the host's mirror (keeping local read state). Only `sync` replies move the cursor, so a missed live update is always fetched again, and a live record, or a record of an incremental sync reply, whose `seq` is at or below the cursor is ignored: the synced state already reflects or supersedes it (older items come from `timeline`). A session whose project, or an item whose session or project, isn't in the mirror is ignored in anything but a full snapshot. A tab accepts a sync reply only while the mirror is still in the epoch the request was sent with, so a reply that another tab's newer snapshot has overtaken never moves the mirror back. Read state (unread counts, "mark all read") is local to the browser. Logging out or unpairing clears the mirror and the outbox.

### 11.2 Connecting

On connect the browser sends `sync` (with its cursor and epoch) to every pinned host that `hello` reports online, and again whenever `presence` reports a host online, then renders from the mirror. A host that is offline shows its cached state, labelled with when it was last synced. Session threads load older items with `timeline`.

### 11.3 Notifications

Notifications come from Web Push (section 7.3) when no tab is open, and from live updates when one is. The browser's notification sound is a local preference.

### 11.4 Outbox

Signed commands, responses, cancels, deletes, away settings and settings changes go into an outbox in IndexedDB. Each entry is sealed into a new frame and sent when its host is online (on `hello`, on `presence` online, and when created), and stays until a signed update from the host confirms it:

| Entry | Confirmed by |
|---|---|
| command | an item for that command ID |
| response | the request item no longer `pending` |
| cancel | the command item in a final state |
| delete | `deleted` naming that project or session, or it being absent after a full sync |
| away | `away.time` at least the entry's `time` |
| settings_change | a snapshot whose `change.id` is the entry's `id` |

Commands and deletes keep 24 hours (the bridge refuses older deletes) and settings changes their 7 days; expired entries are failed locally ("Not sent: alex-mbp was offline until it expired"). The bridge de-duplicates by ID, so sending an entry again is always safe.

---

## 12. Conventions

* The server is an API and relay only. It serves no web pages, installers or binaries: `GET /` is `404` with code `no_web_pages`, and other unknown paths `404` with `not_found`. The web app is a separate static site that calls the server cross-origin (every response allows any origin; credentials are tokens, never cookies). It takes the one server it talks to from `/agentio.json` on its own origin, `{"server": "https://agentio.example.com"}`, written by whoever hosts it (docs/self-hosting.md), never from the server: nothing the server says reaches a command the app shows or the server a pairing code must name (§5).
* Lists are wrapped (`{"hosts":[]}`) and never `null`.
* Request logging records the method, the route template, the status and the duration: never bodies, query strings, frames or tokens.
* Self-hosted users run `agentio login --server https://their.server`.
