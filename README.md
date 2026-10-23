# agentio server

The server behind [agentio](https://agentio.sh): accounts, pairing, and a sealed relay that passes end-to-end encrypted notifications, replies and approvals between a computer's coding agents and the user's browsers. It stores no content and holds no key that can decrypt or sign any. One Go binary with an SQLite database, no hosted account or subscription needed.

```sh
cd deploy/compose    # set AGENTIO_PUBLIC_URL in docker-compose.yml first
docker compose up -d # builds the image from this tree; http://localhost:2586
```

[Self-hosting](docs/self-hosting.md) · [API and protocol](docs/api.md)

## What this repository is

This is the published source of the server and of the wire protocol it shares with the clients. agentio is developed in a private repository; this tree is exported from it, unchanged, for every release. Changes contributed here are applied there first and appear here with the next export.

`build.env` names the release and the private source revision this tree was exported from, and `agentio-server version` prints both. There are no prebuilt server binaries: self-host by building the container from this tree ([docs/self-hosting.md](docs/self-hosting.md)).

The `agentio` CLI and the web app are proprietary and not part of this repository. They work with any server built from it: `agentio login --server https://your.server`, and the web app is in every release as a static site you host with a file naming your server ([docs/self-hosting.md](docs/self-hosting.md#the-web-app)). [docs/api.md](docs/api.md) documents everything they send and receive, so you can also write your own clients.

## Layout

| Path | What |
|---|---|
| `server/` | The server: accounts, pairing, the sealed relay, Web Push forwarding |
| `protocol/` | Wire types, signing and sealing shared by the server and the clients, with the shared test vectors |
| `deploy/` | Dockerfile, Compose file, example configuration |
| `docs/` | Self-hosting guide, API and protocol |

## Development

```sh
make test     # go vet and race tests
make server   # bin/agentio-server
make docker   # agentio/server:<version> (PLATFORM=linux/amd64 for x86 servers)
```

## Security

The server is untrusted by design. Every frame between a computer and a browser is signed and then encrypted for that pair with keys they exchanged through the terminal's pairing code, so someone who fully controls the server can neither read what passes through it nor get any text or decision into a paired machine's agents (docs/api.md §5, §6, §9). It can still drop or delay frames and see which machines and browsers talk, when and how much.

Report vulnerabilities to security@agentio.sh; see [agentio.sh/security](https://agentio.sh/security/).

## License

[Apache License 2.0](LICENSE).

<p align="center">
  <a href="https://zazencodes.com/?utm_source=github&utm_medium=referral&utm_campaign=agentio-server">
    <img
      src="docs/assets/zazencodes-banner.png"
      alt="ZazenCodes — Engineering for the Agentic Era"
      width="100%"
    >
  </a>
  <br>
  Created by <a href="https://zazencodes.com/">ZazenCodes</a>
</p>
