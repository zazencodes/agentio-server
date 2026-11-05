# Changelog

## [Unreleased]

## [0.3.4] - 2026-11-05

### Added

- Added an optional `quiet` field to timeline events in the API docs and protocol, marking an event that gets no push or alert; the server is unchanged, since it never reads events

## [0.3.3] - 2026-11-05

### Changed

- Changed the API docs to say the computer may start an agent's turn for a reply, with a nudge that doesn't contain it; the server and the wire are unchanged

## [0.3.2] - 2026-11-05

### Changed

- No changes to the server: this release keeps its version in step with the CLI

## [0.3.1] - 2026-11-05

### Changed

- Changed the pairing confirmation in the API docs to default to yes

## [0.3.0] - 2026-11-04

### Added

- Added sealed protocol read/archive actions, declined and stopped request outcomes, and cooperative stop commands with shared session read and stop state

### Breaking Changes

- Changed the pairing MAC to leave out the host key, which the browser now learns from the sealed confirmation: browsers and computers must both be updated to pair

### Changed

- Changed the pairing code in the API docs to a link to the web app's `/pair` page with the pairing ID and secret in its fragment, which the CLI also shows as a QR code. Self-hosters now pass `agentio login --server … --app …` with the web app they host
- Changed the web app's `Permissions-Policy` in the self-hosting docs to allow the camera on the app's own origin (`camera=(self)`), for its pairing QR scanner

## [0.2.0] - 2026-10-24

### Added

- Added the `remote` field to the protocol's session record, for remote control. The server relays sessions sealed, so it neither reads nor stores the field

## [0.1.0] - 2026-10-23

### Added

- First public release: the core agentio server (accounts, pairing, the sealed relay, Web Push, rate limits, SQLite, admin commands), the shared protocol, and self-hosting with Docker Compose
