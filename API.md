# API

## WebSocket

- **URL:** `wss://spfpsfr.online/assets/chat/socket`
- Messages are JSON objects:
  - `HELLO {did}` → server challenges with `CHALLENGE {nonce}`
  - `AUTH {did, signature, id_pub_jwk, dh_pub_jwk}` → server replies `READY`
  - `SEND {to, payload}` → deliver encrypted payload to peer
  - Server pushes `RECV {id, from, payload}`

## SSE / HTTP Fallback

If WebSocket is unavailable, the client falls back to HTTP endpoints:

- `GET https://spfpsfr.online/stream` — Server‑Sent Events stream of the same JSON messages as WebSocket `RECV`.
- `POST https://spfpsfr.online/send` — send JSON messages identical to WebSocket frames.
- `GET https://spfpsfr.online/events` — long‑poll endpoint returning pending events.

All payloads must be JSON and not exceed 64 KB.
